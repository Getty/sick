#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET;
use JSON::MaybeXS ();
use POSIX qw( strftime );
use lib 't/lib';

use SICK::Bundle;
use SICK::CLI;
use SICK::OpenSSL;
use SICK::State;
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# sick check --format json|prometheus [--output FILE] and sick inventory,
# through SICK::CLI. A step-ca section whose step is t/bin/fake-step (it
# answers "ca health" and records the call), files devices whose
# certificates are made here, records written with SICK::State the way a
# run writes them. The only socket is a closed port on 127.0.0.1.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );
my $scratch = $tmp.'/scratch';
mkdir $scratch or die 'mkdir: '.$!;
local $ENV{TMPDIR} = $scratch;
delete local $ENV{SICK_CONFIG};

my $step = $tmp.'/step';
( my $source = slurp('t/bin/fake-step') ) =~ s/\A#![^\n]*\n/#!$^X\n/;
spew( $step, $source );
chmod 0755, $step or die 'chmod: '.$!;
my $step_log = $tmp.'/step.log';
local $ENV{FAKE_STEP_LOG} = $step_log;
delete local $ENV{FAKE_STEP_EXIT};
delete local $ENV{FAKE_STEP_STDERR};

sub step_calls {
  return [] unless -e $step_log;
  my @calls = map { JSON::MaybeXS->new->decode($_) } split /\n/, slurp($step_log);
  unlink $step_log;
  return \@calls;
}

my $closed_port = do {
  my $listener = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 )
    or plan skip_all => 'cannot listen on 127.0.0.1: '.$!;
  my $port = $listener->sockport;
  close $listener;
  $port;
};

sub cli {
  my ( @argv ) = @_;
  my ( $out, $err ) = ( q{}, q{} );
  open my $out_fh, '>', \$out or die $!;
  open my $err_fh, '>', \$err or die $!;
  my $code = SICK::CLI->new( out => $out_fh, err => $err_fh, env => {} )->run(@argv);
  close $out_fh;
  close $err_fh;
  return ( $code, $out, $err );
}

sub iso { strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime $_[0] ) }

# the CA: a root for long, an intermediate that ends soon, and a stranger
my $pki = $tmp.'/pki';
mkdir $pki or die 'mkdir: '.$!;
my $root  = new_ca( dir => $pki, name => 'root',  cn => 'Example Root CA', days => 1000 );
my $inter = new_ca( dir => $pki, name => 'inter', cn => 'Example Intermediate CA', issuer => $root, days => 20 );
my $other = new_ca( dir => $pki, name => 'other', cn => 'Other Root CA' );
my $root_bundle  = SICK::Bundle->new( cert => $root->{pem} );
my $inter_bundle = SICK::Bundle->new( cert => $inter->{pem} );

# the certificate a device presents: cert.pem in its directory, alone
my %live;
sub presents {
  my ( $name, $ca, %arg ) = @_;
  my $dir = $tmp.'/dev/'.$name;
  File::Path::make_path($dir);
  my $cert = new_cert( ca => $ca, dir => $pki, name => 'leaf-'.$name, cn => $name.'.example.internal',
    san => 'DNS:'.$name.'.example.internal', days => $arg{days} || 60 );
  spew( $dir.'/cert.pem', $cert->{cert_pem} );
  return $live{$name} = SICK::Bundle->new( cert => $cert->{cert_pem} );
}
use File::Path ();

presents( 'web',     $inter );
presents( 'stale',   $inter );
presents( 'foreign', $other );

sub device {
  my ( $name, %extra ) = @_;
  return '  '.$name.":\n    type: files\n    names: [".$name.".example.internal]\n    dir: ".$tmp.'/dev/'.$name."\n"
    .join( q{}, map { '    '.$_.': '.$extra{$_}."\n" } sort keys %extra );
}

my $number = 0;
sub list {
  my ( $devices, %opt ) = @_;
  my $path  = $tmp.'/list'.++$number.'.yml';
  my $state = $opt{state} || $tmp.'/state'.$number;
  my $ca = $opt{selfsigned}
    ? "ca:\n  type: selfsigned\n  dir: $tmp/selfsigned\n"
    : "ca:\n  url: https://ca.example.internal:9000\n  root: $root->{cert}\n  intermediates: $inter->{cert}\n"
    ."  provisioner: sick\n  password_file: $tmp/no-such-password\n  step: $step\n";
  spew( $path, $ca."defaults:\n  lifetime: 90d\n  renew_before: 10d\n  key: ec256\nstate: $state\ndevices:\n".$devices );
  return $path;
}

my $gone = device( 'gone', host => '127.0.0.1', port => $closed_port );
my $owner = 'NOC "Team" \\ Raum 2';
my $all  = device( 'web', owner => q{'}.$owner.q{'} ).device('stale').device('empty').device('foreign').$gone;
my $state_dir = $tmp.'/state';
my $path = list( $all, state => $state_dir );

# records the way sick run writes them
my $state = SICK::State->new( dir => $state_dir );
my %web_issue = (
  time               => '2026-09-01T04:00:00Z',
  serial             => $live{web}->serial,
  fingerprint_sha256 => $live{web}->fingerprint_sha256,
  names              => ['web.example.internal'],
  not_after          => iso( $live{web}->not_after ),
  issuer             => 'CN=Example Intermediate CA'
);
$state->update( 'web', {
  device     => 'web',
  last_check => {
    time => '2026-10-01T04:00:00Z', status => 'ok', detail => 'valid until ...',
    fingerprint_sha256 => $live{web}->fingerprint_sha256, not_after => iso( $live{web}->not_after )
  },
  last_issue           => {%web_issue},
  last_deploy          => { time => '2026-09-01T04:00:05Z', result => 'ok', error => undef },
  last_success         => '2026-10-01T04:00:00Z',
  consecutive_failures => 0,
  next_attempt         => undef
} );
my $stale_issue_fp = 'ab' x 32;
$state->update( 'stale', {
  device     => 'stale',
  last_check => {
    time => '2026-10-02T04:00:00Z', status => 'expiring', detail => 'valid until ...',
    fingerprint_sha256 => $live{stale}->fingerprint_sha256, not_after => iso( $live{stale}->not_after )
  },
  last_issue => {
    time => '2026-10-02T04:00:01Z', serial => 'ABCDEF01', fingerprint_sha256 => $stale_issue_fp,
    names => ['stale.example.internal'], not_after => '2027-01-01T00:00:00Z', issuer => 'CN=Example Intermediate CA'
  },
  last_deploy          => { time => '2026-10-02T04:00:02Z', result => 'failed', error => 'deploy failed: no room' },
  last_failure         => { time => '2026-10-02T04:00:02Z', error => 'deploy failed: no room' },
  consecutive_failures => 3,
  next_attempt         => '2026-10-02T08:00:00Z'
} );
$state->update( 'gone', {
  device     => 'gone',
  last_check => { time => '2026-10-03T04:00:00Z', status => 'unreachable', detail => 'refused', fingerprint_sha256 => undef, not_after => undef },
  last_issue => {
    time => '2026-08-01T04:00:00Z', serial => '0123', fingerprint_sha256 => 'cd' x 32,
    names => ['gone.example.internal'], not_after => '2026-11-01T00:00:00Z', issuer => 'CN=Example Intermediate CA'
  },
  last_deploy          => { time => '2026-08-01T04:00:03Z', result => 'ok', error => undef },
  consecutive_failures => 0
} );

my @everything;    # every output, for the look for key material at the end

sub by_device { return { map { $_->{device} => $_ } @{ $_[0]{devices} } } }

sub parse_prometheus {
  my ( $text ) = @_;
  my ( %help, %type, @samples, @problems );
  for my $line ( split /\n/, $text ) {
    if ( $line =~ /\A# HELP ([a-zA-Z_:][a-zA-Z0-9_:]*) (.+)\z/ ) { push @problems, 'HELP twice: '.$1 if $help{$1}++; next }
    if ( $line =~ /\A# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (gauge|counter)\z/ ) {
      push @problems, 'TYPE twice: '.$1 if $type{$1};
      $type{$1} = $2;
      next;
    }
    my ( $name, $labels, $value ) = $line =~ /\A([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (-?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?)\z/
      or do { push @problems, 'not a sample: '.$line; next };
    push @problems, 'sample before its TYPE: '.$name unless $type{$name} && $help{$name};
    my %label;
    if ( defined $labels ) {
      while ( $labels =~ /\G([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\[\\"n])*)"(?:,|\z)/gc ) {
        my ( $key, $raw ) = ( $1, $2 );
        $raw =~ s/\\(.)/$1 eq 'n' ? "\n" : $1/ge;
        $label{$key} = $raw;
      }
      push @problems, 'labels not parsed: '.$labels unless ( pos($labels) || 0 ) == length $labels;
    }
    push @samples, { name => $name, labels => \%label, value => $value };
  }
  # every family in one block, every series once
  my ( @blocks, %series );
  for my $sample (@samples) {
    push @blocks, $sample->{name} unless @blocks && $blocks[-1] eq $sample->{name};
    my $key = $sample->{name}.'|'.join( ',', map { $_.'='.$sample->{labels}{$_} } sort keys %{ $sample->{labels} } );
    push @problems, 'series twice: '.$key if $series{$key}++;
  }
  my %block;
  push @problems, map { 'family in two blocks: '.$_ } grep { $block{$_}++ } @blocks;
  return ( \@samples, \@problems, \%type );
}

# value of one series, undef when it is not there
sub value_of {
  my ( $samples, $name, %labels ) = @_;
  my @found = grep {
    my $s = $_;
    $s->{name} eq $name && !grep { !defined $s->{labels}{$_} || $s->{labels}{$_} ne $labels{$_} } keys %labels
  } @$samples;
  return @found ? $found[0]{value} : undef;
}

subtest 'the table is the table it was' => sub {
  my $plain = list( device('empty').device('foreign'), state => $state_dir );
  # a record that cannot be read: the table does not read records
  spew( $state_dir.'/devices/foreign.json', "{oops\n" );
  step_calls();
  my ( $code, $out, $err ) = cli( '--config', $plain, 'check' );
  is $code, 0, 'exit code 0';
  my @lines = split /\n/, $out;
  is $lines[0], 'DEVICE   STATUS      RENEW  DETAIL', 'the header';
  is_deeply [ sort @lines[ 1 .. $#lines ] ], [
    'empty    missing     yes    the device presents no certificate',
    'foreign  foreign-ca  yes    issued by CN=Other Root CA'
  ], 'the rows, byte for byte';
  is $err, q{}, 'nothing on standard error: no record was read';
  is_deeply step_calls(), [], 'the CA was not asked';
  my @table = cli( '--config', $plain, 'check', '--format', 'table' );
  is_deeply \@table, [ $code, $out, $err ], '--format table is the same';
  unlink $state_dir.'/devices/foreign.json';
  push @everything, $out;
};

subtest 'json' => sub {
  step_calls();
  my $before = time;
  my ( $code, $out, $err ) = cli( '--config', $path, 'check', '--format', 'json' );
  my $after = time;
  push @everything, $out, $err;
  is $code, 1, 'exit code 1: a device could not be checked, as with the table';
  is $err, q{}, 'nothing on standard error';
  like $out, qr/\A\{\n   "ca" : \{/, 'pretty and canonical';
  my $data = JSON::MaybeXS->new->decode($out);
  is_deeply [ sort keys %$data ], [qw( ca devices generated_at generated_at_epoch )], 'the top level';
  ok $data->{generated_at_epoch} >= $before && $data->{generated_at_epoch} <= $after, 'generated_at_epoch is now';
  is $data->{generated_at}, iso( $data->{generated_at_epoch} ), 'generated_at is the same time in ISO 8601 UTC';

  my $ca = $data->{ca};
  is $ca->{type}, 'step-ca', 'ca.type';
  ok JSON::MaybeXS::is_bool( $ca->{reachable} ) && $ca->{reachable}, 'ca.reachable is true';
  is $ca->{detail}, undef, '... without a detail';
  is_deeply $ca->{root}, {
    subject            => 'CN=Example Root CA',
    not_after          => iso( $root_bundle->not_after ),
    not_after_epoch    => $root_bundle->not_after,
    fingerprint_sha256 => $root_bundle->fingerprint_sha256
  }, 'ca.root';
  is_deeply $ca->{intermediates}, [ {
    subject         => 'CN=Example Intermediate CA',
    not_after       => iso( $inter_bundle->not_after ),
    not_after_epoch => $inter_bundle->not_after
  } ], 'ca.intermediates';
  is_deeply [ map { [ $_->{command}, $_->{flags} ] } @{ step_calls() } ],
    [ [ 'health', { '--ca-url' => ['https://ca.example.internal:9000'], '--root' => [ $root->{cert} ] } ] ],
    'step ca health was asked once, with the URL and the root';

  my $device = by_device($data);
  is_deeply [ sort keys %$device ], [qw( empty foreign gone stale web )], 'every device';
  my @keys = qw( chain_not_after chain_not_after_epoch consecutive_failures detail device host last_issue
    last_success last_success_epoch live matches_last_issue names next_attempt next_attempt_epoch owner port renew
    renew_before_seconds state_error status type );
  is_deeply [ sort keys %{ $device->{$_} } ], [ sort @keys ], 'the fields of '.$_ for sort keys %$device;

  my $web = $device->{web};
  is_deeply [ @$web{qw( device type status host port renew_before_seconds )} ], [ 'web', 'files', 'ok', undef, 443, 864000 ],
    'web: device, type, status, host, port, renew_before_seconds';
  ok JSON::MaybeXS::is_bool( $web->{renew} ) && !$web->{renew}, '... renew is false';
  like $web->{detail}, qr/^valid until /, '... detail';
  is_deeply $web->{names}, ['web.example.internal'], '... names';
  is $web->{owner}, $owner, '... owner as in the list';
  is $device->{empty}{owner}, undef, 'owner is null for a device without one';
  my $leaf = $live{web};
  my %live = %{ $web->{live} };
  my $remaining = delete $live{remaining_seconds};
  is_deeply \%live, {
    fingerprint_sha256 => $leaf->fingerprint_sha256,
    serial             => $leaf->serial,
    issuer             => 'CN=Example Intermediate CA',
    not_before         => iso( $leaf->not_before ),
    not_before_epoch   => $leaf->not_before,
    not_after          => iso( $leaf->not_after ),
    not_after_epoch    => $leaf->not_after,
    lifetime_seconds   => $leaf->not_after - $leaf->not_before
  }, '... live: the certificate it presents';
  ok $remaining <= $leaf->not_after - $before && $remaining >= $leaf->not_after - $after, '... remaining_seconds';
  is $web->{chain_not_after_epoch}, $inter_bundle->not_after, '... chain_not_after is the end of the intermediate';
  is $web->{chain_not_after}, iso( $inter_bundle->not_after ), '... also in ISO 8601';
  ok $web->{chain_not_after_epoch} < $web->{live}{not_after_epoch}, '... which ends before the certificate does';
  ok JSON::MaybeXS::is_bool( $web->{matches_last_issue} ) && $web->{matches_last_issue}, '... matches_last_issue is true';
  is_deeply $web->{last_issue}, \%web_issue, '... last_issue as on record';
  is_deeply [ @$web{qw( last_success last_success_epoch consecutive_failures next_attempt next_attempt_epoch state_error )} ],
    [ '2026-10-01T04:00:00Z', 1790827200, 0, undef, undef, undef ], '... and the rest of the record';

  my $stale = $device->{stale};
  is $stale->{status}, 'ok', 'stale: its certificate is fine';
  ok JSON::MaybeXS::is_bool( $stale->{matches_last_issue} ) && !$stale->{matches_last_issue},
    '... but it is not the certificate issued last: matches_last_issue is false';
  is $stale->{chain_not_after_epoch}, $inter_bundle->not_after, '... chain_not_after';
  is_deeply [ @$stale{qw( consecutive_failures next_attempt next_attempt_epoch last_success )} ],
    [ 3, '2026-10-02T08:00:00Z', 1790928000, undef ], '... failures, back-off, no success';

  my $empty = $device->{empty};
  is_deeply [ @$empty{qw( status live chain_not_after matches_last_issue last_issue consecutive_failures last_success )} ],
    [ 'missing', undef, undef, undef, undef, 0, undef ], 'empty: missing, nothing live, no record';
  ok $empty->{renew}, '... renew is true';

  my $foreign = $device->{foreign};
  is $foreign->{status}, 'foreign-ca', 'foreign: foreign-ca';
  is $foreign->{live}{issuer}, 'CN=Other Root CA', '... live names the other issuer';
  is $foreign->{chain_not_after}, undef, '... and there is no chain to our root';
  is $foreign->{matches_last_issue}, undef, '... no record, no comparison';

  my $gone = $device->{gone};
  is_deeply [ @$gone{qw( status renew live matches_last_issue chain_not_after host port )} ],
    [ 'unreachable', undef, undef, undef, undef, '127.0.0.1', $closed_port ], 'gone: unreachable, nothing known';
  like $gone->{detail}, qr/^127\.0\.0\.1:$closed_port: \S/, '... detail says why';
  is $gone->{last_issue}{serial}, '0123', '... the record is there all the same';
};

subtest 'prometheus' => sub {
  my $odd_name = 'odd "one" \\ here';
  my $odd = list( $all."  'odd \"one\" \\ here':\n    type: files\n    names: [odd.example.internal]\n    dir: $tmp/dev/odd\n",
    state => $state_dir );
  my ( $code, $out, $err ) = cli( '--config', $odd, 'check', '--format', 'prometheus' );
  push @everything, $out, $err;
  is $code, 1, 'exit code 1, as with the table';
  is $err, q{}, 'nothing on standard error';
  like $out, qr/\n\z/, 'ends with a newline';
  my ( $samples, $problems, $type ) = parse_prometheus($out);
  is_deeply $problems, [], 'the exposition format: HELP and TYPE before each family, one block per family, each series once';
  is_deeply [ grep { $type->{$_} ne 'gauge' } sort keys %$type ], [], 'every metric is a gauge';
  is_deeply [ sort keys %$type ], [ sort qw(
    sick_check_timestamp_seconds sick_ca_up sick_ca_certificate_not_after_seconds sick_device_info
    sick_device_reachable sick_device_renew_due sick_certificate_not_after_seconds
    sick_certificate_remaining_seconds sick_certificate_lifetime_seconds sick_device_renew_before_seconds
    sick_chain_not_after_seconds sick_device_matches_last_issue sick_device_consecutive_failures
    sick_device_last_success_timestamp_seconds ) ], 'the metrics';

  ok abs( value_of( $samples, 'sick_check_timestamp_seconds' ) - time ) < 60, 'sick_check_timestamp_seconds';
  is value_of( $samples, 'sick_ca_up' ), 1, 'sick_ca_up 1';
  is value_of( $samples, 'sick_ca_certificate_not_after_seconds', role => 'root', subject => 'CN=Example Root CA' ),
    $root_bundle->not_after, 'the end of the root';
  is value_of( $samples, 'sick_ca_certificate_not_after_seconds', role => 'intermediate', subject => 'CN=Example Intermediate CA' ),
    $inter_bundle->not_after, 'the end of the intermediate';

  my %status = ( web => 'ok', stale => 'ok', empty => 'missing', foreign => 'foreign-ca', gone => 'unreachable', $odd_name => 'missing' );
  for my $name ( sort keys %status ) {
    is value_of( $samples, 'sick_device_info', device => $name, type => 'files', status => $status{$name} ), 1,
      'sick_device_info of '.$name;
    is value_of( $samples, 'sick_device_renew_before_seconds', device => $name ), 864000, '... renew_before';
  }
  like $out, qr/^sick_device_info\{device="odd \\"one\\" \\\\ here",/m, 'label values are escaped';
  my @info = grep { $_->{name} eq 'sick_device_info' } @$samples;
  is_deeply [ map { $_->{labels}{device} } grep { exists $_->{labels}{owner} } @info ], ['web'],
    'only the device with an owner has the label owner';
  is value_of( $samples, 'sick_device_info', device => 'web', owner => $owner ), 1, '... which is the owner of the list';
  like $out, qr/^sick_device_info\{device="web",type="files",status="ok",owner="NOC \\"Team\\" \\\\ Raum 2"\} 1$/m,
    '... escaped like the other labels, after status';

  is value_of( $samples, 'sick_device_reachable', device => 'gone' ), 0, 'gone is not reachable';
  is value_of( $samples, 'sick_device_reachable', device => 'web' ),  1, 'web is';
  is value_of( $samples, 'sick_device_renew_due', device => 'web' ),   0, 'web is not due';
  is value_of( $samples, 'sick_device_renew_due', device => 'empty' ), 1, 'empty is';
  is value_of( $samples, 'sick_device_renew_due', device => 'gone' ), undef, 'gone: unknown, so no value';

  for my $name (qw( web stale foreign )) {
    is value_of( $samples, 'sick_certificate_not_after_seconds', device => $name ), $live{$name}->not_after,
      'certificate metrics of '.$name.': not_after';
    is value_of( $samples, 'sick_certificate_lifetime_seconds', device => $name ),
      $live{$name}->not_after - $live{$name}->not_before, '... lifetime';
    ok value_of( $samples, 'sick_certificate_remaining_seconds', device => $name ) > 50 * 86400, '... remaining';
  }
  for my $name ( 'empty', 'gone', $odd_name ) {
    is( ( grep { $_->{name} =~ /\Asick_certificate_/ && $_->{labels}{device} eq $name } @$samples ), 0,
      'no certificate metrics for '.$name.', which presents none' );
  }
  is value_of( $samples, 'sick_chain_not_after_seconds', device => 'web' ), $inter_bundle->not_after, 'chain of web';
  is value_of( $samples, 'sick_chain_not_after_seconds', device => 'foreign' ), undef, '... none for foreign';
  is value_of( $samples, 'sick_device_matches_last_issue', device => 'web' ),   1, 'web matches its last issue';
  is value_of( $samples, 'sick_device_matches_last_issue', device => 'stale' ), 0, 'stale does not';
  is value_of( $samples, 'sick_device_matches_last_issue', device => $_ ), undef, '... no value for '.$_
    for 'empty', 'foreign', 'gone';
  is value_of( $samples, 'sick_device_consecutive_failures', device => 'stale' ), 3, 'stale: 3 failures';
  is value_of( $samples, 'sick_device_consecutive_failures', device => 'empty' ), 0, 'empty: 0';
  is value_of( $samples, 'sick_device_last_success_timestamp_seconds', device => 'web' ), 1790827200, 'last success of web';
  is( ( grep { $_->{name} eq 'sick_device_last_success_timestamp_seconds' } @$samples ), 1, '... and of nobody else' );
};

subtest 'a record that cannot be read' => sub {
  my $broken_state = $tmp.'/broken-state';
  my $one = list( device('web'), state => $broken_state );
  File::Path::make_path( $broken_state.'/devices' );
  my $record = spew( $broken_state.'/devices/web.json', "{oops\n" );
  my ( $code, $out, $err ) = cli( '--config', $one, 'check', '--format', 'json' );
  push @everything, $out, $err;
  is $code, 0, 'exit code 0: it changes nothing about the devices';
  is $err, "sick: web: cannot read state record '$record': not valid JSON\n", 'it is said on standard error';
  my $web = JSON::MaybeXS->new->decode($out)->{devices}[0];
  is $web->{state_error}, "cannot read state record '$record': not valid JSON", '... and in state_error';
  is_deeply [ @$web{qw( last_issue matches_last_issue consecutive_failures )} ], [ undef, undef, 0 ], '... the record counts as empty';
  ( $code, $out, $err ) = cli( '--config', $one, 'inventory' );
  like $err, qr/^sick: web: cannot read state record /, 'inventory says it as well';
  is $code, 0, '... with exit code 0';
  step_calls();
};

subtest 'a CA that does not answer' => sub {
  my $one = list( device('web'), state => $state_dir );
  local $ENV{FAKE_STEP_EXIT}   = 1;
  local $ENV{FAKE_STEP_STDERR} = "client GET https://ca.example.internal:9000/health failed: dial tcp 192.0.2.9:9000: connect: connection refused\n";
  my ( $code, $out, $err ) = cli( '--config', $one, 'check', '--format', 'json' );
  push @everything, $out, $err;
  is $code, 0, 'exit code 0: the devices could be checked';
  my $data = JSON::MaybeXS->new->decode($out);
  ok JSON::MaybeXS::is_bool( $data->{ca}{reachable} ) && !$data->{ca}{reachable}, 'ca.reachable is false';
  is $data->{ca}{detail}, 'step ca health failed (exit 1): client GET https://ca.example.internal:9000/health failed: dial tcp 192.0.2.9:9000: connect: connection refused',
    '... and the detail says why, in the words of step';
  ( $code, $out, $err ) = cli( '--config', $one, 'check', '--format', 'prometheus' );
  push @everything, $out, $err;
  my ($samples) = parse_prometheus($out);
  is value_of( $samples, 'sick_ca_up' ), 0, 'sick_ca_up 0';
  step_calls();
};

subtest 'a self-signed CA has no health' => sub {
  my $self = list( device('empty'), selfsigned => 1 );
  my ( $code, $out, $err ) = cli( '--config', $self, 'check', '--format', 'json' );
  push @everything, $out, $err;
  my $data = JSON::MaybeXS->new->decode($out);
  is $data->{ca}{type}, 'selfsigned', 'ca.type';
  ok exists $data->{ca}{reachable} && !defined $data->{ca}{reachable}, 'ca.reachable is null';
  is $data->{ca}{root}{subject}, 'CN=SICK self-signed CA', 'ca.root';
  is_deeply $data->{ca}{intermediates}, [], 'no intermediates';
  ( $code, $out, $err ) = cli( '--config', $self, 'check', '--format', 'prometheus' );
  push @everything, $out, $err;
  my ($samples) = parse_prometheus($out);
  is( ( grep { $_->{name} eq 'sick_ca_up' } @$samples ), 0, 'no sick_ca_up' );
  is value_of( $samples, 'sick_ca_certificate_not_after_seconds', role => 'root' ) > time, 1, 'the root is there';
};

subtest '--output' => sub {
  my $dir  = $tmp.'/textfile';
  mkdir $dir or die 'mkdir: '.$!;
  my $file = spew( $dir.'/sick.prom', "old\n" );
  my $inode = ( stat $file )[1];
  my $umask = umask 077;
  my ( $code, $out, $err ) = cli( '--config', $path, 'check', '--format', 'prometheus', '--output', $file );
  umask $umask;
  is $code, 1, 'exit code as without --output';
  is $out, q{}, 'nothing on standard output';
  is $err, q{}, 'nothing on standard error';
  my $written = slurp($file);
  push @everything, $written;
  like $written, qr/^sick_check_timestamp_seconds [0-9]+$/m, 'the file holds the metrics';
  my ( undef, $problems ) = parse_prometheus($written);
  is_deeply $problems, [], '... in the exposition format';
  is sprintf( '%04o', ( stat $file )[2] & 07777 ), '0644', 'mode 0644, whatever the umask';
  isnt( ( stat $file )[1], $inode, 'a new file renamed into place, not the old one rewritten' );
  opendir my $dh, $dir or die $!;
  is_deeply [ sort grep { !/\A\.\.?\z/ } readdir $dh ], ['sick.prom'], 'nothing left beside it';

  ( $code, $out, $err ) = cli( '--config', $path, 'check', '--format', 'json', '--output', $dir.'/sick.json' );
  ok eval { JSON::MaybeXS->new->decode( slurp( $dir.'/sick.json' ) ) }, 'json goes there as well';

  my $nowhere = $tmp.'/no-such-dir/sick.prom';
  ( $code, $out, $err ) = cli( '--config', $path, 'check', '--format', 'prometheus', '--output', $nowhere );
  is $code, 1, 'a directory that is not there: exit code 1';
  like $err, qr/^sick: cannot write '\Q$nowhere\E': \S.*\n\z/, '... with path and reason';
  is $out, q{}, '... and nothing on standard output';

  ( $code, $out, $err ) = cli( '--config', $path, 'check', '--format', 'prometheus', '--output', $scratch );
  is $code, 1, 'a directory as the file: exit code 1';
  like $err, qr/^sick: cannot write '\Q$scratch\E': \S/, '... saying why';
  opendir $dh, $tmp or die $!;
  is_deeply [ grep { /\A\.sick-/ } readdir $dh ], [], '... and nothing is left behind';
  step_calls();
};

subtest 'inventory from the records alone' => sub {
  step_calls();
  my ( $code, $out, $err ) = cli( '--config', $path, 'inventory' );
  push @everything, $out, $err;
  is $code, 0, 'exit code 0, although a device is unreachable: nobody was asked';
  is $err, q{}, 'nothing on standard error';
  is_deeply step_calls(), [], 'the CA was not asked either';
  my @lines = split /\n/, $out;
  like $lines[0], qr/^DEVICE +STATUS +SERIAL +FINGERPRINT +UNTIL +DEPLOYED +VERIFIED +ISSUER +NAMES +OWNER$/, 'the header';
  my $web = $live{web};
  my $until = strftime( '%Y-%m-%d %H:%M', gmtime $web->not_after );
  like $out, qr/^web +ok +\Q${\ $web->serial }\E +\Q${\ substr( $web->fingerprint_sha256, 0, 16 ) }\E +\Q$until\E +2026-09-01 04:00 +2026-10-01 04:00 +CN=Example Intermediate CA +web\.example\.internal +\Q$owner\E$/m,
    'web: what was issued, deployed and last seen';
  like $out, qr/^stale +expiring +ABCDEF01 +abababababababab +2027-01-01 00:00 +failed 2026-10-02 04:00 +- +CN=Example Intermediate CA +stale\.example\.internal +-$/m,
    'stale: a failed deployment, the certificate issued last never seen';
  like $out, qr/^gone +unreachable +0123 +cdcdcdcdcdcdcdcd +2026-11-01 00:00 +2026-08-01 04:00 +2026-08-01 04:00 +CN=Example Intermediate CA +gone\.example\.internal +-$/m,
    'gone: the last look is on record';
  like $out, qr/^empty +- +- +- +- +- +- +- +- +-$/m, 'empty: no record, no owner';
  like $out, qr/^foreign +(?:- +){8}-$/m, 'foreign: no record';
  unlike $out, qr/[ \t]\n/, 'no line ends in blanks';

  ( $code, $out, $err ) = cli( '--config', $path, 'inventory', '--format', 'json', 'web', 'empty' );
  push @everything, $out, $err;
  is $code, 0, 'json: exit code 0';
  my $data = JSON::MaybeXS->new->decode($out);
  is_deeply [ sort keys %$data ], [qw( devices generated_at generated_at_epoch )], 'the top level';
  is_deeply [ map { $_->{device} } @{ $data->{devices} } ], [qw( web empty )], 'the devices asked for, in that order';
  is_deeply $data->{devices}[0], {
    device             => 'web',
    type               => 'files',
    owner              => $owner,
    names              => ['web.example.internal'],
    issuer             => 'CN=Example Intermediate CA',
    serial             => $web->serial,
    fingerprint_sha256 => $web->fingerprint_sha256,
    not_after          => iso( $web->not_after ),
    not_after_epoch    => $web->not_after,
    issued             => '2026-09-01T04:00:00Z',
    last_deploy        => { time => '2026-09-01T04:00:05Z', result => 'ok', error => undef },
    last_verified      => '2026-10-01T04:00:00Z',
    last_status        => 'ok',
    last_checked       => '2026-10-01T04:00:00Z',
    state_error        => undef
  }, 'web, from its record';
  is_deeply [ @{ $data->{devices}[1] }{qw( device type owner names serial last_deploy last_verified last_status )} ],
    [ 'empty', 'files', undef, undef, undef, undef, undef, undef ], 'empty: nothing on record, no owner';
  ok exists $data->{devices}[1]{owner}, '... owner is there as null';

  ( $code, $out, $err ) = cli( '--config', $path, 'inventory', 'nobody' );
  is $code, 2, 'a name that is not in the list: exit code 2';
  is $err, "sick: unknown device 'nobody'\n", '... naming it';
};

subtest 'inventory --live' => sub {
  my ( $code, $out, $err ) = cli( '--config', $path, 'inventory', '--live' );
  push @everything, $out, $err;
  is $code, 1, 'exit code 1: a device is unreachable, as with check';
  like( ( split /\n/, $out )[0], qr/^DEVICE +STATUS +LIVE +SERIAL +FINGERPRINT +UNTIL +DEPLOYED +VERIFIED +ISSUER +NAMES +OWNER$/,
    'the header has the column LIVE' );
  like $out, qr/^web +ok +yes +/m, 'web presents the certificate issued last';
  like $out, qr/^stale +ok +no +ABCDEF01 /m, 'stale presents another one: the mismatch shows';
  like $out, qr/^gone +unreachable +\? +0123 /m, 'gone: unknown';
  like $out, qr/^empty +missing +- +/m, 'empty: nothing issued to compare with';

  ( $code, $out, $err ) = cli( '--config', $path, 'inventory', '--live', '--format', 'json', 'web', 'stale' );
  push @everything, $out, $err;
  is $code, 0, 'only reachable devices: exit code 0';
  my $data = JSON::MaybeXS->new->decode($out);
  my $device = by_device($data);
  ok JSON::MaybeXS::is_bool( $device->{web}{matches_last_issue} ) && $device->{web}{matches_last_issue}, 'json: web matches';
  ok !$device->{stale}{matches_last_issue}, '... stale does not';
  is $device->{stale}{live}{fingerprint_sha256}, $live{stale}->fingerprint_sha256, '... live is what it presents';
  is $device->{stale}{fingerprint_sha256}, $stale_issue_fp, '... beside what was issued';
  is $device->{web}{owner}, $owner, '... and the owner';
  is_deeply [ @{ $device->{stale} }{qw( status last_status )} ], [qw( ok expiring )], '... the status of now and the one on record';
};

subtest 'the command line' => sub {
  my %wrong = (
    'an unknown format'               => [ [ 'check', '--format', 'xml' ], "sick: --format: unknown format 'xml' (table, json or prometheus)\n" ],
    'prometheus for inventory'        => [ [ 'inventory', '--format', 'prometheus' ], "sick: --format: unknown format 'prometheus' (table or json)\n" ],
    '--live for check'                => [ [ 'check', '--live' ],                "sick: --live does not go with 'check'\n" ],
    '--output for inventory'          => [ [ 'inventory', '--output', $tmp.'/x' ], "sick: --output does not go with 'inventory'\n" ],
    '--format for run'                => [ [ 'run', '--format', 'json' ],        "sick: --format does not go with 'run'\n" ],
    'an empty --output'               => [ [ 'check', '--output', q{} ],          "sick: --output needs a file\n" ]
  );
  for my $case ( sort keys %wrong ) {
    my ( $argv, $message ) = @{ $wrong{$case} };
    my ( $code, $out, $err ) = cli( '--config', $path, @$argv );
    is $code, 2, $case.': exit code 2';
    is $err, $message."Try 'sick --help'.\n", '... saying why';
    is $out, q{}, '... nothing on standard output';
  }
  my ( $code, $out ) = cli('--help');
  like $out, qr/^  sick \[--config <file>\] check \[--format table\|json\|prometheus\] \[--output <file>\]/m, 'the usage names the formats';
  like $out, qr/^  sick \[--config <file>\] inventory \[--format table\|json\] \[--live\]/m, '... and inventory';
};

subtest 'the alert rules use the metrics there are' => sub {
  my $rules = slurp('contrib/prometheus/sick-alerts.yml');
  my %used = map { $_ => 1 } $rules =~ /\b(sick_[a-z_]+)\b/g;
  my ( $code, $out ) = cli( '--config', $path, 'check', '--format', 'prometheus' );
  my ( undef, undef, $type ) = parse_prometheus($out);
  ok scalar( keys %used ) >= 8, 'the rules use metrics of SICK';
  is_deeply [ grep { !$type->{$_} } sort keys %used ], [], '... and each of them is one sick check writes';
  step_calls();
};

subtest 'no key material anywhere' => sub {
  my $all_out = join "\n", @everything;
  ok length $all_out > 1000, 'there is output to look at';
  unlike $all_out, qr/PRIVATE KEY|-----BEGIN|key\.pem/, 'no key, no PEM, no key file';
};

done_testing;
