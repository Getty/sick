#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Path ();
use File::Temp qw( tempdir );
use IO::Socket::INET;
use lib 't/lib';

use SICK::Bundle;
use SICK::Config;
use SICK::Issuer;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Runner;
use SICK::State;
use SICK::Target::Files;
use JSON::MaybeXS qw( decode_json );
use POSIX qw( strftime );
use Test::SICK::PKI qw( new_ca new_cert new_csr slurp spew );

# SICK::Runner with the SelfSigned issuer and the files target: the four
# steps, and everything that can go wrong between them. Nothing leaves this
# machine; the only socket is a closed port on 127.0.0.1.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

# Every private temporary directory of this test is made in here, so that
# what is left behind can be counted.
my $scratch = $tmp.'/scratch';
mkdir $scratch or die 'mkdir: '.$!;
local $ENV{TMPDIR} = $scratch;

sub leftovers {
  opendir my $dh, $scratch or die 'cannot read '.$scratch.': '.$!;
  return [ sort grep { !/\A\.\.?\z/ } readdir $dh ];
}

sub files_in {
  my ( $dir ) = @_;
  opendir my $dh, $dir or return [];
  return [ sort grep { !/\A\.\.?\z/ } readdir $dh ];
}

sub fingerprint_in {
  my ( $dir ) = @_;
  return SICK::Bundle->from_files( cert => $dir.'/cert.pem' )->fingerprint_sha256;
}

#### targets that misbehave on purpose

my %count;    # what the test targets were asked to do
my %switch;   # how they are told to behave

{
  package SICK::Target::Lazy;    # says it deployed and did nothing
  our @ISA = ('SICK::Target::Files');
  sub deploy { $count{lazy_deploy}++; return }

  package SICK::Target::Fragile;    # dies in deploy as long as it is told to
  our @ISA = ('SICK::Target::Files');

  sub deploy {
    my ( $self, $bundle ) = @_;
    $count{fragile_deploy}++;
    die "the device hung up\n" if $switch{fragile};
    return $self->SUPER::deploy($bundle);
  }

  package SICK::Target::Keeper;    # the key stays on the device: hands out a request
  our @ISA = ('SICK::Target::Files');

  sub csr {
    my ( $self, $spec ) = @_;
    $count{keeper_csr}++;
    die "the device refuses to make a request\n" if $switch{keeper_refuses};
    return $switch{keeper_csr};
  }

  sub deploy {
    my ( $self, $bundle ) = @_;
    $count{keeper_got_key}++ if defined $bundle->key;
    return $self->SUPER::deploy($bundle);
  }

  package SICK::Target::Bare;    # presents its certificate alone, like a switch with one slot
  our @ISA = ('SICK::Target::Files');

  sub presented_cert {
    my ( $self ) = @_;
    my $bundle = $self->SUPER::presented_cert or return undef;
    return SICK::Bundle->new( cert => $bundle->cert );
  }

  package SICK::Target::Slow;    # needs a few looks until it shows the new certificate
  our @ISA = ('SICK::Target::Files');
  sub verify_timeout { 20 }

  sub deploy {
    my ( $self, $bundle ) = @_;
    $switch{slow_old} = $self->SUPER::presented_cert;
    $switch{slow_looks} = 0;
    return $self->SUPER::deploy($bundle);
  }

  sub presented_cert {
    my ( $self ) = @_;
    return $self->SUPER::presented_cert unless exists $switch{slow_looks};
    return $self->SUPER::presented_cert if ++$switch{slow_looks} > 2;
    die "unreachable: the web server is restarting\n" if $switch{slow_looks} == 1;
    return $switch{slow_old};
  }
}

{
  package SICK::Target::Recorder;    # writes down the roots it was given, when looking and when deploying
  our @ISA = ('SICK::Target::Files');

  sub presented_cert {
    my ( $self ) = @_;
    push @{ $switch{recorded}{look} }, $self->trust_roots;
    return $self->SUPER::presented_cert;
  }

  sub deploy {
    my ( $self, $bundle ) = @_;
    push @{ $switch{recorded}{deploy} }, $self->trust_roots;
    return $self->SUPER::deploy($bundle);
  }
}
$INC{ 'SICK/Target/'.$_.'.pm' } = __FILE__ for qw( Lazy Fragile Keeper Bare Slow Recorder );

# an issuer that refuses the way a CA does
{
  package Local::Issuer::Moody;
  our @ISA = ('SICK::Issuer::SelfSigned');

  sub issue {
    my ( $self, $spec ) = @_;
    $count{issue}++;
    Carp::croak('step failed (exit 1): the lifetime is longer than the provisioner allows') if $switch{ca_refuses};
    my $bundle = $self->SUPER::issue($spec);
    # a CA tool that wrote the key of another certificate
    return SICK::Bundle->new( cert => $bundle->cert, chain => $bundle->chain, key => $switch{wrong_key} )
      if $switch{wrong_key};
    return $bundle;
  }

  sub sign {
    my ( $self, $csr, $spec ) = @_;
    $count{sign}++;
    return $self->SUPER::sign( $csr, $spec );
  }
}

my $issuer = Local::Issuer::Moody->new( dir => $tmp.'/ca' );
our $now   = time;    # the clock of the runner; a subtest moves it with local
my @log;

sub runner {
  my ( $yaml, %arg ) = @_;
  my $config = SICK::Config->load_string( $yaml, 'list.yml' );
  return SICK::Runner->new(
    config         => $config,
    issuer         => $issuer,
    now            => sub { $now },
    log            => sub { push @log, @_ },
    verify_timeout => 0,
    %arg,
  );
}

sub device_yaml {
  my ( $name, %arg ) = @_;
  my $type = delete $arg{type} || 'files';
  $arg{names} ||= '['.$name.'.example.internal]';
  $arg{dir} = $tmp.'/'.$name unless exists $arg{dir};
  delete $arg{dir} unless defined $arg{dir};
  return join q{}, '  '.$name.":\n", '    type: '.$type."\n", map { '    '.$_.': '.$arg{$_}."\n" } sort keys %arg;
}

sub brief { [ map { [ @$_{qw( device action reason )} ] } @_ ] }

my $closed_port = do {
  my $listener = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 )
    or plan skip_all => 'cannot listen on 127.0.0.1: '.$!;
  my $port = $listener->sockport;
  close $listener;
  $port;
};

subtest 'construction' => sub {
  my $config = SICK::Config->load_string( "devices:\n".device_yaml('web'), 'list.yml' );
  my $runner = SICK::Runner->new( config => $config, issuer => $issuer );
  isa_ok $runner, 'SICK::Runner';
  is $runner->config, $config, 'config';
  is $runner->issuer, $issuer, 'issuer';

  my %bad = (
    'no config'            => [ { issuer => $issuer }, qr/^SICK::Runner->new needs a config/ ],
    'no issuer'            => [ { config => $config }, qr/^SICK::Runner->new needs an issuer/ ],
    'a clock that is none' => [ { config => $config, issuer => $issuer, now => 12 }, qr/^SICK::Runner->new: now must be a code reference/ ],
    'a log that is none'   => [ { config => $config, issuer => $issuer, log => 'stderr' }, qr/^SICK::Runner->new: log must be a code reference/ ],
    'a timeout that is none' => [ { config => $config, issuer => $issuer, verify_timeout => 'soon' }, qr/^SICK::Runner->new: verify_timeout must be a number of seconds/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $arg, $message ) = @{ $bad{$case} };
    ok !eval { SICK::Runner->new(%$arg); 1 }, 'dies for '.$case;
    like $@, $message, '... saying so';
  }
};

subtest 'the issuer of the ca section' => sub {
  my $selfsigned = SICK::Issuer->from_ca( type => 'selfsigned', dir => $tmp.'/other-ca', name => 'Some CA' );
  isa_ok $selfsigned, 'SICK::Issuer::SelfSigned';
  is $selfsigned->dir, $tmp.'/other-ca', '... with its directory; the name is not its business';

  my %step = ( url => 'https://ca.example.internal:9000', root => '/etc/sick/root_ca.crt', provisioner => 'sick', password_file => '/etc/sick/provisioner.pw' );
  isa_ok( SICK::Issuer->from_ca(%step), 'SICK::Issuer::StepCA', 'no type' );
  isa_ok( SICK::Issuer->from_ca( %step, type => 'step-ca' ), 'SICK::Issuer::StepCA', 'type step-ca' );
  isa_ok( SICK::Issuer->from_ca( %step, type => 'StepCA' ),  'SICK::Issuer::StepCA', 'type StepCA' );

  ok !eval { SICK::Issuer->from_ca( type => 'letsencrypt' ); 1 }, 'an unknown type dies';
  like $@, qr/^ca\.type: unknown type 'letsencrypt' \(step-ca or selfsigned\)/, '... naming the two there are';
  ok !eval { SICK::Issuer->from_ca( url => 'https://ca.example.internal' ); 1 }, 'a step-ca without its keys dies';
  like $@, qr/^ca: missing 'root'/, '... naming the first one that is missing';
  ok !eval { SICK::Issuer->from_ca( type => 'selfsigned', dir => $tmp.'/x', url => 'https://ca.example.internal' ); 1 },
    'a key the issuer does not know dies';
  like $@, qr/^ca: unknown key 'url'/, '... naming it';
};

subtest 'first run renews, second run changes nothing' => sub {
  my $runner = runner( "devices:\n".device_yaml('web').device_yaml( 'db', names => '[db.example.internal, 192.0.2.20]' ) );
  my $dir    = $tmp.'/web';

  my @states = $runner->check;
  is_deeply [ map { [ @$_{qw( device reason renew not_after )} ] } @states ],
    [ [ 'web', 'missing', 1, undef ], [ 'db', 'missing', 1, undef ] ],
    'check before: both missing, in the order of the list';
  ok !-e $dir, '... and check wrote nothing';

  @log = ();
  my @first = $runner->run;
  is_deeply brief(@first), [ [ 'web', 'renewed', 'missing' ], [ 'db', 'renewed', 'missing' ] ], 'first run: renewed';
  is_deeply [ map { $_->{error} } @first ], [ undef, undef ], '... without an error';
  is_deeply files_in($dir), [qw( .sick cert.pem chain.pem fullchain.pem key.pem )], 'the files are there, with the generations of the files target in .sick';

  my $deployed = SICK::Bundle->from_files( cert => $dir.'/cert.pem' );
  is_deeply $deployed->names, ['web.example.internal'], 'the certificate carries the names of the device';
  ok $deployed->is_issued_by( $issuer->root_pem ), '... and comes from the CA';
  is_deeply( SICK::Bundle->from_files( cert => $tmp.'/db/cert.pem' )->names, [ '192.0.2.20', 'db.example.internal' ],
    'the second device got its own' );

  ok scalar( grep { /^web: / } @log ), 'the log names the device';
  ok !scalar( grep { !/^(?:web|db): / } @log ), '... on every line';
  unlike join( "\n", @log ), qr/PRIVATE KEY/, '... and holds no key';
  like join( "\n", @log ), qr/^web: wrote cert\.pem/m, 'what the target says is passed through';

  my $fingerprint = $deployed->fingerprint_sha256;
  my @second = $runner->run;
  is_deeply brief(@second), [ [ 'web', 'unchanged', 'ok' ], [ 'db', 'unchanged', 'ok' ] ], 'second run: unchanged';
  is fingerprint_in($dir), $fingerprint, '... and the certificate is the same';

  @states = $runner->check('web');
  is scalar @states, 1, 'check for one device';
  is_deeply [ @{ $states[0] }{qw( device reason renew )} ], [ 'web', 'ok', 0 ], '... ok now';
  is $states[0]{not_after}, $deployed->not_after, '... with the end of the certificate';
  like $states[0]{detail}, qr/^valid until \d{4}-\d\d-\d\d /, '... and a detail for humans';

  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'force renews what is fine' => sub {
  my $runner = runner( "devices:\n".device_yaml('web') );
  my $before = fingerprint_in( $tmp.'/web' );

  is_deeply brief( $runner->run( ['web'] ) ), [ [ 'web', 'unchanged', 'ok' ] ], 'without force: unchanged';
  my @forced = $runner->run( ['web'], force => 1 );
  is_deeply brief(@forced), [ [ 'web', 'renewed', 'forced' ] ], 'with force: renewed, and the reason says why';
  isnt fingerprint_in( $tmp.'/web' ), $before, 'a new certificate is in place';

  ok !eval { $runner->run( ['web'], forced => 1 ); 1 }, 'a misspelled option dies';
  like $@, qr/^run: unknown option 'forced'/, '... instead of being ignored';
  ok !eval { $runner->run('web'); 1 }, 'names that are no list die';
  like $@, qr/^run takes the device names as an array reference/, '... saying so';
};

subtest 'dry run only looks' => sub {
  my $runner = runner( "devices:\n".device_yaml('web').device_yaml('fresh') );
  my $before = fingerprint_in( $tmp.'/web' );
  %count = ();

  my @results = $runner->run( [], dry_run => 1 );
  is_deeply brief(@results), [ [ 'web', 'unchanged', 'ok' ], [ 'fresh', 'would-renew', 'missing' ] ],
    'what is due is announced, what is fine is unchanged';
  ok !-e $tmp.'/fresh', 'nothing was written';
  is $count{issue}, undef, 'the CA was not asked for anything';

  @results = $runner->run( ['web'], dry_run => 1, force => 1 );
  is_deeply brief(@results), [ [ 'web', 'would-renew', 'forced' ] ], 'dry run with force';
  is fingerprint_in( $tmp.'/web' ), $before, '... leaves the certificate alone';
  is $count{issue}, undef, '... and the CA as well';
};

subtest 'the reasons to renew' => sub {
  my $list = "defaults:\n  lifetime: 40d\n  renew_before: 10d\ndevices:\n";

  my $runner = runner( $list.device_yaml('clock') );
  is_deeply brief( $runner->run ), [ [ 'clock', 'renewed', 'missing' ] ], 'missing';
  my $first = fingerprint_in( $tmp.'/clock' );

  local $now = $now + 29 * 86400;
  is_deeply brief( $runner->run ), [ [ 'clock', 'unchanged', 'ok' ] ], 'eleven days left with renew_before 10d: fine';
  $now += 2 * 86400;
  my @states = $runner->check;
  is_deeply [ @{ $states[0] }{qw( reason renew )} ], [ 'expiring', 1 ], 'nine days left: check says expiring';
  is_deeply brief( $runner->run ), [ [ 'clock', 'renewed', 'expiring' ] ], '... and run renews';
  isnt fingerprint_in( $tmp.'/clock' ), $first, '... for real';

  my $renamed = runner( $list.device_yaml( 'clock', names => '[clock.example.internal, 192.0.2.30]' ) );
  is_deeply brief( $renamed->run ), [ [ 'clock', 'renewed', 'names' ] ], 'another name in the list: names';
  is_deeply( SICK::Bundle->from_files( cert => $tmp.'/clock/cert.pem' )->names, [ '192.0.2.30', 'clock.example.internal' ],
    '... and the new certificate has them' );

  my $elsewhere = SICK::Issuer::SelfSigned->new( dir => $tmp.'/foreign-ca' );
  SICK::Target::Files->new( device => $renamed->config->device('clock') )
    ->deploy( $elsewhere->issue( $renamed->config->device('clock')->spec ) );
  is_deeply brief( $renamed->run ), [ [ 'clock', 'renewed', 'foreign-ca' ] ], 'a certificate of another CA: foreign-ca';
};

subtest 'a target that does not deploy is caught by the second look' => sub {
  %count = ();
  my $runner = runner( "devices:\n".device_yaml( 'lazy', type => 'lazy' ) );
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'lazy', 'failed', 'missing' ] ], 'failed';
  is $count{lazy_deploy}, 1, 'deploy was called';
  like $results[0]{error}, qr/^verification failed: the device presents no certificate/, 'the error names the reason';

  # with a certificate that is already there and stays
  my $device = $runner->config->device('lazy');
  SICK::Target::Files->new( device => $device )->deploy( $issuer->issue( $device->spec ) );
  my $old = fingerprint_in( $tmp.'/lazy' );
  @results = $runner->run( [], force => 1 );
  is_deeply brief(@results), [ [ 'lazy', 'failed', 'forced' ] ], 'failed again';
  like $results[0]{error},
    qr/^verification failed: the device does not present the new certificate \(SHA-256 [0-9a-f]{16}\.\.\.\) but another one \(\Q${\ substr $old, 0, 16 }\E\.\.\.\)/,
    'the error says that the old certificate is still presented';
  unlike $results[0]{error}, qr/ at \S+ line \d+/, '... without the place in the code';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'an unreachable device fails and the others go on' => sub {
  my $list = "devices:\n"
    .device_yaml( 'gone', host => '127.0.0.1', port => $closed_port )
    .device_yaml('next');
  my $runner = runner($list);

  my @states = $runner->check;
  is_deeply [ map { [ @$_{qw( device reason renew not_after )} ] } @states ],
    [ [ 'gone', 'unreachable', undef, undef ], [ 'next', 'missing', 1, undef ] ],
    'check: unreachable is not missing, and nothing is known about renewing';
  like $states[0]{detail}, qr/^127\.0\.0\.1:$closed_port: \S/, '... with the address and the reason';

  %count = ();
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'gone', 'failed', 'unreachable' ], [ 'next', 'renewed', 'missing' ] ],
    'run: the first fails, the second is renewed all the same';
  like $results[0]{error}, qr/^unreachable: 127\.0\.0\.1:$closed_port: \S/, 'the error says unreachable';
  is $count{issue}, 1, 'no certificate was issued for the device that did not answer';
  ok !-e $tmp.'/gone', '... and nothing was deployed to it';

  @results = $runner->run( ['gone'], force => 1 );
  is_deeply brief(@results), [ [ 'gone', 'failed', 'unreachable' ] ], 'force does not make a device reachable';
  is $count{issue}, 1, '... and issues nothing for it';
};

subtest 'a CA that refuses' => sub {
  %count = ();
  local $switch{ca_refuses} = 1;
  my $runner = runner( "devices:\n".device_yaml( 'refused', type => 'fragile' ).device_yaml('next') );
  my $before = fingerprint_in( $tmp.'/next' );

  my @results = $runner->run( [], force => 1 );
  is_deeply brief(@results), [ [ 'refused', 'failed', 'missing' ], [ 'next', 'failed', 'forced' ] ], 'failed';
  is $results[0]{error}, 'issuing failed: step failed (exit 1): the lifetime is longer than the provisioner allows',
    'the words of the CA reach the user';
  is $count{fragile_deploy}, undef, 'deploy was not called';
  ok !-e $tmp.'/refused', 'the device is untouched';
  is fingerprint_in( $tmp.'/next' ), $before, '... and so is one that had a certificate';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'what step says reaches the user' => sub {
  # the real step-ca issuer with a step that refuses, as t/21 has it
  my $step = $tmp.'/step';
  ( my $source = slurp('t/bin/fake-step') ) =~ s/\A#![^\n]*\n/#!$^X\n/;
  spew( $step, $source );
  chmod 0755, $step or die 'chmod: '.$!;
  my $root = new_ca( dir => $tmp, name => 'step-root' );
  my $marker = 'placeholder-'.$$.'-not-a-real-password';
  my $refusing = SICK::Issuer->from_ca(
    url           => 'https://ca.example.internal:9000',
    root          => $root->{cert},
    provisioner   => 'sick',
    password_file => spew( $tmp.'/provisioner.pw', $marker."\n" ),
    step          => $step,
  );
  local $ENV{FAKE_STEP_EXIT}   = 1;
  local $ENV{FAKE_STEP_STDERR} = "The request was forbidden by the certificate authority: requested duration of 9528h1m0s is more than the authorized maximum certificate duration of 24h1m0s.\nRe-run with STEPDEBUG=1 for more info.\n";

  my $runner = runner( "devices:\n".device_yaml('stepped'), issuer => $refusing );
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'stepped', 'failed', 'missing' ] ], 'failed';
  is $results[0]{error},
    'issuing failed: step failed (exit 1): The request was forbidden by the certificate authority: requested duration of 9528h1m0s is more than the authorized maximum certificate duration of 24h1m0s.',
    'the error is what step said - one line, without its progress report';
  unlike $results[0]{error}, qr/\Q$marker\E/, '... and has no password in it';
  ok !-e $tmp.'/stepped', 'the device is untouched';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a CA that signs through an intermediate, a device that presents its certificate alone' => sub {
  # step-ca and a switch: the certificate comes from the intermediate, and
  # the device shows the certificate and nothing else
  my $step = $tmp.'/step';
  my $root  = new_ca( dir => $tmp, name => 'chain-root',  cn => 'Chain Root' );
  my $inter = new_ca( dir => $tmp, name => 'chain-inter', cn => 'Chain Intermediate', issuer => $root );
  my $leaf  = new_cert( ca => $inter, dir => $tmp, name => 'chain-leaf', cn => 'chained.example.internal',
    san => 'DNS:chained.example.internal', days => 90 );
  my $fixtures = $tmp.'/chain-fixtures';
  mkdir $fixtures or die 'mkdir: '.$!;
  spew( $fixtures.'/fullchain.pem', $leaf->{cert_pem}.$inter->{pem} );
  spew( $fixtures.'/key.pem',       $leaf->{key_pem} );
  local $ENV{FAKE_STEP_FIXTURES} = $fixtures;

  my %ca = (
    url           => 'https://ca.example.internal:9000',
    root          => $root->{cert},
    provisioner   => 'sick',
    password_file => $tmp.'/provisioner.pw',
    step          => $step,
  );
  my $list = "devices:\n".device_yaml( 'chained', type => 'bare' );
  local $now = time;

  my $without = runner( $list, issuer => SICK::Issuer->from_ca(%ca) );
  is_deeply brief( $without->run ), [ [ 'chained', 'renewed', 'missing' ] ], 'first run: renewed';
  is( SICK::Target->class_for('bare')->new( device => $without->config->device('chained') )->presented_cert->chain,
    undef, 'the device presents the certificate alone' );
  is_deeply brief( $without->run ), [ [ 'chained', 'renewed', 'foreign-ca' ] ],
    'without ca.intermediates the second run does not recognize it: foreign-ca, renewed again, every time';

  my $with = runner( $list, issuer => SICK::Issuer->from_ca( %ca, intermediates => $inter->{cert} ) );
  is_deeply brief( $with->run ), [ [ 'chained', 'unchanged', 'ok' ] ], 'with ca.intermediates: unchanged';
  my ($state) = $with->check;
  is $state->{reason}, 'ok', '... and check agrees';

  my $missing = runner( $list, issuer => SICK::Issuer->from_ca( %ca, intermediates => $tmp.'/no-such-intermediate.crt' ) );
  my @results = $missing->run;
  is_deeply brief(@results), [ [ 'chained', 'failed', 'error' ] ], 'an intermediates file that cannot be read fails the device';
  like $results[0]{error}, qr/^cannot read ca\.intermediates '\Q$tmp\E\/no-such-intermediate\.crt': \S/, '... with path and reason';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a deployment that dies, and the run after it' => sub {
  %count = ();
  my $runner = runner( "devices:\n".device_yaml( 'fragile', type => 'fragile' ) );

  {
    local $switch{fragile} = 1;
    my @results = $runner->run;
    is_deeply brief(@results), [ [ 'fragile', 'failed', 'missing' ] ], 'failed';
    is $results[0]{error}, 'deploy failed: the device hung up', 'the error is the message of the target';
    is_deeply leftovers(), [], 'no temporary directory with a key is left';
    is_deeply files_in( $tmp.'/fragile' ), [], 'nothing reached the device';
  }

  is_deeply brief( $runner->run ), [ [ 'fragile', 'renewed', 'missing' ] ], 'the next run works';
  is $count{fragile_deploy}, 2, 'deploy was called twice in all';
  is_deeply brief( $runner->run ), [ [ 'fragile', 'unchanged', 'ok' ] ], '... and the one after has nothing to do';
};

subtest 'a device that makes its own key' => sub {
  %count = ();
  my $request = new_csr( dir => $tmp, name => 'keeper', cn => 'keeper.example.internal', san => 'DNS:keeper.example.internal' );
  local $switch{keeper_csr} = $request->{csr_pem};
  my $runner = runner( "devices:\n".device_yaml( 'keeper', type => 'keeper' ) );

  is_deeply brief( $runner->run ), [ [ 'keeper', 'renewed', 'missing' ] ], 'renewed';
  is_deeply [ @count{qw( keeper_csr sign issue keeper_got_key )} ], [ 1, 1, undef, undef ],
    'the request was signed; no key was made and none was handed to the target';
  is_deeply files_in( $tmp.'/keeper' ), [qw( .sick cert.pem chain.pem fullchain.pem )], 'no key on disk';

  my ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'x509', '-noout', '-pubkey' ], stdin => slurp( $tmp.'/keeper/cert.pem' ) );
  my ( $want ) = SICK::OpenSSL::run( [ 'req', '-noout', '-pubkey' ], stdin => $request->{csr_pem} );
  is $out, $want, 'the certificate is for the key of the request';

  %count = ();
  local $switch{keeper_refuses} = 1;
  my @results = $runner->run( [], force => 1 );
  is_deeply brief(@results), [ [ 'keeper', 'failed', 'forced' ] ], 'a device that cannot make a request fails';
  is $results[0]{error}, 'certificate request failed: the device refuses to make a request', '... with its message';
  is_deeply [ @count{qw( sign issue )} ], [ undef, undef ], '... before the CA is asked';
};

subtest 'a device that takes a moment' => sub {
  %switch = ();
  my $list = "devices:\n".device_yaml( 'slow', type => 'slow' );

  my $impatient = runner($list);
  my @results = $impatient->run;
  is_deeply brief(@results), [ [ 'slow', 'failed', 'missing' ] ], 'without time to wait: failed';
  like $results[0]{error}, qr/^verification failed: unreachable: the web server is restarting/, '... with what the first look saw';

  %switch = ();
  my $patient = runner( $list, verify_timeout => undef, verify_interval => 0.1 );
  @results = $patient->run( [], force => 1 );
  is_deeply brief(@results), [ [ 'slow', 'renewed', 'forced' ] ], 'with the time the target asks for: renewed';
  is $switch{slow_looks}, 3, '... after looking three times';
};

subtest 'unknown devices' => sub {
  %count = ();
  my $runner = runner( "devices:\n".device_yaml('web').device_yaml( 'db', names => '[db.example.internal, 192.0.2.20]' ) );

  ok !eval { $runner->run( [ 'web', 'nobody' ], force => 1 ); 1 }, 'run dies for a name that is not in the list';
  like $@, qr/^unknown device 'nobody'/, '... naming it';
  is $count{issue}, undef, '... before anything is done to the others';
  ok !eval { $runner->check('nobody'); 1 }, 'check dies as well';
  like $@, qr/^unknown device 'nobody'/, '... the same way';

  is_deeply brief( $runner->run( [ 'db', 'web', 'db' ] ) ), [ [ 'db', 'unchanged', 'ok' ], [ 'web', 'unchanged', 'ok' ] ],
    'given names: their order, each once';
};

subtest 'a device nothing can be done with' => sub {
  my $list = "devices:\n"
    .device_yaml( 'exotic', type => 'no-such-box' )
    .device_yaml( 'wrong', dir => undef )
    .device_yaml('web');
  my $runner = runner($list);

  my @states = $runner->check;
  is_deeply [ map { [ @$_{qw( device reason renew )} ] } @states ],
    [ [ 'exotic', 'error', undef ], [ 'wrong', 'error', undef ], [ 'web', 'ok', 0 ] ], 'check: error, error, ok';
  like $states[0]{detail}, qr/^no target for type 'no-such-box'; install a SICK-Target-\* distribution/, 'a type without a module';
  like $states[1]{detail}, qr/^devices\.wrong: missing 'dir'/, 'an option that is missing';

  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'exotic', 'failed', 'error' ], [ 'wrong', 'failed', 'error' ], [ 'web', 'unchanged', 'ok' ] ],
    'run: the two fail, the third is looked at';
  like $results[0]{error}, qr/^no target for type 'no-such-box'/, '... with the same message';
};

subtest 'a CA whose root cannot be read' => sub {
  my $broken = SICK::Issuer->from_ca(
    url           => 'https://ca.example.internal:9000',
    root          => $tmp.'/no-such-root.crt',
    provisioner   => 'sick',
    password_file => $tmp.'/no-such.pw',
  );
  my $runner = runner( "devices:\n".device_yaml('web').device_yaml('db'), issuer => $broken );
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'web', 'failed', 'error' ], [ 'db', 'failed', 'error' ] ], 'every device fails';
  like $_->{error}, qr/^cannot read ca\.root '\Q$tmp\E\/no-such-root\.crt': \S/, '... with the path and the reason' for @results;
};

subtest 'a CA whose root or intermediates are not what they say' => sub {
  my $root    = new_ca( dir => $tmp, name => 'check-root',    cn => 'Check Root' );
  my $inter   = new_ca( dir => $tmp, name => 'check-inter',   cn => 'Check Intermediate', issuer => $root );
  my $foreign = new_ca( dir => $tmp, name => 'check-foreign', cn => 'Check Foreign Root' );
  my $stray   = new_ca( dir => $tmp, name => 'check-stray',   cn => 'Check Stray Intermediate', issuer => $foreign );
  my %ca = (
    url           => 'https://ca.example.internal:9000',
    root          => $root->{cert},
    provisioner   => 'sick',
    password_file => $tmp.'/no-such.pw',
  );
  my $list = "devices:\n".device_yaml('web').device_yaml('db');

  my @results = runner( $list, issuer => SICK::Issuer->from_ca( %ca, root => $inter->{cert} ) )->run;
  is_deeply brief(@results), [ [ 'web', 'failed', 'error' ], [ 'db', 'failed', 'error' ] ],
    'the intermediate as root: every device fails, none is renewed';
  like $_->{error}, qr/^ca\.root '\Q$inter->{cert}\E' is not a self-signed CA certificate: issued by CN=Check Root\z/,
    '... naming ca.root, the path and the issuer' for @results;

  @results = runner( $list, issuer => SICK::Issuer->from_ca( %ca, intermediates => $stray->{cert} ) )->run;
  is_deeply brief(@results), [ [ 'web', 'failed', 'error' ], [ 'db', 'failed', 'error' ] ],
    'an intermediate of another CA: every device fails, none is renewed';
  like $_->{error}, qr/^ca\.intermediates '\Q$stray->{cert}\E': the certificate 'CN=Check Stray Intermediate' does not lead to ca\.root/,
    '... naming ca.intermediates, the path and the subject' for @results;
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'the roots of the CA reach every target' => sub {
  my $next     = new_ca( dir => $tmp, name => 'next-root',     cn => 'Next Root' );
  my $previous = new_ca( dir => $tmp, name => 'previous-root', cn => 'Previous Root' );
  my $list     = "devices:\n".device_yaml( 'recorded', type => 'recorder' );
  my $root     = $issuer->root_pem;
  my $pem      = sub { ( my $text = $_[0] ) =~ s/\A.*?(-----BEGIN CERTIFICATE-----)/$1/s; $text };

  $switch{recorded} = {};
  my $rolling = Local::Issuer::Moody->new( dir => $tmp.'/ca', additional_roots => [ $next->{cert}, $previous->{cert} ] );
  my $runner  = runner( $list, issuer => $rolling );
  my @expected = ( $root, $pem->( $next->{pem} ), $pem->( $previous->{pem} ) );

  $runner->check;
  is scalar @{ $switch{recorded}{look} }, 1, 'check makes the target once';
  is_deeply $switch{recorded}{look}[0], \@expected,
    '... and hands it the root of the issuer first, then the additional roots in the order of the list';
  is( ( grep { /BEGIN CERTIFICATE.*BEGIN CERTIFICATE/s } @{ $switch{recorded}{look}[0] } ), 0, '... one certificate each' );

  $switch{recorded} = {};
  is_deeply brief( $runner->run ), [ [ 'recorded', 'renewed', 'missing' ] ], 'run renews';
  is_deeply $switch{recorded}{deploy}, [ \@expected ], '... and the target that deploys has the same roots';
  is_deeply $switch{recorded}{look}[0], \@expected, '... as the one that looked';

  $switch{recorded} = {};
  runner( $list )->check;
  is_deeply $switch{recorded}{look}, [ [$root] ], 'without additional roots: the root alone';

  my @results = runner( $list, issuer => Local::Issuer::Moody->new( dir => $tmp.'/ca', additional_roots => [ $tmp.'/no-such-root.crt' ] ) )->run;
  is_deeply brief(@results), [ [ 'recorded', 'failed', 'error' ] ], 'an additional root that cannot be read fails the device';
  like $results[0]{error}, qr/^cannot read ca\.additional_roots '\Q$tmp\E\/no-such-root\.crt': \S/, '... with path and reason';
  delete $switch{recorded};
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a bundle whose key does not belong to its certificate is not deployed' => sub {
  my $stranger = new_cert( ca => new_ca( dir => $tmp, name => 'stranger-ca' ), dir => $tmp, name => 'stranger' );
  local $switch{wrong_key} = $stranger->{key_pem};
  %count = ();
  my $runner  = runner( "devices:\n".device_yaml( 'mismatch', type => 'lazy' ) );
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'mismatch', 'failed', 'missing' ] ], 'the device fails';
  is $results[0]{error}, 'not deployed: the private key does not belong to the certificate',
    '... saying why, without the key';
  is $count{issue}, 1, 'the certificate was issued';
  is $count{lazy_deploy}, undef, '... and never handed to the target';
  ok !-e $tmp.'/mismatch', 'the device is untouched';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

#### the state: records and back-off

my $states = 0;

# a fresh state directory
sub new_state { SICK::State->new( dir => $tmp.'/state-'.++$states ) }

sub record {
  my ( $state, $name ) = @_;
  my $path = $state->record_path($name);
  return -e $path ? decode_json( slurp($path) ) : undef;
}

sub iso { strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime $_[0] ) }
sub utc { strftime( '%Y-%m-%d %H:%M:%S UTC', gmtime $_[0] ) }

subtest 'construction with a state' => sub {
  my $config = SICK::Config->load_string( "devices:\n".device_yaml('web'), 'list.yml' );
  my $state  = new_state();
  my $runner = SICK::Runner->new( config => $config, issuer => $issuer, state => $state );
  ok $runner->has_state, 'has_state';
  is $runner->state, $state, 'state';
  ok !SICK::Runner->new( config => $config, issuer => $issuer )->has_state, 'without one: has_state is false';
  ok !eval { SICK::Runner->new( config => $config, issuer => $issuer, state => '/var/lib/sick' ); 1 },
    'a state that is a path dies';
  like $@, qr/^SICK::Runner->new: state must be a SICK::State/, '... saying so';
};

subtest 'the record after a run' => sub {
  %count = ();
  my $state  = new_state();
  my $runner = runner( "devices:\n".device_yaml('kept'), state => $state );
  local $now = time + 60;

  $runner->check;
  ok !-e $state->dir, 'check writes nothing';
  is_deeply brief( $runner->run( [], dry_run => 1 ) ), [ [ 'kept', 'would-renew', 'missing' ] ], 'dry run';
  ok !-e $state->dir, '... writes nothing either';

  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'kept', 'renewed', 'missing' ] ], 'run: renewed';
  is $results[0]{state_error}, undef, '... and the record was written';
  my $deployed = SICK::Bundle->from_files( cert => $tmp.'/kept/cert.pem' );
  my $record   = record( $state, 'kept' );
  is $state->record_path('kept'), $state->dir.'/devices/kept.json', 'one file per device';
  is $record->{device}, 'kept', 'the record names the device';
  is_deeply $record->{last_check},
    { time => iso($now), status => 'missing', detail => 'the device presents no certificate', fingerprint_sha256 => undef, not_after => undef },
    'last_check: what the first look saw';
  is_deeply $record->{last_issue},
    {
      time               => iso($now),
      serial             => $deployed->serial,
      fingerprint_sha256 => $deployed->fingerprint_sha256,
      names              => ['kept.example.internal'],
      not_after          => iso( $deployed->not_after ),
      issuer             => $deployed->issuer_dn
    },
    'last_issue: the facts of the certificate the device presents now';
  like $record->{last_issue}{serial}, qr/\A[0-9A-F]+\z/, '... with its serial';
  is_deeply $record->{last_deploy}, { time => iso($now), result => 'ok', error => undef }, 'last_deploy: ok';
  is $record->{last_success}, iso($now), 'last_success';
  is $record->{consecutive_failures}, 0, 'no failures';
  ok exists $record->{next_attempt} && !defined $record->{next_attempt}, 'no back-off';
  is( ( stat $state->record_path('kept') )[2] & 07777, 0644, 'the record is 0644: there is no secret in it' );
  is( ( stat $state->dir.'/devices' )[2] & 07777, 0755, '... in a directory of 0755' );

  local $now = $now + 3600;
  is_deeply brief( $runner->run ), [ [ 'kept', 'unchanged', 'ok' ] ], 'second run: unchanged';
  my $second = record( $state, 'kept' );
  is_deeply [ @{ $second->{last_check} }{qw( time status fingerprint_sha256 not_after )} ],
    [ iso($now), 'ok', $deployed->fingerprint_sha256, iso( $deployed->not_after ) ],
    'last_check: the live certificate';
  is_deeply $second->{last_issue}, $record->{last_issue}, 'last_issue: unchanged';
  is $second->{last_success}, iso($now), 'last_success: this run';
  is $count{issue}, 1, 'one certificate in all';
};

subtest 'a device whose deployment keeps failing is deferred' => sub {
  %count = ();
  my $state  = new_state();
  my $runner = runner( "devices:\n".device_yaml( 'shaky', type => 'fragile' ), state => $state );
  local $switch{fragile} = 1;
  local $now  = time + 60;
  my $start   = $now;

  is_deeply brief( $runner->run ), [ [ 'shaky', 'failed', 'missing' ] ], 'first attempt: failed';
  my $record = record( $state, 'shaky' );
  is $record->{consecutive_failures}, 1, 'one failure';
  is $record->{next_attempt}, iso( $start + 3600 ), 'next attempt in an hour';
  is_deeply $record->{last_deploy}, { time => iso($now), result => 'failed', error => 'deploy failed: the device hung up' },
    'last_deploy: failed, with the error';
  is_deeply $record->{last_failure}, { time => iso($now), error => 'deploy failed: the device hung up' }, 'last_failure';
  ok $record->{last_issue}{fingerprint_sha256}, 'the discarded certificate is on record';
  ok !exists $record->{last_success}, 'no success yet';

  $now = $start + 3600 - 15 * 60 - 1;
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'shaky', 'deferred', 'missing' ] ], 'a second before the grace: deferred';
  is $results[0]{error}, 'back-off after 1 failure, next attempt '.utc( $start + 3600 ), '... saying until when';
  is $count{issue}, 1, '... nothing issued';
  is $count{fragile_deploy}, 1, '... nothing deployed';
  is record( $state, 'shaky' )->{last_check}{time}, iso($now), 'the look is on record';
  is record( $state, 'shaky' )->{consecutive_failures}, 1, '... and the count unchanged';

  my $before = slurp( $state->record_path('shaky') );
  is_deeply brief( $runner->run( [], dry_run => 1 ) ), [ [ 'shaky', 'deferred', 'missing' ] ], 'a dry run says deferred too';
  is slurp( $state->record_path('shaky') ), $before, '... and writes nothing';

  # 1, 2, 4, 8, 16, 24, 24 hours
  my $at = $start + 3600;
  for my $step ( [ 2, 2 ], [ 3, 4 ], [ 4, 8 ], [ 5, 16 ], [ 6, 24 ], [ 7, 24 ] ) {
    my ( $failures, $hours ) = @$step;
    $now = $at;
    is_deeply brief( $runner->run ), [ [ 'shaky', 'failed', 'missing' ] ], 'attempt '.$failures.' when due: failed';
    $record = record( $state, 'shaky' );
    is $record->{consecutive_failures}, $failures, '... '.$failures.' failures';
    is $record->{next_attempt}, iso( $at + $hours * 3600 ), '... next attempt '.$hours.' hours later';
    $at += $hours * 3600;
  }
  is $count{issue}, 7, 'one certificate per attempt, none in between';

  $now = $at - 15 * 60 - 1;
  @results = $runner->run;
  is_deeply brief(@results), [ [ 'shaky', 'deferred', 'missing' ] ], 'deferred again';
  is $results[0]{error}, 'back-off after 7 failures, next attempt '.utc($at), '... in the plural';
  is_deeply brief( $runner->run( [], force => 1 ) ), [ [ 'shaky', 'failed', 'missing' ] ], 'force ignores the back-off';
  is $count{issue}, 8, '... and issues';
  is record( $state, 'shaky' )->{consecutive_failures}, 8, '... and its failure counts';

  # a daily timer: back after about 24 hours, a little early or late
  $at = $now + 86400;
  is record( $state, 'shaky' )->{next_attempt}, iso($at), 'the cap: 24 hours';
  $now = $at - 15 * 60 - 1;
  is_deeply brief( $runner->run ), [ [ 'shaky', 'deferred', 'missing' ] ], 'a second before the grace: deferred';
  is $count{issue}, 8, '... nothing issued';
  $now = $at - 15 * 60;
  is_deeply brief( $runner->run ), [ [ 'shaky', 'failed', 'missing' ] ], '15 minutes early: due, and tried';
  is $count{issue}, 9, '... issuing';
  is record( $state, 'shaky' )->{consecutive_failures}, 9, '... and counting';

  $switch{fragile} = 0;
  $now = $now + 86400;
  is_deeply brief( $runner->run ), [ [ 'shaky', 'renewed', 'missing' ] ], 'the device is fixed: renewed';
  $record = record( $state, 'shaky' );
  is $record->{consecutive_failures}, 0, 'the count starts over';
  ok !defined $record->{next_attempt}, '... without back-off';
  is $record->{last_success}, iso($now), 'last_success';
  is_deeply $record->{last_deploy}, { time => iso($now), result => 'ok', error => undef }, 'last_deploy: ok';
  is $record->{last_issue}{fingerprint_sha256}, fingerprint_in( $tmp.'/shaky' ), 'last_issue: the one deployed';
  is $record->{last_failure}{error}, 'deploy failed: the device hung up', 'the last failure stays on record';
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a device that is fine ends the back-off' => sub {
  my $state  = new_state();
  my $runner = runner( "devices:\n".device_yaml('steady'), state => $state );
  local $now = time + 60;
  is_deeply brief( $runner->run ), [ [ 'steady', 'renewed', 'missing' ] ], 'renewed';
  $state->update( 'steady', { consecutive_failures => 3, next_attempt => iso( $now + 7200 ) } );
  is_deeply brief( $runner->run ), [ [ 'steady', 'unchanged', 'ok' ] ], 'a back-off does not matter for a device that is fine';
  my $record = record( $state, 'steady' );
  is $record->{consecutive_failures}, 0, '... and is reset';
  ok !defined $record->{next_attempt}, '... completely';
};

subtest 'a device that is not judged changes nothing in the back-off' => sub {
  %count = ();
  my $state  = new_state();
  my $runner = runner(
    "devices:\n".device_yaml( 'gone', host => '127.0.0.1', port => $closed_port ).device_yaml( 'odd', type => 'no-such-type' ),
    state => $state
  );
  local $now = time + 60;
  $state->update( 'gone', { consecutive_failures => 2, next_attempt => iso( $now + 3600 ), owner => 'netops' } );

  is_deeply brief( $runner->run ), [ [ 'gone', 'failed', 'unreachable' ], [ 'odd', 'failed', 'error' ] ],
    'unreachable and error, not deferred';
  my $gone = record( $state, 'gone' );
  is $gone->{consecutive_failures}, 2, 'unreachable: the count stays';
  is $gone->{next_attempt}, iso( $now + 3600 ), '... and so does the next attempt';
  is $gone->{last_check}{status}, 'unreachable', '... the look is on record';
  like $gone->{last_check}{detail}, qr/^127\.0\.0\.1:$closed_port: \S/, '... with the reason';
  is $gone->{owner}, 'netops', 'a field SICK does not know is kept';

  my $odd = record( $state, 'odd' );
  is $odd->{last_check}{status}, 'error', 'error: on record';
  ok !exists $odd->{consecutive_failures}, '... and no failure counted';
  is $count{issue}, undef, 'nothing issued';
};

subtest 'a CA that refuses counts toward the back-off' => sub {
  %count = ();
  local $switch{ca_refuses} = 1;
  my $state  = new_state();
  my $runner = runner( "devices:\n".device_yaml( 'refused', type => 'fragile' ), state => $state );
  local $now = time + 60;
  is_deeply brief( $runner->run ), [ [ 'refused', 'failed', 'missing' ] ], 'failed';
  my $record = record( $state, 'refused' );
  is $record->{consecutive_failures}, 1, 'counted';
  is $record->{next_attempt}, iso( $now + 3600 ), '... with a back-off';
  like $record->{last_failure}{error}, qr/^issuing failed: step failed/, 'last_failure: the words of the CA';
  ok !exists $record->{last_issue}, 'nothing issued';
  ok !exists $record->{last_deploy}, 'nothing deployed';
  is_deeply brief( $runner->run ), [ [ 'refused', 'deferred', 'missing' ] ], 'the next run waits';
  is $count{issue}, 1, '... and does not ask the CA';
};

subtest 'a record that cannot be read' => sub {
  my $state  = new_state();
  my $runner = runner( "devices:\n".device_yaml('broken').device_yaml('listed').device_yaml('blocked'), state => $state );
  local $now = time + 60;
  my %path = map { $_ => $state->record_path($_) } qw( broken listed blocked );
  File::Path::make_path( $state->dir.'/devices', $path{blocked} );
  spew( $path{broken}, "{\"consecutive_failures\": 3, \"next_attempt\": \"2999-01-01T00:00:00Z\"" );
  spew( $path{listed}, "[1, 2]\n" );

  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'broken', 'renewed', 'missing' ], [ 'listed', 'renewed', 'missing' ], [ 'blocked', 'renewed', 'missing' ] ],
    'every device is worked on as if it had no record';
  is $results[0]{state_error}, 'cannot read state record \''.$path{broken}.'\': not valid JSON', 'broken JSON: path and reason';
  is $results[1]{state_error}, 'cannot read state record \''.$path{listed}.'\': not a JSON object', 'no object';
  like $results[2]{state_error},
    qr/^cannot read state record '\Q$path{blocked}\E': Is a directory; cannot write state record '\Q$path{blocked}\E': \S/,
    'a directory in its place: cannot be read, and not written either';
  is record( $state, 'broken' )->{consecutive_failures}, 0, 'the broken record is replaced';
  is record( $state, 'listed' )->{device}, 'listed', '... and so is the list';
  ok( ( grep { /\Abroken: cannot read state record / } @log ), 'the problem is logged' );

  SKIP: {
    skip 'root reads every file', 2 unless $>;
    my $locked = $state->record_path('broken');
    chmod 0000, $locked;
    my @again = $runner->run( ['broken'] );
    is $again[0]{action}, 'unchanged', 'an unreadable record: the device is worked on';
    like $again[0]{state_error}, qr/^cannot read state record '\Q$locked\E': Permission denied/, '... and the record reported';
    chmod 0644, $locked;
  }
};

subtest 'the file of a device' => sub {
  my $state = SICK::State->new( dir => '/var/lib/sick' );
  is $state->record_path('switch'),     '/var/lib/sick/devices/switch.json',       'a plain name';
  is $state->record_path('core-sw_1.a'), '/var/lib/sick/devices/core-sw_1.a.json', 'dots, dashes and underscores stay';
  is $state->record_path('../up'),      '/var/lib/sick/devices/%2E.%2Fup.json',    'no way out of the directory';
  is $state->record_path('two words'),  '/var/lib/sick/devices/two%20words.json',  'a space';
  is $state->lock_path, '/var/lib/sick/sick.lock', 'the lock';
  ok !eval { SICK::State->new( dir => q{} ); 1 }, 'an empty directory dies';
  like $@, qr/^SICK::State->new needs the state directory/, '... saying so';
};

subtest 'no record holds a key' => sub {
  my @records = glob $tmp.'/state-*/devices/*.json';
  cmp_ok scalar @records, '>=', 8, 'there are records to look at';
  for my $path (@records) {
    my $text = slurp($path);
    unlike $text, qr/PRIVATE KEY/, $path.': no private key';
    unlike $text, qr/key\.pem/,    '... and no path of one';
  }
};

done_testing;
