#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET;
use lib 't/lib';

use SICK::Bundle;
use SICK::Config;
use SICK::Issuer;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Runner;
use SICK::Target::Files;
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
$INC{ 'SICK/Target/'.$_.'.pm' } = __FILE__ for qw( Lazy Fragile Keeper Slow );

# an issuer that refuses the way a CA does
{
  package Local::Issuer::Moody;
  our @ISA = ('SICK::Issuer::SelfSigned');

  sub issue {
    my ( $self, $spec ) = @_;
    $count{issue}++;
    Carp::croak('step failed (exit 1): the lifetime is longer than the provisioner allows') if $switch{ca_refuses};
    return $self->SUPER::issue($spec);
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
  is_deeply files_in($dir), [qw( cert.pem chain.pem fullchain.pem key.pem )], 'the files are there';

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
  local $ENV{FAKE_STEP_STDERR} = "The request was forbidden by the certificate authority:\nrequested duration of 9528h0m0s is more than the authorized maximum certificate duration of 24h1m0s.\n";

  my $runner = runner( "devices:\n".device_yaml('stepped'), issuer => $refusing );
  my @results = $runner->run;
  is_deeply brief(@results), [ [ 'stepped', 'failed', 'missing' ] ], 'failed';
  like $results[0]{error},
    qr/^issuing failed: step failed \(exit 1\): The request was forbidden by the certificate authority:\nrequested duration of 9528h0m0s is more than the authorized maximum/,
    'the error is what step printed';
  unlike $results[0]{error}, qr/\Q$marker\E/, '... and has no password in it';
  ok !-e $tmp.'/stepped', 'the device is untouched';
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
  is_deeply files_in( $tmp.'/keeper' ), [qw( cert.pem chain.pem fullchain.pem )], 'no key on disk';

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
  like $_->{error}, qr/^cannot read CA root '\Q$tmp\E\/no-such-root\.crt': \S/, '... with the path and the reason' for @results;
};

done_testing;
