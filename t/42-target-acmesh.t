#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Digest::SHA qw( sha256_hex );
use File::Temp qw( tempdir );
use JSON::PP;
use lib 't/lib';

use SICK::Bundle;
use SICK::Command;
use SICK::Device;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Target;
use SICK::Target::Acmesh;
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# SICK::Target::Acmesh, twice: against t/bin/fake-acme-sh, which records
# what it is called with, and - when acme.sh is installed - against the real
# thing with its localcopy hook. The second half is skipped without acme.sh;
# set SICK_TEST_ACME_SH to the program when it is not in the PATH.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

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

sub mode_of { sprintf '%04o', ( stat $_[0] )[2] & 07777 }

# The fake acme.sh, runnable by the perl that runs this test.
my $fake = $tmp.'/acme.sh';
( my $source = slurp('t/bin/fake-acme-sh') ) =~ s/\A#![^\n]*\n/#!$^X\n/;
spew( $fake, $source );
chmod 0755, $fake or die 'chmod: '.$!;

my $log = $tmp.'/acme.log';
local $ENV{FAKE_ACME_LOG} = $log;

# the calls the fake recorded since the last look
sub calls {
  return [] unless -e $log;
  my @calls = map { JSON::PP->new->decode($_) } grep { /\S/ } split /\n/, slurp($log);
  unlink $log;
  return \@calls;
}

my $issuer = SICK::Issuer::SelfSigned->new( dir => $tmp.'/ca' );
my @names  = ( 'router.example.internal', 'router.hq.example.org', '192.0.2.9' );
my %spec   = ( names => [@names], lifetime => 30 * 86400, key => 'ec256' );
my $bundle = $issuer->issue( {%spec} );

# a secret that is none, and the file it lives in
my $token      = 'placeholder-'.$$.'-not-a-real-token';
my $token_file = spew( $tmp.'/router.token', $token."\n" );

my $count = 0;

sub target {
  my ( %options ) = @_;
  my $log_to = delete $options{log};
  my $class  = delete $options{class} || 'SICK::Target::Acmesh';
  my $names  = delete $options{names} || \@names;
  $options{hook}    = 'localcopy' unless exists $options{hook};
  $options{acme_sh} = $fake       unless exists $options{acme_sh};
  delete $options{$_} for grep { !defined $options{$_} } keys %options;
  my $device = SICK::Device->new(
    name         => 'router',
    type         => 'acmesh',
    names        => $names,
    lifetime     => $spec{lifetime},
    renew_before => 10 * 86400,
    key          => $spec{key},
    options      => \%options,
  );
  return $class->new( device => $device, log => $log_to );
}

# where the localcopy hook is to put things, as the env of a device
sub copy_to {
  my ( $dir ) = @_;
  mkdir $dir unless -d $dir;
  return {
    DEPLOY_LOCALCOPY_CERTIFICATE => $dir.'/cert.pem',
    DEPLOY_LOCALCOPY_CERTKEY     => $dir.'/key.pem',
    DEPLOY_LOCALCOPY_FULLCHAIN   => $dir.'/fullchain.pem',
    DEPLOY_LOCALCOPY_CA          => $dir.'/ca.pem'
  };
}

subtest 'the class' => sub {
  is( SICK::Target->class_for('acmesh'), 'SICK::Target::Acmesh', 'type acmesh' );
  my $target = target();
  isa_ok $target, 'SICK::Target';
  is $target->hook,      'localcopy',               'hook';
  is $target->acme_sh,   $fake,                     'acme_sh as given';
  is $target->cert_name, 'router.example.internal', 'the first name is the name of the certificate';
  is target( acme_sh => undef )->acme_sh, 'acme.sh', 'acme.sh from the PATH when nothing is given';
  is_deeply [ $target->endpoint ], [ 'router.example.internal', 443 ], 'the certificate is looked at over TLS, like for any device';
};

subtest 'validate' => sub {
  my $good = target(
    env       => { DEPLOY_PROXMOXVE_USER => 'sick', DEPLOY_PROXMOXVE_API_TOKEN_NAME => 'sick' },
    env_files => { DEPLOY_PROXMOXVE_API_TOKEN_KEY => '/etc/sick/pve.token' },
    home      => '/var/lib/sick/acme',
  );
  is $good->validate, $good, 'hook, env, env_files, acme_sh and home are the options';

  my %bad = (
    'no hook'                    => [ { hook => undef }, qr/^devices\.router: missing 'hook'/ ],
    'a hook that is a path'      => [ { hook => '../evil' }, qr/^devices\.router\.hook: invalid hook name '\.\.\/evil'/ ],
    'two hooks'                  => [ { hook => 'ssh,localcopy' }, qr/^devices\.router\.hook: invalid hook name 'ssh,localcopy'/ ],
    'a hook that is a list'      => [ { hook => ['ssh'] }, qr/^devices\.router\.hook: invalid hook name ''/ ],
    'an unknown option'          => [ { colour => 'blue' }, qr/^devices\.router: unknown key 'colour' for type 'acmesh'/ ],
    'env as a list'              => [ { env => ['A=1'] }, qr/^devices\.router\.env: must be a mapping of variable names/ ],
    'env_files as a string'      => [ { env_files => '/etc/sick/x' }, qr/^devices\.router\.env_files: must be a mapping of variable names/ ],
    'a variable name with space' => [ { env => { 'A B' => 1 } }, qr/^devices\.router\.env: invalid variable name 'A B'/ ],
    'a variable name with ='     => [ { env_files => { 'A=B' => '/x' } }, qr/^devices\.router\.env_files: invalid variable name 'A=B'/ ],
    'a nested value'             => [ { env => { A => { b => 1 } } }, qr/^devices\.router\.env\.A: must be a plain value/ ],
    'a file that is no path'     => [ { env_files => { A => q{} } }, qr/^devices\.router\.env_files\.A: must be the path of a file/ ],
    'a variable in both'         => [ { env => { A => 1 }, env_files => { A => '/x' } }, qr/^devices\.router\.env_files\.A: is also in env/ ],
    'a path of acme.sh in env'   => [ { env => { DOMAIN_PATH => '/x' } }, qr/^devices\.router\.env\.DOMAIN_PATH: is set by SICK itself/ ],
    'the home of acme.sh in env' => [ { env_files => { LE_WORKING_DIR => '/x' } }, qr/^devices\.router\.env_files\.LE_WORKING_DIR: is set by SICK itself/ ],
    'debug output in env'        => [ { env => { DEBUG => 2 } }, qr/^devices\.router\.env\.DEBUG: is set by SICK itself/ ],
    'a relative home'            => [ { home => 'acme' }, qr/^devices\.router\.home: must be an absolute path without whitespace/ ],
    'a home with a space'        => [ { home => '/var/lib/my acme' }, qr/^devices\.router\.home: must be an absolute path without whitespace/ ],
    'an empty acme_sh'           => [ { acme_sh => q{} }, qr/^devices\.router\.acme_sh: must be the name or the path/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $options, $message ) = @{ $bad{$case} };
    ok !eval { target(%$options)->validate; 1 }, 'dies for '.$case;
    like $@, $message, '... with its place in the device list';
  }

  ok !eval { target( hook => undef )->deploy($bundle); 1 }, 'deploy validates as well';
  like $@, qr/^devices\.router: missing 'hook'/, '... with the same message';
  is_deeply calls(), [], '... before acme.sh is started';
};

subtest 'deploy lays out the certificate and runs acme.sh' => sub {
  my $out = $tmp.'/out1';
  my @lines;
  my $target = target(
    env       => { %{ copy_to($out) }, ROUTER_OS_HOST => 'router.example.internal' },
    env_files => { SICK_TEST_TOKEN => $token_file },
    log       => sub { push @lines, @_ },
  );

  # what must not reach acme.sh from the environment SICK runs in
  local $ENV{DOMAIN_PATH} = $tmp.'/elsewhere';
  local $ENV{CERT_PATH}   = $tmp.'/elsewhere/cert';
  local $ENV{DEBUG}       = 2;
  local $ENV{LOG_FILE}    = $tmp.'/acme-debug.log';

  is $target->deploy($bundle), undef, 'deploy returns nothing';

  my $calls = calls();
  is scalar @$calls, 1, 'acme.sh was started once';
  my $call = $calls->[0];
  my $home = $call->{argv}[6];
  is_deeply $call->{argv},
    [ '--deploy', '-d', 'router.example.internal', '--deploy-hook', 'localcopy',
      '--home', $home, '--config-home', $home, '--cert-home', $home ],
    'the command line: deploy, first name, hook, and one home for everything';
  like $home, qr{^\Q$scratch\E/sick-}, 'the home is a private temporary directory';
  is $call->{home_mode}, '0700', '... that nobody else can enter';
  ok !-e $home, '... and that is gone afterwards';
  is_deeply leftovers(), [], 'nothing is left in the temporary directory';

  is_deeply $call->{files},
    {
      'router.example.internal.key'  => '0600',
      'router.example.internal.cer'  => '0644',
      'router.example.internal.conf' => '0600',
      'ca.cer'                       => '0644',
      'fullchain.cer'                => '0644'
    },
    'the files acme.sh expects, the key readable for nobody else';
  is $call->{dir_mode}, '0700', 'the directory of the certificate is private';
  ok $call->{key_is_pem}, 'the key file holds the key';
  is $call->{conf}, "Le_Domain='router.example.internal'\nLe_Alt='router.hq.example.org,192.0.2.9'\nLe_Keylength='ec-256'\n",
    'the configuration names the certificate, its other names and its kind of key';
  is $call->{umask}, '0077', 'acme.sh runs with a umask that keeps what it writes private';

  is $call->{env_sha}{SICK_TEST_TOKEN}, sha256_hex($token), 'the secret of env_files is in the environment';
  is $call->{env_sha}{ROUTER_OS_HOST}, sha256_hex('router.example.internal'), '... next to the variables of env';
  ok !scalar( grep { index( $_, $token ) >= 0 } @{ $call->{argv} } ), '... and not on the command line';
  my %set = map { $_ => 1 } @{ $call->{env_set} };
  ok !$set{$_}, $_.' of the calling environment does not reach acme.sh' for qw( DOMAIN_PATH CERT_PATH DEBUG LOG_FILE );
  is $call->{no_timestamp}, 1, 'timestamps are switched off';

  is slurp( $out.'/cert.pem' ),      $bundle->cert,      'the hook received the certificate';
  is slurp( $out.'/key.pem' ),       $bundle->key,       '... the key';
  is slurp( $out.'/fullchain.pem' ), $bundle->fullchain, '... the full chain';
  is slurp( $out.'/ca.pem' ),        q{},                '... and an empty chain file, there being no intermediate';

  like $lines[0], qr/^running \Q$fake\E --deploy -d router\.example\.internal --deploy-hook localcopy --home /, 'the log has the command';
  is_deeply [ @lines[ 1 .. $#lines ] ], [ q{acme.sh: 'localcopy' deploy success}, 'acme.sh: Success' ], '... and what acme.sh printed';
  unlike join( "\n", @lines ), qr/\Q$token\E|PRIVATE KEY/, '... but neither the secret nor the key';
};

subtest 'a certificate with a chain, and a single name' => sub {
  my $root    = new_ca( dir => $tmp, name => 'root' );
  my $inter   = new_ca( dir => $tmp, name => 'inter', issuer => $root );
  my $leaf    = new_cert( dir => $tmp, name => 'leaf', ca => $inter, cn => 'solo.example.internal', san => 'DNS:solo.example.internal' );
  my $chained = SICK::Bundle->new( cert => $leaf->{cert_pem}, chain => $inter->{pem}, key => $leaf->{key_pem} );

  my $out = $tmp.'/out2';
  target( names => ['solo.example.internal'], env => copy_to($out) )->deploy($chained);
  is slurp( $out.'/ca.pem' ),        $inter->{pem},                   'ca.cer is the chain';
  is slurp( $out.'/fullchain.pem' ), $leaf->{cert_pem}.$inter->{pem}, 'fullchain.cer is certificate plus chain';
  is calls()->[0]{conf}, "Le_Domain='solo.example.internal'\nLe_Alt='no'\nLe_Keylength='ec-256'\n",
    'no other names: Le_Alt is "no", as acme.sh writes it';
};

subtest 'a home that stays' => sub {
  my $home   = $tmp.'/acme-home/nested';
  my $out    = $tmp.'/out3';
  my $target = target( home => $home, env => copy_to($out) );
  my $dir    = $home.'/router.example.internal';

  $target->deploy($bundle);
  my $call = calls()->[0];
  is $call->{argv}[6], $home, 'acme.sh works in the given home';
  is mode_of($home), '0700', 'which was created private';
  is mode_of($dir),  '0700', '... like the directory of the certificate';
  ok $call->{key_is_pem}, 'the key was there while acme.sh ran';
  is_deeply files_in($dir), [qw( ca.cer fullchain.cer router.example.internal.cer router.example.internal.conf )],
    '... and is removed afterwards; no temporary files either';
  is slurp( $out.'/key.pem' ), $bundle->key, 'the hook got it all the same';

  my $second = $issuer->issue( {%spec} );
  $target->deploy($second);
  is slurp( $out.'/cert.pem' ), $second->cert, 'a second deployment replaces the certificate';
  is slurp( $dir.'/router.example.internal.conf' ),
    "Le_Domain='router.example.internal'\nLe_Alt='router.hq.example.org,192.0.2.9'\nLe_Keylength='ec-256'\nLe_DeployHook='localcopy,'\nLe_DeployHook='localcopy,'\n",
    'the configuration is written once and then left to acme.sh';
  is_deeply leftovers(), [], 'no private temporary directory was needed';

  my $failing = target( home => $home, hook => 'sickfail' );
  ok !eval { $failing->deploy($bundle); 1 }, 'a failing hook';
  ok !-e $dir.'/router.example.internal.key', '... does not leave the key behind either';
  calls();
};

subtest 'a hook that fails' => sub {
  my @lines;
  my $target = target( hook => 'sickfail', log => sub { push @lines, @_ } );
  ok !eval { $target->deploy($bundle); 1 }, 'deploy dies';
  like $@, qr/^acme\.sh failed \(exit 1\): the device said no\nError deploying for domain: router\.example\.internal\nError encountered while deploying\./,
    '... with the exit code and what acme.sh wrote as error';
  is $lines[-1], 'acme.sh: Trying the device', 'what it printed before is in the log';
  my $home = calls()->[0]{argv}[6];
  ok !-e $home, 'the private home is gone all the same';
  is_deeply leftovers(), [], '... and nothing else is left';

  ok !eval { target( hook => 'nosuchhook' )->deploy($bundle); 1 }, 'a hook acme.sh does not have';
  like $@, qr/^acme\.sh failed \(exit 1\): The deploy hook nosuchhook was not found\./, '... is reported in its words';
  calls();
};

subtest 'secrets stay secret' => sub {
  my @lines;
  my $target = target( hook => 'sickleak', env_files => { SICK_TEST_TOKEN => $token_file }, log => sub { push @lines, @_ } );
  $target->deploy($bundle);
  is $lines[-1], 'acme.sh: Logging in with [hidden]', 'a secret the hook prints is hidden in the log';
  unlike join( "\n", @lines ), qr/\Q$token\E/, '... everywhere';

  my $failing = target( hook => 'sickleak', env => { SICK_TEST_EXIT => 3 }, env_files => { SICK_TEST_TOKEN => $token_file } );
  ok !eval { $failing->deploy($bundle); 1 }, 'the same hook failing';
  is $@ =~ s/ at \S+ line \d+\.\n\z//r, 'acme.sh failed (exit 3): The device did not like [hidden] at all',
    '... has the secret hidden in the error message';
  calls();

  my $missing = $tmp.'/no-such.token';
  my $home    = $tmp.'/acme-home-untouched';
  my $unread  = target( home => $home, env_files => { SICK_TEST_TOKEN => $missing } );
  ok !eval { $unread->deploy($bundle); 1 }, 'a secret file that is missing';
  like $@, qr/^cannot read secret file '\Q$missing\E': \S/, '... is named with its path and the reason';
  unlike $@, qr/\n.*\n/s, '... on one line';
  is_deeply calls(), [], 'acme.sh was not started';
  ok !-e $home, '... and nothing was laid out';
};

subtest 'what cannot work' => sub {
  my $missing = $tmp.'/bin/acme.sh';
  ok !eval { target( acme_sh => $missing )->deploy($bundle); 1 }, 'acme.sh is not installed';
  like $@, qr/^cannot run '\Q$missing\E': \S/, '... says which program is missing';
  is_deeply leftovers(), [], '... and leaves nothing behind';

  my $no_key = SICK::Bundle->new( cert => $bundle->cert );
  ok !eval { target()->deploy($no_key); 1 }, 'a bundle without a key';
  like $@, qr/^the acmesh target needs the private key of the certificate/, '... is refused';
  is_deeply calls(), [], '... before acme.sh is started';

  {
    package SICK::Target::AcmeshImpatient;
    our @ISA = ('SICK::Target::Acmesh');
    sub deploy_timeout { 1 }
  }
  my $marker = $tmp.'/waiting';
  local $ENV{SICK_TEST_MARKER} = $marker;
  ok !eval { target( class => 'SICK::Target::AcmeshImpatient', hook => 'sickwait' )->deploy($bundle); 1 }, 'a hook that does not finish';
  like $@, qr/^'\Q$fake\E' timed out after 1s/, '... is stopped after the timeout';
  ok -e $marker, '... having been started';
  my ( $home, $pid ) = split /\n/, slurp($marker);
  ok !kill( 0, $pid ), '... the program is not running any more';
  ok !-e $home, 'its home with the key is gone';
  is_deeply leftovers(), [], '... like everything else';
  calls();
};

#### the real acme.sh

my $real = defined $ENV{SICK_TEST_ACME_SH} && length $ENV{SICK_TEST_ACME_SH} ? $ENV{SICK_TEST_ACME_SH} : 'acme.sh';
my $version = do {
  my @result = eval { SICK::Command::run( [ $real, '--version' ], timeout => 30 ) };
  @result && $result[2] == 0 && $result[0] =~ /^v?([0-9]+\.[0-9]+\.[0-9]+)/m ? $1 : undef;
};

subtest 'the real acme.sh with its localcopy hook' => sub {
  plan skip_all => 'acme.sh is not installed (SICK_TEST_ACME_SH names it when it is not in the PATH)'
    unless defined $version;
  diag 'acme.sh '.$version.' ('.$real.')';
  local $ENV{FAKE_ACME_LOG};
  delete $ENV{FAKE_ACME_LOG};

  # nothing of this may send acme.sh somewhere else
  local $ENV{DOMAIN_PATH}    = $tmp.'/elsewhere';
  local $ENV{LE_WORKING_DIR} = $tmp.'/elsewhere';
  local $ENV{CERT_HOME}      = $tmp.'/elsewhere';

  for my $key (qw( ec256 rsa2048 )) {
    my $issued = $issuer->issue( { %spec, key => $key } );
    my $out    = $tmp.'/real-'.$key;
    my @lines;
    target( acme_sh => $real, env => copy_to($out), log => sub { push @lines, @_ } )->deploy($issued);

    is slurp( $out.'/cert.pem' ),      $issued->cert,      $key.': the certificate is where the hook was told to put it';
    is slurp( $out.'/key.pem' ),       $issued->key,       '... the key';
    is slurp( $out.'/fullchain.pem' ), $issued->fullchain, '... the full chain';
    is mode_of( $out.'/key.pem' ), '0600', '... the key private';
    ok scalar( grep { /^acme\.sh: .*'localcopy' deploy success/ } @lines ), '... and acme.sh says so in the log';
    ok !scalar( grep { /^acme\.sh: \[/ } @lines ), '... without timestamps';
  }
  is_deeply leftovers(), [], 'no home, no key, nothing is left in the temporary directory';

  subtest 'a chain' => sub {
    my $root    = new_ca( dir => $tmp, name => 'real-root' );
    my $inter   = new_ca( dir => $tmp, name => 'real-inter', issuer => $root );
    my $leaf    = new_cert( dir => $tmp, name => 'real-leaf', ca => $inter, cn => 'solo.example.internal', san => 'DNS:solo.example.internal' );
    my $chained = SICK::Bundle->new( cert => $leaf->{cert_pem}, chain => $inter->{pem}, key => $leaf->{key_pem} );
    my $out     = $tmp.'/real-chain';
    target( acme_sh => $real, names => ['solo.example.internal'], env => copy_to($out) )->deploy($chained);
    is slurp( $out.'/ca.pem' ),        $inter->{pem},                   'the hook receives the chain as its CA file';
    is slurp( $out.'/fullchain.pem' ), $leaf->{cert_pem}.$inter->{pem}, '... and certificate plus chain as full chain';
  };

  subtest 'names that are no host names' => sub {
    for my $first ( '192.0.2.9', '*.wild.example.internal', '2001:db8::9' ) {
      my $out = $tmp.'/real-name';
      unlink glob $out.'/*';
      target( acme_sh => $real, names => [ $first, 'other.example.internal' ], env => copy_to($out) )->deploy($bundle);
      is slurp( $out.'/cert.pem' ), $bundle->cert, 'a certificate whose first name is '.$first;
    }
  };

  subtest 'a secret reaches the hook through the environment only' => sub {
    # the reload command of the hook prints the variable: it can only do
    # that when the value arrived, and what it prints has to be hidden
    my $out = $tmp.'/real-secret';
    my @lines;
    target(
      acme_sh   => $real,
      env       => { %{ copy_to($out) }, DEPLOY_LOCALCOPY_RELOADCMD => 'echo "token is $SICK_TEST_TOKEN"' },
      env_files => { SICK_TEST_TOKEN => $token_file },
      log       => sub { push @lines, @_ },
    )->deploy($bundle);
    is slurp( $out.'/cert.pem' ), $bundle->cert, 'deployed';
    ok scalar( grep { $_ eq 'acme.sh: token is [hidden]' } @lines ), 'the hook saw the value of env_files, and the log hides it';
    unlike join( "\n", @lines ), qr/\Q$token\E/, '... everywhere';
    unlike $lines[0], qr/token/, '... and it never was on the command line';
  };

  subtest 'failures' => sub {
    my $out = $tmp.'/real-fail';
    my $failing = target( acme_sh => $real, env => { %{ copy_to($out) }, DEPLOY_LOCALCOPY_RELOADCMD => 'echo service is down >&2; exit 3' } );
    ok !eval { $failing->deploy($bundle); 1 }, 'a reload command of the hook that fails';
    like $@, qr/^acme\.sh failed \(exit 1\): service is down/, '... fails the deployment with its message';

    ok !eval { target( acme_sh => $real, hook => 'nosuchhook' )->deploy($bundle); 1 }, 'a hook that does not exist';
    like $@, qr/^acme\.sh failed \(exit 1\): The deploy hook nosuchhook was not found/, '... is reported by acme.sh';
    is_deeply leftovers(), [], 'nothing is left in the temporary directory';
  };

  subtest 'a home that stays' => sub {
    my $home = $tmp.'/real-home';
    my $out  = $tmp.'/real-kept';
    my $dir  = $home.'/router.example.internal';
    target( acme_sh => $real, home => $home, env => copy_to($out) )->deploy($bundle);
    is slurp( $out.'/cert.pem' ), $bundle->cert, 'deployed';
    ok !-e $dir.'/router.example.internal.key', 'the key is gone from the home';
    my $conf = slurp( $dir.'/router.example.internal.conf' );
    like $conf, qr/^Le_Domain='router\.example\.internal'$/m, 'the configuration SICK started';
    like $conf, qr/^SAVED_DEPLOY_LOCALCOPY_CERTIFICATE='\Q$out\E\/cert\.pem'$/m, '... is where acme.sh remembers what the hook was given';
    is mode_of( $dir.'/router.example.internal.conf' ), '0600', '... readable for nobody else';

    # acme.sh uses what it remembered: no env this time
    my $second = $issuer->issue( {%spec} );
    target( acme_sh => $real, home => $home )->deploy($second);
    is slurp( $out.'/cert.pem' ), $second->cert, 'a second deployment without env goes to the remembered place';
  };

  subtest 'through the runner' => sub {
    plan skip_all => 'YAML::PP is not installed' unless eval { require SICK::Config; require SICK::Runner; 1 };
    {
      package SICK::Target::AcmeshCopy;    # looks at the copy instead of asking a TLS server
      our @ISA = ('SICK::Target::Acmesh');
      sub verify_timeout { 0 }

      sub presented_cert {
        my ( $self ) = @_;
        my $cert = $self->option('env')->{DEPLOY_LOCALCOPY_CERTIFICATE};
        return -s $cert ? SICK::Bundle->from_files( cert => $cert ) : undef;
      }
    }
    $INC{'SICK/Target/AcmeshCopy.pm'} = __FILE__;

    my $out = $tmp.'/real-runner';
    mkdir $out or die 'mkdir: '.$!;
    my $config = SICK::Config->load_string( <<"YAML", 'list.yml' );
devices:
  copy:
    type: acmesh-copy
    hook: localcopy
    acme_sh: $real
    names: [copy.example.internal, 192.0.2.40]
    env:
      DEPLOY_LOCALCOPY_CERTIFICATE: $out/cert.pem
      DEPLOY_LOCALCOPY_CERTKEY: $out/key.pem
YAML
    my $runner = SICK::Runner->new( config => $config, issuer => $issuer );
    is_deeply [ map { [ @$_{qw( device action reason )} ] } $runner->run ], [ [ 'copy', 'renewed', 'missing' ] ], 'first run: renewed';
    is_deeply( SICK::Bundle->from_files( cert => $out.'/cert.pem' )->names, [ '192.0.2.40', 'copy.example.internal' ],
      'the certificate with the names of the device is where the hook put it' );
    is_deeply [ map { [ @$_{qw( device action reason )} ] } $runner->run ], [ [ 'copy', 'unchanged', 'ok' ] ], 'second run: unchanged';
    is_deeply leftovers(), [], 'nothing is left in the temporary directory';
  };
};

done_testing;
