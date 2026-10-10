#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Fcntl qw( LOCK_EX LOCK_NB LOCK_UN );
use File::Path ();
use File::Temp qw( tempdir );
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

use SICK::Bundle;
use SICK::CLI;
use SICK::Command;
use SICK::OpenSSL;
use Test::SICK::PKI qw( new_ca slurp spew );

# The sick command line: in this process through SICK::CLI, where output and
# exit code are easy to look at, and as the real program bin/sick, where the
# exit code is the one a shell sees. A self-signed CA and files devices; the
# only sockets are closed ports on 127.0.0.1.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

my $scratch = $tmp.'/scratch';
mkdir $scratch or die 'mkdir: '.$!;
local $ENV{TMPDIR} = $scratch;
delete local $ENV{SICK_CONFIG};

sub leftovers {
  opendir my $dh, $scratch or die 'cannot read '.$scratch.': '.$!;
  return [ sort grep { !/\A\.\.?\z/ } readdir $dh ];
}

my $closed_port = do {
  my $listener = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 )
    or plan skip_all => 'cannot listen on 127.0.0.1: '.$!;
  my $port = $listener->sockport;
  close $listener;
  $port;
};

# sick in this process: ( exit code, standard output, standard error )
sub cli {
  my ( @argv ) = @_;
  my %env = ref $argv[0] eq 'HASH' ? %{ shift @argv } : ();
  my ( $out, $err ) = ( q{}, q{} );
  open my $out_fh, '>', \$out or die $!;
  open my $err_fh, '>', \$err or die $!;
  my $code = SICK::CLI->new( out => $out_fh, err => $err_fh, env => \%env )->run(@argv);
  close $out_fh;
  close $err_fh;
  return ( $code, $out, $err );
}

# sick as a program: ( exit code, standard output, standard error )
sub program {
  my ( @argv ) = @_;
  my ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-Ilib', 'bin/sick', @argv ], timeout => 120 );
  return ( $exit, $out, $err );
}

my $number = 0;

# a device list with a self-signed CA and a state directory of its own;
# returns its path
sub list {
  my ( $devices, %ca ) = @_;
  my $path = $tmp.'/list'.++$number.'.yml';
  my %section = ( type => 'selfsigned', dir => $tmp.'/ca', %ca );
  spew( $path,
    "ca:\n".join( q{}, map { '  '.$_.': '.$section{$_}."\n" } sort keys %section )
      ."defaults:\n  lifetime: 40d\n  renew_before: 10d\n  key: ec256\n"
      ."state: ".state_of($path)."\n"
      ."devices:\n".$devices );
  return $path;
}

sub state_of { $_[0] =~ s/list([0-9]+)\.yml\z/state$1/r }

# takes the lock of a state directory the way another sick run would
sub hold_lock {
  my ( $dir, $content ) = @_;
  File::Path::make_path($dir);
  open my $fh, '>>', $dir.'/sick.lock' or die 'cannot open the lock: '.$!;
  flock $fh, LOCK_EX | LOCK_NB or die 'cannot take the lock: '.$!;
  if ( defined $content ) {
    truncate $fh, 0;
    print {$fh} $content;
    $fh->flush;
  }
  return $fh;
}

sub lock_is_free {
  my ( $dir ) = @_;
  open my $fh, '>>', $dir.'/sick.lock' or return 0;
  my $free = flock $fh, LOCK_EX | LOCK_NB;
  return $free ? 1 : 0;
}

sub files_device {
  my ( $name, %extra ) = @_;
  return '  '.$name.":\n    type: files\n    names: [".$name.".example.internal]\n    dir: ".$tmp.'/'.$name."\n"
    .join( q{}, map { '    '.$_.': '.$extra{$_}."\n" } sort keys %extra );
}

my $gone = files_device( 'gone', host => '127.0.0.1', port => $closed_port );

subtest 'help and version' => sub {
  for my $flag (qw( --help -h )) {
    my ( $code, $out, $err ) = cli($flag);
    is $code, 0, $flag.' exits with 0';
    like $out, qr/^Usage:\n  sick \[--config <file>\] check/, '... and prints the usage';
    like $out, qr/^  \Q$_\E\b/m, '... naming '.$_ for qw( check run trust );
    like $out, qr/--\Q$_\E\b/, '... and --'.$_ for qw( config force dry-run verbose help version );
    like $out, qr/^  0 .*\n  1 .*\n  2 .*\n  3  run: another sick run holds the lock/m, '... and the exit codes';
    is $err, q{}, '... nothing on standard error';
  }
  is_deeply [ cli( 'run', '--help' ) ], [ 0, SICK::CLI->usage, q{} ], '--help wins wherever it stands';

  my ( $code, $out, $err ) = cli('--version');
  is_deeply [ $code, $out, $err ], [ 0, 'sick '.SICK::CLI->VERSION."\n", q{} ], '--version prints the version';
};

subtest 'a command line that is wrong is exit code 2' => sub {
  my $path = list( files_device('unused') );
  my %wrong = (
    'no command'                => [ [],                                    qr/^sick: no command given\n/ ],
    'an unknown command'        => [ ['renew'],                             qr/^sick: unknown command 'renew'\n/ ],
    'an unknown option'         => [ [ 'check', '--frobnicate' ],           qr/^sick: unknown option: frobnicate\n/ ],
    '--config without a value'  => [ [ 'check', '--config' ],               qr/^sick: option config requires an argument\n/ ],
    '--force for check'         => [ [ '--config', $path, 'check', '--force' ], qr/^sick: --force does not go with 'check'\n/ ],
    '--dry-run for trust'       => [ [ '--config', $path, 'trust', '-n', $tmp.'/t' ], qr/^sick: --dry-run does not go with 'trust'\n/ ],
    'trust without a directory' => [ [ '--config', $path, 'trust' ],        qr/^sick: trust needs the directory to write to\n/ ],
    'trust with two'            => [ [ '--config', $path, 'trust', $tmp.'/a', $tmp.'/b' ], qr/^sick: trust takes one directory\n/ ]
  );
  for my $case ( sort keys %wrong ) {
    my ( $argv, $message ) = @{ $wrong{$case} };
    my ( $code, $out, $err ) = cli(@$argv);
    is $code, 2, $case.': exit code 2';
    like $err, $message, '... with the reason';
    like $err, qr/^Try 'sick --help'\.$/m, '... and where to look';
    is $out, q{}, '... nothing on standard output';
  }
  ok !-e $tmp.'/unused', 'nothing was done to any device';
  ok !-e $tmp.'/t',      '... and no directory was written';
};

subtest 'the device list' => sub {
  my $missing = $tmp.'/no-such-list.yml';
  my ( $code, $out, $err ) = cli( 'check', '--config', $missing );
  is $code, 2, 'a list that is not there: exit code 2';
  like $err, qr/^sick: cannot read config file '\Q$missing\E': \S.*\n\z/, '... with path and reason, on one line';
  unlike $err, qr/ at \S+ line \d+/, '... and without the place in the code';

  my $broken = spew( $tmp.'/broken.yml', "devices:\n  web:\n    names: [web.example.internal]\n" );
  ( $code, $out, $err ) = cli( '-c', $broken, 'run' );
  is $code, 2, 'a list that is wrong: exit code 2';
  is $err, 'sick: '.$broken.': devices.web: missing \'type\''."\n", '... with the place in the list';

  my $no_issuer = list( files_device('web'), type => 'letsencrypt' );
  ( $code, $out, $err ) = cli( 'check', '-c', $no_issuer );
  is $code, 2, 'a ca section that makes no issuer: exit code 2';
  is $err, 'sick: '.$no_issuer.': ca.type: unknown type \'letsencrypt\' (step-ca or selfsigned)'."\n", '... saying why';

  my $step = spew( $tmp.'/step.yml', "ca:\n  url: https://ca.example.internal:9000\n".files_device('web') =~ s/\A/devices:\n/r );
  ( $code, $out, $err ) = cli( 'check', '-c', $step );
  is $code, 2, 'a step-ca section without its keys: exit code 2';
  is $err, 'sick: '.$step.': ca: missing \'root\''."\n", '... naming the first one that is missing';

  ( $code, $out, $err ) = cli( { SICK_CONFIG => $missing }, 'check' );
  like $err, qr/^sick: cannot read config file '\Q$missing\E'/, 'without --config the list is $SICK_CONFIG';
  ( $code, $out, $err ) = cli( { SICK_CONFIG => $missing }, 'check', '--config', $broken );
  like $err, qr/^sick: \Q$broken\E: /, '--config goes before $SICK_CONFIG';

SKIP: {
    skip 'this machine has an /etc/sick/sick.yml', 1 if -e '/etc/sick/sick.yml';
    ( $code, $out, $err ) = cli('check');
    like $err, qr{^sick: cannot read config file '/etc/sick/sick\.yml'}, 'without both it is /etc/sick/sick.yml';
  }
};

subtest 'check' => sub {
  my $path = list( files_device('web').files_device('database') );
  my ( $code, $out, $err ) = cli( 'check', '--config', $path );
  is $code, 0, 'exit code 0: every device could be looked at, due or not';
  is $out, <<'TABLE', 'an aligned table';
DEVICE    STATUS   RENEW  DETAIL
web       missing  yes    the device presents no certificate
database  missing  yes    the device presents no certificate
TABLE
  is $err, q{}, 'nothing on standard error';
  ok !-e $tmp.'/web', 'check changes nothing';

  ( $code, $out, $err ) = cli( 'check', '--config', $path, 'database' );
  is $out, <<'TABLE', 'one device by name';
DEVICE    STATUS   RENEW  DETAIL
database  missing  yes    the device presents no certificate
TABLE

  ( $code, $out, $err ) = cli( 'check', '--config', $path, 'web', 'nobody' );
  is $code, 2, 'a name that is not in the list: exit code 2';
  is $err, "sick: unknown device 'nobody'\n", '... naming it';
  is $out, q{}, '... and no table';

  my $with_gone = list( $gone.files_device('web') );
  ( $code, $out, $err ) = cli( 'check', '--config', $with_gone );
  is $code, 1, 'a device that does not answer: exit code 1';
  like $out, qr/^gone    unreachable  \?      127\.0\.0\.1:$closed_port: \S.*\n^web     missing      yes    the device/m,
    '... shown as unreachable, renewal unknown; the others are listed all the same';
  unlike $out, qr/[ \t]\n/, 'no line of the table ends in blanks';
};

subtest 'run' => sub {
  my $path = list( files_device('web').files_device('database') );
  my $dir  = $tmp.'/web';

  my ( $code, $out, $err ) = cli( 'run', '--dry-run', '--config', $path );
  is $code, 0, 'dry run: exit code 0';
  is $out, <<'TABLE', '... saying what would be renewed';
DEVICE    ACTION       REASON   ERROR
web       would-renew  missing
database  would-renew  missing
TABLE
  ok !-e $dir, '... and writing nothing';

  ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 0, 'first run: exit code 0';
  is $out, <<'TABLE', '... both renewed';
DEVICE    ACTION   REASON   ERROR
web       renewed  missing
database  renewed  missing
TABLE
  is $err, q{}, '... and silent on standard error';
  my $first = SICK::Bundle->from_files( cert => $dir.'/cert.pem' )->fingerprint_sha256;

  ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 0, 'second run: exit code 0';
  like $out, qr/^web       unchanged  ok\ndatabase  unchanged  ok\n/m, '... nothing to do';
  is( SICK::Bundle->from_files( cert => $dir.'/cert.pem' )->fingerprint_sha256, $first, '... and nothing done' );

  ( $code, $out, $err ) = cli( 'run', '-n', '-f', '--config', $path, 'web' );
  like $out, qr/^web     would-renew  forced\n\z/m, 'dry run with force, one device';
  is( SICK::Bundle->from_files( cert => $dir.'/cert.pem' )->fingerprint_sha256, $first, '... still nothing done' );

  ( $code, $out, $err ) = cli( '--config', $path, 'run', '--force', '--verbose', 'web' );
  is $code, 0, 'force: exit code 0';
  like $out, qr/^web     renewed  forced\n\z/m, '... renewed although it was fine; the other device is not touched';
  isnt( SICK::Bundle->from_files( cert => $dir.'/cert.pem' )->fingerprint_sha256, $first, '... for real' );
  like $err, qr/^web: issuing a certificate for web\.example\.internal\n/m, '--verbose reports on standard error';
  like $err, qr/^web: wrote cert\.pem/m, '... including what the target says';
  unlike $err, qr/PRIVATE KEY/, '... but no key';

  ( $code, $out, $err ) = cli( 'run', '--force', '--config', $path, 'nobody', 'web' );
  is $code, 2, 'a name that is not in the list: exit code 2';
  is $err, "sick: unknown device 'nobody'\n", '... naming it';
  is $out, q{}, '... before anything is done';

  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a device that fails is exit code 1, and the others go on' => sub {
  my $path = list( $gone.files_device('after') );
  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 1, 'exit code 1';
  like $out, qr/^gone    failed   unreachable  unreachable: 127\.0\.0\.1:$closed_port: \S.*\nafter   renewed  missing\n\z/m,
    'the table says which one failed and why, and that the next one was renewed';
  ok -s $tmp.'/after/cert.pem', '... which it was';

  my $failing = list( files_device( 'stuck', reload => '"echo the service is down >&2; echo and stays down >&2; exit 3"' ) );
  ( $code, $out, $err ) = cli( 'run', '--config', $failing );
  is $code, 1, 'a deployment that fails: exit code 1';
  like $out, qr/^stuck   failed  missing  deploy failed: reload failed \(exit 3\): the service is down; and stays down; there is no previous certificate to restore, the new one stays in place\n\z/m,
    '... with the error on one line of the table';
  unlike $out.$err, qr/ at \S+ line \d+/, '... and without the place in the code';
};

subtest 'one run at a time' => sub {
  my $path  = list( files_device('locked') );
  my $state = state_of($path);
  my $lock  = $state.'/sick.lock';

  {
    my $held = hold_lock( $state, "4242\n" );
    my ( $code, $out, $err ) = cli( 'run', '--config', $path );
    is $code, 3, 'while another run holds the lock: exit code 3';
    is $err, "sick: another sick run holds the lock '$lock' (pid 4242)\n", '... naming the lock and its holder';
    is $out, q{}, '... and doing nothing';
    ok !-e $tmp.'/locked', '... to any device';

    truncate $held, 0;
    ( $code, $out, $err ) = cli( 'run', '--force', '--config', $path, 'locked' );
    is $code, 3, 'a holder that has not written its pid yet: exit code 3';
    is $err, "sick: another sick run holds the lock '$lock'\n", '... without a pid';

    ( $code, $out, $err ) = program( 'run', '--config', $path );
    is $code, 3, 'bin/sick exits with 3 as well';
    like $err, qr/^sick: another sick run holds the lock '\Q$lock\E'\n\z/, '... saying why';

    ( $code, $out, $err ) = cli( 'check', '--config', $path );
    is $code, 0, 'check takes no lock';
    like $out, qr/^locked  missing/m, '... and looks';
    ( $code, $out, $err ) = cli( 'run', '--dry-run', '--config', $path );
    is $code, 0, 'neither does a dry run';
    like $out, qr/^locked  would-renew  missing/m, '... which says what would be done';
    ( $code, $out, $err ) = cli( 'trust', '--config', $path, $tmp.'/trust/locked' );
    is $code, 0, 'nor trust';
  }

  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 0, 'once the other run is gone: exit code 0';
  like $out, qr/^locked  renewed  missing/m, '... renewed';
  is slurp($lock), $$."\n", 'the lock file names the last run';
  ok lock_is_free($state), 'the lock is released after the run';
  ok -s $state.'/devices/locked.json', 'the record is written';
};

subtest 'the lock goes with a run that dies' => sub {
  my $path  = list( files_device('dying') );
  my $state = state_of($path);
  {
    no warnings 'redefine';
    local *SICK::Runner::run = sub { die "the run fell over\n" };
    my ( $code, $out, $err ) = cli( 'run', '--config', $path );
    is $code, 1, 'a run that dies: exit code 1';
    is $err, "sick: the run fell over\n", '... saying why';
    ok -e $state.'/sick.lock', 'the lock had been taken';
    ok lock_is_free($state), '... and is free again';
  }
  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 0, 'the next run works';
};

subtest 'a state directory that cannot be used' => sub {
  my $file = spew( $tmp.'/plain-file', "not a directory\n" );
  my $path = list( files_device('homeless') );
  spew( $path, slurp($path) =~ s/^state: .*$/state: $file\/state/mr );
  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 1, 'run: exit code 1';
  like $err, qr/^sick: cannot take the lock '\Q$file\E\/state\/sick\.lock': \S.*\n\z/, '... with path and reason';
  ok !-e $tmp.'/homeless', '... and nothing done';
  ( $code, $out, $err ) = cli( 'check', '--config', $path );
  is $code, 0, 'check does not need it';
};

subtest 'a record that cannot be written' => sub {
  my $path   = list( files_device('unrecorded') );
  my $record = state_of($path).'/devices/unrecorded.json';
  File::Path::make_path($record);
  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  like $out, qr/^unrecorded  renewed  missing\n/m, 'the device is renewed';
  is $code, 1, '... but without its record the run is exit code 1';
  like $err, qr/^sick: unrecorded: cannot read state record '\Q$record\E': Is a directory; cannot write state record '\Q$record\E': \S/m,
    '... saying why';
};

subtest 'a device that keeps failing is deferred' => sub {
  # a directory below a plain file: every deployment fails before it writes
  my $file = spew( $tmp.'/flaky-file', "not a directory\n" );
  my $path = list( "  flaky:\n    type: files\n    names: [flaky.example.internal]\n    dir: $file/certs\n" );
  my ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 1, 'first run: exit code 1';
  like $out, qr/^flaky   failed  missing  deploy failed: /m, '... deploy failed';

  ( $code, $out, $err ) = cli( 'run', '--config', $path );
  is $code, 1, 'second run: still exit code 1, the device is not served';
  like $out, qr/^flaky   deferred  missing  back-off after 1 failure, next attempt \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\n\z/m,
    '... deferred, saying until when';

  ( $code, $out, $err ) = cli( 'run', '--force', '--config', $path );
  like $out, qr/^flaky   failed  missing  deploy failed: /m, '--force tries again';
  like slurp( state_of($path).'/devices/flaky.json' ), qr/"consecutive_failures"\s*:\s*2/, '... and that counts';
  unlike slurp( state_of($path).'/devices/flaky.json' ), qr/PRIVATE KEY|key\.pem/, 'no key in the record';

  my $broken = state_of($path).'/devices/flaky.json';
  spew( $broken, "{oops\n" );
  ( $code, $out, $err ) = cli( 'run', '--config', $path );
  like $err, qr/^sick: flaky: cannot read state record '\Q$broken\E': not valid JSON\n/m, 'a broken record is reported';
  like $out, qr/^flaky   failed  missing  deploy failed: /m, '... and the device worked on as if it had none';
};

subtest 'trust' => sub {
  my $path = list( files_device('web'), name => '"Example <Internal> CA"' );
  my $dir  = $tmp.'/trust/site';
  my ( $code, $out, $err ) = cli( 'trust', $dir, '--config', $path );
  is $code, 0, 'exit code 0';
  is $out, 'wrote root_ca.pem, root_ca.crt, trust-linux.sh, trust-macos.sh, trust-windows.ps1, trust-nss.sh, root_ca.mobileconfig, index.html to '.$dir."\n", '... saying what was written';
  is $err, q{}, '... nothing on standard error';
  ok -s $dir.'/'.$_, $_.' is there' for qw( root_ca.pem root_ca.crt trust-linux.sh trust-macos.sh trust-windows.ps1 trust-nss.sh root_ca.mobileconfig index.html );
  is slurp( $dir.'/root_ca.pem' ), slurp( $tmp.'/ca/ca.crt' ), 'the root certificate is the one of the CA';
  like slurp( $dir.'/index.html' ), qr/<h1>Trust Example &lt;Internal&gt; CA<\/h1>/, 'the page uses the name of the ca section';

  my $unnamed = list( files_device('web') );
  ( $code, $out, $err ) = cli( 'trust', $tmp.'/trust/unnamed', '--config', $unnamed );
  like slurp( $tmp.'/trust/unnamed/index.html' ), qr/<h1>Trust SICK self-signed CA<\/h1>/,
    'without a name it is the common name of the root certificate';

  my $blocked = spew( $tmp.'/a-file', "in the way\n" );
  ( $code, $out, $err ) = cli( 'trust', $blocked.'/site', '--config', $path );
  is $code, 1, 'a directory that cannot be made: exit code 1';
  like $err, qr/^sick: cannot create directory '\Q$blocked\E\/site': \S.*\n\z/, '... with path and reason';
  is $out, q{}, '... and no claim of success';
};

subtest 'trust for a CA that signs through an intermediate' => sub {
  # A step-ca section: trust reads its two certificate files and calls nothing.
  my $pki = $tmp.'/pki';
  mkdir $pki or die 'mkdir: '.$!;
  my $root  = new_ca( dir => $pki, name => 'root',  cn => 'Example Internal Root CA' );
  my $inter = new_ca( dir => $pki, name => 'inter', cn => 'Example Internal Intermediate CA', issuer => $root );
  my $section = sub {
    my ( %ca ) = @_;
    return spew( $tmp.'/list'.++$number.'.yml',
      "ca:\n  url: https://ca.example.internal:9000\n  root: $root->{cert}\n"
        .join( q{}, map { '  '.$_.': '.$ca{$_}."\n" } sort keys %ca )
        ."  provisioner: sick\n  password_file: $tmp/no-such-password\ndevices:\n".files_device('web') );
  };

  my $dir = $tmp.'/trust/chained';
  my ( $code, $out, $err ) = cli( 'trust', $dir, '--config', $section->( intermediates => $inter->{cert} ) );
  is $code, 0, 'exit code 0';
  is $out, 'wrote root_ca.pem, root_ca.crt, intermediate_ca.pem, intermediate_ca.crt, ca_bundle.pem, trust-linux.sh, trust-macos.sh, trust-windows.ps1, trust-nss.sh, root_ca.mobileconfig, index.html to '.$dir."\n",
    '... saying what was written: the intermediate and the bundle as well';
  is $err, q{}, '... nothing on standard error';
  is slurp( $dir.'/intermediate_ca.pem' ), $inter->{pem}, 'the intermediate is the one of the ca section';
  is slurp( $dir.'/ca_bundle.pem' ), $root->{pem}.$inter->{pem}, 'the bundle is root and intermediate';
  like slurp( $dir.'/index.html' ), qr/<a href="intermediate_ca\.crt"/, 'the page offers it';

  ( $code, $out, $err ) = cli( 'trust', $dir, '--config', $section->() );
  is $code, 0, 'the same CA without intermediates in its section: exit code 0';
  is $out, 'wrote root_ca.pem, root_ca.crt, trust-linux.sh, trust-macos.sh, trust-windows.ps1, trust-nss.sh, root_ca.mobileconfig, index.html to '.$dir."\n", '... the root files, the scripts and the page';
  ok !-e $dir.'/'.$_, '... and '.$_.' is no longer offered' for qw( intermediate_ca.pem intermediate_ca.crt ca_bundle.pem );

  my $missing = $tmp.'/no-such-intermediate.crt';
  ( $code, $out, $err ) = cli( 'trust', $tmp.'/trust/nothing', '--config', $section->( intermediates => $missing ) );
  is $code, 1, 'an intermediates file that is not there: exit code 1';
  like $err, qr/^sick: cannot read ca\.intermediates '\Q$missing\E': \S.*\n\z/, '... with path and reason';
  is $out, q{}, '... no claim of success';
  ok !-e $tmp.'/trust/nothing', '... and nothing written';

  # a root replacement: the next root is published, and only there
  my $next = new_ca( dir => $pki, name => 'next', cn => 'Example Internal Root CA 2' );
  ( $code, $out, $err ) = cli( 'trust', $dir, '--config', $section->( additional_roots => '[ '.$next->{cert}.' ]' ) );
  is $code, 0, 'a section with additional_roots: exit code 0';
  is $out, 'wrote root_ca.pem, root_ca.crt, root_ca_2.pem, root_ca_2.crt, ca_bundle.pem, trust-linux.sh, trust-macos.sh, trust-windows.ps1, trust-nss.sh, root_ca.mobileconfig, index.html to '.$dir."\n",
    '... the additional root and the bundle as well';
  is slurp( $dir.'/root_ca.pem' ),   $root->{pem}, 'root_ca.pem stays the root of the section';
  is slurp( $dir.'/root_ca_2.pem' ), $next->{pem}, 'root_ca_2.pem is the additional root';

  ( $code, $out, $err ) = cli( 'trust', $tmp.'/trust/selfroot', '--config', $section->( additional_roots => '[ '.$inter->{cert}.' ]' ) );
  is $code, 1, 'an additional root that is none: exit code 1';
  like $err, qr/^sick: ca\.additional_roots '\Q$inter->{cert}\E' is not a self-signed CA certificate: issued by \S.*\n\z/,
    '... naming the key, the path and the reason';
  ok !-e $tmp.'/trust/selfroot', '... and nothing written';
};

subtest 'the program' => sub {
  my ( $code, $out, $err ) = program('--help');
  is_deeply [ $code, $out, $err ], [ 0, SICK::CLI->usage, q{} ], 'bin/sick --help';

  ( $code, $out, $err ) = program('--version');
  is_deeply [ $code, $out ], [ 0, 'sick '.SICK::CLI->VERSION."\n" ], 'bin/sick --version';

  ( $code, $out, $err ) = program('frobnicate');
  is $code, 2, 'an unknown command exits with 2';
  like $err, qr/^sick: unknown command 'frobnicate'\n/, '... and says so on standard error';

  my $path = list( files_device('prog').$gone );
  ( $code, $out, $err ) = program( 'check', '--config', $path );
  is $code, 1, 'check with a device that does not answer exits with 1';
  like $out, qr/^DEVICE  STATUS       RENEW  DETAIL\nprog    missing      yes    /, '... after printing the table';

  ( $code, $out, $err ) = program( 'run', '--config', $path, 'prog' );
  is $code, 0, 'run for the device that works exits with 0';
  like $out, qr/^prog    renewed  missing\n\z/m, '... having renewed it';

  ( $code, $out, $err ) = program( 'run', '--config', $path );
  is $code, 1, 'run for both exits with 1';
  like $out, qr/^prog    unchanged  ok\ngone    failed     unreachable  unreachable: /m, '... the table has both';

  {
    local $ENV{SICK_CONFIG} = $path;
    ( $code, $out, $err ) = program( 'trust', $tmp.'/trust/program' );
    is $code, 0, 'trust, with the list from $SICK_CONFIG, exits with 0';
    ok -s $tmp.'/trust/program/index.html', '... and wrote the page';
  }
  is_deeply leftovers(), [], 'no temporary directory is left';
};

subtest 'a run that is terminated takes its key with it' => sub {
  # An acmesh device whose "acme.sh" never finishes: while it waits, the
  # new key lies in the private home. Then sick is told to stop.
  my $fake = $tmp.'/acme.sh';
  ( my $source = slurp('t/bin/fake-acme-sh') ) =~ s/\A#![^\n]*\n/#!$^X\n/;
  spew( $fake, $source );
  chmod 0755, $fake or die 'chmod: '.$!;
  my $marker = $tmp.'/waiting';

  my $path = list( <<"YAML" );
  waiting:
    type: acmesh
    hook: sickwait
    acme_sh: $fake
    host: 127.0.0.1
    port: $closed_port
    names: [waiting.example.internal]
YAML
  # the device has to be judged before anything is issued: let it present
  # nothing instead of being unreachable
  my $lib = $tmp.'/lib/SICK/Target';
  File::Path::make_path($lib);
  spew( $lib.'/AcmeshMute.pm', <<'PERL' );
package SICK::Target::AcmeshMute;
use strict;
use warnings;
use parent 'SICK::Target::Acmesh';
sub presented_cert { return undef }
1;
PERL
  spew( $path, slurp($path) =~ s/type: acmesh/type: acmesh-mute/r );

  my $pid = fork;
  die 'fork: '.$! unless defined $pid;
  unless ($pid) {
    $ENV{SICK_TEST_MARKER} = $marker;
    open STDOUT, '>', $tmp.'/terminated.out';
    open STDERR, '>', $tmp.'/terminated.err';
    { no warnings 'exec'; exec { $^X } $^X, '-Ilib', '-I'.$tmp.'/lib', 'bin/sick', 'run', '--config', $path }
    POSIX::_exit(127);
  }

  my $waited = 0;
  until ( -s $marker || $waited >= 600 ) { select undef, undef, undef, 0.1; $waited++ }
  unless ( -s $marker ) {
    kill 'KILL', $pid;
    waitpid $pid, 0;
    plan skip_all => 'the run did not get as far as the hook: '.slurp( $tmp.'/terminated.err' );
  }
  select undef, undef, undef, 0.2;    # the fake writes home and pid in one go, but let it finish
  my ( $home, $hook_pid ) = split /\n/, slurp($marker);
  my $key = $home.'/waiting.example.internal/waiting.example.internal.key';

  like $home, qr{^\Q$scratch\E/sick-}, 'while the hook runs, acme.sh has a private home';
  is sprintf( '%04o', ( stat $home )[2] & 07777 ), '0700', '... that nobody else can enter';
  ok -s $key, '... with the new key in it';
  is sprintf( '%04o', ( stat $key )[2] & 07777 ), '0600', '... readable for nobody else';

  kill 'TERM', $pid;
  waitpid $pid, 0;
  my $status = $?;
  kill 'TERM', $hook_pid if $hook_pid && $hook_pid =~ /\A[0-9]+\z/;

  is $status >> 8, 143, 'sick ends with the exit code of a terminated program';
  is $status & 127, 0, '... by leaving, not by being killed';
  ok !-e $key,  'the key is gone';
  ok !-e $home, '... with the whole home';
  is_deeply leftovers(), [], '... and nothing else is left in the temporary directory';
};

done_testing;
