#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

use SICK::Command;
use SICK::OpenSSL;

# SICK::OpenSSL::run and the SICK::Command::run underneath it: no shell,
# stdin in, stdout/stderr/exit out.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

subtest 'available and version' => sub {
  ok SICK::OpenSSL::available(), 'available';
  like SICK::OpenSSL::version(), qr/SSL/, 'version reports the program';
  like SICK::OpenSSL::major(), qr/\A[0-9]+\z/, 'major is a number';

  local $ENV{SICK_OPENSSL} = $tmp.'/no-such-openssl';
  ok !SICK::OpenSSL::available(), 'not available when the program does not exist';
  is SICK::OpenSSL::version(), q{}, '... and it has no version';
  my $ok = eval { SICK::OpenSSL::run( ['version'] ); 1 };
  ok !$ok, 'run dies';
  like $@, qr/^cannot run '\Q$tmp\E\/no-such-openssl': /, '... and says which program is missing';
};

subtest 'stdout, stderr and exit code' => sub {
  my ( $out, $err, $exit ) = SICK::OpenSSL::run( ['version'] );
  like $out, qr/SSL/, 'stdout';
  is $err,  q{}, 'nothing on stderr';
  is $exit, 0,   'exit 0';

  ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'x509', '-noout', '-subject' ], stdin => "not a certificate\n" );
  is $out, q{}, 'no stdout on failure';
  isnt $err,  q{}, 'the reason is on stderr';
  isnt $exit, 0,   'non-zero exit is returned, not thrown';

  my $ok = eval { SICK::OpenSSL::run_checked( [ 'x509', '-noout', '-subject' ], stdin => "not a certificate\n" ); 1 };
  ok !$ok, 'run_checked dies on a non-zero exit';
  like $@, qr/^openssl x509 failed \(exit [0-9]+\): \S/, '... with command, exit code and stderr';
  unlike $@, qr/not a certificate/, '... and without the input';

  $ok = eval { SICK::OpenSSL::run('version'); 1 };
  ok !$ok, 'arguments must be an array reference';
};

subtest 'stdin goes through, however large' => sub {
  my ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'dgst', '-sha256', '-r' ], stdin => 'abc' );
  is $exit, 0, 'exit 0';
  like $out, qr/\Aba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\b/, 'sha256 of the stdin';

  # more than any pipe buffer in both directions
  my $big = join q{}, map { sprintf "%07d\n", $_ } 1 .. 200_000;
  ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'enc', '-base64', '-A' ], stdin => $big );
  is $exit, 0, 'large input: exit 0';
  ( my $back, $err, $exit ) = SICK::OpenSSL::run( [ 'enc', '-base64', '-A', '-d' ], stdin => $out );
  is $exit, 0, 'large output: exit 0';
  ok $back eq $big, '1.6 MB survive the round trip';
};

subtest 'no shell' => sub {
  my $marker = $tmp.'/shell-was-here';
  my @hostile = ( '; touch '.$marker, '$(touch '.$marker.')', '`touch '.$marker.'`', '| touch '.$marker );
  for my $arg (@hostile) {
    SICK::OpenSSL::run( [ 'version', $arg ] );
    my ($out) = SICK::Command::run( [ $^X, '-e', 'print $ARGV[0]', $arg ] );
    is $out, $arg, 'argument arrives verbatim: '.$arg;
  }
  # a single element is a program name, not a command line
  my $ok = eval { SICK::Command::run( [ 'touch '.$marker ] ); 1 };
  ok !$ok, 'a one-element list with a space is not split into a command';
  ok !-e $marker, 'no shell interpreted any argument';
};

subtest 'environment, umask and exit codes of SICK::Command' => sub {
  local $ENV{SICK_TEST_KEEP} = 'kept';
  local $ENV{SICK_TEST_DROP} = 'dropped';
  my ( $out, $err, $exit ) = SICK::Command::run(
    [ $^X, '-e', 'print join q{,}, map { $ENV{$_} // q{undef} } qw( SICK_TEST_KEEP SICK_TEST_DROP SICK_TEST_NEW )' ],
    env => { SICK_TEST_NEW => 'new', SICK_TEST_DROP => undef },
  );
  is $out, 'kept,undef,new', 'env adds and removes variables for the program';
  is $ENV{SICK_TEST_DROP}, 'dropped', '... and leaves our own environment alone';
  ok !exists $ENV{SICK_TEST_NEW}, '... in both directions';

  my $before = umask;
  ( $out ) = SICK::Command::run( [ $^X, '-e', 'printf q{%03o}, umask' ], umask => 077 );
  is $out, '077', 'umask applies to the program';
  is umask, $before, '... and not to us';

  ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-e', 'print STDERR q{oops}; exit 7' ] );
  is $exit, 7,      'exit code';
  is $err,  'oops', 'stderr';

  ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-e', 'kill q{KILL}, $$' ] );
  is $exit, 128 + 9, 'a program killed by a signal reports 128 + signal';

  ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-e', 'print scalar <STDIN> // q{eof}' ] );
  is $out, 'eof', 'without stdin the program reads an end of file';

  ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-e', 'close STDIN; print q{done}' ], stdin => 'x' x 300_000 );
  is $out, 'done', 'a program that does not read its stdin does not hang us';
};

subtest 'timeout' => sub {
  my $start = time;
  my $ok = eval { SICK::Command::run( [ $^X, '-e', 'sleep 30' ], timeout => 1 ); 1 };
  ok !$ok, 'dies';
  like $@, qr/^'\Q$^X\E' timed out after 1s/, '... naming program and limit';
  cmp_ok time - $start, '<', 10, '... without waiting for the program';

  my ( $out, $err, $exit ) = SICK::Command::run( [ $^X, '-e', 'print q{quick}' ], timeout => 20 );
  is $out, 'quick', 'a quick program is not affected by its timeout';
};

subtest 'a child of the program that keeps the pipes open' => sub {
  my $start = time;
  my ( $out, $err, $exit ) = SICK::Command::run(
    [ $^X, '-e', 'print q{parent}; $| = 1; unless (fork) { sleep 20; exit } exit 3' ] );
  is $out,  'parent', 'output of the program itself';
  is $exit, 3,        'its exit code';
  cmp_ok time - $start, '<', 10, 'we do not wait for the grandchild';
};

done_testing;
