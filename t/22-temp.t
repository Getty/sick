#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use SICK::Command;
use SICK::Temp;

# SICK::Temp: a private directory that goes away with its object.

sub mode_of { sprintf '%04o', ( stat $_[0] )[2] & 07777 }

subtest 'a private directory' => sub {
  my $tmp = SICK::Temp->dir;
  isa_ok $tmp, 'SICK::Temp';
  ok -d $tmp->path, 'the directory exists';
  is mode_of( $tmp->path ), '0700', 'mode 0700';
  is q{}.$tmp, $tmp->path, 'the object stringifies to the path';
  like $tmp->path, qr{\A/}, 'the path is absolute';
  isnt( SICK::Temp->dir->path, $tmp->path, 'every call makes a new one' );

  my $old = umask 0;
  my $open = SICK::Temp->dir;
  umask $old;
  is mode_of( $open->path ), '0700', 'mode 0700 whatever the umask';
};

subtest 'files' => sub {
  my $tmp = SICK::Temp->dir;
  is $tmp->file('key.pem'), $tmp->path.'/key.pem', 'file gives a path inside';
  ok !-e $tmp->file('key.pem'), '... without creating it';

  my $path = $tmp->write( 'key.pem', "content\n" );
  is $path, $tmp->file('key.pem'), 'write returns the path';
  is mode_of($path), '0600', 'default mode 0600';
  open my $fh, '<', $path or die $!;
  is scalar <$fh>, "content\n", 'content';
  close $fh;

  is mode_of( $tmp->write( 'cert.pem', 'x', 0644 ) ), '0644', 'an explicit mode';

  my $old = umask 0;
  my $wide = $tmp->write( 'wide-umask.pem', 'x' );
  umask 0777;
  my $narrow = $tmp->write( 'narrow-umask.pem', 'x' );
  umask $old;
  is mode_of($wide),   '0600', 'mode 0600 with umask 0';
  is mode_of($narrow), '0600', 'mode 0600 with umask 0777';

  my $ok = eval { $tmp->write( 'key.pem', 'again' ); 1 };
  ok !$ok, 'writing an existing file dies';
  like $@, qr/^cannot create temporary file '\Q$path\E': \S/, '... with path and reason';

  for my $bad ( '../escape', 'sub/dir', q{}, '.', '..', undef ) {
    $ok = eval { $tmp->file($bad); 1 };
    ok !$ok, 'file refuses '.( defined $bad ? '"'.$bad.'"' : 'undef' );
  }
};

subtest 'gone with the object' => sub {
  my $path;
  {
    my $tmp = SICK::Temp->dir;
    $path = $tmp->path;
    $tmp->write( 'key.pem', 'x' );
    mkdir $tmp->file('sub') or die $!;
    ok -e $path.'/key.pem', 'in use';
  }
  ok !-e $path, 'removed at the end of the scope, with what was in it';

  eval {
    my $tmp = SICK::Temp->dir;
    $path = $tmp->path;
    $tmp->write( 'key.pem', 'x' );
    die "interrupted\n";
  };
  is $@, "interrupted\n", 'the code died';
  ok !-e $path, '... and the directory is removed all the same';

  my $tmp = SICK::Temp->dir;
  $path = $tmp->path;
  $tmp->remove;
  ok !-e $path, 'remove removes it right away';
  $tmp->remove;
  pass 'removing twice is harmless';
};

subtest 'a child process does not remove it' => sub {
  my $tmp = SICK::Temp->dir;
  my $pid = fork;
  die 'fork: '.$! unless defined $pid;
  unless ($pid) {
    undef $tmp;
    SICK::Temp->cleanup;
    exit 0;
  }
  waitpid $pid, 0;
  ok -d $tmp->path, 'still there after a forked child destroyed its copy and exited';

  SICK::Command::run( [ $^X, '-e', '1' ] );
  ok -d $tmp->path, 'still there after running a command';
};

subtest 'cleanup and the end of the program' => sub {
  my $one = SICK::Temp->dir;
  my $two = SICK::Temp->dir;
  my @paths = ( $one->path, $two->path );
  SICK::Temp->cleanup;
  ok !-e $_, 'cleanup removed '.$_ for @paths;

  # a program that exits while it still holds a directory
  my $program = 'use SICK::Temp; our $keep = SICK::Temp->dir; $keep->write( q{key.pem}, q{x} ); print $keep->path; exit 3';
  my ( $out, $err, $exit ) = SICK::Command::run( [ $^X, ( map { '-I'.$_ } grep { !ref } @INC ), '-e', $program ] );
  is $exit, 3, 'the program exited';
  like $out, qr{\A/.+}, '... after telling us its directory';
  ok !-e $out, '... which was removed at its end';

  # ... and one that dies
  $program = 'use SICK::Temp; my $tmp = SICK::Temp->dir; print $tmp->path; die qq{boom\n}';
  ( $out, $err, $exit ) = SICK::Command::run( [ $^X, ( map { '-I'.$_ } grep { !ref } @INC ), '-e', $program ] );
  isnt $exit, 0, 'the program died';
  ok length $out && !-e $out, '... and its directory is gone';
};

done_testing;
