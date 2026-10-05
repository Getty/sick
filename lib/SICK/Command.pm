package SICK::Command;
# ABSTRACT: Run an external program without a shell and capture its output

use strict;
use warnings;
use Carp qw( croak );
use Errno ();
use IO::Handle;
use IO::Select;
use POSIX qw( WNOHANG );
use Time::HiRes qw( sleep time );

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Command;

    my ( $out, $err, $exit ) = SICK::Command::run(
      [ 'step', 'ca', 'health' ],
      stdin   => '',
      env     => { STEPDEBUG => undef },
      umask   => 077,
      timeout => 10,
    );

=head1 DESCRIPTION

Everything SICK starts - C<openssl>, C<step>, C<acme.sh>, a reload command -
goes through this one function. The program is started with C<fork> and the
list form of C<exec>: no shell ever sees the arguments, whatever they contain.
Nothing is exported.

=cut

sub run {
  my ( $argv, %opt ) = @_;
  croak 'SICK::Command::run needs a non-empty list of arguments'
    unless ref $argv eq 'ARRAY' && @$argv && !grep { !defined || ref } @$argv;
  my @cmd   = map { q{}.$_ } @$argv;
  my $name  = $cmd[0];
  my $stdin = defined $opt{stdin} ? $opt{stdin} : q{};

  pipe( my $in_r,   my $in_w )   or croak 'cannot create a pipe: '.$!;
  pipe( my $out_r,  my $out_w )  or croak 'cannot create a pipe: '.$!;
  pipe( my $err_r,  my $err_w )  or croak 'cannot create a pipe: '.$!;
  pipe( my $stat_r, my $stat_w ) or croak 'cannot create a pipe: '.$!;

  my $pid = fork;
  croak 'cannot fork for \''.$name.'\': '.$! unless defined $pid;

  unless ($pid) {
    # Child. Never return into the caller's code and never run its END
    # blocks or destructors: whatever happens ends in exec or _exit.
    eval {
      close $_ for $in_w, $out_r, $err_r, $stat_r;
      POSIX::dup2( fileno $in_r,  0 ) // die 'stdin: '.$!."\n";
      POSIX::dup2( fileno $out_w, 1 ) // die 'stdout: '.$!."\n";
      POSIX::dup2( fileno $err_w, 2 ) // die 'stderr: '.$!."\n";
      if ( $opt{env} ) {
        for my $key ( keys %{ $opt{env} } ) {
          if ( defined $opt{env}{$key} ) { $ENV{$key} = $opt{env}{$key} }
          else                           { delete $ENV{$key} }
        }
      }
      umask $opt{umask} if defined $opt{umask};
      # $stat_w is close-on-exec: the parent reads EOF when exec succeeded
      # and the error number when it did not.
      { no warnings 'exec'; exec { $cmd[0] } @cmd }
      1;
    };
    my $errno = $! + 0;
    syswrite $stat_w, $errno || Errno::ENOENT();
    POSIX::_exit(127);
  }

  close $_ for $in_r, $out_w, $err_w, $stat_w;

  my $exec_errno = q{};
  1 while sysread( $stat_r, $exec_errno, 64, length $exec_errno );
  close $stat_r;
  if ( length $exec_errno ) {
    waitpid $pid, 0;
    local $! = $exec_errno + 0;
    croak 'cannot run \''.$name.'\': '.$!;
  }

  local $SIG{PIPE} = 'IGNORE';

  my ( $out, $err ) = ( q{}, q{} );
  my %sink     = ( fileno($out_r) => \$out, fileno($err_r) => \$err );
  my $readers  = IO::Select->new( $out_r, $err_r );
  my $writers  = IO::Select->new;
  my $offset   = 0;
  my $deadline = defined $opt{timeout} ? time + $opt{timeout} : undef;
  my ( $status, $timed_out );

  if ( length $stdin ) {
    $in_w->blocking(0);
    $writers->add($in_w);
  }
  else {
    close $in_w;
  }

  while ( $readers->count || $writers->count ) {
    # Once the program is gone, whatever it wrote is already in the pipes.
    my $wait = defined $status ? 0.05 : 0.1;
    if ( defined $deadline && !defined $status ) {
      my $left = $deadline - time;
      if ( $left <= 0 ) { $timed_out = 1; last }
      $wait = $left if $left < $wait;
    }

    my ( $can_read, $can_write ) = IO::Select::select( $readers, $writers, undef, $wait );

    for my $fh ( @{ $can_write || [] } ) {
      my $n = syswrite $fh, $stdin, 65536, $offset;
      if ( defined $n ) {
        $offset += $n;
        next if $offset < length $stdin;
      }
      elsif ( $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR} ) {
        next;
      }
      # everything written, or the program stopped reading (EPIPE)
      $writers->remove($fh);
      close $fh;
    }

    for my $fh ( @{ $can_read || [] } ) {
      my $n = sysread $fh, my $buf, 65536;
      if ($n) {
        ${ $sink{ fileno $fh } } .= $buf;
        next;
      }
      next if !defined $n && ( $!{EAGAIN} || $!{EINTR} );
      $readers->remove($fh);
      close $fh;
    }

    # The program is gone, the pipes are drained, and still there is no end
    # of file: something it started holds them open. Do not wait for that.
    last if defined $status && !@{ $can_read || [] };
    $status = $? if !defined $status && waitpid( $pid, WNOHANG ) == $pid;
  }

  unless ( defined $status ) {
    until ($timed_out) {
      my $reaped = waitpid $pid, defined $deadline ? WNOHANG : 0;
      if ( $reaped == $pid ) { $status = $?; last }
      if ( $reaped == -1 )   { $status = 0;  last }
      if ( time >= $deadline ) { $timed_out = 1; last }
      sleep 0.02;
    }
  }

  if ( $timed_out && !defined $status ) {
    kill 'TERM', $pid;
    my $grace = time + 2;
    my $reaped = 0;
    while ( time < $grace ) {
      $reaped = waitpid $pid, WNOHANG;
      last if $reaped;
      sleep 0.02;
    }
    unless ($reaped) {
      kill 'KILL', $pid;
      waitpid $pid, 0;
    }
    croak '\''.$name.'\' timed out after '.$opt{timeout}.'s';
  }

  my $exit = $status & 127 ? 128 + ( $status & 127 ) : $status >> 8;
  return ( $out, $err, $exit );
}

=func run

    my ( $stdout, $stderr, $exit ) = SICK::Command::run( \@argv, %options );

Runs C<$argv[0]> with the remaining elements as its arguments and returns
what it wrote to standard output and standard error together with its exit
code. A program that was killed by signal C<N> reports C<128 + N>.

Options:

=over 4

=item C<stdin>

Text for the program's standard input. Without it the program reads an end
of file.

=item C<env>

Hashref of environment variables for the program only. An undefined value
removes the variable.

=item C<umask>

The umask of the program, for example C<077> when it is going to write a key.

=item C<timeout>

Seconds. A program that runs longer is terminated and C<run> croaks with
C<< '<program>' timed out after <N>s >>.

=back

Croaks with C<< cannot run '<program>': <reason> >> when the program cannot
be started, for instance because it is not installed. A non-zero exit code
is not an error here: the caller decides what it means.

=cut

1;
