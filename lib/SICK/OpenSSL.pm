package SICK::OpenSSL;
# ABSTRACT: Call the openssl command line without a shell

use strict;
use warnings;
use Carp qw( croak );
use SICK::Command;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::OpenSSL;

    die "openssl is not installed\n" unless SICK::OpenSSL::available();

    my ( $out, $err, $exit ) = SICK::OpenSSL::run(
      [ 'x509', '-noout', '-enddate' ],
      stdin => $pem,
    );

    my $text = SICK::OpenSSL::run_checked( [ 'x509', '-noout', '-text' ], stdin => $pem );

=head1 DESCRIPTION

SICK does not parse X.509 in Perl. Whatever it needs to know about a
certificate, a key or a request it asks the C<openssl> program, and this
module is the only place that starts it - through L<SICK::Command>, so
without a shell. Nothing is exported.

C<openssl> is a prerequisite of a run, not of the installation. OpenSSL
1.1.1 or newer is expected.

=cut

sub bin {
  return defined $ENV{SICK_OPENSSL} && length $ENV{SICK_OPENSSL}
    ? $ENV{SICK_OPENSSL}
    : 'openssl';
}

=func bin

    my $program = SICK::OpenSSL::bin();

The program that is started: C<$ENV{SICK_OPENSSL}> when that is set, otherwise
C<openssl> from the C<PATH>.

=cut

sub run {
  my ( $args, %opt ) = @_;
  croak 'SICK::OpenSSL::run needs an array reference of arguments'
    unless ref $args eq 'ARRAY';
  return SICK::Command::run( [ bin(), @$args ], %opt );
}

=func run

    my ( $stdout, $stderr, $exit ) = SICK::OpenSSL::run( \@args, stdin => $text );

Runs C<openssl> with C<@args> and returns its standard output, its standard
error and its exit code. C<stdin> is fed to the program; the other options
of L<SICK::Command/run> (C<env>, C<umask>, C<timeout>) are passed through.

A non-zero exit code is returned, not thrown. Croaks with
C<< cannot run 'openssl': <reason> >> when the program is not there.

=cut

sub run_checked {
  my ( $args, %opt ) = @_;
  my ( $out, $err, $exit ) = run( $args, %opt );
  return $out unless $exit;
  $err =~ s/\s+\z//;
  croak 'openssl '.( @$args ? $args->[0] : q{} ).' failed (exit '.$exit.'): '.$err;
}

=func run_checked

    my $stdout = SICK::OpenSSL::run_checked( \@args, stdin => $text );

Like L</run>, for calls that are expected to work: returns the standard
output and croaks with C<< openssl <command> failed (exit <N>): <stderr> >>
otherwise. Only what C<openssl> itself printed ends up in the message, never
the input.

=cut

sub available {
  my @result = eval { run( ['version'] ) };
  return @result && $result[2] == 0 ? 1 : 0;
}

=func available

    my $bool = SICK::OpenSSL::available();

True when C<openssl> can be started.

=cut

my %VERSION_OF;

sub version {
  my $bin = bin();
  unless ( exists $VERSION_OF{$bin} ) {
    my @result = eval { run( ['version'] ) };
    $VERSION_OF{$bin} = @result && $result[2] == 0 ? $result[0] : q{};
    $VERSION_OF{$bin} =~ s/\s+\z//;
  }
  return $VERSION_OF{$bin};
}

=func version

    my $text = SICK::OpenSSL::version();   # 'OpenSSL 3.5.7 9 Jun 2026 (...)'

The output of C<openssl version>, or the empty string when it cannot be
started. Asked once per program.

=cut

sub major {
  return version() =~ /\AOpenSSL ([0-9]+)\./ ? $1 + 0 : 0;
}

=func major

    my $major = SICK::OpenSSL::major();   # 3

The major version of OpenSSL, C<0> for anything that does not call itself
OpenSSL (LibreSSL for one).

=cut

1;
