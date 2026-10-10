package SICK::CLI;
# ABSTRACT: The sick command line - check, run, trust

use Moo;
use Getopt::Long ();
use SICK::Config;
use SICK::Issuer;
use SICK::Runner;
use SICK::Trust;
use Types::Standard qw( FileHandle HashRef );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::CLI;

    exit SICK::CLI->new->run(@ARGV);

    # with the output somewhere else
    my $code = SICK::CLI->new( out => $out_fh, err => $err_fh )->run( 'check', '--config', $path );

=head1 DESCRIPTION

Everything the C<sick> program does, as a class, so that it can be tested
and embedded: it parses the arguments, loads the device list, builds the
issuer and the L<SICK::Runner>, prints the result as a table and turns it
into an exit code. The commands and options are described in L<sick>.

Nothing in here calls C<exit> or dies: L</run> returns the exit code.

=cut

my $USAGE = <<'USAGE';
Usage:
  sick [--config <file>] check [<device> ...]
  sick [--config <file>] run [--force] [--dry-run] [--verbose] [<device> ...]
  sick [--config <file>] trust <directory>
  sick --help | --version

Commands:
  check    Show which certificate every device presents. Changes nothing.
  run      Renew what is due: check, issue, deploy, check again.
  trust    Write the certificates clients have to know - the root, and the
           intermediate and further roots when the CA has them -, an Apple
           configuration profile and a page with instructions into a
           directory.

Options:
  -c, --config <file>  The device list. Default: $SICK_CONFIG, otherwise
                       /etc/sick/sick.yml.
  -f, --force          run: renew also what is not due.
  -n, --dry-run        run: only say what would be renewed.
  -v, --verbose        run: report what is being done, on standard error.
  -h, --help           This text.
  -V, --version        The version.

Without device names, check and run work on every device of the list.

Exit codes:
  0  nothing failed
  1  at least one device failed or could not be checked
  2  the command line or the device list is wrong
USAGE

my $DEFAULT_CONFIG = '/etc/sick/sick.yml';

# An argument that is not given or false gets its default, as it always did.
around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  delete @arg{ grep { !$arg{$_} } qw( out err env ) };
  return \%arg;
};

=method new

    my $cli = SICK::CLI->new( out => $fh, err => $fh, env => \%env );

All arguments are optional: where tables and messages are printed
(C<STDOUT> and C<STDERR>) and where C<SICK_CONFIG> is looked up (C<%ENV>).

=cut

has out => ( is => 'ro', isa => FileHandle, builder => 1 );
has err => ( is => 'ro', isa => FileHandle, builder => 1 );
has env => ( is => 'ro', isa => HashRef,    builder => 1 );

sub _build_out { \*STDOUT }
sub _build_err { \*STDERR }
sub _build_env { \%ENV }

=attr out

Where tables and other output go. C<STDOUT>.

=attr err

Where messages go. C<STDERR>.

=attr env

The environment C<SICK_CONFIG> is looked up in: C<%ENV> itself.

=cut

sub usage { $USAGE }

=method usage

The text C<sick --help> prints.

=cut

sub run {
  my ( $self, @argv ) = @_;
  $self = $self->new unless ref $self;

  my ( %opt, @complaints );
  my $parser = Getopt::Long::Parser->new( config => [qw( gnu_getopt )] );
  my $parsed = do {
    local $SIG{__WARN__} = sub { push @complaints, @_ };
    $parser->getoptionsfromarray(
      \@argv, \%opt,
      'config|c=s', 'force|f', 'dry-run|n', 'verbose|v', 'help|h', 'version|V',
    );
  };
  unless ($parsed) {
    my $complaint = @complaints ? $complaints[0] : 'invalid arguments';
    $complaint =~ s/\s+\z//;
    return $self->_misuse( lcfirst $complaint );
  }

  if ( $opt{help} ) {
    print { $self->out } $USAGE;
    return 0;
  }
  if ( $opt{version} ) {
    print { $self->out } 'sick '.$VERSION."\n";
    return 0;
  }

  my $command = shift @argv;
  return $self->_misuse('no command given') unless defined $command;
  my %command = map { $_ => '_'.$_ } qw( check run trust );
  return $self->_misuse( 'unknown command \''.$command.'\'' ) unless $command{$command};

  my %allowed = ( check => [], run => [qw( force dry-run verbose )], trust => [] );
  for my $option (qw( force dry-run verbose )) {
    return $self->_misuse( '--'.$option.' does not go with \''.$command.'\'' )
      if $opt{$option} && !grep { $_ eq $option } @{ $allowed{$command} };
  }

  my $method = $command{$command};
  my $code   = eval { $self->$method( \%opt, @argv ) };
  return $code if defined $code;
  # nothing below is meant to die; if it does, say so and fail
  return $self->_fail( $self->_message($@) );
}

=method run

    my $code = $cli->run(@ARGV);

Does what the arguments ask for and returns the exit code:

=over 4

=item C<0>

Nothing failed. For C<check> that means every device could be looked at,
whatever the state of its certificate; for C<run> that no device ended as
C<failed>.

=item C<1>

At least one device failed (C<run>) or could not be checked (C<check>:
C<unreachable> or C<error>), or C<trust> could not write its files.

=item C<2>

The command cannot be carried out as given: unknown command or option, a
device name that is not in the list, a device list that cannot be read or
is not valid, a C<ca> section that does not make an issuer.

=back

Works as a class method too.

=cut

#### commands

sub _check {
  my ( $self, $opt, @names ) = @_;
  my $runner = $self->_runner($opt) or return 2;
  my @states = eval { $runner->check(@names) };
  return $self->_died( $self->_message($@) ) if $@;

  $self->_table(
    [qw( DEVICE STATUS RENEW DETAIL )],
    map { [ $_->{device}, $_->{reason}, !defined $_->{renew} ? '?' : $_->{renew} ? 'yes' : 'no', $_->{detail} ] } @states
  );
  return ( grep { !defined $_->{renew} } @states ) ? 1 : 0;
}

sub _run {
  my ( $self, $opt, @names ) = @_;
  my $runner = $self->_runner($opt) or return 2;
  my @results = eval { $runner->run( \@names, force => $opt->{force} ? 1 : 0, dry_run => $opt->{'dry-run'} ? 1 : 0 ) };
  return $self->_died( $self->_message($@) ) if $@;

  $self->_table(
    [qw( DEVICE ACTION REASON ERROR )],
    map { [ @$_{qw( device action reason )}, defined $_->{error} ? $_->{error} : q{} ] } @results
  );
  return ( grep { $_->{action} eq 'failed' } @results ) ? 1 : 0;
}

sub _trust {
  my ( $self, $opt, @args ) = @_;
  return $self->_misuse('trust needs the directory to write to') unless @args;
  return $self->_misuse('trust takes one directory') if @args > 1;

  my ( $config, $issuer ) = $self->_setup($opt) or return 2;
  my @files = eval {
    SICK::Trust->write(
      $args[0],
      root_pem             => $issuer->root_pem,
      intermediates_pem    => $issuer->intermediates_pem,
      additional_roots_pem => $issuer->additional_roots_pem,
      name                 => $config->ca_name,
    );
  };
  return $self->_fail( $self->_message($@) ) unless @files;
  print { $self->out } 'wrote '.join( ', ', map { s{.*/}{}r } @files ).' to '.$args[0]."\n";
  return 0;
}

#### internals

sub _message {
  my ( $self, $error ) = @_;
  $error = defined $error ? q{}.$error : q{};
  $error =~ s/ at \S+ line [0-9]+\.?\n?\z//;
  $error =~ s/\s+\z//;
  return length $error ? $error : 'unknown error';
}

sub _say_error {
  my ( $self, $message ) = @_;
  print { $self->err } 'sick: '.$message."\n";
  return;
}

# The command line is wrong: exit code 2, with a pointer to the help unless
# the message is about the device list.
sub _misuse {
  my ( $self, $message, $plain ) = @_;
  $self->_say_error($message);
  print { $self->err } 'Try \'sick --help\'.'."\n" unless $plain;
  return 2;
}

sub _fail {
  my ( $self, $message ) = @_;
  $self->_say_error($message);
  return 1;
}

# The runner dies for a device name it does not know, and that is the
# caller's mistake; anything else is a failure.
sub _died {
  my ( $self, $message ) = @_;
  return $message =~ /\Aunknown device / ? $self->_misuse( $message, 'plain' ) : $self->_fail($message);
}

sub config_path {
  my ( $self, $opt ) = @_;
  return $opt->{config} if defined $opt->{config} && length $opt->{config};
  my $from_env = $self->env->{SICK_CONFIG};
  return defined $from_env && length $from_env ? $from_env : $DEFAULT_CONFIG;
}

# Device list and issuer, or nothing after having said why not.
sub _setup {
  my ( $self, $opt ) = @_;
  my $path   = $self->config_path( $opt || {} );
  my $config = eval { SICK::Config->load($path) };
  unless ($config) {
    $self->_say_error( $self->_message($@) );
    return;
  }
  my $issuer = eval { SICK::Issuer->from_ca( %{ $config->ca } ) };
  unless ($issuer) {
    $self->_say_error( $path.': '.$self->_message($@) );
    return;
  }
  return ( $config, $issuer );
}

sub _runner {
  my ( $self, $opt ) = @_;
  my ( $config, $issuer ) = $self->_setup($opt) or return;
  my $err = $self->err;
  return SICK::Runner->new(
    config => $config,
    issuer => $issuer,
    ( $opt->{verbose} ? ( log => sub { print {$err} $_[0]."\n" } ) : () ),
  );
}

# Columns as wide as their widest cell, two spaces apart; the last one is
# as long as it is, and whatever it holds stays on its line.
sub _table {
  my ( $self, $head, @rows ) = @_;
  for my $row (@rows) {
    for my $cell (@$row) {
      $cell = q{} unless defined $cell;
      $cell =~ s/\s*\n\s*/; /g;
      $cell =~ s/[\x00-\x1f\x7f]/ /g;
    }
  }
  my @width = map { my $i = $_; ( sort { $b <=> $a } map { length $_->[$i] } $head, @rows )[0] } 0 .. $#$head - 1;
  for my $row ( $head, @rows ) {
    my $line = join( q{}, map { sprintf '%-*s  ', $width[$_], $row->[$_] } 0 .. $#width ).$row->[-1];
    $line =~ s/\s+\z//;
    print { $self->out } $line."\n";
  }
  return;
}

1;
