package SICK::CLI;
# ABSTRACT: The sick command line - check, run, inventory, trust

use Moo;
use Getopt::Long ();
use Path::Tiny ();
use SICK::Config;
use SICK::Issuer;
use SICK::Report;
use SICK::Runner;
use SICK::State;
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
issuer and the L<SICK::Runner>, prints the result as a table - or as JSON
or for Prometheus (L<SICK::Report>) - and turns it into an exit code. The
commands and options are described in L<sick>.

Nothing in here calls C<exit> or dies: L</run> returns the exit code.

=cut

my $USAGE = <<'USAGE';
Usage:
  sick [--config <file>] check [--format table|json|prometheus] [--output <file>] [<device> ...]
  sick [--config <file>] run [--force] [--dry-run] [--verbose] [<device> ...]
  sick [--config <file>] inventory [--format table|json] [--live] [<device> ...]
  sick [--config <file>] trust <directory>
  sick --help | --version

Commands:
  check      Show which certificate every device presents. Changes nothing.
  run        Renew what is due: check, issue, deploy, check again.
  inventory  What was issued, deployed and last seen per device, from the
             records of the runs. Asks nobody, unless --live.
  trust      Write the certificates clients have to know - the root, and the
             intermediate and further roots when the CA has them -, install
             and remove scripts, an Apple configuration profile and a page
             with instructions into a directory.

Options:
  -c, --config <file>  The device list. Default: $SICK_CONFIG, otherwise
                       /etc/sick/sick.yml.
  -f, --force          run: renew also what is not due or deferred.
  -n, --dry-run        run: only say what would be renewed.
  -v, --verbose        run: report what is being done, on standard error.
      --format <f>     check: table (default), json or prometheus;
                       inventory: table or json.
  -o, --output <file>  check: write to this file instead, replacing it at once
                       (for the textfile collector of node_exporter).
      --live           inventory: look at the devices as well.
  -h, --help           This text.
  -V, --version        The version.

Without device names, check, run and inventory work on every device of the list.

Exit codes:
  0  nothing failed
  1  at least one device failed, was deferred or could not be checked
  2  the command line or the device list is wrong
  3  run: another sick run holds the lock of the state directory
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
      'format=s', 'output|o=s', 'live',
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
  my %command = map { $_ => '_'.$_ } qw( check run inventory trust );
  return $self->_misuse( 'unknown command \''.$command.'\'' ) unless $command{$command};

  my %allowed = (
    check     => [qw( format output )],
    run       => [qw( force dry-run verbose )],
    inventory => [qw( format live )],
    trust     => []
  );
  for my $option (qw( force dry-run verbose format output live )) {
    return $self->_misuse( '--'.$option.' does not go with \''.$command.'\'' )
      if defined $opt{$option} && !grep { $_ eq $option } @{ $allowed{$command} };
  }
  if ( defined $opt{format} ) {
    my @formats = $command eq 'check' ? qw( table json prometheus ) : qw( table json );
    return $self->_misuse( '--format: unknown format \''.$opt{format}.'\' ('
        .join( ', ', @formats[ 0 .. $#formats - 1 ] ).' or '.$formats[-1].')' )
      unless grep { $_ eq $opt{format} } @formats;
  }
  return $self->_misuse('--output needs a file') if defined $opt{output} && !length $opt{output};

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

At least one device failed or was deferred (C<run>) or could not be
checked (C<check>, C<inventory --live>: C<unreachable> or C<error>), or
C<trust> could not write its files, or C<check --output> its file. Also a
C<run> that cannot take its lock for another reason than another run
(C<< cannot take the lock '<path>': <reason> >>), or that could not write
the record of a device.

=item C<2>

The command cannot be carried out as given: unknown command or option, a
format the command does not have, a device name that is not in the list,
a device list that cannot be read or is not valid, a C<ca> section that
does not make an issuer.

=item C<3>

C<run> did nothing because another C<sick run> holds the lock of the state
directory: C<< another sick run holds the lock '<path>' (pid <pid>) >>
(L<SICK::State/lock>). C<run --dry-run>, C<check> and C<trust> take no
lock and never end with C<3>, nor does C<inventory>.

=back

Works as a class method too.

=cut

#### commands

sub _check {
  my ( $self, $opt, @names ) = @_;
  my ( $config, $issuer ) = $self->_setup($opt) or return 2;
  my $runner = $self->_runner( $opt, $config, $issuer );
  my @states = eval { $runner->check(@names) };
  return $self->_died( $self->_message($@) ) if $@;

  my $format = defined $opt->{format} ? $opt->{format} : 'table';
  my $text;
  if ( $format eq 'table' ) {
    $text = $self->_table_text(
      [qw( DEVICE STATUS RENEW DETAIL )],
      map { [ $_->{device}, $_->{reason}, !defined $_->{renew} ? '?' : $_->{renew} ? 'yes' : 'no', $_->{detail} ] } @states
    );
  }
  else {
    my $report = $self->_report( $config, $issuer );
    my $data   = $report->check( \@states );
    $self->_state_errors($data);
    $text = $format eq 'json' ? $report->json($data) : $report->prometheus($data);
  }
  return 1 unless $self->_emit( $opt, $text );
  return ( grep { !defined $_->{renew} } @states ) ? 1 : 0;
}

sub _run {
  my ( $self, $opt, @names ) = @_;
  my ( $config, $issuer ) = $self->_setup($opt) or return 2;
  my $state = SICK::State->new( dir => $config->state_dir );

  # One run at a time per state directory; the lock goes with $lock, also
  # when something below dies. A dry run changes nothing and waits for no one.
  my $lock;
  unless ( $opt->{'dry-run'} ) {
    $lock = eval { $state->lock };
    unless ($lock) {
      my $message = $self->_message($@);
      $self->_say_error($message);
      return $message =~ /\Aanother sick run holds the lock / ? 3 : 1;
    }
  }

  my $runner  = $self->_runner( $opt, $config, $issuer, $state );
  my @results = eval { $runner->run( \@names, force => $opt->{force} ? 1 : 0, dry_run => $opt->{'dry-run'} ? 1 : 0 ) };
  return $self->_died( $self->_message($@) ) if $@;

  $self->_table(
    [qw( DEVICE ACTION REASON ERROR )],
    map { [ @$_{qw( device action reason )}, defined $_->{error} ? $_->{error} : q{} ] } @results
  );
  my @unwritten;
  for my $result ( grep { defined $_->{state_error} } @results ) {
    $self->_say_error( $result->{device}.': '.$result->{state_error} );
    push @unwritten, $result if $result->{state_error} =~ /cannot write state record /;
  }
  return ( @unwritten || grep { $_->{action} eq 'failed' || $_->{action} eq 'deferred' } @results ) ? 1 : 0;
}

sub _inventory {
  my ( $self, $opt, @names ) = @_;
  my ( $config, $issuer ) = $self->_setup($opt) or return 2;
  my $report = $self->_report( $config, $issuer );

  my ( @states, $data );
  if ( $opt->{live} ) {
    @states = eval { $self->_runner( $opt, $config, $issuer )->check(@names) };
    return $self->_died( $self->_message($@) ) if $@;
    $data = $report->inventory( \@names, states => \@states );
  }
  else {
    $data = eval { $report->inventory( \@names ) };
    return $self->_died( $self->_message($@) ) unless $data;
  }
  $self->_state_errors($data);

  if ( defined $opt->{format} && $opt->{format} eq 'json' ) {
    print { $self->out } $report->json($data);
  }
  else {
    my $time  = sub { defined $_[0] ? $_[0] =~ s/\A(\S+)T([0-9]{2}:[0-9]{2}).*\z/$1 $2/r : '-' };
    my $plain = sub { defined $_[0] && length $_[0] ? $_[0] : '-' };
    my @rows;
    for my $entry ( @{ $data->{devices} } ) {
      my $deploy = $entry->{last_deploy};
      push @rows, [
        $entry->{device},
        $plain->( $entry->{ $opt->{live} ? 'status' : 'last_status' } ),
        ( $opt->{live}
          ? ( !defined $entry->{fingerprint_sha256} ? '-' : !defined $entry->{matches_last_issue} ? '?'
              : $entry->{matches_last_issue} ? 'yes' : 'no' )
          : () ),
        $plain->( $entry->{serial} ),
        $plain->( defined $entry->{fingerprint_sha256} ? substr( $entry->{fingerprint_sha256}, 0, 16 ) : undef ),
        $time->( $entry->{not_after} ),
        !$deploy ? '-' : ( defined $deploy->{result} && $deploy->{result} eq 'ok' ? q{} : 'failed ' ).$time->( $deploy->{time} ),
        $time->( $entry->{last_verified} ),
        $plain->( $entry->{issuer} ),
        $plain->( $entry->{names} ? join( ',', @{ $entry->{names} } ) : undef )
      ];
    }
    $self->_table(
      [ qw( DEVICE STATUS ), ( $opt->{live} ? 'LIVE' : () ), qw( SERIAL FINGERPRINT UNTIL DEPLOYED VERIFIED ISSUER NAMES ) ],
      @rows
    );
  }
  return 0 unless $opt->{live};
  return ( grep { !defined $_->{renew} } @states ) ? 1 : 0;
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
  my ( $self, $opt, $config, $issuer, $state ) = @_;
  unless ($config) {
    ( $config, $issuer ) = $self->_setup($opt) or return;
  }
  my $err = $self->err;
  return SICK::Runner->new(
    config => $config,
    issuer => $issuer,
    ( $state          ? ( state => $state ) : () ),
    ( $opt->{verbose} ? ( log => sub { print {$err} $_[0]."\n" } ) : () ),
  );
}

sub _report {
  my ( $self, $config, $issuer ) = @_;
  return SICK::Report->new( config => $config, issuer => $issuer, state => SICK::State->new( dir => $config->state_dir ) );
}

# A record that could not be read is said, and does not change the answer.
sub _state_errors {
  my ( $self, $data ) = @_;
  $self->_say_error( $_->{device}.': '.$_->{state_error} ) for grep { defined $_->{state_error} } @{ $data->{devices} };
  return;
}

# Standard output, or --output: written beside the file and renamed over
# it, so that a reader - node_exporter - sees the old file or the new one.
sub _emit {
  my ( $self, $opt, $text ) = @_;
  unless ( defined $opt->{output} ) {
    print { $self->out } $text;
    return 1;
  }
  my $path = $opt->{output};
  my $reason = eval { $self->_publish( $path, $text ); 1 } ? undef : $self->_reason($@);
  return 1 unless defined $reason;
  $self->_say_error( 'cannot write \''.$path.'\': '.$reason );
  return 0;
}

# Path::Tiny's move copies when renaming fails; CORE rename does not.
sub _publish {
  my ( $self, $path, $text ) = @_;
  my $aside = Path::Tiny->tempfile(
    DIR      => Path::Tiny::path($path)->parent->stringify,
    TEMPLATE => '.sick-XXXXXXXX',
    UNLINK   => 0
  );
  my $ok = eval {
    $aside->chmod(0644);
    $aside->append_raw($text);
    rename( $aside->stringify, $path ) or die $!."\n";
    1;
  };
  unless ($ok) {
    my $error = $@;
    eval { $aside->remove };
    die $error;
  }
  return;
}

# The reason of the system out of a Path::Tiny exception or a message.
sub _reason {
  my ( $self, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  return $self->_message($error);
}

# Columns as wide as their widest cell, two spaces apart; the last one is
# as long as it is, and whatever it holds stays on its line.
sub _table {
  my ( $self, @table ) = @_;
  print { $self->out } $self->_table_text(@table);
  return;
}

sub _table_text {
  my ( $self, $head, @rows ) = @_;
  for my $row (@rows) {
    for my $cell (@$row) {
      $cell = q{} unless defined $cell;
      $cell =~ s/\s*\n\s*/; /g;
      $cell =~ s/[\x00-\x1f\x7f]/ /g;
    }
  }
  my @width = map { my $i = $_; ( sort { $b <=> $a } map { length $_->[$i] } $head, @rows )[0] } 0 .. $#$head - 1;
  my $text = q{};
  for my $row ( $head, @rows ) {
    my $line = join( q{}, map { sprintf '%-*s  ', $width[$_], $row->[$_] } 0 .. $#width ).$row->[-1];
    $line =~ s/\s+\z//;
    $text .= $line."\n";
  }
  return $text;
}

1;
