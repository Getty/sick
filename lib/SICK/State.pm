package SICK::State;
# ABSTRACT: What SICK remembers between runs - one record per device, and the lock of the run

use Moo;
use Carp qw( croak );
use Fcntl qw( LOCK_EX LOCK_NB );
use JSON::MaybeXS ();
use Path::Tiny ();
use Types::Standard qw( HasMethods Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::State;

    my $state = SICK::State->new( dir => '/var/lib/sick' );

    my $lock = $state->lock;          # croaks when another run holds it
    my ( $record, $problem ) = $state->read('switch');
    warn $problem."\n" if defined $problem;
    $state->update( 'switch', { consecutive_failures => 0, next_attempt => undef } );
    undef $lock;                      # released; also when the program ends

=head1 DESCRIPTION

The state directory (C<state> in the device list, F</var/lib/sick> without
it) holds what a run wants to know about the runs before it, and the lock
that keeps two runs apart:

    /var/lib/sick/sick.lock               the lock of sick run
    /var/lib/sick/devices/switch.json     one record per device

A record is a JSON object, written by L<SICK::Runner> - its fields are
described there. It is evidence about certificates, never a secret: it
holds neither a key nor the path of one, and the files are written with
mode C<0644>, the directories made with C<0755>.

Each record is written aside in the same directory and renamed into place,
so that a reader sees the old record or the new one and never half of one.
Top-level fields the writer does not set are kept, also fields SICK does
not know.

A record that cannot be read or is no JSON object counts as empty: the
problem is returned beside it, with the path and the reason, and the next
write replaces it. Nothing about a record stops a run.

=cut

has dir => ( is => 'ro', isa => Str, required => 1 );

=attr dir

Required. The state directory. It is created when something is written
into it.

=cut

has _json => ( is => 'lazy', isa => HasMethods [qw( encode decode )], init_arg => undef );

sub _build__json { JSON::MaybeXS->new( utf8 => 1, canonical => 1, pretty => 1, convert_blessed => 1 ) }

around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  croak 'SICK::State->new needs the state directory'
    unless defined $arg{dir} && !ref $arg{dir} && length $arg{dir};
  return \%arg;
};

sub lock_path { $_[0]->dir.'/sick.lock' }

=method lock_path

    my $path = $state->lock_path;    # '/var/lib/sick/sick.lock'

=cut

sub record_path {
  my ( $self, $name ) = @_;
  croak 'record_path needs the name of a device' unless defined $name && length $name;
  return $self->dir.'/devices/'.$self->_file_name($name).'.json';
}

=method record_path

    my $path = $state->record_path('switch');    # '/var/lib/sick/devices/switch.json'

Where the record of a device is. Letters, digits, C<_>, C<-> and C<.> of
the name are kept; every other byte, and a leading dot, is written as
C<%XX>, so that every name of the device list is one file in the directory.

=cut

sub lock {
  my ( $self ) = @_;
  my $path = $self->lock_path;
  my ( $fh, $reason );
  eval {
    $self->_mkdir( Path::Tiny::path( $self->dir ) );
    $fh = Path::Tiny::path($path)->filehandle( '>>', ':raw' );
    1;
  } or $reason = $self->_reason($@);
  croak 'cannot take the lock \''.$path.'\': '.$reason if defined $reason;

  unless ( flock $fh, LOCK_EX | LOCK_NB ) {
    croak 'cannot take the lock \''.$path.'\': '.$! unless $!{EWOULDBLOCK};
    # Not slurp: Path::Tiny reads under a shared lock and would wait for
    # the run that holds the exclusive one.
    my $holder = eval { local $/; readline Path::Tiny::path($path)->filehandle( '<', ':raw' ) };
    my $pid    = defined $holder && $holder =~ /\A([0-9]+)\n?\z/ ? $1 : undef;
    croak 'another sick run holds the lock \''.$path.'\''.( defined $pid ? ' (pid '.$pid.')' : q{} );
  }

  # Who holds it, for the message of the next one. The lock does not
  # depend on it.
  truncate $fh, 0;
  print {$fh} $$."\n";
  $fh->flush;
  return $fh;
}

=method lock

    my $lock = $state->lock;

Takes an exclusive lock on L</lock_path> without waiting, writes the
process id into the file and returns the handle: the lock is held as long
as the handle is open. It goes when the handle goes out of scope, and with
the process - also after a C<die> or a signal - because it is an C<flock>
on an open file, not the existence of a file. Nothing has to be cleaned up
after a crash. Programs started while it is held do not inherit it (Perl
opens files close-on-exec).

Croaks with C<< another sick run holds the lock '<path>' (pid <pid>) >>
when another process holds it (without the pid when the file does not name
one yet), and with C<< cannot take the lock '<path>': <reason> >> when the
directory or the file cannot be made.

=cut

sub read {
  my ( $self, $name ) = @_;
  my $path = $self->record_path($name);
  my $file = Path::Tiny::path($path);
  return {} unless -e $path || -l $path;

  return ( {}, 'cannot read state record \''.$path.'\': Is a directory' ) if $file->is_dir;
  my $text = eval { $file->slurp_raw };
  return ( {}, 'cannot read state record \''.$path.'\': '.$self->_reason($@) ) unless defined $text;
  my $record;
  eval { $record = $self->_json->decode($text); 1 }
    or return ( {}, 'cannot read state record \''.$path.'\': not valid JSON' );
  return ( {}, 'cannot read state record \''.$path.'\': not a JSON object' ) unless ref $record eq 'HASH';
  return $record;
}

=method read

    my ( $record, $problem ) = $state->read('switch');

The record of a device as a hash reference, C<{}> when there is none.
When the file cannot be read or holds no JSON object, the record is C<{}>
as well and C<$problem> says
C<< cannot read state record '<path>': <reason> >> - the reason of the
system, C<not valid JSON> or C<not a JSON object>. Never croaks for a
record.

=cut

sub update {
  my ( $self, $name, $fields ) = @_;
  croak 'update needs the fields as a hash reference' unless ref $fields eq 'HASH';
  my ($record) = $self->read($name);
  my %new = ( %$record, %$fields );
  $self->_put( $self->record_path($name), $self->_json->encode( \%new ) );
  return \%new;
}

=method update

    my $record = $state->update( 'switch', { consecutive_failures => 1, ... } );

Reads the record, sets the given top-level fields, keeps the others and
writes it; returns the new record. A record that could not be read is
replaced. Croaks with C<< cannot write state record '<path>': <reason> >>.

Two processes that update the same record at the same time can lose one
of the updates: L<SICK::Runner> writes records only in C<sick run>, which
holds L</lock>.

=cut

#### internals

sub _file_name {
  my ( $self, $name ) = @_;
  my $bytes = $name;
  utf8::encode($bytes) if utf8::is_utf8($bytes);
  $bytes =~ s/([^A-Za-z0-9_.-])/sprintf '%%%02X', ord $1/ge;
  $bytes =~ s/\A\./%2E/;
  return $bytes;
}

# Written aside in the same directory and published with CORE rename:
# Path::Tiny's move copies when renaming fails, and a reader would see half
# a record.
sub _put {
  my ( $self, $path, $content ) = @_;
  my $dir = Path::Tiny::path($path)->parent;
  my $aside;
  my $reason = eval {
    $self->_mkdir($dir);
    $aside = Path::Tiny->tempfile( DIR => $dir->stringify, TEMPLATE => '.sick-XXXXXXXX', UNLINK => 0 );
    $aside->chmod(0644);
    $aside->append_raw($content);
    1;
  } ? undef : $self->_reason($@);
  $reason = q{}.$! if !defined $reason && !rename( $aside->stringify, $path );
  if ( defined $reason ) {
    eval { $aside->remove } if $aside;
    croak 'cannot write state record \''.$path.'\': '.$reason;
  }
  return $path;
}

# The directories that are made get 0755 whatever the umask; one that is
# there already keeps its mode.
sub _mkdir {
  my ( $self, $dir ) = @_;
  return if $dir->is_dir;
  chmod 0755, $_ for $dir->mkpath;
  return;
}

# The reason of the system out of a Path::Tiny exception.
sub _reason {
  my ( $self, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  ( $error = defined $error ? q{}.$error : q{} ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  $error =~ s/\s+\z//;
  return length $error ? $error : 'unknown error';
}

1;
