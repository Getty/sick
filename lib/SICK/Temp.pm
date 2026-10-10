package SICK::Temp;
# ABSTRACT: A private temporary directory that disappears with its object

use Moo;
use Carp qw( croak );
use Fcntl qw( O_CREAT O_EXCL O_WRONLY );
use Path::Tiny ();
use Types::Standard qw( InstanceOf Int );
use namespace::autoclean;
use overload
  q{""}    => sub { $_[0]->path },
  bool     => sub { 1 },
  fallback => 1;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Temp;

    {
      my $tmp = SICK::Temp->dir;                       # mode 0700
      my $key = $tmp->file('key.pem');                 # a path inside it
      $tmp->write( 'request.csr', $csr_pem, 0644 );    # default mode 0600
      ...
    }
    # the directory and everything in it is gone

=head1 DESCRIPTION

Private keys exist as files for the moment between issuing a certificate and
installing it. They live in a directory only the current user can enter, and
that directory is removed as soon as the object goes out of scope - also
when the code in between dies.

Directories that are still alive when the program ends normally are removed
then. A program that is killed by a signal runs neither destructors nor
C<END> blocks; a caller that wants to clean up in that case installs a
signal handler that calls C<exit>, or calls L</cleanup>.

=cut

# The directories of this process that still exist, for END and cleanup.
my %LIVE;

has _dir => (
  is       => 'ro',
  isa      => InstanceOf['Path::Tiny'],
  init_arg => undef,
  builder  => 1
);

sub _build__dir {
  my ( $self ) = @_;
  my $dir = eval { Path::Tiny->tempdir( 'sick-XXXXXXXXXX', CLEANUP => 0 ) };
  croak 'cannot create a temporary directory: '.( $@ =~ s/ at \S+ line [0-9]+\.?\s*\z//r )
    unless defined $dir;
  chmod 0700, $dir->stringify
    or croak 'cannot restrict temporary directory \''.$dir.'\': '.$!;
  return $dir;
}

has _pid => ( is => 'ro', isa => Int, init_arg => undef, default => sub { $$ } );

sub BUILD {
  my ( $self ) = @_;
  $LIVE{ $self->path } = $self->_pid;
  return;
}

sub dir { shift->new }

=method dir

    my $tmp = SICK::Temp->dir;

Creates a new directory with mode C<0700> below the system's temporary
directory (C<$TMPDIR>) and returns the object that owns it. The object
stringifies to the path. C<< SICK::Temp->new >> is the same.

=cut

sub path { $_[0]->_dir->stringify }

=method path

    my $path = $tmp->path;

The absolute path of the directory, as a plain string: it goes into the
argument lists of external programs (L<SICK::Command/run>).

=cut

sub file {
  my ( $self, $name ) = @_;
  croak 'SICK::Temp->file needs a plain file name'
    if !defined $name || !length $name || $name =~ m{/} || $name =~ /\A\.\.?\z/;
  return $self->_dir->child($name)->stringify;
}

=method file

    my $path = $tmp->file('key.pem');

The path of a file with that name inside the directory, as a plain string.
The file is not created.

=cut

sub write {
  my ( $self, $name, $content, $mode ) = @_;
  $mode = 0600 unless defined $mode;
  my $path = $self->file($name);
  sysopen( my $fh, $path, O_WRONLY | O_CREAT | O_EXCL, $mode )
    or croak 'cannot create temporary file \''.$path.'\': '.$!;
  chmod $mode, $fh
    or croak 'cannot set the mode of temporary file \''.$path.'\': '.$!;
  print {$fh} defined $content ? $content : q{}
    or croak 'cannot write temporary file \''.$path.'\': '.$!;
  close $fh
    or croak 'cannot write temporary file \''.$path.'\': '.$!;
  return $path;
}

=method write

    my $path = $tmp->write( $name, $content );
    my $path = $tmp->write( $name, $content, 0644 );

Creates the file with C<$content> and returns its path. The mode defaults to
C<0600> and does not depend on the umask. Croaks when the file exists.

=cut

sub remove {
  my ( $self ) = @_;
  return unless $self->_pid == $$;
  delete $LIVE{ $self->path };
  $self->_remove_tree( $self->path );
  return;
}

=method remove

    $tmp->remove;

Removes the directory now. Happens by itself when the object is destroyed;
a forked child never removes the directory of its parent.

=cut

sub cleanup {
  my ( $class ) = @_;
  for my $path ( keys %LIVE ) {
    next unless $LIVE{$path} == $$;
    delete $LIVE{$path};
    $class->_remove_tree($path);
  }
  return;
}

sub _remove_tree {
  my ( $self, $path ) = @_;
  my $dir = Path::Tiny::path($path);
  $dir->remove_tree( { safe => 0, error => \my $errors } ) if $dir->is_dir;
  return;
}

=method cleanup

    SICK::Temp->cleanup;

Removes every directory this process created and has not removed yet. Runs
at the normal end of the program; meant to be called from a signal handler
as well.

=cut

# During global destruction END has already removed every directory of this
# process, and the attributes may be gone.
sub DEMOLISH {
  my ( $self, $in_global_destruction ) = @_;
  return if $in_global_destruction;
  local ( $@, $!, $? );
  $self->remove;
  return;
}

END {
  local ( $@, $!, $? );
  __PACKAGE__->cleanup;
}

1;
