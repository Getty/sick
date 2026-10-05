package SICK::Temp;
# ABSTRACT: A private temporary directory that disappears with its object

use strict;
use warnings;
use Carp qw( croak );
use Fcntl qw( O_CREAT O_EXCL O_WRONLY );
use File::Path qw( remove_tree );
use File::Temp ();
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

sub dir {
  my ( $class ) = @_;
  my $path = eval { File::Temp::tempdir( 'sick-XXXXXXXXXX', TMPDIR => 1 ) };
  croak 'cannot create a temporary directory: '.( $@ =~ s/ at \S+ line [0-9]+\.?\s*\z//r )
    unless defined $path;
  chmod 0700, $path
    or croak 'cannot restrict temporary directory \''.$path.'\': '.$!;
  $LIVE{$path} = $$;
  return bless { path => $path, pid => $$ }, $class;
}

=method dir

    my $tmp = SICK::Temp->dir;

Creates a new directory with mode C<0700> below the system's temporary
directory (C<$TMPDIR>) and returns the object that owns it. The object
stringifies to the path.

=cut

sub path { $_[0]->{path} }

=method path

    my $path = $tmp->path;

The absolute path of the directory.

=cut

sub file {
  my ( $self, $name ) = @_;
  croak 'SICK::Temp->file needs a plain file name'
    if !defined $name || !length $name || $name =~ m{/} || $name =~ /\A\.\.?\z/;
  return $self->path.'/'.$name;
}

=method file

    my $path = $tmp->file('key.pem');

The path of a file with that name inside the directory. The file is not
created.

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
  return unless $self->{pid} == $$;
  my $path = $self->{path};
  delete $LIVE{$path};
  remove_tree( $path, { safe => 0, error => \my $errors } ) if -d $path;
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
    remove_tree( $path, { safe => 0, error => \my $errors } ) if -d $path;
  }
  return;
}

=method cleanup

    SICK::Temp->cleanup;

Removes every directory this process created and has not removed yet. Runs
at the normal end of the program; meant to be called from a signal handler
as well.

=cut

sub DESTROY {
  my ( $self ) = @_;
  local ( $@, $!, $? );
  $self->remove;
  return;
}

END {
  local ( $@, $!, $? );
  __PACKAGE__->cleanup;
}

1;
