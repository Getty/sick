package SICK::Target::Files;
# ABSTRACT: Write certificate, chain and key as PEM files and run a reload command

use strict;
use warnings;
use parent 'SICK::Target';
use Carp qw( croak );
use File::Path qw( make_path );
use File::Temp ();
use SICK::Bundle;
use SICK::Command;

our $VERSION = '0.001';

=head1 SYNOPSIS

In the device list:

    devices:
      grafana:
        type: files
        names: [grafana.example.internal]
        dir: /srv/certs/grafana
        reload: "docker restart grafana"
        mode_key: 0640

      proxy:
        type: files
        host: proxy.example.internal        # check what the service really presents
        names: [proxy.example.internal]
        dir: /etc/haproxy/certs
        reload: [systemctl, reload, haproxy]

=head1 DESCRIPTION

The target for everything that runs on the machine SICK runs on, or reads
its certificate from a directory SICK can write to: four PEM files in one
directory, and a command that tells the service to pick them up.

    cert.pem        the certificate
    chain.pem       the intermediate certificates (empty when there are none)
    fullchain.pem   certificate and chain in one file
    key.pem         the private key

Every file is written under a temporary name next to its destination and
then renamed, so a reader sees either the old content or the new, never
half of a file. All four are written before the first one is renamed, and
C<cert.pem> comes last.

=head2 Options

=over 4

=item C<dir>

Required. The directory. It is created (mode C<0755>) when it is missing.

=item C<reload>

Optional. A command that runs after the files are in place. Written as a
list it is started directly; written as one string it is handed to
C</bin/sh -c>, with everything that implies - it is your device list. When
the command does not exit with 0 the deployment has failed.

=item C<mode_key>

Optional. The file mode of C<key.pem> as octal digits. C<0600> when not
set. The other files are C<0644>.

=back

=head2 Which certificate is presented

Without C<host>, the certificate in C<cert.pem> is taken for what the device
presents. That is cheap and needs no network, but it only says what is on
disk: when the reload command failed, the files are new and the service
still runs with the old certificate, and the next run sees nothing to do.
Set C<host> (and C<port>) and SICK asks the service itself, like for any
other device.

=cut

my @FILES = qw( key.pem chain.pem fullchain.pem cert.pem );

sub required_options { qw( dir ) }
sub optional_options { qw( reload mode_key ) }

sub dir { $_[0]->option('dir') }

sub mode_key {
  my ( $self ) = @_;
  my $mode = $self->option('mode_key');
  return 0600 unless defined $mode;
  croak $self->device->path.'.mode_key: invalid file mode \''.( ref $mode ? q{} : $mode ).'\''
    unless !ref $mode && $mode =~ /\A0?[0-7]{3}\z/;
  return oct $mode;
}

sub validate {
  my ( $self ) = @_;
  $self->SUPER::validate;
  my $path = $self->device->path;

  croak $path.'.dir: must be a directory path' if ref $self->dir;
  $self->mode_key;

  my $reload = $self->option('reload');
  if ( ref $reload eq 'ARRAY' ) {
    croak $path.'.reload: must be a command or a non-empty list of program and arguments'
      if !@$reload || grep { !defined || ref || !length } @$reload;
  }
  elsif ( ref $reload ) {
    croak $path.'.reload: must be a command or a non-empty list of program and arguments';
  }
  return $self;
}

=method validate

Checks the options: C<dir> is there, C<mode_key> is a file mode, C<reload>
is a string or a list of strings. Croaks with the place in the device list,
C<< devices.grafana: missing 'dir' >>.

=cut

sub deploy {
  my ( $self, $bundle ) = @_;
  croak 'deploy needs a SICK::Bundle' unless ref $bundle && eval { $bundle->can('fullchain') };
  $self->validate;
  my $dir = $self->dir;

  unless ( -d $dir ) {
    make_path( $dir, { mode => 0755, error => \my $errors } );
    croak 'cannot create directory \''.$dir.'\': '.( values %{ $errors->[0] } )[0]
      if $errors && @$errors;
  }

  my %content = (
    'cert.pem'      => $bundle->cert,
    'chain.pem'     => defined $bundle->chain ? $bundle->chain : q{},
    'fullchain.pem' => $bundle->fullchain
  );
  $content{'key.pem'} = $bundle->key if defined $bundle->key;

  my %staged;
  my $done = eval {
    for my $name ( grep { exists $content{$_} } @FILES ) {
      $staged{$name} = $self->_stage( $name, $content{$name}, $name eq 'key.pem' ? $self->mode_key : 0644 );
    }
    for my $name ( grep { exists $staged{$_} } @FILES ) {
      rename $staged{$name}, $dir.'/'.$name
        or die 'cannot write \''.$dir.'/'.$name.'\': '.$!."\n";
      delete $staged{$name};
    }
    1;
  };
  unless ($done) {
    my $error = $@;
    unlink values %staged;
    $error =~ s/\s+\z//;
    croak $error;
  }
  $self->log( 'wrote '.join( ', ', grep { exists $content{$_} } reverse @FILES ).' to '.$dir );

  $self->_reload;
  return;
}

=method deploy

    $target->deploy($bundle);

Writes the files and runs C<reload>. A bundle without a key leaves an
existing C<key.pem> alone.

Croaks with C<< reload failed (exit <N>): <stderr> >> when the reload
command does not succeed - the files are in place by then - and with
C<< cannot write '<path>': <reason> >> when a file cannot be written. All
files are written under their temporary names first, so a directory that is
full or not writable leaves the old files as they were.

=cut

sub presented_cert {
  my ( $self ) = @_;
  return $self->SUPER::presented_cert if defined $self->device->host;

  $self->validate;
  my $cert = $self->dir.'/cert.pem';
  return undef unless -e $cert;
  my $chain = $self->dir.'/chain.pem';
  my $bundle = eval { SICK::Bundle->from_files( cert => $cert, ( -s $chain ? ( chain => $chain ) : () ) ) };
  return $bundle if $bundle;
  my $error = $@;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  croak 'unreachable: '.$error if $error =~ /\Acannot read /;
  return undef;
}

=method presented_cert

    my $bundle = $target->presented_cert;

With a C<host>: what the service presents over TLS
(L<SICK::Target/presented_cert>). Without: the certificate in C<cert.pem>
with C<chain.pem> as its chain, or C<undef> when there is no C<cert.pem> or
no certificate in it. A C<cert.pem> that exists and cannot be read is
C<< unreachable: cannot read certificate file ... >>.

=cut

#### internals

# Write one file under a temporary name in the target directory, mode set
# before any content goes in. Returns the temporary path.
sub _stage {
  my ( $self, $name, $content, $mode ) = @_;
  my $dir = $self->dir;
  my $tmp = eval { File::Temp->new( DIR => $dir, TEMPLATE => '.'.$name.'.XXXXXXXX', UNLINK => 0 ) }
    or die 'cannot write \''.$dir.'/'.$name.'\': '.( $! ? $! : 'cannot create a temporary file' )."\n";
  my $path = $tmp->filename;
  my $ok = chmod( $mode, $path ) && print( {$tmp} $content ) && close($tmp);
  unless ($ok) {
    my $reason = q{}.$!;
    unlink $path;
    die 'cannot write \''.$dir.'/'.$name.'\': '.$reason."\n";
  }
  return $path;
}

sub _reload {
  my ( $self ) = @_;
  my $reload = $self->option('reload');
  return unless defined $reload && ( ref $reload || length $reload );

  my @command = ref $reload ? @$reload : ( '/bin/sh', '-c', $reload );
  $self->log( 'running reload: '.( ref $reload ? join( q{ }, @$reload ) : $reload ) );
  my ( $out, $err, $exit ) = SICK::Command::run( \@command );
  return unless $exit;
  $err =~ s/\A\s+//;
  $err =~ s/\s+\z//;
  croak 'reload failed (exit '.$exit.')'.( length $err ? ': '.$err : q{} );
}

1;
