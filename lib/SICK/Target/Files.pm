package SICK::Target::Files;
# ABSTRACT: Publish certificate, chain and key as PEM files in one step and run a reload command

use Moo;
extends 'SICK::Target';
use Carp qw( croak );
use Path::Tiny ();
use POSIX ();
use Time::HiRes ();
use SICK::Bundle;
use SICK::Command;
use namespace::autoclean;

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

=head2 Generations

Certificate, chain and key are published together, as one generation:

    dir/
      cert.pem       -> .sick/current/cert.pem
      chain.pem      -> .sick/current/chain.pem
      fullchain.pem  -> .sick/current/fullchain.pem
      key.pem        -> .sick/current/key.pem
      .sick/
        current      -> 20261010T211500.123456Z-1a2b3c4d
        previous     -> 20260905T030000.654321Z-9f8e7d6c
        20261010T211500.123456Z-1a2b3c4d/   cert.pem chain.pem fullchain.pem key.pem
        20260905T030000.654321Z-9f8e7d6c/   cert.pem chain.pem fullchain.pem key.pem

A deploy writes the four files into a new directory below C<.sick>, named
after the time (UTC) and the start of the certificate's SHA-256 fingerprint.
Only when all four are complete does it switch C<.sick/current> to it, with
a new link under a temporary name renamed over the old one: one atomic
step. The four names in C<dir> are relative links to
C<.sick/current/E<lt>fileE<gt>>, made once and left alone. At any moment
they lead to one generation, the old one or the new one, never to the new
key beside the old certificate. A program that opens the names one after the
other can still straddle a switch; one that wants to be sure resolves the
generation once (the real path of C<cert.pem>, or C<.sick/current>) and
reads all files from there. The generation it found stays on disk for one
more deploy.

The previous generation is kept for the rollback, older ones are removed:
at most two remain. The key in a generation has C<mode_key>, the other files
C<0644>, the directories C<0755>.

Plain files left in the four places by an earlier SICK become a generation
of their own on the first deploy, the previous one; the names become links
(the log says so). The content does not change in that step, and the new
certificate can roll back to them like to any other generation.

=head2 Rollback

When C<reload> fails - exits with something else than 0, or cannot be
started - C<.sick/current> goes back to the previous generation, C<reload>
runs once more so that the service runs with the old certificate again, and
the new generation is removed. The deployment has failed either way, and
the message says what the rollback achieved (L</deploy>). On the first
deploy into a directory there is no previous generation: the new files stay,
and the message says that as well.

=head2 Containers and symbolic links

Mount the directory into a container, not the single files. A bind mount
of one file resolves the link once, when the container starts, and pins
that file of that generation: the container never sees a later certificate,
and the file disappears from the host two deploys later. The links are
relative, so they work in the container wherever the directory is mounted.

=head2 Options

=over 4

=item C<dir>

Required. The directory. It is created (mode C<0755>) when it is missing,
and so is C<.sick> in it.

=item C<reload>

Optional. A command that runs after the switch to the new generation.
Written as a list it is started directly; written as one string it is
handed to C</bin/sh -c>, with everything that implies - it is your device
list. When the command does not exit with 0 the deployment has failed and
the previous generation is restored (L</Rollback>).

=item C<mode_key>

Optional. The file mode of C<key.pem> (the file in the generation) as
octal digits. C<0600> when not set. The other files are C<0644>.

=back

=head2 Which certificate is presented

Without C<host>, the certificate in C<cert.pem> is taken for what the device
presents. That is cheap and needs no network, but it only says what is on
disk: a reload that reported success without doing anything leaves a
service with the old certificate, and the next run sees nothing to do.
Set C<host> (and C<port>) and SICK asks the service itself, like for any
other device.

=cut

my @FILES = qw( key.pem chain.pem fullchain.pem cert.pem );
my $STORE = '.sick';

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

  for my $path ( $dir, $self->_store ) {
    next if Path::Tiny::path($path)->is_dir;
    eval { Path::Tiny::path($path)->mkdir; chmod 0755, $path or die $!."\n"; 1 }
      or croak 'cannot create directory \''.$path.'\': '.$self->_reason($@);
  }

  my $previous = $self->_current;
  $previous = $self->_adopt unless defined $previous;
  my $before   = $self->_generation('previous');

  my %content = (
    'cert.pem'      => [ $bundle->cert, 0644 ],
    'chain.pem'     => [ defined $bundle->chain ? $bundle->chain : q{}, 0644 ],
    'fullchain.pem' => [ $bundle->fullchain, 0644 ]
  );
  if ( defined $bundle->key ) {
    $content{'key.pem'} = [ $bundle->key, $self->mode_key ];
  }
  elsif ( -e $dir.'/key.pem' ) {
    # a device that keeps its key: the key it has goes along into the new
    # generation
    my $key = eval { Path::Tiny::path( $dir.'/key.pem' )->slurp_raw }
      // croak 'cannot read \''.$dir.'/key.pem\': '.$self->_reason($@);
    $content{'key.pem'} = [ $key, $self->mode_key ];
  }

  my $generation = $self->_write_generation( $bundle->fingerprint_sha256, \%content );
  $self->log( 'wrote '.join( ', ', grep { exists $content{$_} } reverse @FILES ).' to '.$dir.' as generation '.$generation );

  my $switched = eval {
    $self->_switch( current => $generation );
    $self->_switch( previous => $previous ) if defined $previous;
    1;
  };
  unless ($switched) {
    my $error = $@;
    Path::Tiny::path( $self->_store, $generation )->remove_tree( { safe => 0 } )
      unless ( $self->_current // q{} ) eq $generation;
    croak $self->_reason($error);
  }
  my @replaced = $self->_link_names;
  $self->log( 'replaced '.join( ', ', @replaced ).' in '.$dir.', which were no links, by links to .sick/current' ) if @replaced;

  $self->_roll_back( $@, $generation, $previous, $before ) unless eval { $self->_reload; 1 };
  $self->_prune;
  return;
}

=method deploy

    $target->deploy($bundle);

Writes a new generation, switches C<.sick/current> to it, runs C<reload>
and removes the generations older than the previous one. A bundle without a
key takes the key that is there into the new generation.

Croaks with C<< cannot create directory '<path>': <reason> >> or
C<< cannot write '<path>': <reason> >> when the generation cannot be
written; nothing visible has changed then. When the reload fails it goes back
to the previous generation as described under L</Rollback> and croaks with
the reason of the reload and what became of the rollback:

    reload failed (exit 3): <stderr>; restored the previous certificate (generation <name>) and ran the reload again
    reload failed (exit 3): <stderr>; restored the previous certificate (generation <name>), but the reload after that failed as well: <reason>
    reload failed (exit 3): <stderr>; there is no previous certificate to restore, the new one stays in place

A reload that cannot be started reads C<< cannot run '<program>': <reason> >>
in place of C<< reload failed ... >>.

=cut

# Without a host the answer is a file that deploy wrote itself: waiting does
# not change it.
sub verify_timeout {
  my ( $self ) = @_;
  return defined $self->device->host ? $self->SUPER::verify_timeout : 0;
}

sub presented_cert {
  my ( $self ) = @_;
  return $self->SUPER::presented_cert if defined $self->device->host;

  $self->validate;
  my $cert = Path::Tiny::path( $self->dir )->child('cert.pem')->stringify;
  return undef unless Path::Tiny::path($cert)->exists;
  my $chain = Path::Tiny::path( $self->dir )->child('chain.pem')->stringify;
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

sub _store { $_[0]->dir.'/'.$STORE }

# The generation a link in .sick points to, or undef when there is none or
# its directory is gone.
sub _generation {
  my ( $self, $link ) = @_;
  my $name = readlink $self->_store.'/'.$link;
  return undef unless defined $name && length $name && $name !~ m{/} && -d $self->_store.'/'.$name;
  return $name;
}

sub _current { $_[0]->_generation('current') }

# Write a generation directory with the files in %$content (name => [
# content, mode ]) and return its name. On failure the directory is removed
# and the error is the first one.
sub _write_generation {
  my ( $self, $fingerprint, $content ) = @_;
  # to the microsecond: a name is never used twice, also not after the
  # generation that had it was removed (a reader may still hold it)
  my $now  = Time::HiRes::time();
  my $base = POSIX::strftime( '%Y%m%dT%H%M%S', gmtime $now ).sprintf( '.%06dZ', ( $now - int $now ) * 1e6 )
    .'-'.substr( $fingerprint, 0, 8 );
  my ( $name, $path );
  # CORE mkdir: it is the one that says the name was taken (EEXIST)
  for my $n ( 1 .. 100 ) {
    $name = $n == 1 ? $base : $base.'.'.$n;
    $path = $self->_store.'/'.$name;
    last if mkdir $path, 0700;
    croak 'cannot create directory \''.$path.'\': '.$! unless $!{EEXIST} && $n < 100;
  }
  my $done = eval {
    chmod 0755, $path or die 'cannot write \''.$path.'\': '.$!."\n";
    for my $file ( grep { exists $content->{$_} } @FILES ) {
      my $staged = $self->_stage( $path, $file, @{ $content->{$file} } );
      # CORE rename, not Path::Tiny's move: that one copies when renaming
      # fails and moves into a directory of that name
      rename $staged, $path.'/'.$file
        or die 'cannot write \''.$path.'/'.$file.'\': '.$!."\n";
    }
    1;
  };
  unless ($done) {
    my $error = $@;
    eval { Path::Tiny::path($path)->remove_tree( { safe => 0 } ) };
    $error =~ s/\s+\z//;
    croak $error;
  }
  return $name;
}

# Point .sick/$link at $generation: a new link under a temporary name,
# renamed over the old one, so the link is the old one or the new one and
# never missing.
sub _switch {
  my ( $self, $link, $generation ) = @_;
  $self->_relink( $self->_store, $link, $generation );
  return;
}

sub _relink {
  my ( $self, $dir, $name, $target ) = @_;
  my $aside = $dir.'/.'.$name.'.sick-'.$$;
  unlink $aside if -l $aside;
  symlink $target, $aside or croak 'cannot write \''.$dir.'/'.$name.'\': '.$!;
  unless ( rename $aside, $dir.'/'.$name ) {
    my $error = $!;
    unlink $aside;
    croak 'cannot write \''.$dir.'/'.$name.'\': '.$error;
  }
  return;
}

# The four names in dir as links to .sick/current/<name>, for the files the
# current generation has; a link of ours to a file it does not have goes.
# Returns the names that were something else before and were replaced.
sub _link_names {
  my ( $self ) = @_;
  my $dir     = $self->dir;
  my $current = $self->_current;
  my @replaced;
  for my $name (@FILES) {
    my $path   = $dir.'/'.$name;
    my $target = $STORE.'/current/'.$name;
    my $link   = readlink $path;
    unless ( -e $self->_store.'/'.$current.'/'.$name ) {
      unlink $path if defined $link && $link eq $target;
      next;
    }
    next if defined $link && $link eq $target;
    croak 'cannot write \''.$path.'\': it is a directory' if -d $path && !-l $path;
    push @replaced, $name if -e $path || -l $path;
    $self->_relink( $dir, $name, $target );
  }
  return @replaced;
}

# The plain files of an earlier SICK become a generation of their own, the
# current one, and the names become links to it; same content, so a reader
# sees no change. Returns the name of that generation, or undef when there
# are no plain files.
sub _adopt {
  my ( $self ) = @_;
  my $dir   = $self->dir;
  my @plain = grep { -f $dir.'/'.$_ && !-l $dir.'/'.$_ } @FILES;
  return undef unless @plain;

  my %content;
  for my $name (@plain) {
    my $path = $dir.'/'.$name;
    my $data = eval { Path::Tiny::path($path)->slurp_raw }
      // croak 'cannot read \''.$path.'\': '.$self->_reason($@);
    $content{$name} = [ $data, ( stat $path )[2] & 07777 ];
  }
  my $fingerprint = exists $content{'cert.pem'}
    ? eval { SICK::Bundle->new( cert => $content{'cert.pem'}[0] )->fingerprint_sha256 }
    : undef;
  my $generation = $self->_write_generation( $fingerprint // 'unknown', \%content );
  $self->_switch( current => $generation );
  $self->_link_names;
  $self->log( 'moved '.join( ', ', sort @plain ).' of an earlier SICK into generation '.$generation.', '.$dir
      .' now links to '.$STORE.'/current' );
  return $generation;
}

# The reload failed: back to the previous generation, reload again, and
# croak with what happened.
sub _roll_back {
  my ( $self, $error, $generation, $previous, $before ) = @_;
  my $reason = $self->_reason($error);
  croak $reason.'; there is no previous certificate to restore, the new one stays in place'
    unless defined $previous;

  $self->log( 'reload failed, going back to generation '.$previous );
  my $restored = eval {
    $self->_switch( current => $previous );
    if ( defined $before ) { $self->_switch( previous => $before ) }
    else                   { unlink $self->_store.'/previous' }
    $self->_link_names;
    1;
  };
  croak $reason.'; could not restore the previous certificate: '.$self->_reason($@) unless $restored;
  eval { Path::Tiny::path( $self->_store, $generation )->remove_tree( { safe => 0 } ) };

  my $again = eval { $self->_reload; 1 } ? undef : $self->_reason($@);
  croak $reason.'; restored the previous certificate (generation '.$previous.')'
    .( defined $again ? ', but the reload after that failed as well: '.$again : ' and ran the reload again' );
}

# Every generation but current and previous goes. A generation that cannot
# be removed is logged and left; the deployment has happened all the same.
sub _prune {
  my ( $self ) = @_;
  my %keep = map { defined ? ( $_ => 1 ) : () } $self->_current, $self->_generation('previous');
  for my $child ( Path::Tiny::path( $self->_store )->children ) {
    my $name = $child->basename;
    next if $name =~ /\A\./ || $keep{$name} || -l $child->stringify || !$child->is_dir;
    eval { $child->remove_tree( { safe => 0 } ); 1 }
      or $self->log( 'cannot remove generation '.$name.': '.$self->_reason($@) );
  }
  return;
}

# Write one file under a temporary name in $dir, mode set before any
# content goes in. Returns the temporary path. The file is created by
# File::Temp (O_EXCL, mode 0600) and filled in place: not with spew, which
# writes a file of its own with a mode from the umask.
sub _stage {
  my ( $self, $dir, $name, $content, $mode ) = @_;
  my $aside = eval { Path::Tiny->tempfile( DIR => $dir, TEMPLATE => '.'.$name.'.XXXXXXXX', UNLINK => 0 ) }
    or die 'cannot write \''.$dir.'/'.$name.'\': '.( $! ? $! : 'cannot create a temporary file' )."\n";
  my $ok = eval { $aside->chmod($mode); $aside->append_raw($content); 1 };
  unless ($ok) {
    my $reason = $self->_reason($@);
    eval { $aside->remove };
    die 'cannot write \''.$dir.'/'.$name.'\': '.$reason."\n";
  }
  return $aside->stringify;
}

# The reason of the system out of a Path::Tiny exception.
sub _reason {
  my ( $self, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  ( $error = defined $error ? $error : q{} ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  return length $error ? $error : 'unknown error';
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
