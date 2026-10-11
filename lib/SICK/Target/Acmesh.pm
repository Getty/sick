package SICK::Target::Acmesh;
# ABSTRACT: Hand a certificate to one of the deploy hooks of acme.sh

use Moo;
extends 'SICK::Target';
use Carp qw( croak );
use Path::Tiny ();
use SICK::Command;
use SICK::Config;
use SICK::Names;
use SICK::Temp;
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

In the device list:

    devices:
      router:
        type: acmesh
        hook: routeros                    # logs in with ssh and scp, by key
        names: [router.example.internal]
        env:
          ROUTER_OS_HOST: router.example.internal
          ROUTER_OS_USERNAME: sick
          ROUTER_OS_SSH_CMD: ssh -i /etc/sick/router.key -o UserKnownHostsFile=/etc/sick/known_hosts
          ROUTER_OS_SCP_CMD: scp -i /etc/sick/router.key -o UserKnownHostsFile=/etc/sick/known_hosts

      hypervisor:
        type: acmesh
        hook: proxmoxve
        host: pve.example.internal
        port: 8006
        names: [pve.example.internal, 192.0.2.30]
        env:
          DEPLOY_PROXMOXVE_SERVER: pve.example.internal
          # both default to root@pam; the token belongs to sick@pve
          DEPLOY_PROXMOXVE_USER: sick
          DEPLOY_PROXMOXVE_USER_REALM: pve
          DEPLOY_PROXMOXVE_API_TOKEN_NAME: sick
        env_files:
          DEPLOY_PROXMOXVE_API_TOKEN_KEY: /etc/sick/pve.token

Without C<DEPLOY_PROXMOXVE_USER> and C<DEPLOY_PROXMOXVE_USER_REALM> (for
C<proxmoxbs> the C<DEPLOY_PROXMOXBS_> pair) the hook logs in as
C<root@pam>. Token, rights and the alternative of the node's own ACME
client: F<contrib/devices/proxmox/README.md> in the distribution.

=head1 DESCRIPTION

L<acme.sh|https://github.com/acmesh-official/acme.sh> ships some sixty
I<deploy hooks>: shell scripts that install a certificate on a RouterOS
router, a Proxmox host, a FRITZ!Box, a Synology and so on. They do not care
where the certificate came from. This target borrows them: it lays the
certificate out the way acme.sh keeps its own, and runs

    acme.sh --deploy -d <first name> --deploy-hook <hook>
      --home <home> --config-home <home> --cert-home <home>

acme.sh issues nothing here, contacts no CA and needs no account. It is a
prerequisite of a run for devices of this type, not of the installation;
the hook may need more (C<ssh>, C<curl>).

=head2 What is known to work

The mechanism is verified against acme.sh 3.1.6 with the C<localcopy> hook
(C<docs/findings/acmesh-deploy.md> in the distribution has the details).
B<No other hook has been run by the authors of this module.> A hook is
somebody else's shell script that talks to your device with the credentials
you give it; read it before you point it at something that matters.

=head2 Options

=over 4

=item C<hook>

Required. The name of the deploy hook, as in C<acme.sh --deploy-hook>:
C<routeros>, C<proxmoxve>, C<localcopy>, ...

=item C<env>

A mapping of environment variables for the hook - its settings. Which ones
a hook reads stands at the top of its script.

=item C<env_files>

A mapping of environment variables to files: the variable is set to the
first line of the file. For everything secret. The values go into the
environment of acme.sh and nowhere else - not onto a command line, not into
a log line; should acme.sh or the hook print one, it is replaced by
C<[hidden]> before SICK passes the output on. That catches the value as it
stands in the file, not something a hook made of it (a part, an encoding).

=item C<acme_sh>

The C<acme.sh> program. Defaults to C<acme.sh> from the C<PATH>. The hooks
are looked for next to the script (C<deploy/E<lt>hookE<gt>.sh>), which is
where an installation and a checkout of acme.sh have them, and below
C<home>.

=item C<home>

The directory acme.sh works in. Without it - the normal case - that is a
private temporary directory which is gone when the deployment is over.

Give a C<home> only when a hook has to remember something between two
runs, or to use a hook of your own in C<< <home>/deploy/ >>. Know what
acme.sh does there: it writes every setting a hook was given, B<secrets
included>, to C<< <home>/<first name>/<first name>.conf >>, and uses them
again when the variable is not set the next time. SICK creates the
directories with mode C<0700> and removes the private key from C<home> when
acme.sh has finished.

B<Never use the home of an acme.sh that also runs as a cron job.> Its
C<--cron> treats every directory in there as a certificate of its own and
tries to renew it - for the names of your internal device, at a public CA.

=back

=head2 Which certificate is presented

Like every device: SICK connects to C<host> and C<port> (the first name and
C<443> when they are not set) and looks at the certificate
(L<SICK::Target/presented_cert>). Set them to where the service of the hook
really listens.

=cut

# What acme.sh derives its paths from, and what would make it talk more
# than it should. None of it may leak in from the environment SICK was
# started in, and none of it is the device list's to set.
my @UNSET = qw(
  DOMAIN_PATH DOMAIN_BACKUP_PATH DOMAIN_CONF DOMAIN_SSL_CONF
  CSR_PATH CERT_KEY_PATH CERT_PATH CA_CERT_PATH CERT_FULLCHAIN_PATH
  CERT_PFX_PATH CERT_PKCS8_PATH
  ACCOUNT_CONF_PATH _SCRIPT_HOME
  DEBUG LOG_FILE LOG_LEVEL SYS_LOG OUTPUT_INSECURE
);
my @RESERVED = ( @UNSET, qw( LE_WORKING_DIR LE_CONFIG_HOME CERT_HOME NO_TIMESTAMP ) );

sub required_options { qw( hook ) }
sub optional_options { qw( env env_files acme_sh home ) }

sub hook { $_[0]->option('hook') }

sub acme_sh {
  my ( $self ) = @_;
  my $program = $self->option('acme_sh');
  return defined $program && length $program ? $program : 'acme.sh';
}

sub cert_name { $_[0]->device->names->[0] }

=method hook

The name of the deploy hook.

=method acme_sh

The program that is started: the C<acme_sh> option, or C<acme.sh>.

=method cert_name

The first name of the device. acme.sh knows a certificate by its first
name: it is the argument of C<-d>, the name of the directory below C<home>
and what the hook receives as the domain.

=cut

sub deploy_timeout { 300 }

=method deploy_timeout

Seconds acme.sh and its hook may take. C<300>; after that they are stopped
and the deployment has failed.

=cut

sub validate {
  my ( $self ) = @_;
  $self->SUPER::validate;
  my $path = $self->device->path;

  my $hook = $self->hook;
  croak $path.'.hook: invalid hook name \''.( ref $hook ? q{} : $hook ).'\''
    unless !ref $hook && $hook =~ /\A[A-Za-z0-9_]+\z/;

  my %reserved = map { $_ => 1 } @RESERVED;
  my %seen;
  for my $option (qw( env env_files )) {
    my $map = $self->option($option);
    next unless defined $map;
    croak $path.'.'.$option.': must be a mapping of variable names' unless ref $map eq 'HASH';
    for my $name ( sort keys %$map ) {
      croak $path.'.'.$option.': invalid variable name \''.$name.'\''
        unless $name =~ /\A[A-Za-z_][A-Za-z0-9_]*\z/;
      croak $path.'.'.$option.'.'.$name.': is set by SICK itself' if $reserved{$name};
      croak $path.'.'.$option.'.'.$name.': is also in '.$seen{$name} if $seen{$name};
      $seen{$name} = $option;
      my $value = $map->{$name};
      croak $path.'.'.$option.'.'.$name.': must be a plain value' if ref $value || !defined $value;
      croak $path.'.'.$option.'.'.$name.': must be the path of a file'
        if $option eq 'env_files' && !length $value;
    }
  }

  my $program = $self->option('acme_sh');
  croak $path.'.acme_sh: must be the name or the path of the acme.sh program'
    if defined $program && ( ref $program || !length $program );

  my $home = $self->option('home');
  croak $path.'.home: must be an absolute path without whitespace'
    if defined $home && ( ref $home || $home !~ m{\A/\S*\z} );

  return $self;
}

=method validate

Checks the options: C<hook> is there and looks like a hook name, C<env> and
C<env_files> are mappings of variable names to plain values, no variable is
in both or is one that SICK sets itself (the ones acme.sh takes its paths
from), C<home> is an absolute path without whitespace - acme.sh does not
work in any other. Croaks with the place in the device list,
C<< devices.router: missing 'hook' >>.

=cut

sub deploy {
  my ( $self, $bundle ) = @_;
  croak 'deploy needs a SICK::Bundle' unless ref $bundle && eval { $bundle->can('fullchain') };
  $self->validate;
  croak 'the acmesh target needs the private key of the certificate: a deploy hook installs key and certificate together'
    unless defined $bundle->key;

  my $name = $self->cert_name;
  # the name becomes a directory, a file name and a line in a file acme.sh
  # reads as shell code
  croak $self->device->path.'.names: \''.$name.'\' cannot be the name of a certificate in acme.sh'
    unless SICK::Names::is_valid($name) && $name !~ m{[/'\\\s]};

  # secrets first: nothing is put anywhere when one of them cannot be read
  my %secret = map { $_ => SICK::Config->read_secret( $self->option('env_files')->{$_} ) }
    sort keys %{ $self->option('env_files') || {} };

  my $home = $self->option('home');
  my $private;
  unless ( defined $home ) {
    $private = SICK::Temp->dir;
    $home    = $private->path;
  }
  my @command = (
    $self->acme_sh, '--deploy', '-d', $name, '--deploy-hook', $self->hook,
    '--home', $home, '--config-home', $home, '--cert-home', $home
  );
  my %env = (
    %{ $self->option('env') || {} },
    %secret,
    ( map { $_ => undef } @UNSET ),
    NO_TIMESTAMP => 1
  );

  my ( $out, $err, $exit ) = eval {
    $self->_stage( $home, $name, $bundle );
    $self->log( 'running '.join( q{ }, @command ) );
    SICK::Command::run( \@command, env => \%env, umask => 077, timeout => $self->deploy_timeout );
  };
  my $died = $@;
  # the key has no business in a home that stays
  eval { Path::Tiny::path( $self->_key_file( $home, $name ) )->remove } unless $private;
  unless ( defined $exit ) {
    $died =~ s/ at \S+ line [0-9]+\.?\s*\z//;
    croak $died;
  }

  ( $out, $err ) = map { $self->_hide( $_, values %secret ) } $out, $err;
  $self->log( 'acme.sh: '.$_ ) for grep { /\S/ } split /\r?\n/, $out;
  return unless $exit;

  $err =~ s/\A\s+//;
  $err =~ s/\s+\z//;
  unless ( length $err ) {
    ($err) = reverse grep { /\S/ } split /\r?\n/, $out;
    $err = q{} unless defined $err;
  }
  croak 'acme.sh failed (exit '.$exit.')'.( length $err ? ': '.$err : q{} );
}

=method deploy

    $target->deploy($bundle);

Reads the files of C<env_files>, lays out the bundle below C<home>

    <home>/<first name>/<first name>.key     the private key (mode 0600)
    <home>/<first name>/<first name>.cer     the certificate
    <home>/<first name>/ca.cer               the chain (empty when there is none)
    <home>/<first name>/fullchain.cer        certificate and chain
    <home>/<first name>/<first name>.conf    Le_Domain, Le_Alt and Le_Keylength,
                                             unless it exists

and runs acme.sh with the variables of C<env> and C<env_files> in its
environment. The directory is always the plain one, also for an EC key;
C<--ecc> is not used.

What acme.sh prints is handed to the log, line by line. Croaks with
C<< acme.sh failed (exit <N>): <what it printed as error> >> when acme.sh
does not exit with 0, with C<< cannot run 'acme.sh': <reason> >> when it is
not installed, with C<< cannot read secret file '<path>': <reason> >> when
a file of C<env_files> is missing or unreadable - before anything else
happens -, and when the bundle has no key.

A hook that failed may have changed the device half way; that is between
the hook and the device. The next run starts from what the device presents.

=cut

#### internals

sub _key_file {
  my ( $self, $home, $name ) = @_;
  return Path::Tiny::path($home)->child( $name, $name.'.key' )->stringify;
}

# Put the bundle where acme.sh looks for a certificate of that name.
sub _stage {
  my ( $self, $home, $name, $bundle ) = @_;
  my $dir = Path::Tiny::path($home)->child($name)->stringify;

  unless ( Path::Tiny::path($dir)->is_dir ) {
    eval { Path::Tiny::path($dir)->mkdir( { mode => 0700 } ); 1 }
      or croak 'cannot create directory \''.$dir.'\': '.$self->_reason($@);
  }

  my @alt = @{ $self->device->names };
  shift @alt;

  $self->_put( $self->_key_file( $home, $name ), $bundle->key, 0600 );
  $self->_put( $dir.'/'.$name.'.cer', $bundle->cert,      0644 );
  $self->_put( $dir.'/ca.cer',        defined $bundle->chain ? $bundle->chain : q{}, 0644 );
  $self->_put( $dir.'/fullchain.cer', $bundle->fullchain, 0644 );
  # Older releases of acme.sh (3.1.0 for one) read the file without asking
  # whether it is there, and a few hooks look into it. When it exists, it
  # belongs to acme.sh: the hooks keep their state in it.
  my %keylength = ( rsa2048 => '2048', rsa3072 => '3072', rsa4096 => '4096', ec256 => 'ec-256' );
  my $keylength = $keylength{ $self->device->key };
  $self->_put(
    $dir.'/'.$name.'.conf',
    join( q{},
      'Le_Domain=\''.$name.'\''."\n",
      'Le_Alt=\''.( @alt ? join( ',', @alt ) : 'no' ).'\''."\n",
      ( defined $keylength ? 'Le_Keylength=\''.$keylength.'\''."\n" : () ) ),
    0600
  ) unless Path::Tiny::path($dir)->child( $name.'.conf' )->exists;
  return;
}

# One file, written aside with its mode set before any content goes in, then
# renamed over what was there. The file aside is created by File::Temp
# (O_EXCL, mode 0600) and filled in place - not with spew, which writes a
# file of its own with a mode from the umask - and published with CORE
# rename: Path::Tiny's move copies when renaming fails.
sub _put {
  my ( $self, $path, $content, $mode ) = @_;
  my $dir = Path::Tiny::path($path)->parent->stringify;
  my $aside = eval { Path::Tiny->tempfile( DIR => $dir, TEMPLATE => '.sick-XXXXXXXX', UNLINK => 0 ) }
    or croak 'cannot write \''.$path.'\': '.( $! ? $! : 'cannot create a temporary file' );
  my $reason = eval { $aside->chmod($mode); $aside->append_raw($content); 1 } ? undef : $self->_reason($@);
  $reason = q{}.$! if !defined $reason && !rename( $aside->stringify, $path );
  if ( defined $reason ) {
    eval { $aside->remove };
    croak 'cannot write \''.$path.'\': '.$reason;
  }
  return $path;
}

# The reason of the system out of a Path::Tiny exception.
sub _reason {
  my ( $self, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  ( $error = defined $error ? $error : q{} ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  return length $error ? $error : 'unknown error';
}

# Take every secret out of a text that is about to be shown to somebody.
sub _hide {
  my ( $self, $text, @secrets ) = @_;
  $text = q{} unless defined $text;
  for my $secret ( sort { length $b <=> length $a } grep { defined && length } @secrets ) {
    $text =~ s/\Q$secret\E/[hidden]/g;
  }
  return $text;
}

1;
