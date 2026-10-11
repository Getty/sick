package SICK::Issuer::SelfSigned;
# ABSTRACT: A throwaway CA made of plain openssl, for tests and for trying things out

use Moo;
extends 'SICK::Issuer';
use Carp qw( croak );
use Fcntl qw( LOCK_EX O_CREAT O_RDWR );
use POSIX qw( strftime );
use Path::Tiny ();
use SICK::Bundle;
use SICK::Names;
use SICK::OpenSSL;
use SICK::Temp;
use Types::Standard qw( Bool Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Issuer::SelfSigned;

    my $issuer = SICK::Issuer::SelfSigned->new( dir => '/var/lib/sick/test-ca' );

    my $bundle = $issuer->issue( {
      names    => [ 'grafana.example.internal', '192.0.2.10' ],
      lifetime => 30 * 86400,
      key      => 'ec256',
    } );

    my $signed = $issuer->sign( $csr_pem, $spec );    # no key in this bundle
    my $root   = $issuer->root_pem;

In the device list:

    ca:
      type: selfsigned
      dir: /var/lib/sick/test-ca

=head1 DESCRIPTION

A certificate authority that needs nothing but C<openssl>: the first use
creates a root certificate and its key in C<dir>, and every certificate is
signed by that root directly. There is no server, no provisioner and no
revocation.

This exists so that SICK can be tested and tried out without a step-ca. Its
root key lies unencrypted in C<dir>, readable for the user who runs SICK. Do
not put real devices behind it; use L<SICK::Issuer::StepCA>.

=cut

my $CONFIG = <<'CONFIG';
[ca]
default_ca = sick_ca

[sick_ca]
database        = $ENV::SICK_WORK/index.txt
new_certs_dir   = $ENV::SICK_WORK/certs
serial          = $ENV::SICK_WORK/serial
default_md      = sha256
policy          = sick_policy
unique_subject  = no
copy_extensions = none
email_in_dn     = no
x509_extensions = sick_leaf

[sick_policy]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = optional
emailAddress           = optional

[sick_leaf]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
subjectAltName         = $ENV::SICK_SAN

[sick_root]
basicConstraints     = critical,CA:TRUE
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[req]
distinguished_name = sick_dn
prompt             = no
encrypt_key        = no
string_mask        = utf8only

[sick_dn]
CN = unused
CONFIG

sub attributes          { qw( dir ) }
sub required_attributes { qw( dir ) }

has dir => ( is => 'ro', isa => Str, required => 1 );

=attr dir

Required. The directory of the CA: C<ca.crt>, C<ca.key> (mode C<0600>) and
the empty lock file C<ca.lock>. It is created with mode C<0700> when it does
not exist, and the CA in it when neither C<ca.crt> nor C<ca.key> is there.

The CA is created under an exclusive lock on C<ca.lock>, so two processes
starting at once end up with one CA. The key is put into place first, the
certificate last. One of the two files without the other is an error,
C<< the CA in '<dir>' is incomplete: '<path>' is missing beside '<path>' >>,
never a reason to make a new CA: every device would turn C<foreign-ca>.
Before the first use the key is checked against the certificate; a key that
does not belong is C<< the CA in '<dir>' is broken: '<key>' is not the key
of '<cert>' >>, and a file that cannot be read
C<< cannot use the CA in '<dir>': <reason> >>.

=cut

# Set once the CA in dir was found whole; rw because it is a memo of
# _ensure_ca, not a setting.
has _ca_ready => ( is => 'rw', isa => Bool, init_arg => undef, default => 0 );

sub root_lifetime_days { 3650 }
sub root_subject       { '/CN=SICK self-signed CA' }

sub issue {
  my ( $self, $spec ) = @_;
  $spec = $self->check_spec($spec);
  $self->_ensure_ca;

  my $tmp    = SICK::Temp->dir;
  my $key    = $tmp->file('key.pem');
  my $csr    = $tmp->file('request.csr');
  my $params = $self->key_params( $spec->{key} );

  $self->_openssl(
    $tmp,
    [ 'genpkey',
      $params->{type} eq 'rsa'
      ? ( '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:'.$params->{bits} )
      : ( '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:'.$params->{curve},
          '-pkeyopt', 'ec_param_enc:named_curve' ),
      '-out', $key ],
  );
  $self->_openssl( $tmp,
    [ 'req', '-new', '-config', $self->_config($tmp), '-key', $key,
      '-subj', '/CN='.$spec->{names}[0], '-out', $csr ] );

  my $cert = $self->_sign_request( $tmp, $csr, $spec );
  return SICK::Bundle->from_files( cert => $cert, key => $key );
}

=method issue

    my $bundle = $issuer->issue($spec);

Generates a key of the requested type and a certificate for it that carries
exactly the names of the spec - host names as DNS SANs, addresses as IP
SANs, the first name as common name - and is valid from now for C<lifetime>
seconds. The bundle has no chain: the root signs directly.

The key exists as a file only inside a private temporary directory
(L<SICK::Temp>) that is gone when C<issue> returns or dies.

=cut

sub sign {
  my ( $self, $csr_pem, $spec ) = @_;
  $spec = $self->check_spec($spec);
  croak 'not a PEM certificate request'
    unless defined $csr_pem && $csr_pem =~ /-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----/;
  $self->_ensure_ca;

  my $tmp  = SICK::Temp->dir;
  my $csr  = $tmp->write( 'request.csr', $csr_pem );
  my $cert = $self->_sign_request( $tmp, $csr, $spec );
  return SICK::Bundle->from_files( cert => $cert );
}

=method sign

    my $bundle = $issuer->sign( $csr_pem, $spec );

Signs a certificate request. The public key and the subject come from the
request; the names come from the spec, whatever the request asks for. The
bundle has no key.

L<SICK::Issuer::StepCA/sign> is stricter: there the names of the request
have to be the names of the spec.

=cut

sub root_pem {
  my ( $self ) = @_;
  $self->_ensure_ca;
  return SICK::Bundle->from_files( cert => $self->_ca_cert )->cert;
}

=method root_pem

The root certificate as PEM. Creates the CA when there is none yet.

=cut

sub health { return undef }

=method health

C<undef>: the CA is a directory on this machine, there is nobody to ask
(L<SICK::Issuer/health>).

=cut

#### internals

# Paths in the CA directory, as plain strings for the command lines.
sub _ca_file { Path::Tiny::path( $_[0]->dir )->child( $_[1] )->stringify }
sub _ca_cert { $_[0]->_ca_file('ca.crt') }
sub _ca_key  { $_[0]->_ca_file('ca.key') }

# The reason of the system out of a Path::Tiny exception.
sub _reason {
  my ( $self, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  ( $error = defined $error ? $error : q{} ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  return length $error ? $error : 'unknown error';
}

sub _config {
  my ( $self, $tmp ) = @_;
  my $path = $tmp->file('openssl.cnf');
  $tmp->write( 'openssl.cnf', $CONFIG, 0600 ) unless Path::Tiny::path($path)->exists;
  return $path;
}

# Every call gets the two variables the configuration refers to, and a umask
# that keeps whatever openssl writes private.
sub _openssl {
  my ( $self, $tmp, $args, %opt ) = @_;
  return SICK::OpenSSL::run_checked(
    $args,
    umask => 077,
    env   => { SICK_WORK => $tmp->path, SICK_SAN => $opt{san} || 'DNS:unused.invalid' },
  );
}

# The CA is there and whole, or made now, or an error. Checked once per
# object: a run asks for every device.
sub _ensure_ca {
  my ( $self ) = @_;
  return if $self->_ca_ready;
  my $dir = $self->dir;

  # Both files there: a whole CA, since the certificate is put into place
  # last. Anything else is looked at again under the lock, because another
  # process may be creating the CA right now.
  unless ( -f $self->_ca_cert && -f $self->_ca_key ) {
    unless ( Path::Tiny::path($dir)->is_dir ) {
      eval { Path::Tiny::path($dir)->mkdir( { mode => 0700 } ); 1 }
        or croak 'cannot create CA directory \''.$dir.'\': '.$self->_reason($@);
    }
    my $lock = $self->_lock;
    my %there = map { $_ => -f $_ } $self->_ca_cert, $self->_ca_key;
    if ( !grep { $_ } values %there ) {
      $self->_create_ca;
    }
    elsif ( my ($missing) = grep { !$there{$_} } sort keys %there ) {
      my ($present) = grep { $there{$_} } sort keys %there;
      croak 'the CA in \''.$dir.'\' is incomplete: \''.$missing.'\' is missing beside \''.$present
        .'\' (restore it, or remove \''.$present.'\' for a new CA)';
    }
  }

  my $matches = eval { SICK::Bundle->from_files( cert => $self->_ca_cert, key => $self->_ca_key )->key_matches };
  unless ( defined $matches ) {
    ( my $error = $@ ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
    croak 'cannot use the CA in \''.$dir.'\': '.$error;
  }
  croak 'the CA in \''.$dir.'\' is broken: \''.$self->_ca_key.'\' is not the key of \''.$self->_ca_cert.'\''
    unless $matches;
  $self->_ca_ready(1);
  return;
}

# An exclusive lock on ca.lock in the CA directory, held as long as the
# handle lives. The file stays: removing it would let a waiting process
# lock a file nobody else sees any more.
sub _lock {
  my ( $self ) = @_;
  my $path = $self->_ca_file('ca.lock');
  sysopen my $fh, $path, O_RDWR | O_CREAT, 0600
    or croak 'cannot open \''.$path.'\': '.$!;
  flock $fh, LOCK_EX
    or croak 'cannot lock \''.$path.'\': '.$!;
  return $fh;
}

# Key and certificate are made beside their places, then renamed: the key
# first, the certificate last, so a crash in between leaves a key alone,
# which the next use refuses instead of taking the pair for whole.
sub _create_ca {
  my ( $self ) = @_;
  my $dir      = $self->dir;
  my $tmp      = SICK::Temp->dir;
  my $new_key  = $self->_ca_file( '.ca.key.'.$$ );
  my $new_cert = $self->_ca_file( '.ca.crt.'.$$ );
  my $done = eval {
    $self->_openssl(
      $tmp,
      [ 'req', '-new', '-x509', '-config', $self->_config($tmp), '-newkey', 'rsa:2048',
        '-keyout', $new_key, '-out', $new_cert, '-sha256',
        '-days', $self->root_lifetime_days, '-subj', $self->root_subject,
        '-extensions', 'sick_root' ],
    );
    $self->_file_op( 'cannot protect the CA key', $new_key, chmod => 0600 );
    $self->_file_op( 'cannot set the mode of the CA certificate', $new_cert, chmod => 0644 );
    # CORE rename, not Path::Tiny's move: that one copies when renaming
    # fails, with a mode from the umask, and moves into a directory of that
    # name
    rename $new_key, $self->_ca_key
      or die 'cannot write \''.$self->_ca_key.'\': '.$!."\n";
    rename $new_cert, $self->_ca_cert
      or die 'cannot write \''.$self->_ca_cert.'\': '.$!."\n";
    1;
  };
  unless ($done) {
    my $error = $@;
    eval { Path::Tiny::path($_)->remove } for $new_key, $new_cert;
    $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
    $error =~ s/\s+\z//;
    croak 'cannot create the CA in \''.$dir.'\': '.$error;
  }
  return;
}

# One Path::Tiny operation on a file of the new CA; dies with our words and
# the reason of the system.
sub _file_op {
  my ( $self, $what, $path, $method, @arg ) = @_;
  eval { Path::Tiny::path($path)->$method(@arg); 1 }
    or die $what.': '.$self->_reason($@)."\n";
  return;
}

sub _sign_request {
  my ( $self, $tmp, $csr, $spec ) = @_;

  my $certs = $tmp->file('certs');
  eval { Path::Tiny::path($certs)->mkdir( { mode => 0700 } ); 1 }
    or croak 'cannot create \''.$certs.'\': '.$self->_reason($@);
  $tmp->write( 'index.txt', q{} );
  my $serial = $self->_openssl( $tmp, [ 'rand', '-hex', '16' ] );
  $serial =~ s/\s+//g;
  $tmp->write( 'serial', $serial."\n" );

  my $now  = time;
  my $cert = $tmp->file('cert.pem');
  my $san  = join ',', map { ( SICK::Names::is_ip($_) ? 'IP:' : 'DNS:' ).$_ } @{ $spec->{names} };

  $self->_openssl(
    $tmp,
    [ 'ca', '-batch', '-notext', '-config', $self->_config($tmp),
      '-cert', $self->_ca_cert, '-keyfile', $self->_ca_key,
      '-in', $csr, '-out', $cert, '-preserveDN', '-md', 'sha256',
      '-startdate', strftime( '%Y%m%d%H%M%SZ', gmtime $now ),
      '-enddate',   strftime( '%Y%m%d%H%M%SZ', gmtime( $now + $spec->{lifetime} ) ) ],
    san => $san,
  );
  return $cert;
}

1;
