package SICK::Issuer::SelfSigned;
# ABSTRACT: A throwaway CA made of plain openssl, for tests and for trying things out

use strict;
use warnings;
use parent 'SICK::Issuer';
use Carp qw( croak );
use File::Path qw( make_path );
use POSIX qw( strftime );
use SICK::Bundle;
use SICK::Names;
use SICK::OpenSSL;
use SICK::Temp;

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

sub dir { $_[0]->{dir} }

=attr dir

Required. The directory of the CA: C<ca.crt> and C<ca.key> (mode C<0600>).
It is created with mode C<0700> when it does not exist, and the CA in it
when one of the two files is missing.

=cut

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

#### internals

sub _ca_cert { $_[0]->dir.'/ca.crt' }
sub _ca_key  { $_[0]->dir.'/ca.key' }

sub _config {
  my ( $self, $tmp ) = @_;
  my $path = $tmp->file('openssl.cnf');
  $tmp->write( 'openssl.cnf', $CONFIG, 0600 ) unless -e $path;
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

sub _ensure_ca {
  my ( $self ) = @_;
  my $dir = $self->dir;
  return if -s $self->_ca_cert && -s $self->_ca_key;

  unless ( -d $dir ) {
    make_path( $dir, { mode => 0700, error => \my $errors } );
    croak 'cannot create CA directory \''.$dir.'\': '.( values %{ $errors->[0] } )[0]
      if $errors && @$errors;
  }

  my $tmp      = SICK::Temp->dir;
  my $new_key  = $dir.'/.ca.key.'.$$;
  my $new_cert = $dir.'/.ca.crt.'.$$;
  my $done = eval {
    $self->_openssl(
      $tmp,
      [ 'req', '-new', '-x509', '-config', $self->_config($tmp), '-newkey', 'rsa:2048',
        '-keyout', $new_key, '-out', $new_cert, '-sha256',
        '-days', $self->root_lifetime_days, '-subj', $self->root_subject,
        '-extensions', 'sick_root' ],
    );
    chmod 0600, $new_key  or die 'cannot protect the CA key: '.$!."\n";
    chmod 0644, $new_cert or die 'cannot set the mode of the CA certificate: '.$!."\n";
    rename $new_key,  $self->_ca_key  or die 'cannot write \''.$self->_ca_key.'\': '.$!."\n";
    rename $new_cert, $self->_ca_cert or die 'cannot write \''.$self->_ca_cert.'\': '.$!."\n";
    1;
  };
  unless ($done) {
    my $error = $@;
    unlink $new_key, $new_cert;
    $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
    $error =~ s/\s+\z//;
    croak 'cannot create the CA in \''.$dir.'\': '.$error;
  }
  return;
}

sub _sign_request {
  my ( $self, $tmp, $csr, $spec ) = @_;

  mkdir $tmp->file('certs'), 0700
    or croak 'cannot create \''.$tmp->file('certs').'\': '.$!;
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
