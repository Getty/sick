package Test::SICK::PKI;

# Test helper: throwaway CAs and certificates, made with plain openssl calls
# that do not go through the issuers under test. Everything is generated at
# test time into a directory the test owns; nothing here is a fixture.

use strict;
use warnings;
use Carp qw( croak );
use Exporter qw( import );
use SICK::OpenSSL;

our @EXPORT_OK = qw( new_ca new_cert new_csr slurp spew );

my $CONFIG = <<'CONFIG';
[req]
distinguished_name = dn
prompt             = no

[dn]
CN = unused

[ca_ext]
basicConstraints     = critical,CA:TRUE
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[leaf_ext]
basicConstraints     = CA:FALSE
subjectKeyIdentifier = hash

[leaf_san_ext]
basicConstraints     = CA:FALSE
subjectKeyIdentifier = hash
subjectAltName       = $ENV::SICK_TEST_SAN

[csr_san_ext]
subjectAltName = $ENV::SICK_TEST_SAN
CONFIG

my $serial = 1000;

sub slurp {
  my ( $path ) = @_;
  open my $fh, '<', $path or croak 'cannot read '.$path.': '.$!;
  local $/;
  return scalar <$fh>;
}

sub spew {
  my ( $path, $content ) = @_;
  open my $fh, '>', $path or croak 'cannot write '.$path.': '.$!;
  print {$fh} $content;
  close $fh or croak 'cannot write '.$path.': '.$!;
  return $path;
}

sub _openssl {
  my ( $args, %opt ) = @_;
  my ( $out, $err, $exit ) = SICK::OpenSSL::run(
    $args,
    umask => 077,
    env   => { SICK_TEST_SAN => $opt{san} || 'DNS:unused.invalid' },
  );
  croak 'openssl '.join( q{ }, @$args ).' failed: '.$err if $exit;
  return $out;
}

sub _config {
  my ( $dir ) = @_;
  my $path = $dir.'/test-openssl.cnf';
  spew( $path, $CONFIG ) unless -e $path;
  return $path;
}

sub _key {
  my ( $path ) = @_;
  _openssl( [ 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $path ] );
  return $path;
}

# new_ca( dir => $dir, name => 'root', cn => 'Some CA', issuer => $other_ca )
# -> { cert => $path, key => $path, pem => $text }
sub new_ca {
  my ( %arg ) = @_;
  my $dir    = $arg{dir}  or croak 'new_ca needs dir';
  my $name   = $arg{name} or croak 'new_ca needs name';
  my $cn     = $arg{cn} || 'SICK test '.$name;
  my $config = _config($dir);
  my $key    = _key( $dir.'/'.$name.'.key' );
  my $cert   = $dir.'/'.$name.'.crt';

  if ( my $issuer = $arg{issuer} ) {
    my $csr = $dir.'/'.$name.'.csr';
    _openssl( [ 'req', '-new', '-config', $config, '-key', $key, '-subj', '/CN='.$cn, '-out', $csr ] );
    _openssl( [ 'x509', '-req', '-in', $csr, '-CA', $issuer->{cert}, '-CAkey', $issuer->{key},
        '-set_serial', ++$serial, '-days', 30, '-extfile', $config, '-extensions', 'ca_ext',
        '-out', $cert ] );
  }
  else {
    _openssl( [ 'req', '-new', '-x509', '-config', $config, '-key', $key, '-subj', '/CN='.$cn,
        '-days', 30, '-extensions', 'ca_ext', '-out', $cert ] );
  }

  return { cert => $cert, key => $key, pem => slurp($cert) };
}

# new_cert( ca => $ca, dir => $dir, name => 'leaf', cn => 'host.example',
#           san => 'DNS:host.example,IP:192.0.2.1', days => 30 )
# -> { cert => $path, key => $path, csr => $path, cert_pem => $text, key_pem => $text }
# Without san the certificate has no subjectAltName extension at all.
sub new_cert {
  my ( %arg ) = @_;
  my $ca     = $arg{ca}   or croak 'new_cert needs ca';
  my $dir    = $arg{dir}  or croak 'new_cert needs dir';
  my $name   = $arg{name} or croak 'new_cert needs name';
  my $cn     = $arg{cn} || $name.'.example';
  my $config = _config($dir);
  my $key    = _key( $dir.'/'.$name.'.key' );
  my $csr    = $dir.'/'.$name.'.csr';
  my $cert   = $dir.'/'.$name.'.crt';

  _openssl( [ 'req', '-new', '-config', $config, '-key', $key, '-subj', '/CN='.$cn, '-out', $csr ] );
  _openssl(
    [ 'x509', '-req', '-in', $csr, '-CA', $ca->{cert}, '-CAkey', $ca->{key},
      '-set_serial', ++$serial, '-days', defined $arg{days} ? $arg{days} : 30,
      '-extfile', $config, '-extensions', $arg{san} ? 'leaf_san_ext' : 'leaf_ext',
      '-out', $cert ],
    san => $arg{san},
  );

  return {
    cert     => $cert,
    key      => $key,
    csr      => $csr,
    cert_pem => slurp($cert),
    key_pem  => slurp($key)
  };
}

# new_csr( dir => $dir, name => 'device', cn => 'device.example',
#          san => 'DNS:device.example,IP:192.0.2.1' )
# -> { csr => $path, key => $path, csr_pem => $text }
# A request the way a device makes it: its own key, and with san the names
# in the request itself.
sub new_csr {
  my ( %arg ) = @_;
  my $dir    = $arg{dir}  or croak 'new_csr needs dir';
  my $name   = $arg{name} or croak 'new_csr needs name';
  my $cn     = $arg{cn} || $name.'.example';
  my $config = _config($dir);
  my $key    = _key( $dir.'/'.$name.'.key' );
  my $csr    = $dir.'/'.$name.'.csr';

  _openssl(
    [ 'req', '-new', '-config', $config, '-key', $key, '-subj', '/CN='.$cn,
      ( $arg{san} ? ( '-reqexts', 'csr_san_ext' ) : () ), '-out', $csr ],
    san => $arg{san},
  );

  return { csr => $csr, key => $key, csr_pem => slurp($csr) };
}

1;
