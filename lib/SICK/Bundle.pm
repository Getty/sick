package SICK::Bundle;
# ABSTRACT: A certificate with its chain and key, and what openssl says about it

use strict;
use warnings;
use Carp qw( croak );
use SICK::Names;
use SICK::OpenSSL;
use SICK::Temp;
use Time::Local qw( timegm );

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Bundle;

    my $bundle = SICK::Bundle->new(
      cert  => $cert_pem,
      chain => $intermediates_pem,    # or undef
      key   => $key_pem,              # or undef
    );

    my $bundle = SICK::Bundle->from_files(
      cert => '/srv/certs/grafana/cert.pem',
      key  => '/srv/certs/grafana/key.pem',
    );

    $bundle->names;                 # [ '192.0.2.199', 'ant.example.internal' ]
    $bundle->not_after;             # 1791166501
    $bundle->fingerprint_sha256;    # '64c90e0c...' (64 hex digits)
    $bundle->is_issued_by($root_pem) or die "not ours\n";

    print {$fh} $bundle->fullchain;

=head1 DESCRIPTION

What an issuer hands out and what a target installs: one certificate, the
intermediate certificates that belong to it, and - unless the key never left
the device - the private key, all as PEM text.

Everything else is derived from the certificate by asking C<openssl> (see
L<SICK::OpenSSL>); nothing is parsed in Perl. The derived values are read on
first use and kept.

A bundle may hold a private key. It never puts key material into a message,
and nothing here writes the key anywhere.

=cut

my $CERT_BLOCK = qr/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s;
my $KEY_BLOCK  = qr/-----BEGIN (?<label>[A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \k<label>-----/s;

my %MONTH = (
  Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4,  Jun => 5,
  Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11
);

sub new {
  my ( $class, %arg ) = @_;
  my $self = bless {}, $class;

  my @certs = $self->_cert_blocks( $arg{cert} );
  croak 'cert is not a PEM certificate' unless @certs;
  my @extra = $self->_cert_blocks( $arg{chain} );
  croak 'chain is not a list of PEM certificates'
    if defined $arg{chain} && $arg{chain} =~ /\S/ && !@extra;
  my @chain = ( @certs[ 1 .. $#certs ], @extra );

  $self->{cert}  = $certs[0];
  $self->{chain} = @chain ? join( q{}, @chain ) : undef;

  if ( defined $arg{key} ) {
    croak 'key is not a PEM private key' unless $arg{key} =~ /($KEY_BLOCK)/;
    my $key = $1;
    $key =~ s/\r\n/\n/g;
    $self->{key} = $key."\n";
  }

  return $self;
}

=method new

    my $bundle = SICK::Bundle->new( cert => $pem, chain => $pem, key => $pem );

C<cert> is required, C<chain> and C<key> may be C<undef> or left out.

C<cert> may hold more than one certificate, as the certificate file of
C<step> or a C<fullchain.pem> does: the first one is the certificate, the
others go in front of C<chain>. Text around the PEM blocks is dropped.

Croaks when C<cert> contains no PEM certificate, when a given C<chain>
contains none, or when a given C<key> is no PEM private key. The key is not
checked against the certificate.

=cut

sub from_files {
  my ( $class, %arg ) = @_;
  croak 'from_files needs the path of a certificate file' unless defined $arg{cert};
  my %label = ( cert => 'certificate', chain => 'chain', key => 'key' );
  my %pem;
  for my $part ( grep { defined $arg{$_} } qw( cert chain key ) ) {
    $pem{$part} = $class->_slurp( $arg{$part}, $label{$part} );
  }
  return $class->new(%pem);
}

=method from_files

    my $bundle = SICK::Bundle->from_files( cert => $path, chain => $path, key => $path );

Reads the parts from files and builds the bundle like L</new>; C<chain> and
C<key> are optional. Croaks with
C<< cannot read certificate file '<path>': <reason> >> (C<chain file>,
C<key file>) when a given file cannot be read.

=cut

sub cert  { $_[0]->{cert} }
sub chain { $_[0]->{chain} }
sub key   { $_[0]->{key} }

=method cert

The certificate as PEM, one block with a trailing newline.

=method chain

The intermediate certificates as PEM, or C<undef> when there are none.

=method key

The private key as PEM, or C<undef> when the bundle has none.

=cut

sub fullchain {
  my ( $self ) = @_;
  return $self->cert.( defined $self->chain ? $self->chain : q{} );
}

=method fullchain

The certificate followed by its chain, the way servers want it in one file.

=cut

sub names {
  my ( $self ) = @_;
  $self->_read_names;
  return [ @{ $self->{names} } ];
}

=method names

    my $names = $bundle->names;    # [ '192.0.2.199', 'ant.example.internal' ]

The names the certificate is valid for: its DNS and IP subject alternative
names, lower case and sorted. A certificate without any of them answers with
its common name. See L<SICK::Names/normalize> for the spelling.

=cut

sub dns_names {
  my ( $self ) = @_;
  $self->_read_names;
  return [ @{ $self->{dns_names} } ];
}

sub ip_names {
  my ( $self ) = @_;
  $self->_read_names;
  return [ @{ $self->{ip_names} } ];
}

=method dns_names

The host names among L</names>: those from DNS SANs, or the common name when
the certificate has no SAN at all.

=method ip_names

The addresses among L</names>: those from IP SANs. An address in a DNS SAN
is not an IP SAN, and clients do not accept it as one; L<SICK::Decision>
compares by kind for that reason.

=cut

sub not_before         { $_[0]->_info->{not_before} }
sub not_after          { $_[0]->_info->{not_after} }
sub fingerprint_sha256 { $_[0]->_info->{fingerprint_sha256} }
sub subject_dn         { $_[0]->_info->{subject_dn} }
sub issuer_dn          { $_[0]->_info->{issuer_dn} }

sub common_name {
  my ( $self ) = @_;
  unless ( exists $self->{common_name} ) {
    my $subject = eval {
      SICK::OpenSSL::run_checked(
        [ 'x509', '-noout', '-subject', '-nameopt', 'multiline,utf8,-esc_msb' ],
        stdin => $self->cert,
      );
    };
    croak 'cannot read the certificate: '.$self->_first_line($@) unless defined $subject;
    $self->{common_name} = SICK::Names::cn_from_text($subject);
  }
  return $self->{common_name};
}

sub is_self_signed {
  my ( $self ) = @_;
  return $self->subject_dn eq $self->issuer_dn ? 1 : 0;
}

=method not_before

Start of the validity as epoch seconds.

=method not_after

End of the validity as epoch seconds.

=method fingerprint_sha256

The SHA-256 fingerprint of the certificate: 64 hex digits, lower case, no
colons.

=method subject_dn

The subject as an RFC 2253 string, for instance C<CN=ant.example.internal>.

=method issuer_dn

The issuer in the same form.

=method common_name

The common name of the subject as C<openssl> prints it (UTF-8 bytes), or
C<undef> when the subject has none.

=method is_self_signed

True when subject and issuer are the same name, as they are for a root
certificate. The signature is not checked.

=cut

sub is_issued_by {
  my ( $self, $ca_pem ) = @_;
  my @anchors = $self->_cert_blocks($ca_pem);
  croak 'is_issued_by needs the PEM certificate of a CA' unless @anchors;

  my $tmp     = SICK::Temp->dir;
  my $ca_file = $tmp->write( 'ca.pem',   join( q{}, @anchors ), 0644 );
  my $cert    = $tmp->write( 'cert.pem', $self->cert,           0644 );

  # Only the given CA may be the anchor: without these the default trust
  # store of the system takes part, and any certificate of a public CA
  # would pass.
  my @args = ( 'verify', '-no_check_time', '-CAfile', $ca_file );
  push @args, '-no-CApath'  if SICK::OpenSSL::major() >= 1;
  push @args, '-no-CAstore' if SICK::OpenSSL::major() >= 3;
  push @args, '-untrusted', $tmp->write( 'chain.pem', $self->chain, 0644 )
    if defined $self->chain;
  push @args, $cert;

  my ( $out, $err, $exit ) = SICK::OpenSSL::run(
    \@args,
    env => { SSL_CERT_DIR => $tmp->path, SSL_CERT_FILE => $ca_file },
  );
  return $exit == 0 ? 1 : 0;
}

=method is_issued_by

    my $bool = $bundle->is_issued_by($ca_pem);

True when C<openssl verify> builds a chain from the certificate to the given
CA, using the chain of the bundle for the steps in between. C<$ca_pem> is
the root certificate; it may contain further trusted certificates, for
example the intermediate of a CA whose devices do not send it along.

Only the signatures count: the validity period is not checked, so an expired
certificate of this CA is still issued by it. The trust store of the system
plays no part.

=cut

#### internals

sub _cert_blocks {
  my ( $self, $pem ) = @_;
  return unless defined $pem;
  my @blocks = $pem =~ /($CERT_BLOCK)/g;
  s/\r\n/\n/g for @blocks;
  return map { $_."\n" } @blocks;
}

sub _slurp {
  my ( $self, $path, $label ) = @_;
  open my $fh, '<', $path
    or croak 'cannot read '.$label.' file \''.$path.'\': '.$!;
  croak 'cannot read '.$label.' file \''.$path.'\': Is a directory' if -d $fh;
  local $/;
  my $content = <$fh>;
  return defined $content ? $content : q{};
}

sub _info {
  my ( $self ) = @_;
  return $self->{info} ||= do {
    my $out = eval {
      SICK::OpenSSL::run_checked(
        [ 'x509', '-noout', '-subject', '-issuer', '-startdate', '-enddate',
          '-fingerprint', '-sha256', '-nameopt', 'RFC2253' ],
        stdin => $self->cert,
      );
    };
    croak 'cannot read the certificate: '.$self->_first_line($@) unless defined $out;

    my %info;
    for my $line ( split /\r?\n/, $out ) {
      if    ( $line =~ /\Asubject=\s*(.*)\z/ )   { $info{subject_dn} = $1 }
      elsif ( $line =~ /\Aissuer=\s*(.*)\z/ )    { $info{issuer_dn}  = $1 }
      elsif ( $line =~ /\AnotBefore=(.*)\z/ )    { $info{not_before} = $self->_epoch($1) }
      elsif ( $line =~ /\AnotAfter=(.*)\z/ )     { $info{not_after}  = $self->_epoch($1) }
      elsif ( $line =~ /\Asha256 Fingerprint=([0-9A-Fa-f:]+)\z/i ) {
        ( $info{fingerprint_sha256} = lc $1 ) =~ tr/://d;
      }
    }
    for my $field (qw( subject_dn issuer_dn not_before not_after fingerprint_sha256 )) {
      croak 'cannot read the certificate: openssl did not report its '.$field
        unless defined $info{$field};
    }
    \%info;
  };
}

sub _epoch {
  my ( $self, $text ) = @_;
  # "Oct  5 02:35:01 2026 GMT"
  return unless $text =~ /\A([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}):([0-9]{2}):([0-9]{2})\s+([0-9]{4})\s+GMT\z/;
  return unless exists $MONTH{$1};
  return timegm( $5, $4, $3, $2, $MONTH{$1}, $6 );
}

sub _read_names {
  my ( $self ) = @_;
  return if $self->{names};

  my $text = eval {
    SICK::OpenSSL::run_checked(
      [ 'x509', '-noout', '-text', '-certopt',
        'no_header,no_version,no_serial,no_signame,no_validity,no_subject,no_issuer,no_pubkey,no_sigdump,no_aux' ],
      stdin => $self->cert,
    );
  };
  croak 'cannot read the certificate: '.$self->_first_line($@) unless defined $text;
  my ( $dns, $ip ) = SICK::Names::san_from_text($text);

  unless ( @$dns || @$ip ) {
    my $subject = eval {
      SICK::OpenSSL::run_checked(
        [ 'x509', '-noout', '-subject', '-nameopt', 'multiline,utf8,-esc_msb' ],
        stdin => $self->cert,
      );
    };
    croak 'cannot read the certificate: '.$self->_first_line($@) unless defined $subject;
    my $cn = SICK::Names::cn_from_text($subject);
    $dns = SICK::Names::canonical( [$cn] ) if defined $cn;
  }

  $self->{dns_names} = $dns;
  $self->{ip_names}  = $ip;
  $self->{names}     = [ sort @$dns, @$ip ];
  return;
}

sub _first_line {
  my ( $self, $error ) = @_;
  $error = q{} unless defined $error;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  my ($line) = grep { /\S/ } split /\r?\n/, $error;
  return defined $line ? $line : 'unknown error';
}

1;
