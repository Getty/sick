package SICK::Issuer;
# ABSTRACT: Base class for whatever issues the certificates

use strict;
use warnings;
use Carp qw( croak );
use SICK::Names;
use SICK::OpenSSL;

our $VERSION = '0.001';

=head1 SYNOPSIS

    package My::Issuer;
    use parent 'SICK::Issuer';

    sub attributes          { qw( url token_file ) }
    sub required_attributes { qw( url ) }

    sub issue {
      my ( $self, $spec ) = @_;
      $spec = $self->check_spec($spec);
      ...
      return SICK::Bundle->new( cert => $cert_pem, chain => $chain_pem, key => $key_pem );
    }

    sub sign {
      my ( $self, $csr_pem, $spec ) = @_;
      $spec = $self->check_spec($spec);
      ...
      return SICK::Bundle->new( cert => $cert_pem, chain => $chain_pem );
    }

    sub root_pem { ... }

=head1 DESCRIPTION

An issuer turns a request into a L<SICK::Bundle>. SICK is not a CA and does
not want to be one: an issuer asks one. L<SICK::Issuer::StepCA> is the one
for real use, L<SICK::Issuer::SelfSigned> the one for tests.

What is to be issued is described by a I<spec>, a plain hash reference:

    {
      names    => [ 'switch.example.internal', '192.0.2.199' ],
      lifetime => 34300800,     # seconds
      key      => 'rsa2048',    # rsa2048, rsa3072, rsa4096 or ec256
    }

L<SICK::Device/spec> returns one. Host names become DNS SANs, IP addresses
IP SANs, and the first name is the subject.

=cut

my %KEY = (
  rsa2048 => { type => 'rsa', bits  => 2048 },
  rsa3072 => { type => 'rsa', bits  => 3072 },
  rsa4096 => { type => 'rsa', bits  => 4096 },
  ec256   => { type => 'ec',  curve => 'P-256' }
);

sub attributes          { () }
sub required_attributes { () }

=method attributes

The constructor arguments a subclass knows. The base class has none.

=method required_attributes

Those of them it cannot do without.

=cut

sub new {
  my ( $class, %arg ) = @_;
  delete $arg{type};
  my %known = map { $_ => 1 } $class->attributes;
  my @unknown = sort grep { !$known{$_} } keys %arg;
  croak 'ca: unknown key \''.$unknown[0].'\' for '.$class if @unknown;
  for my $required ( $class->required_attributes ) {
    croak 'ca: missing \''.$required.'\''
      unless defined $arg{$required} && length $arg{$required};
  }
  return bless { %arg }, $class;
}

=method new

    my $issuer = SICK::Issuer::StepCA->new( %{ $config->ca } );

Takes the C<ca> section of the device list. C<type> is what selected the
class and is ignored here. Croaks with C<< ca: missing '<key>' >> when a
required attribute is not given and with C<< ca: unknown key '<key>' ... >>
for one the class does not know.

=cut

sub issue    { croak( ( ref( $_[0] ) || $_[0] ).' does not implement issue' ) }
sub sign     { croak( ( ref( $_[0] ) || $_[0] ).' does not implement sign' ) }
sub root_pem { croak( ( ref( $_[0] ) || $_[0] ).' does not implement root_pem' ) }

=method issue

    my $bundle = $issuer->issue($spec);

Makes a new key and has a certificate issued for it. Returns a
L<SICK::Bundle> with the key.

=method sign

    my $bundle = $issuer->sign( $csr_pem, $spec );

Has a certificate issued for a request whose key lives somewhere else, on
the device for instance. Returns a L<SICK::Bundle> without a key.

=method root_pem

    my $pem = $issuer->root_pem;

The root certificate of the CA as PEM: what L<SICK::Decision> checks
presented certificates against and what clients have to trust.

All three have to be implemented by a subclass.

=cut

sub check_spec {
  my ( $self, $spec ) = @_;
  croak 'spec must be a hash reference' unless ref $spec eq 'HASH';

  my $names = $spec->{names};
  croak 'spec needs a non-empty list of names' unless ref $names eq 'ARRAY' && @$names;
  my ( @names, %seen );
  for my $name (@$names) {
    croak 'spec: invalid name \''.( defined $name && !ref $name ? $name : q{} ).'\''
      unless SICK::Names::is_valid($name);
    my $normal = SICK::Names::normalize($name);
    push @names, $normal unless $seen{$normal}++;
  }

  my $lifetime = $spec->{lifetime};
  croak 'spec needs a lifetime in whole seconds, greater than zero'
    unless defined $lifetime && !ref $lifetime && $lifetime =~ /\A[0-9]+\z/ && $lifetime > 0;

  my $key = defined $spec->{key} ? $spec->{key} : 'rsa2048';
  croak 'spec: invalid key type \''.( ref $key ? q{} : $key ).'\'' unless !ref $key && $KEY{$key};

  return { names => \@names, lifetime => $lifetime + 0, key => $key };
}

=method check_spec

    $spec = $self->check_spec($spec);

Returns a checked copy of a spec: names valid (L<SICK::Names/is_valid>),
normalized and without duplicates, lifetime a positive number of seconds,
key type known (C<rsa2048> when left out). Croaks otherwise. Subclasses call
it first thing in L</issue> and L</sign>.

=cut

sub key_params {
  my ( $self, $key ) = @_;
  croak 'invalid key type \''.( defined $key ? $key : q{} ).'\'' unless defined $key && $KEY{$key};
  return { %{ $KEY{$key} } };
}

=method key_params

    my $params = $self->key_params('rsa2048');    # { type => 'rsa', bits => 2048 }
    my $params = $self->key_params('ec256');      # { type => 'ec', curve => 'P-256' }

What a key type means.

=cut

sub csr_names {
  my ( $self, $csr_pem ) = @_;
  croak 'not a PEM certificate request'
    unless defined $csr_pem && $csr_pem =~ /-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----/;

  my $text = SICK::OpenSSL::run_checked(
    [ 'req', '-noout', '-text', '-reqopt', 'no_header,no_version,no_pubkey,no_sigdump,no_signame,no_subject' ],
    stdin => $csr_pem,
  );
  my ( $dns, $ip ) = SICK::Names::san_from_text($text);
  return [ sort @$dns, @$ip ] if @$dns || @$ip;

  my $subject = SICK::OpenSSL::run_checked(
    [ 'req', '-noout', '-subject', '-nameopt', 'multiline,utf8,-esc_msb' ],
    stdin => $csr_pem,
  );
  my $cn = SICK::Names::cn_from_text($subject);
  return defined $cn ? SICK::Names::canonical( [$cn] ) : [];
}

=method csr_names

    my $names = $self->csr_names($csr_pem);

The names a certificate request asks for, sorted: its DNS and IP SANs, or
its common name when it has none. For issuers whose CA takes the names from
the request and not from the spec.

=cut

1;
