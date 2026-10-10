package SICK::Issuer;
# ABSTRACT: Base class for whatever issues the certificates

use Moo;
use Carp qw( croak );
use SICK::Names;
use SICK::OpenSSL;
use namespace::autoclean;

# The two issuers of from_ca. Each extends this class, which is a Moo class
# from the line above on, while the rest of this file is not compiled yet.
# So: no has here, and no method modifier in a subclass that would wrap a
# method of this class - either would be lost when this file loads first.
use SICK::Issuer::SelfSigned;
use SICK::Issuer::StepCA;

our $VERSION = '0.001';

=head1 SYNOPSIS

    package My::Issuer;
    use Moo;
    extends 'SICK::Issuer';
    use Types::Standard qw( Str );
    use namespace::autoclean;

    has url        => ( is => 'ro', isa => Str, required => 1 );
    has token_file => ( is => 'ro', isa => Str );

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

    sub intermediates_pem { ... }    # optional

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

The constructor arguments a subclass knows, the names of its C<has>
declarations for the C<ca> section. The base class has none. Any other key
is an error (see L</new>).

=method required_attributes

Those of them it cannot do without. Their C<has> says C<< required => 1 >>
as well, but the check here comes first and speaks the words of the device
list.

=cut

my %TYPE = (
  stepca     => 'SICK::Issuer::StepCA',
  selfsigned => 'SICK::Issuer::SelfSigned'
);

sub from_ca {
  my ( $class, %ca ) = @_;
  my $type = defined $ca{type} && !ref $ca{type} && length $ca{type} ? $ca{type} : 'step-ca';
  ( my $normal = lc $type ) =~ s/[^a-z0-9]//g;
  my $issuer = $TYPE{$normal}
    or croak 'ca.type: unknown type \''.$type.'\' (step-ca or selfsigned)';
  return $issuer->new(%ca);
}

=method from_ca

    my $issuer = SICK::Issuer->from_ca( %{ $config->ca } );

The issuer the C<ca> section of the device list asks for: C<type: step-ca>
(the default when there is no C<type>) is a L<SICK::Issuer::StepCA>,
C<type: selfsigned> a L<SICK::Issuer::SelfSigned>. The type is compared
like a device type, without case and punctuation. Croaks with
C<< ca.type: unknown type '<type>' (step-ca or selfsigned) >> for anything
else, and like L</new> when the section does not fit the issuer.

=cut

# The checks of the ca section come before Moo's own: unknown keys are an
# error, and a required key that is empty counts as missing.
around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  delete @arg{qw( type name )};
  my %known = map { $_ => 1 } $class->attributes;
  my @unknown = sort grep { !$known{$_} } keys %arg;
  croak 'ca: unknown key \''.$unknown[0].'\' for '.$class if @unknown;
  for my $required ( $class->required_attributes ) {
    croak 'ca: missing \''.$required.'\''
      unless defined $arg{$required} && length $arg{$required};
  }
  delete @arg{ grep { !defined $arg{$_} || !length $arg{$_} } keys %arg };
  return \%arg;
};

=method new

    my $issuer = SICK::Issuer::StepCA->new( %{ $config->ca } );

Takes the C<ca> section of the device list. C<type> is what selected the
class and C<name> is for humans (L<SICK::Config/ca_name>); both are ignored
here. Croaks with C<< ca: missing '<key>' >> when a
required attribute is not given and with C<< ca: unknown key '<key>' ... >>
for one the class does not know. An optional key that is empty or C<undef>
counts as not given, so its default applies.

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

sub intermediates_pem { return undef }

=method intermediates_pem

    my $pem = $issuer->intermediates_pem;    # or undef

The intermediate certificates of the CA as PEM, or C<undef> when the issuer
knows of none - which is what the base class answers. They are no trust
anchors. L<SICK::Decision> uses them to build the chain from a certificate
to L</root_pem> when a device presents its certificate without them, and
L<SICK::Trust> publishes them next to the root, because the clients of such
a device are in the same position.

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
