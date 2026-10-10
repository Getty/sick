package SICK::Device;
# ABSTRACT: One entry of the SICK device list

use Moo;
use Carp qw( croak );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    my $device = $config->device('switch');

    $device->name;            # 'switch'
    $device->type;            # 'cisco-sb'
    $device->host;            # '192.0.2.199', or undef
    $device->port;            # 443
    $device->names;           # [ 'switch.example.internal', '192.0.2.199' ]
    $device->lifetime;        # 34300800 (seconds)
    $device->renew_before;    # 2592000 (seconds)
    $device->key;             # 'rsa2048'
    $device->options;         # { credentials => '/etc/sick/switch.cred' }

    my $bundle = $issuer->issue( $device->spec );

=head1 DESCRIPTION

A device as L<SICK::Config> read it: the settings every device has, with the
C<defaults> of the list already applied, and the remaining keys of its entry
as L</options> for the target of its type. Objects are made by
L<SICK::Config>, which is also where the values are checked; they are not
changed afterwards.

=cut

around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  for my $required (qw( name type names lifetime renew_before key )) {
    croak 'SICK::Device->new needs '.$required unless defined $arg{$required};
  }
  croak 'SICK::Device->new needs names as a non-empty array reference'
    unless ref $arg{names} eq 'ARRAY' && @{ $arg{names} };
  $arg{names} = [ @{ $arg{names} } ];
  delete $arg{port}    unless defined $arg{port};
  delete $arg{options} unless $arg{options};
  return \%arg;
};

=method new

    my $device = SICK::Device->new(
      name         => 'grafana',
      type         => 'files',
      names        => ['grafana.example.internal'],
      lifetime     => 34300800,
      renew_before => 2592000,
      key          => 'rsa2048',
      options      => { dir => '/srv/certs/grafana' },
    );

Takes the values exactly as the accessors return them; C<host>, C<port> and
C<options> are optional. Nothing is parsed or normalized here - that is the
work of L<SICK::Config/load>.

=cut

has name         => ( is => 'ro', required => 1 );
has type         => ( is => 'ro', required => 1 );
has host         => ( is => 'ro' );
has port         => ( is => 'ro', default => 443 );
has _names       => ( is => 'ro', required => 1, init_arg => 'names' );
has lifetime     => ( is => 'ro', required => 1 );
has renew_before => ( is => 'ro', required => 1 );
has key          => ( is => 'ro', required => 1 );
has options      => ( is => 'ro', default => sub { {} } );

sub names { [ @{ shift->_names } ] }

=attr name

The key of the entry in the device list.

=attr type

The device type as written in the list, for instance C<cisco-sb>. See
L<SICK::Target/class_for>.

=attr host

Where the device is reached, or C<undef> when the entry has no C<host>.

=attr port

The TLS port of the device. Defaults to C<443>.

=method names

The names the certificate has to carry, in the order of the list, lower
case. The first one becomes the subject. Every call returns a new array
reference: changing it changes nothing in the device.

=attr lifetime

How long a new certificate is valid, in seconds.

=attr renew_before

How long before its end a certificate is renewed, in seconds.

=attr key

The key type of a new certificate: C<rsa2048>, C<rsa3072>, C<rsa4096> or
C<ec256>.

=attr options

Hash reference of the keys of the entry that belong to the device type, such
as C<dir> and C<reload> of a C<files> device.

=cut

sub path { 'devices.'.$_[0]->name }

=method path

    croak $device->path.': missing \'dir\'';    # devices.grafana: missing 'dir'

Where the entry sits in the device list, for error messages.

=cut

sub spec {
  my ( $self ) = @_;
  return {
    names    => $self->names,
    lifetime => $self->lifetime,
    key      => $self->key
  };
}

=method spec

    my $bundle = $issuer->issue( $device->spec );

What an issuer needs to know: C<< { names => [...], lifetime => $seconds,
key => $type } >>. See L<SICK::Issuer>.

=cut

1;
