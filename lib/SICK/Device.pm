package SICK::Device;
# ABSTRACT: One entry of the SICK device list

use Moo;
use Carp qw( croak );
use Types::Standard qw( ArrayRef HashRef Int Maybe Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    my $device = $config->device('switch');

    $device->name;            # 'switch'
    $device->type;            # 'cisco-sb'
    $device->host;            # '192.0.2.199', or undef
    $device->port;            # 443, or the default port of the type
    $device->has_port;        # true only when the entry sets port
    $device->names;           # [ 'switch.example.internal', '192.0.2.199' ]
    $device->lifetime;        # 34300800 (seconds)
    $device->renew_before;    # 2592000 (seconds)
    $device->key;             # 'rsa2048'
    $device->owner;           # 'Netzwerk-Team', or undef
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
  delete $arg{port}         unless defined $arg{port};
  delete $arg{default_port} unless defined $arg{default_port};
  delete $arg{owner}   unless defined $arg{owner};
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
      owner        => 'Monitoring',
      options      => { dir => '/srv/certs/grafana' },
      default_port => 443,
    );

Takes the values exactly as the accessors return them; C<host>, C<port>,
C<owner>, C<options> and C<default_port> are optional. C<port> is the port
the entry sets, C<default_port> the one of the device type
(L<SICK::Target/default_port>), C<443> when not given. Nothing is parsed or normalized here - that is the
work of L<SICK::Config/load>.

=cut

has name         => ( is => 'ro', isa => Str,           required => 1 );
has type         => ( is => 'ro', isa => Str,           required => 1 );
has host         => ( is => 'ro', isa => Maybe[Str] );
# Private: port is the method below, the one of the entry or the default
# of the type; has_port tells the two apart.
has _port        => ( is => 'ro', isa => Int,           init_arg => 'port', predicate => 'has_port' );
has default_port => ( is => 'ro', isa => Int,           default  => 443 );
has _names       => ( is => 'ro', isa => ArrayRef[Str], required => 1, init_arg => 'names' );
has lifetime     => ( is => 'ro', isa => Int,           required => 1 );
has renew_before => ( is => 'ro', isa => Int,           required => 1 );
has key          => ( is => 'ro', isa => Str,           required => 1 );
has owner        => ( is => 'ro', isa => Maybe[Str] );
has options      => ( is => 'ro', isa => HashRef,       default  => sub { {} } );

sub names { [ @{ shift->_names } ] }

sub port { $_[0]->has_port ? $_[0]->_port : $_[0]->default_port }

=attr name

The key of the entry in the device list.

=attr type

The device type as written in the list, for instance C<cisco-sb>. See
L<SICK::Target/class_for>.

=attr host

Where the device is reached, or C<undef> when the entry has no C<host>.

=method port

The TLS port of the device: the C<port> of the entry, or L</default_port>
when it has none.

=method has_port

True when the entry sets C<port>, also C<port: 443>; false when L</port> is
the default. For a target that has to tell a port somebody chose from one
nobody chose.

=attr default_port

The port of a device of this type without C<port>: what
L<SICK::Target/default_port> of its class answers, as L<SICK::Config> found
it. C<443> when not given.

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

=attr owner

Who to ask about the device, free text from the list, or C<undef> when the
entry has no C<owner>.

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
