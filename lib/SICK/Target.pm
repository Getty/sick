package SICK::Target;
# ABSTRACT: Base class and plugin loader for the device types SICK can deploy to

use strict;
use warnings;
use Carp qw( croak );
use SICK::Bundle;
use SICK::Names;
use SICK::OpenSSL;

our $VERSION = '0.001';

=head1 SYNOPSIS

Using a target:

    my $class  = SICK::Target->class_for( $device->type );    # 'cisco-sb' -> SICK::Target::CiscoSB
    my $target = $class->new( device => $device, log => sub { print "$_[0]\n" } );
    $target->validate;

    my $presented = $target->presented_cert;    # SICK::Bundle, undef, or dies "unreachable: ..."
    my $csr       = $target->csr($spec);        # PEM, or undef
    $target->deploy($bundle);

Writing one:

    package SICK::Target::MyBox;
    use parent 'SICK::Target';

    sub required_options { qw( credentials ) }
    sub optional_options { qw( slot ) }

    sub deploy {
      my ( $self, $bundle ) = @_;
      my $credentials = $self->option('credentials');
      $self->log('installing the certificate');
      ...
    }

    1;

=head1 DESCRIPTION

A target knows one kind of device: how to put a certificate on it and, where
the device does not simply serve it over TLS, how to find out which one is
there now. The core ships L<SICK::Target::Files>; everything that needs more
than core Perl lives in a distribution of its own, C<SICK-Target-*>.

The C<type> of a device in the device list selects the class, see
L</class_for>. A target class is a subclass of this one and implements
L</deploy>.

=cut

sub class_for {
  my ( $self, $type ) = @_;
  croak 'class_for needs a device type' unless defined $type && length $type;
  my $wanted = $self->_normalize_type($type);

  my %candidate;
  for my $dir ( grep { defined && !ref } @INC ) {
    opendir my $dh, $dir.'/SICK/Target' or next;
    for my $file ( readdir $dh ) {
      next unless $file =~ /\A([A-Za-z_][A-Za-z0-9_]*)\.pm\z/;
      $candidate{$1} ||= 1;
    }
    closedir $dh;
  }
  for my $loaded ( keys %INC ) {
    $candidate{$1} ||= 1 if $loaded =~ m{\ASICK/Target/([A-Za-z_][A-Za-z0-9_]*)\.pm\z};
  }

  my ($name) = grep { length $wanted && $self->_normalize_type($_) eq $wanted } sort keys %candidate;
  croak 'no target for type \''.$type.'\'; install a SICK-Target-* distribution that provides it'
    unless defined $name;

  my $class = 'SICK::Target::'.$name;
  my $file  = 'SICK/Target/'.$name.'.pm';
  unless ( $INC{$file} ) {
    # the one place a module is loaded at run time: its name comes from the
    # device list
    my $loaded = eval { require $file; 1 };
    unless ($loaded) {
      my $error = $@;
      $error =~ s/\s+\z//;
      croak 'cannot load '.$class.' for type \''.$type.'\': '.$error;
    }
  }

  croak $class.' (type \''.$type.'\') is not a SICK::Target' unless $class->isa('SICK::Target');
  croak $class.' (type \''.$type.'\') does not implement deploy'
    unless $class->can('deploy') && $class->can('deploy') != SICK::Target->can('deploy');
  return $class;
}

=method class_for

    my $class = SICK::Target->class_for('cisco-sb');    # 'SICK::Target::CiscoSB'

Finds and loads the class for a device type. Type and module name are
compared without case and without anything that is not a letter or a digit:
C<cisco-sb>, C<cisco_sb> and C<CiscoSB> all mean C<SICK::Target::CiscoSB>.
The modules directly below C<SICK/Target/> in C<@INC> are the candidates,
together with those already loaded.

Croaks with

    no target for type 'cisco-sb'; install a SICK-Target-* distribution that provides it

when there is no such module, with C<< cannot load <class> ... >> when it
does not compile, and when the class is not a C<SICK::Target> or does not
implement L</deploy>.

=cut

sub new {
  my ( $class, %arg ) = @_;
  my $device = $arg{device};
  croak $class.'->new needs a device'
    unless ref $device && eval { $device->can('names') && $device->can('options') };
  croak $class.'->new: log must be a code reference'
    if defined $arg{log} && ref $arg{log} ne 'CODE';
  return bless { device => $device, log => $arg{log} }, $class;
}

=method new

    my $target = $class->new( device => $device, log => sub { my ($message) = @_; ... } );

C<device> is the L<SICK::Device> the target works on. C<log> is optional: a
code reference that is called with one line of text whenever the target has
something to say. Nothing is checked yet, see L</validate>.

=cut

sub device { $_[0]->{device} }

=method device

The L<SICK::Device>.

=cut

sub log {
  my ( $self, $message ) = @_;
  $self->{log}->($message) if $self->{log};
  return;
}

=method log

    $self->log('importing the certificate');

Hands a message to the C<log> callback, if there is one. Never log secrets.

=cut

sub option {
  my ( $self, $name ) = @_;
  return $self->device->options->{$name};
}

=method option

    my $dir = $self->option('dir');

One of the type-specific settings of the device, C<undef> when not set.

=cut

sub required_options { () }
sub optional_options { () }

=method required_options

The option names a target type cannot do without. A subclass overrides this;
L</validate> checks the device against it.

=method optional_options

The option names it accepts on top.

=cut

sub validate {
  my ( $self ) = @_;
  my $device  = $self->device;
  my $options = $device->options;
  my @required = $self->required_options;
  my %known    = map { $_ => 1 } @required, $self->optional_options;

  my @unknown = sort grep { !$known{$_} } keys %$options;
  croak $device->path.': '.( @unknown == 1 ? 'unknown key ' : 'unknown keys ' )
    .join( ', ', map { '\''.$_.'\'' } @unknown ).' for type \''.$device->type.'\''
    if @unknown;

  for my $name (@required) {
    croak $device->path.': missing \''.$name.'\''
      unless defined $options->{$name} && ( ref $options->{$name} || length $options->{$name} );
  }
  return $self;
}

=method validate

    $target->validate;

Checks the type-specific settings of the device: every required option is
there and none is unknown. Croaks with the place in the device list,
C<< devices.grafana: missing 'dir' >> or
C<< devices.grafana: unknown key 'colour' for type 'files' >>. Returns the
target.

A subclass with more to check calls C<< $self->SUPER::validate >> first.

=cut

sub deploy { croak( ( ref( $_[0] ) || $_[0] ).' does not implement deploy' ) }

=method deploy

    $target->deploy($bundle);

Installs the certificate, the chain and - when the L<SICK::Bundle> has one -
the key on the device. Has to be implemented by every target. Dies when the
device does not end up serving the certificate.

=cut

# An explicit undef, also in list context: the result is used as one value,
# for instance as a hash value in an argument list.
sub csr { return undef }

=method csr

    my $csr_pem = $target->csr($spec);

A target whose device can make its own key returns a certificate request for
the spec (see L<SICK::Issuer>) here; the certificate is then signed for that
request and the bundle handed to L</deploy> has no key. The default returns
C<undef>: SICK generates the key.

=cut

sub connect_timeout { 10 }

sub endpoint {
  my ( $self ) = @_;
  my $device = $self->device;
  my $host = defined $device->host ? $device->host : $device->names->[0];
  return ( $host, $device->port );
}

sub verify_timeout { 30 }

=method verify_timeout

Seconds a device may take after L</deploy> until it presents the new
certificate - the time its web server needs to restart, for instance.
L<SICK::Runner> asks L</presented_cert> again and again for that long before
it calls the deployment failed. C<30>; a target overrides it for a device
that is slower, or with C<0> where the answer cannot change by waiting.

=method endpoint

    my ( $host, $port ) = $target->endpoint;

Where L</presented_cert> connects to: C<host> and C<port> of the device. A
device without C<host> is reached under its first name.

=method connect_timeout

Seconds L</presented_cert> waits for the device. C<10>.

=cut

sub presented_cert {
  my ( $self ) = @_;
  my ( $host, $port ) = $self->endpoint;
  my $timeout = $self->connect_timeout;

  my @args = ( 's_client', '-connect', ( SICK::Names::is_ip($host) == 6 ? '['.$host.']' : $host ).':'.$port, '-showcerts' );
  my ($sni) = grep { !SICK::Names::is_ip($_) && !/\*/ } $host, @{ $self->device->names };
  push @args, '-servername', $sni if defined $sni;

  my ( $out, $err, $exit ) = eval { SICK::OpenSSL::run( \@args, stdin => q{}, timeout => $timeout ) };
  unless ( defined $exit ) {
    my $error = $@;
    croak 'unreachable: '.$host.':'.$port.' did not answer within '.$timeout.'s'
      if $error =~ /timed out after/;
    $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
    croak $error;
  }

  croak 'unreachable: '.$host.':'.$port.': '.$self->_connect_error($err)
    unless $out =~ /^CONNECTED\(/m;

  my @certs = $out =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg;
  return undef unless @certs;
  return SICK::Bundle->new( cert => join( "\n", @certs )."\n" );
}

=method presented_cert

    my $bundle = $target->presented_cert;

The certificate the device serves right now, as a L<SICK::Bundle> without a
key; the certificates the device sends along are its chain. The default
connects to L</endpoint> with C<openssl s_client>; a target overrides it
when the device has to be asked differently.

There are three outcomes, and they are not the same thing:

=over 4

=item *

a bundle - the device answered with a certificate;

=item *

C<undef> - the device was reached, but does not speak TLS there or sent no
certificate (an explicit C<undef>, in list context too);

=item *

an exception C<< unreachable: <host>:<port>: <reason> >> - no connection:
refused, timed out, name not resolved. Nothing is known about the
certificate then, and nothing should be done to the device.

=back

=cut

#### internals

sub _normalize_type {
  my ( $self, $type ) = @_;
  $type = lc $type;
  $type =~ s/[^a-z0-9]//g;
  return $type;
}

# The reason out of what s_client printed, without the noise around it.
sub _connect_error {
  my ( $self, $stderr ) = @_;
  my @lines = grep { /\S/ } split /\r?\n/, defined $stderr ? $stderr : q{};
  for my $line (@lines) {
    # <thread>:error:<code>:<library>:<function>:<reason>:<file>:<line>:<data>
    next unless $line =~ /:error:[0-9A-Fa-f]+:[^:]*:[^:]*:([^:]+):[^:]*:[0-9]+:(.*)\z/;
    my ( $reason, $data ) = ( $1, $2 );
    return $data if $reason =~ /\Asystem lib/i && $data =~ /\S/ && $data !~ /\Acalling /;
    return $reason;
  }
  return @lines ? $lines[0] : 'no connection';
}

1;
