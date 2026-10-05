package SICK::Config;
# ABSTRACT: The SICK device list

use strict;
use warnings;
use Carp qw( croak );
use SICK::Device;
use SICK::Duration;
use SICK::Names;
use YAML::PP;
use YAML::PP::Common qw( PRESERVE_ORDER );

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Config;

    my $config = SICK::Config->load('/etc/sick/sick.yml');

    $config->ca;                 # { url => ..., root => ..., provisioner => ..., password_file => ... }
    $config->defaults;           # { lifetime => 34300800, renew_before => 2592000, key => 'rsa2048' }

    for my $device ( $config->devices ) {
      print $device->name, ': ', join( ', ', @{ $device->names } ), "\n";
    }

    my $switch = $config->device('switch') or die "no such device\n";

    my $password = SICK::Config->read_secret('/etc/sick/router.pw');

=head1 DESCRIPTION

The device list is the only configuration SICK has:

    ca:
      url: https://ca.example.internal:9000
      root: /etc/sick/root_ca.crt
      provisioner: sick
      password_file: /etc/sick/provisioner.pw
    defaults:
      lifetime: 397d
      renew_before: 30d
      key: rsa2048
    devices:
      switch:
        type: cisco-sb
        host: 192.0.2.199
        names: [switch.example.internal, 192.0.2.199]
        credentials: /etc/sick/switch.cred
      grafana:
        type: files
        names: [grafana.example.internal]
        dir: /srv/certs/grafana
        reload: "docker restart grafana"

=over 4

=item C<ca>

Where certificates come from. C<type> is C<step-ca> (the default) or
C<selfsigned>; the other keys are C<url>, C<root>, C<provisioner>,
C<password_file>, C<step> and C<dir>. Which of them are needed is decided by
the issuer, see L<SICK::Issuer::StepCA> and L<SICK::Issuer::SelfSigned>.

=item C<defaults>

C<lifetime> (C<397d>), C<renew_before> (C<30d>) and C<key> (C<rsa2048>) for
every device that does not set its own. Durations are written as in
L<SICK::Duration>; key types are C<rsa2048>, C<rsa3072>, C<rsa4096> and
C<ec256>.

=item C<devices>

One entry per device, by name. Every entry needs a C<type> and a non-empty
list of C<names>; C<host>, C<port>, C<lifetime>, C<renew_before> and C<key>
are optional. All other keys belong to the device type and end up in
L<SICK::Device/options>; the target of that type checks them
(L<SICK::Target/validate>).

=back

Secrets are never part of the list, only the paths of the files that hold
them. A key that is not known is an error, not something to skip silently:
at the top level, in C<ca> and in C<defaults>. Every error names the file
and the place in it, for example
C<< /etc/sick/sick.yml: devices.switch: missing 'type' >>.

All scalars are read as plain text, so C<mode_key: 0600> stays C<0600>.

=cut

my @TOP_KEYS     = qw( ca defaults devices );
my @CA_KEYS      = qw( type url root provisioner password_file step dir );
my @DEFAULT_KEYS = qw( lifetime renew_before key );
my @DEVICE_KEYS  = qw( type host port names lifetime renew_before key );
my @KEY_TYPES    = qw( rsa2048 rsa3072 rsa4096 ec256 );
my %BUILTIN      = ( lifetime => '397d', renew_before => '30d', key => 'rsa2048' );

sub load {
  my ( $class, $path ) = @_;
  croak 'SICK::Config->load needs the path of a device list' unless defined $path && length $path;
  open my $fh, '<', $path
    or croak 'cannot read config file \''.$path.'\': '.$!;
  croak 'cannot read config file \''.$path.'\': Is a directory' if -d $fh;
  my $yaml = do { local $/; <$fh> };
  close $fh;
  return $class->load_string( defined $yaml ? $yaml : q{}, $path );
}

=method load

    my $config = SICK::Config->load($path);

Reads and checks a device list. Croaks with
C<< cannot read config file '<path>': <reason> >> when the file cannot be
read, with C<< <path>: invalid YAML: <reason> >> when it is not YAML, and
with C<< <path>: <place>: <problem> >> for everything that is wrong in it.

=cut

sub load_string {
  my ( $class, $yaml, $label ) = @_;
  my $self = bless { path => defined $label ? $label : 'device list' }, $class;

  my @documents = eval {
    YAML::PP->new(
      schema         => ['Failsafe'],
      preserve       => PRESERVE_ORDER,
      cyclic_refs    => 'fatal',
      duplicate_keys => 0,
    )->load_string($yaml);
  };
  if ( my $error = $@ ) {
    $error =~ s/ at \S+ line [0-9]+\.?\s.*\z//s;
    $error =~ s/\s+/ /g;
    $error =~ s/ \z//;
    croak $self->path.': invalid YAML: '.$error;
  }
  croak $self->path.': must contain exactly one YAML document' unless @documents == 1;

  $self->_build( $documents[0] );
  return $self;
}

=method load_string

    my $config = SICK::Config->load_string( $yaml, $label );

The same for YAML text that is already in memory. C<$label> stands in for
the file name in error messages and in L</path>.

=cut

sub path     { $_[0]->{path} }
sub ca       { $_[0]->{ca} }
sub defaults { $_[0]->{defaults} }
sub devices  { @{ $_[0]->{devices} } }

sub device {
  my ( $self, $name ) = @_;
  return defined $name ? $self->{by_name}{$name} : undef;
}

=method path

The file the list was loaded from.

=method ca

Hash reference with the C<ca> section as written: plain strings.

=method defaults

Hash reference with C<lifetime> and C<renew_before> in seconds and C<key>:
the C<defaults> section on top of the built-in defaults.

=method devices

    my @devices = $config->devices;

The devices as L<SICK::Device> objects, in the order of the file.

=method device

    my $device = $config->device($name);

The device of that name, or C<undef>.

=cut

sub read_secret {
  my ( $self, $path ) = @_;
  croak 'read_secret needs the path of a secret file' unless defined $path && length $path;
  open my $fh, '<', $path
    or croak 'cannot read secret file \''.$path.'\': '.$!;
  croak 'cannot read secret file \''.$path.'\': Is a directory' if -d $fh;
  my $line = <$fh>;
  close $fh;
  $line = q{} unless defined $line;
  $line =~ s/\r?\n\z//;
  return $line;
}

=method read_secret

    my $secret = SICK::Config->read_secret($path);

The first line of the file without its line end. Works on the class and on
an object.

Croaks with C<< cannot read secret file '<path>': <reason> >> when the file
is missing or unreadable. The message carries the path and the reason of the
system, never anything from the file.

=cut

#### checks

sub _fail {
  my ( $self, $where, $problem ) = @_;
  croak join ': ', $self->path, ( defined $where ? $where : () ), $problem;
}

sub _section {
  my ( $self, $where, $value ) = @_;
  return {} if !defined $value || ( !ref $value && $value eq q{} );
  $self->_fail( $where, 'must be a mapping' ) unless ref $value eq 'HASH';
  return $value;
}

sub _unknown {
  my ( $self, $where, $hash, @known ) = @_;
  my %known = map { $_ => 1 } @known;
  my @unknown = sort grep { !$known{$_} } keys %$hash;
  return unless @unknown;
  $self->_fail( $where,
    ( @unknown == 1 ? 'unknown key ' : 'unknown keys ' ).join( ', ', map { '\''.$_.'\'' } @unknown ) );
}

sub _duration {
  my ( $self, $where, $text ) = @_;
  $self->_fail( $where, 'invalid duration' ) if ref $text;
  my $seconds = eval { SICK::Duration::parse($text) };
  $self->_fail( $where, 'invalid duration \''.( defined $text ? $text : q{} ).'\'' )
    unless defined $seconds;
  return $seconds;
}

sub _key_type {
  my ( $self, $where, $key ) = @_;
  $self->_fail( $where,
    'invalid key type \''.( defined $key && !ref $key ? $key : q{} ).'\' (one of '.join( ', ', @KEY_TYPES ).')' )
    unless defined $key && !ref $key && grep { $_ eq $key } @KEY_TYPES;
  return $key;
}

sub _plain {
  my ( $self, $value ) = @_;
  return { map { $_ => $self->_plain( $value->{$_} ) } keys %$value } if ref $value eq 'HASH';
  return [ map { $self->_plain($_) } @$value ] if ref $value eq 'ARRAY';
  return $value;
}

sub _build {
  my ( $self, $data ) = @_;
  $self->_fail( undef, 'must be a mapping with the keys '.join( ', ', @TOP_KEYS ) )
    unless ref $data eq 'HASH';
  $self->_unknown( undef, $data, @TOP_KEYS );

  my $ca = $self->_section( 'ca', $data->{ca} );
  $self->_unknown( 'ca', $ca, @CA_KEYS );
  for my $key ( sort keys %$ca ) {
    $self->_fail( 'ca.'.$key, 'must be a plain value' ) if ref $ca->{$key};
  }
  $self->{ca} = { %$ca };

  my $defaults = $self->_section( 'defaults', $data->{defaults} );
  $self->_unknown( 'defaults', $defaults, @DEFAULT_KEYS );
  my %raw = ( %BUILTIN, %$defaults );
  $self->{defaults} = {
    lifetime     => $self->_duration( 'defaults.lifetime',     $raw{lifetime} ),
    renew_before => $self->_duration( 'defaults.renew_before', $raw{renew_before} ),
    key          => $self->_key_type( 'defaults.key', $raw{key} )
  };

  my $devices = $self->_section( 'devices', $data->{devices} );
  $self->{devices} = [];
  $self->{by_name} = {};
  for my $name ( keys %$devices ) {
    my $device = $self->_device( $name, $devices->{$name} );
    push @{ $self->{devices} }, $device;
    $self->{by_name}{$name} = $device;
  }
  return;
}

sub _device {
  my ( $self, $name, $entry ) = @_;
  my $where = 'devices.'.$name;
  $self->_fail( $where, 'must be a mapping' ) unless ref $entry eq 'HASH';

  my $type = $entry->{type};
  $self->_fail( $where, 'missing \'type\'' ) unless defined $type && !ref $type && length $type;
  $self->_fail( $where.'.type', 'invalid type \''.$type.'\'' )
    unless $type =~ /\A[A-Za-z0-9][A-Za-z0-9_-]*\z/;

  my $names = $entry->{names};
  $self->_fail( $where, 'missing \'names\'' )
    unless defined $names && !( !ref $names && $names eq q{} );
  $self->_fail( $where.'.names', 'must be a list' ) unless ref $names eq 'ARRAY';
  $self->_fail( $where, 'missing \'names\' (the list is empty)' ) unless @$names;
  my ( @names, %seen );
  for my $given (@$names) {
    $self->_fail( $where.'.names', 'must be a list of plain names' ) if ref $given || !defined $given;
    $self->_fail( $where.'.names', 'invalid name \''.$given.'\'' ) unless SICK::Names::is_valid($given);
    my $normal = SICK::Names::normalize($given);
    push @names, $normal unless $seen{$normal}++;
  }

  my $host = $entry->{host};
  if ( defined $host ) {
    $self->_fail( $where.'.host', 'invalid host \''.( ref $host ? q{} : $host ).'\'' )
      unless !ref $host && SICK::Names::is_valid($host);
    $host = SICK::Names::normalize($host);
  }

  my $port = $entry->{port};
  if ( defined $port ) {
    $self->_fail( $where.'.port', 'invalid port \''.( ref $port ? q{} : $port ).'\'' )
      unless !ref $port && $port =~ /\A[1-9][0-9]{0,4}\z/ && $port <= 65535;
    $port += 0;
  }

  my $defaults = $self->{defaults};
  my $lifetime = exists $entry->{lifetime}
    ? $self->_duration( $where.'.lifetime', $entry->{lifetime} )
    : $defaults->{lifetime};
  my $renew_before = exists $entry->{renew_before}
    ? $self->_duration( $where.'.renew_before', $entry->{renew_before} )
    : $defaults->{renew_before};
  my $key = exists $entry->{key}
    ? $self->_key_type( $where.'.key', $entry->{key} )
    : $defaults->{key};

  $self->_fail( $where.'.lifetime', 'must be longer than zero' ) unless $lifetime > 0;
  $self->_fail( $where, '\'renew_before\' must be shorter than \'lifetime\'' )
    unless $renew_before < $lifetime;

  my %common = map { $_ => 1 } @DEVICE_KEYS;
  my %options = map { $_ => $self->_plain( $entry->{$_} ) } grep { !$common{$_} } keys %$entry;

  return SICK::Device->new(
    name         => $name,
    type         => $type,
    host         => $host,
    port         => $port,
    names        => \@names,
    lifetime     => $lifetime,
    renew_before => $renew_before,
    key          => $key,
    options      => \%options
  );
}

1;
