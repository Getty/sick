package SICK::Runner;
# ABSTRACT: Check, issue, deploy and check again - device by device

use Moo;
use Carp qw( croak );
use SICK::Decision;
use SICK::Target;
use Time::HiRes ();
use Types::Standard qw( CodeRef HasMethods Maybe Num Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Config;
    use SICK::Issuer;
    use SICK::Runner;

    my $config = SICK::Config->load('/etc/sick/sick.yml');
    my $runner = SICK::Runner->new(
      config => $config,
      issuer => SICK::Issuer->from_ca( %{ $config->ca } ),
      log    => sub { print STDERR "$_[0]\n" },
    );

    for my $state ( $runner->check ) {
      printf "%s: %s\n", $state->{device}, $state->{reason};
    }

    my @results = $runner->run( ['switch'], force => 1 );
    exit 1 if grep { $_->{action} eq 'failed' } @results;

=head1 DESCRIPTION

The one place where the parts meet. For every device of the list:

=over 4

=item 1. B<Check>

The target of the device type says which certificate the device presents
(L<SICK::Target/presented_cert>) and L<SICK::Decision> judges it against
the root of the issuer, with the help of its intermediate certificates
(L<SICK::Issuer/intermediates_pem>). A device
that does not answer is C<unreachable>: nothing is known about it, and
nothing is done to it.

=item 2. B<Issue>

When the certificate has to be renewed, the issuer makes a new one: for a
certificate request of the device when the target hands one over
(L<SICK::Target/csr>, L<SICK::Issuer/sign>), with a fresh key otherwise
(L<SICK::Issuer/issue>).

=item 3. B<Deploy>

The target installs it (L<SICK::Target/deploy>). A bundle with a key is
checked first: when the key is not the key of the certificate
(L<SICK::Bundle/key_matches>), the device fails with C<not deployed: the
private key does not belong to the certificate> and the target is not
called.

=item 4. B<Check again>

The device has to present exactly the certificate that was issued, by
SHA-256 fingerprint. A device may take a moment for that - see
L<SICK::Target/verify_timeout>.

=back

Whatever goes wrong with one device is the result for that device and does
not stop the others. The key of a new certificate exists in memory, and as a
file only where an issuer or a target puts it for a moment into a private
temporary directory (L<SICK::Temp>); a run that is interrupted between
issuing and deploying leaves the device as it was, and the next run starts
over.

=cut

# The checks and messages of the constructor come first; the types are the
# second line.
around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  croak 'SICK::Runner->new needs a config'
    unless ref $arg{config} && eval { $arg{config}->can('devices') && $arg{config}->can('device') };
  croak 'SICK::Runner->new needs an issuer'
    unless ref $arg{issuer} && eval { $arg{issuer}->can('issue') && $arg{issuer}->can('root_pem') };
  for my $code (qw( now log )) {
    croak 'SICK::Runner->new: '.$code.' must be a code reference'
      if defined $arg{$code} && ref $arg{$code} ne 'CODE';
  }
  for my $seconds (qw( verify_timeout verify_interval )) {
    croak 'SICK::Runner->new: '.$seconds.' must be a number of seconds'
      if defined $arg{$seconds} && $arg{$seconds} !~ /\A[0-9]+(?:\.[0-9]+)?\z/;
  }
  delete @arg{ grep { !defined $arg{$_} } qw( now log verify_timeout verify_interval ) };
  return \%arg;
};

=method new

    my $runner = SICK::Runner->new(
      config => $config,           # SICK::Config
      issuer => $issuer,           # SICK::Issuer
      now    => sub { time },      # optional: the clock of the decision
      log    => sub { ... },       # optional: called with one line of text
    );

C<config> and C<issuer> are required. C<log> receives what happens while a
device is worked on, each line starting with the name of the device; the
messages of the target are passed through.

Two more arguments are for tests and impatient callers: C<verify_timeout>
replaces the L<SICK::Target/verify_timeout> of every target, and
C<verify_interval> (C<2>) is the pause between two looks at a device that
does not present the new certificate yet. Both in seconds.

=cut

has config => ( is => 'ro', isa => HasMethods [qw( devices device )], required => 1 );
has issuer => ( is => 'ro', isa => HasMethods [qw( issue root_pem )], required => 1 );

=attr config

The L<SICK::Config>.

=attr issuer

The L<SICK::Issuer>.

=cut

has now => ( is => 'ro', isa => CodeRef, builder => 1 );

sub _build_now { sub { time } }

=attr now

The clock of the decision: a code reference that returns the time as an
epoch. Defaults to C<time>.

=cut

has verify_timeout  => ( is => 'ro', isa => Num, predicate => 1 );
has verify_interval => ( is => 'ro', isa => Num, default   => 2 );

=attr verify_timeout

When given, it replaces the L<SICK::Target/verify_timeout> of every target;
L</has_verify_timeout> says whether it was.

=attr verify_interval

The pause between two looks at a device that does not present the new
certificate yet. C<2>.

=cut

# The callback of new( log => ... ); the method _log calls it.
has _logger => ( is => 'ro', isa => CodeRef, init_arg => 'log', predicate => 1 );

sub check {
  my ( $self, @names ) = @_;
  my @devices = $self->_devices( \@names );
  my @states;
  for my $device (@devices) {
    my ( $target, $presented, $decision ) = eval { $self->_look($device) };
    unless ($decision) {
      my $error = $self->_message($@);
      my $unreachable = $error =~ s/\Aunreachable: //;
      push @states, {
        device    => $device->name,
        reason    => $unreachable ? 'unreachable' : 'error',
        renew     => undef,
        detail    => $error,
        not_after => undef
      };
      next;
    }
    push @states, {
      device    => $device->name,
      reason    => $decision->{reason},
      renew     => $decision->{renew},
      detail    => $decision->{detail},
      not_after => defined $presented ? $presented->not_after : undef
    };
  }
  return @states;
}

=method check

    my @states = $runner->check;                  # every device
    my @states = $runner->check( 'switch', 'grafana' );

Looks at the devices and changes nothing. Returns one hash reference per
device, in the order of the device list (or of the names given):

    {
      device    => 'switch',                      # the name in the device list
      reason    => 'expiring',
      renew     => 1,
      detail    => 'valid until 2026-10-20 08:00:00 UTC, 14 days left',
      not_after => 1792483200,                    # epoch, undef without a certificate
    }

C<reason> is one of the answers of L<SICK::Decision/evaluate> - C<ok>,
C<missing>, C<foreign-ca>, C<names>, C<expiring> - or one of two that mean
the device could not be judged, with C<renew> undefined:

=over 4

=item C<unreachable>

No connection to the device; C<detail> says why. This is not C<missing>.

=item C<error>

Something else stood in the way: no target for the type, an option of the
device that is wrong, a program that is not installed. C<detail> is the
message.

=back

Croaks with C<< unknown device '<name>' >> when a name is not in the list,
before any device is looked at.

=cut

sub run {
  my ( $self, $names, %opt ) = @_;
  croak 'run takes the device names as an array reference' if defined $names && ref $names ne 'ARRAY';
  my @unknown = sort grep { !/\A(?:force|dry_run)\z/ } keys %opt;
  croak 'run: unknown option \''.$unknown[0].'\'' if @unknown;
  my @devices = $self->_devices( $names || [] );
  return map { $self->_run_device( $_, %opt ) } @devices;
}

=method run

    my @results = $runner->run;                                   # every device
    my @results = $runner->run( [ 'switch' ], force => 1 );
    my @results = $runner->run( [], dry_run => 1 );

Does the four steps for every device and returns one hash reference each:

    {
      device => 'switch',
      action => 'renewed',
      reason => 'expiring',
      error  => undef,
    }

C<action> is

=over 4

=item C<unchanged>

The certificate is fine (C<reason> is C<ok>). Nothing was done.

=item C<renewed>

A new certificate was issued and deployed, and the device presents it.
C<reason> says why it was due.

=item C<would-renew>

With C<dry_run>: the certificate is due, for C<reason>. Nothing was issued
and the device was only looked at.

=item C<failed>

C<error> says what went wrong and at which step: C<unreachable: ...> or
another message from the first look (C<reason> is C<unreachable> or
C<error> then), C<certificate request failed: ...>,
C<issuing failed: ...> - with the words of the CA -,
C<deploy failed: ...> or C<verification failed: ...>.

=back

C<force> renews also when the certificate is fine; C<reason> is C<forced>
then. It does not override C<unreachable>: a device that cannot be asked
which certificate it presents cannot be asked afterwards either.

Croaks with C<< unknown device '<name>' >> before anything is done.

=cut

#### internals

sub _log {
  my ( $self, $message ) = @_;
  $self->_logger->($message) if $self->_has_logger;
  return;
}

# What died, as one message without the place in the code.
sub _message {
  my ( $self, $error ) = @_;
  $error = defined $error ? q{}.$error : q{};
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  $error =~ s/\s+\z//;
  return length $error ? $error : 'unknown error';
}

sub _devices {
  my ( $self, $names ) = @_;
  return $self->config->devices unless @$names;
  my ( @devices, %seen );
  for my $name (@$names) {
    my $device = defined $name && !ref $name ? $self->config->device($name) : undef;
    croak 'unknown device \''.( defined $name && !ref $name ? $name : q{} ).'\'' unless $device;
    push @devices, $device unless $seen{$name}++;
  }
  return @devices;
}

# The root is asked for once per runner; a failure is not kept (a lazy
# builder that dies sets nothing), so that it is reported for every device
# and not only for the first one.
has _root_pem => ( is => 'lazy', isa => Maybe [Str], init_arg => undef );

sub _build__root_pem { $_[0]->issuer->root_pem }

# Asked for with every look: an issuer may answer undef, and a file that
# cannot be read is reported for every device.
sub _intermediates_pem {
  my ( $self ) = @_;
  return undef unless $self->issuer->can('intermediates_pem');
  return $self->issuer->intermediates_pem;
}

sub _target {
  my ( $self, $device ) = @_;
  my $name   = $device->name;
  my $class  = SICK::Target->class_for( $device->type );
  my $target = $class->new( device => $device, log => sub { $self->_log( $name.': '.$_[0] ) } );
  $target->validate;
  return $target;
}

# Step 1. Dies with the reason when the device cannot be judged.
sub _look {
  my ( $self, $device ) = @_;
  my $target    = $self->_target($device);
  my $root_pem      = $self->_root_pem;
  my $intermediates = $self->_intermediates_pem;
  my $presented     = $target->presented_cert;
  my $decision      = SICK::Decision::evaluate(
    device            => $device,
    presented         => $presented,
    root_pem          => $root_pem,
    intermediates_pem => $intermediates,
    now               => $self->now->(),
  );
  return ( $target, $presented, $decision );
}

sub _run_device {
  my ( $self, $device, %opt ) = @_;
  my $name   = $device->name;
  my %result = ( device => $name, action => 'failed', reason => undef, error => undef );
  my $failed = sub {
    $result{error} = $_[0];
    $self->_log( $name.': '.$_[0] );
    return \%result;
  };

  my ( $target, $presented, $decision ) = eval { $self->_look($device) };
  unless ($decision) {
    my $error = $self->_message($@);
    $result{reason} = $error =~ /\Aunreachable: / ? 'unreachable' : 'error';
    return $failed->($error);
  }

  $result{reason} = $decision->{reason};
  unless ( $decision->{renew} ) {
    unless ( $opt{force} ) {
      $result{action} = 'unchanged';
      return \%result;
    }
    $result{reason} = 'forced';
  }
  $self->_log( $name.': '.$result{reason}.' ('.$decision->{detail}.')' );

  if ( $opt{dry_run} ) {
    $result{action} = 'would-renew';
    return \%result;
  }

  my $spec = $device->spec;
  my $csr;
  eval { $csr = $target->csr($spec); 1 }
    or return $failed->( 'certificate request failed: '.$self->_message($@) );

  $self->_log( $name.': '
      .( defined $csr ? 'having the request of the device signed' : 'issuing a certificate' )
      .' for '.join( ', ', @{ $spec->{names} } ) );
  my $bundle = eval { defined $csr ? $self->issuer->sign( $csr, $spec ) : $self->issuer->issue($spec) };
  return $failed->( 'issuing failed: '.$self->_message($@) ) unless ref $bundle;

  # A certificate published beside a key that is not its own breaks the
  # service; it is found out here, before the target is asked for anything.
  if ( defined $bundle->key ) {
    my $matches = eval { $bundle->key_matches };
    return $failed->( 'not deployed: '.$self->_message($@) ) unless defined $matches;
    return $failed->('not deployed: the private key does not belong to the certificate') unless $matches;
  }

  $self->_log( $name.': deploying' );
  eval { $target->deploy($bundle); 1 }
    or return $failed->( 'deploy failed: '.$self->_message($@) );

  my $problem = $self->_verify( $target, $bundle );
  return $failed->( 'verification failed: '.$problem ) if defined $problem;

  $self->_log( $name.': renewed, the device presents the new certificate' );
  $result{action} = 'renewed';
  return \%result;
}

# Step 4. Returns undef when the device presents the issued certificate, and
# the reason when it does not do so within the time it is given.
sub _verify {
  my ( $self, $target, $bundle ) = @_;
  my $issued   = $bundle->fingerprint_sha256;
  my $timeout  = $self->has_verify_timeout ? $self->verify_timeout : $target->verify_timeout;
  my $deadline = Time::HiRes::time() + $timeout;

  while (1) {
    my ( $presented, $problem );
    if ( !eval { $presented = $target->presented_cert; 1 } ) {
      $problem = $self->_message($@);
    }
    elsif ( !defined $presented ) {
      $problem = 'the device presents no certificate';
    }
    elsif ( $presented->fingerprint_sha256 ne $issued ) {
      $problem = 'the device does not present the new certificate (SHA-256 '.substr( $issued, 0, 16 )
        .'...) but another one ('.substr( $presented->fingerprint_sha256, 0, 16 ).'...)';
    }
    return $problem unless defined $problem;

    my $left = $deadline - Time::HiRes::time();
    return $problem if $left <= 0;
    my $pause = $self->verify_interval > 0.05 ? $self->verify_interval : 0.05;
    Time::HiRes::sleep( $left < $pause ? $left : $pause );
  }
}

1;
