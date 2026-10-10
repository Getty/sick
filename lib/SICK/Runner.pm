package SICK::Runner;
# ABSTRACT: Check, issue, deploy and check again - device by device

use Moo;
use Carp qw( croak );
use POSIX qw( strftime );
use SICK::Decision;
use SICK::Target;
use Time::HiRes ();
use Time::Local qw( timegm );
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
  croak 'SICK::Runner->new: state must be a SICK::State'
    if defined $arg{state} && !( ref $arg{state} && eval { $arg{state}->can('read') && $arg{state}->can('update') } );
  for my $code (qw( now log )) {
    croak 'SICK::Runner->new: '.$code.' must be a code reference'
      if defined $arg{$code} && ref $arg{$code} ne 'CODE';
  }
  for my $seconds (qw( verify_timeout verify_interval )) {
    croak 'SICK::Runner->new: '.$seconds.' must be a number of seconds'
      if defined $arg{$seconds} && $arg{$seconds} !~ /\A[0-9]+(?:\.[0-9]+)?\z/;
  }
  delete @arg{ grep { !defined $arg{$_} } qw( state now log verify_timeout verify_interval ) };
  return \%arg;
};

=method new

    my $runner = SICK::Runner->new(
      config => $config,           # SICK::Config
      issuer => $issuer,           # SICK::Issuer
      state  => $state,            # optional: SICK::State, records and back-off
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

has state => ( is => 'ro', isa => HasMethods [qw( read update )], predicate => 1 );

=attr state

Optional. A L<SICK::State>: when it is there, L</run> keeps a record per
device and defers devices whose last attempts failed (see
L</"Records and back-off">); L</has_state> says whether it is. Without it
a run remembers nothing, as before. L</check> never touches it.

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
      device      => 'switch',
      action      => 'renewed',
      reason      => 'expiring',
      error       => undef,
      state_error => undef,
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
C<not deployed: ...>, C<deploy failed: ...> or C<verification failed: ...>.

=item C<deferred>

Only with a L</state>: the certificate is due, for C<reason>, but the last
attempts for this device failed and the next one is not due yet. Nothing
was issued. C<error> says
C<< back-off after <N> failures, next attempt <YYYY-MM-DD HH:MM:SS> UTC >>.
The device is not served, so a caller counts it as failed.

=back

C<force> renews also when the certificate is fine; C<reason> is C<forced>
then. It also ignores the back-off. It does not override C<unreachable>: a
device that cannot be asked which certificate it presents cannot be asked
afterwards either.

C<state_error> is C<undef> unless the record of the device could not be
read (C<< cannot read state record '<path>': <reason> >>; the run went on
as if there was none) or written (C<< cannot write state record '<path>':
<reason> >>). Both messages are also logged.

=head2 Records and back-off

With a L</state>, C<run> - not C<dry_run>, not L</check> - writes the
record of each device it worked on (L<SICK::State/update>). Times are UTC
in ISO 8601 (C<2026-10-10T04:17:00Z>):

    {
      "device": "switch",
      "last_check": {                    # the first look of this run
        "time": "...", "status": "expiring", "detail": "valid until ...",
        "fingerprint_sha256": "...",     # null without a certificate
        "not_after": "..."
      },
      "last_issue": {                    # the last certificate issued for it
        "time": "...", "serial": "...", "fingerprint_sha256": "...",
        "names": [ "switch.example.internal" ], "not_after": "...",
        "issuer": "CN=Example Intermediate CA"
      },
      "last_deploy": { "time": "...", "result": "ok", "error": null },
      "last_failure": { "time": "...", "error": "deploy failed: ..." },
      "last_success": "...",             # last run that ended unchanged or renewed
      "consecutive_failures": 0,
      "next_attempt": null               # the back-off, or null
    }

C<last_check> has C<status> C<unreachable> or C<error> when the device
could not be judged. C<last_issue> is written as soon as a certificate is
issued, also when it never reaches the device. C<last_deploy> has
C<result> C<ok> or C<failed>; it is written when a certificate was handed
to the target or refused before (C<not deployed: ...>). A record never
holds a key or the path of one.

An attempt that fails after the decision to renew - the request of the
device, the CA (also a CA that cannot be reached), the key check, the
deployment, the second look - counts: C<consecutive_failures> goes up by
one and C<next_attempt> is the time of that attempt plus
S<2^(failures-1)> hours, at most 24: 1, 2, 4, 8, 16, 24, 24 ... hours.
Until then a run reports the device as C<deferred> instead of issuing
again. The device is due 15 minutes before C<next_attempt> already, so that
a daily timer, which comes back after about 24 hours, does not miss the
cap by seconds and skip a day. C<unchanged> and C<renewed> set the count to C<0> and
C<next_attempt> to null. A device that is C<unreachable>, or that cannot be
judged (C<error>), changes neither: nothing was issued for it.

The certificate of a failed attempt is thrown away and not revoked. Its key
existed only in memory and in a private temporary directory
(L<SICK::Temp>) and is gone, so nobody can use the certificate; it
expires unused. The back-off is what keeps a device that keeps failing from
collecting such certificates - and the CA from being asked - on every run.

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
  my $now    = $self->now->();
  my %result = ( device => $name, action => 'failed', reason => undef, error => undef, state_error => undef );

  # What this run learns about the device, written once at the end; a dry
  # run and a runner without a state remember nothing.
  my $keep = $self->has_state && !$opt{dry_run};
  my ( $record, %update ) = ( {} );
  if ( $self->has_state ) {
    my $problem;
    ( $record, $problem ) = $self->state->read($name);
    if ( defined $problem ) {
      $result{state_error} = $problem;
      $self->_log( $name.': '.$problem );
    }
  }
  my $done = sub {
    $self->_save( $name, \%update, \%result ) if $keep;
    return \%result;
  };
  my $failed = sub {
    $result{error} = $_[0];
    $self->_log( $name.': '.$_[0] );
    return $done->();
  };
  # A failed attempt to renew: counts toward the back-off.
  my $attempt_failed = sub {
    my ( $error ) = @_;
    my $failures = $self->_failures($record) + 1;
    my $hours    = $failures > 5 ? 24 : 2**( $failures - 1 );
    %update = (
      %update,
      consecutive_failures => $failures,
      next_attempt         => $self->_iso( $now + $hours * 3600 ),
      last_failure         => { time => $self->_iso($now), error => $error },
    );
    return $failed->($error);
  };
  my $deploy_failed = sub {
    my ( $error ) = @_;
    $update{last_deploy} = { time => $self->_iso( $self->now->() ), result => 'failed', error => $error };
    return $attempt_failed->($error);
  };

  my ( $target, $presented, $decision ) = eval { $self->_look($device) };
  unless ($decision) {
    my $error = $self->_message($@);
    $result{reason} = $error =~ /\Aunreachable: / ? 'unreachable' : 'error';
    $update{last_check} = $self->_check_record( $now, $result{reason}, $error =~ s/\Aunreachable: //r );
    return $failed->($error);
  }
  $update{last_check} = $self->_check_record( $now, $decision->{reason}, $decision->{detail}, $presented );

  $result{reason} = $decision->{reason};
  unless ( $decision->{renew} ) {
    unless ( $opt{force} ) {
      $result{action} = 'unchanged';
      %update = ( %update, $self->_success($now) );
      return $done->();
    }
    $result{reason} = 'forced';
  }

  # Due from a quarter of an hour before next_attempt: a daily timer looks
  # at the device at about the same time as the day before, and would
  # otherwise miss the 24 hours by seconds and skip a day.
  my $next = $opt{force} ? undef : $self->_epoch( $record->{next_attempt} );
  if ( defined $next && $now < $next - $self->_grace ) {
    my $failures = $self->_failures($record);
    $result{action} = 'deferred';
    return $failed->( 'back-off after '.$failures.' failure'.( $failures == 1 ? q{} : 's' )
        .', next attempt '.strftime( '%Y-%m-%d %H:%M:%S UTC', gmtime $next ) );
  }
  $self->_log( $name.': '.$result{reason}.' ('.$decision->{detail}.')' );

  if ( $opt{dry_run} ) {
    $result{action} = 'would-renew';
    return \%result;
  }

  my $spec = $device->spec;
  my $csr;
  eval { $csr = $target->csr($spec); 1 }
    or return $attempt_failed->( 'certificate request failed: '.$self->_message($@) );

  $self->_log( $name.': '
      .( defined $csr ? 'having the request of the device signed' : 'issuing a certificate' )
      .' for '.join( ', ', @{ $spec->{names} } ) );
  my $bundle = eval { defined $csr ? $self->issuer->sign( $csr, $spec ) : $self->issuer->issue($spec) };
  return $attempt_failed->( 'issuing failed: '.$self->_message($@) ) unless ref $bundle;
  $update{last_issue} = $self->_issue_record($bundle) if $keep;

  # A certificate published beside a key that is not its own breaks the
  # service; it is found out here, before the target is asked for anything.
  if ( defined $bundle->key ) {
    my $matches = eval { $bundle->key_matches };
    return $deploy_failed->( 'not deployed: '.$self->_message($@) ) unless defined $matches;
    return $deploy_failed->('not deployed: the private key does not belong to the certificate') unless $matches;
  }

  $self->_log( $name.': deploying' );
  eval { $target->deploy($bundle); 1 }
    or return $deploy_failed->( 'deploy failed: '.$self->_message($@) );

  my $problem = $self->_verify( $target, $bundle );
  return $deploy_failed->( 'verification failed: '.$problem ) if defined $problem;

  $self->_log( $name.': renewed, the device presents the new certificate' );
  $result{action} = 'renewed';
  %update = (
    %update,
    last_deploy => { time => $self->_iso( $self->now->() ), result => 'ok', error => undef },
    $self->_success($now),
  );
  return $done->();
}

#### records

sub _grace { 15 * 60 }

sub _iso {
  my ( $self, $epoch ) = @_;
  return defined $epoch ? strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime $epoch ) : undef;
}

# The epoch of a time in a record; undef for anything that is not one.
sub _epoch {
  my ( $self, $text ) = @_;
  return undef unless defined $text && !ref $text;
  my ( $y, $m, $d, $hh, $mm, $ss ) = $text =~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z/
    or return undef;
  my $epoch = eval { timegm( $ss, $mm, $hh, $d, $m - 1, $y ) };
  return $epoch;
}

sub _failures {
  my ( $self, $record ) = @_;
  my $count = $record->{consecutive_failures};
  return defined $count && !ref $count && $count =~ /\A[0-9]{1,6}\z/ ? $count + 0 : 0;
}

sub _success {
  my ( $self, $now ) = @_;
  return ( last_success => $self->_iso($now), consecutive_failures => 0, next_attempt => undef );
}

sub _check_record {
  my ( $self, $now, $status, $detail, $presented ) = @_;
  return {
    time               => $self->_iso($now),
    status             => $status,
    detail             => $detail,
    fingerprint_sha256 => $presented ? $presented->fingerprint_sha256 : undef,
    not_after          => $presented ? $self->_iso( $presented->not_after ) : undef,
  };
}

# Facts of the certificate only: never the key, never where it is.
sub _issue_record {
  my ( $self, $bundle ) = @_;
  my %facts = eval {
    (
      serial             => $bundle->serial,
      fingerprint_sha256 => $bundle->fingerprint_sha256,
      names              => $bundle->names,
      not_after          => $self->_iso( $bundle->not_after ),
      issuer             => $bundle->issuer_dn,
    );
  };
  return { time => $self->_iso( $self->now->() ), %facts };
}

sub _save {
  my ( $self, $name, $update, $result ) = @_;
  return unless %$update;
  eval { $self->state->update( $name, { device => $name, %$update } ); 1 } and return;
  my $error = $self->_message($@);
  $self->_log( $name.': '.$error );
  $result->{state_error} = defined $result->{state_error} ? $result->{state_error}.'; '.$error : $error;
  return;
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
