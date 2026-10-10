package SICK::Report;
# ABSTRACT: What sick check and sick inventory say for machines - JSON and Prometheus

use Moo;
use Carp qw( croak );
use JSON::MaybeXS ();
use POSIX qw( strftime );
use SICK::Bundle;
use Time::Local qw( timegm );
use Types::Standard qw( CodeRef HasMethods );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Report;

    my $report = SICK::Report->new( config => $config, issuer => $issuer, state => $state );

    my $data = $report->check( [ $runner->check ] );
    print $report->json($data);
    print $report->prometheus($data);

    my $inventory = $report->inventory( [] );                                   # records only
    my $inventory = $report->inventory( [], states => [ $runner->check ] );     # and a look

=head1 DESCRIPTION

Turns what L<SICK::Runner/check> found out, together with the records of
L<SICK::State> and the certificates of the CA, into one data structure,
and that into JSON or into the text exposition format of Prometheus (for
the textfile collector of node_exporter). It looks at nothing itself: the
devices are looked at by the runner, and the CA is asked by
L<SICK::Issuer/health>, which L</check> calls.

Times are UTC in ISO 8601 (C<2026-10-10T04:17:00Z>), with the same time as
epoch seconds in a field of the same name ending in C<_epoch>. A time a
record holds that is no such time comes out as C<null>. Neither structure
holds a key or the path of one.

=cut

around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my %arg = %{ $class->$orig(@args) };
  croak 'SICK::Report->new needs a config'
    unless ref $arg{config} && eval { $arg{config}->can('devices') && $arg{config}->can('device') };
  croak 'SICK::Report->new needs an issuer'
    unless ref $arg{issuer} && eval { $arg{issuer}->can('root_pem') };
  delete $arg{state} unless defined $arg{state};
  return \%arg;
};

=method new

    my $report = SICK::Report->new(
      config => $config,          # SICK::Config
      issuer => $issuer,          # SICK::Issuer
      state  => $state,           # optional: SICK::State; without it there are no records
      now    => sub { time },     # optional
    );

=cut

has config => ( is => 'ro', isa => HasMethods [qw( devices device )], required => 1 );
has issuer => ( is => 'ro', isa => HasMethods [qw( root_pem )], required => 1 );
has state  => ( is => 'ro', isa => HasMethods [qw( read )], predicate => 1 );
has now    => ( is => 'ro', isa => CodeRef, builder => 1 );

sub _build_now { sub { time } }

=attr config

The L<SICK::Config>.

=attr issuer

The L<SICK::Issuer>.

=attr state

Optional. The L<SICK::State> the records are read from (never written).

=attr now

The clock, a code reference that returns epoch seconds. C<time>.

=cut

has _json => ( is => 'lazy', isa => HasMethods [qw( encode )], init_arg => undef );

sub _build__json { JSON::MaybeXS->new( utf8 => 1, canonical => 1, pretty => 1, convert_blessed => 1 ) }

sub check {
  my ( $self, $states ) = @_;
  croak 'check needs the states of SICK::Runner->check as an array reference' unless ref $states eq 'ARRAY';
  my $now = $self->now->();
  my $ca  = $self->_ca_certificates;
  my ( $up, $why ) = $self->issuer->can('health') ? $self->issuer->health : ();
  return {
    $self->_time( generated_at => $now ),
    ca => {
      type          => $self->_ca_type,
      reachable     => $self->_bool($up),
      detail        => defined $up && !$up ? $why : undef,
      root          => $ca->{root} ? $self->_ca_entry( $ca->{root}, 'fingerprint' ) : undef,
      intermediates => [ map { $self->_ca_entry($_) } @{ $ca->{intermediates} } ]
    },
    devices => [ map { $self->_device_check( $_, $now, $ca, $self->_record( $_->{device} ) ) } @$states ],
  };
}

=method check

    my $data = $report->check( \@states );

The states are those of L<SICK::Runner/check>, in their order; the CA is
asked by L<SICK::Issuer/health>. Returns

    {
      generated_at => '2026-10-10T04:17:00Z', generated_at_epoch => 1791605820,
      ca => {
        type      => 'step-ca',               # or 'selfsigned'
        reachable => true,                    # SICK::Issuer->health; null for selfsigned
        detail    => undef,                   # why not, when reachable is false
        root          => { subject, not_after, not_after_epoch, fingerprint_sha256 },
        intermediates => [ { subject, not_after, not_after_epoch }, ... ],
      },
      devices => [ {
        device, type, status, renew, detail,  # status is the reason of check; renew true|false|null
        names, host, port,                    # as in the device list; host null without one
        live => {                             # the certificate it presents, or null
          fingerprint_sha256, serial, issuer,
          not_before, not_before_epoch, not_after, not_after_epoch,
          remaining_seconds,                  # until not_after, negative once it has ended
          lifetime_seconds,                   # not_after - not_before
        },
        renew_before_seconds,
        chain_not_after, chain_not_after_epoch,
        matches_last_issue,                   # true|false|null
        last_issue,                           # as on record, or null
        last_success, last_success_epoch,
        consecutive_failures,                 # 0 without a record
        next_attempt, next_attempt_epoch,
        state_error,                          # the record could not be read: why
      }, ... ],
    }

B<chain_not_after> is the earliest end along the path from the live
certificate to the root: its intermediates and the root itself, the leaf
not counted. The path is built from what the device sent along, the
intermediates of the CA (L<SICK::Issuer/intermediates_pem>) and the root,
by issuer and subject name; where two certificates of the same name could
be the next step, the one that ends first counts. It is C<null> unless the
certificate is one of this CA (C<status> C<ok>, C<names> or C<expiring>).

B<matches_last_issue> says whether the live certificate is the one issued
last, by SHA-256 fingerprint: C<null> without a record of an issue, and
when the device could not be judged (C<unreachable>, C<error>); C<false>
also when the device presents nothing.

The root of the CA is C<null> and the intermediates are empty when they
cannot be read; the devices say why (C<error>).

=cut

sub inventory {
  my ( $self, $names, %opt ) = @_;
  croak 'inventory takes the device names as an array reference' unless ref $names eq 'ARRAY';
  my $now = $self->now->();
  my ( @entries, $ca );
  if ( my $states = $opt{states} ) {
    $ca = $self->_ca_certificates;
    for my $state (@$states) {
      my @record = $self->_record( $state->{device} );
      my %live   = %{ $self->_device_check( $state, $now, $ca, @record ) };
      push @entries, {
        %{ $self->_device_inventory( $state->{device}, @record ) },
        status             => $live{status},
        renew              => $live{renew},
        detail             => $live{detail},
        live               => $live{live},
        matches_last_issue => $live{matches_last_issue}
      };
    }
  }
  else {
    my @devices;
    if (@$names) {
      my %seen;
      for my $name (@$names) {
        my $device = defined $name && !ref $name ? $self->config->device($name) : undef;
        croak 'unknown device \''.( defined $name && !ref $name ? $name : q{} ).'\'' unless $device;
        push @devices, $device unless $seen{$name}++;
      }
    }
    else {
      @devices = $self->config->devices;
    }
    @entries = map { $self->_device_inventory( $_->name, $self->_record( $_->name ) ) } @devices;
  }
  return { $self->_time( generated_at => $now ), devices => \@entries };
}

=method inventory

    my $data = $report->inventory( \@names );                       # records only
    my $data = $report->inventory( [], states => \@states );        # with a look

What is deployed, per device, from the records alone: nothing is asked
over the network. Without names it is every device of the list. Returns

    {
      generated_at, generated_at_epoch,
      devices => [ {
        device, type,
        names, issuer, serial, fingerprint_sha256,  # of the certificate issued last
        not_after, not_after_epoch,
        issued,                                     # when it was issued
        last_deploy => { time, result, error },     # the last deployment, or null
        last_verified,                              # see below
        last_status, last_checked,                  # the last look of a run
        state_error,
      }, ... ],
    }

All of them C<null> for a device without a record. B<last_verified> is the
last time a run saw the device present the certificate issued last: the
time of a deployment that ended C<ok> (a deployment counts once the device
presents the certificate), or of a look that saw its fingerprint, whichever
is later.

With C<states> from L<SICK::Runner/check> the entries follow those, and
each gains C<status>, C<renew>, C<detail>, C<live> and C<matches_last_issue>
as in L</check>. The CA is not asked.

Croaks with C<< unknown device '<name>' >> for a name that is not in the
list.

=cut

sub json {
  my ( $self, $data ) = @_;
  return $self->_json->encode($data);
}

=method json

    my $bytes = $report->json($data);

The structure as JSON: UTF-8, keys sorted, indented, with a final newline.

=cut

# name, help, and the samples ( [ \%labels, value ], ... ) out of the data
sub _families {
  my ( $self, $data ) = @_;
  my $ca = $data->{ca};
  my @devices = @{ $data->{devices} };
  my $per = sub {
    my ( $code ) = @_;
    return [ map { my @v = $code->($_); @v ? [ { device => $_->{device} }, $v[0] ] : () } @devices ];
  };
  my $num = sub { defined $_[0] ? ( $_[0] ) : () };
  return (
    [ 'sick_check_timestamp_seconds', 'When sick check looked, as epoch seconds.',
      [ [ {}, $data->{generated_at_epoch} ] ] ],
    [ 'sick_ca_up', 'Whether the CA answered its health check (step ca health); absent for a CA that cannot be asked.',
      defined $ca->{reachable} ? [ [ {}, $ca->{reachable} ? 1 : 0 ] ] : [] ],
    [ 'sick_ca_certificate_not_after_seconds', 'End of validity of a certificate of the CA, as epoch seconds.',
      $self->_ca_samples($ca) ],
    [ 'sick_device_info', 'A device of the list, its type and the status of its certificate.',
      [ map { [ { device => $_->{device}, type => $_->{type}, status => $_->{status} }, 1 ] } @devices ] ],
    [ 'sick_device_reachable', 'Whether the device answered; absent when it could not be asked (status error).',
      $per->( sub { $_[0]{status} eq 'unreachable' ? 0 : $_[0]{status} eq 'error' ? () : 1 } ) ],
    [ 'sick_device_renew_due', 'Whether sick run would renew the certificate of the device now.',
      $per->( sub { defined $_[0]{renew} ? ( $_[0]{renew} ? 1 : 0 ) : () } ) ],
    [ 'sick_certificate_not_after_seconds', 'End of validity of the certificate the device presents, as epoch seconds.',
      $per->( sub { $_[0]{live} ? $_[0]{live}{not_after_epoch} : () } ) ],
    [ 'sick_certificate_remaining_seconds', 'Seconds until the certificate the device presents ends; negative once it has.',
      $per->( sub { $_[0]{live} ? $_[0]{live}{remaining_seconds} : () } ) ],
    [ 'sick_certificate_lifetime_seconds', 'Total lifetime of the certificate the device presents, in seconds.',
      $per->( sub { $_[0]{live} ? $_[0]{live}{lifetime_seconds} : () } ) ],
    [ 'sick_device_renew_before_seconds', 'renew_before of the device: sick run renews when less than this is left.',
      $per->( sub { $_[0]{renew_before_seconds} } ) ],
    [ 'sick_chain_not_after_seconds', 'Earliest end of validity along the chain of the presented certificate to the root, as epoch seconds.',
      $per->( sub { $num->( $_[0]{chain_not_after_epoch} ) } ) ],
    [ 'sick_device_matches_last_issue', 'Whether the device presents the certificate issued for it last.',
      $per->( sub { defined $_[0]{matches_last_issue} ? ( $_[0]{matches_last_issue} ? 1 : 0 ) : () } ) ],
    [ 'sick_device_consecutive_failures', 'Attempts to renew that failed in a row.',
      $per->( sub { $_[0]{consecutive_failures} } ) ],
    [ 'sick_device_last_success_timestamp_seconds', 'When a run last ended unchanged or renewed for the device, as epoch seconds.',
      $per->( sub { $num->( $_[0]{last_success_epoch} ) } ) ],
  );
}

sub prometheus {
  my ( $self, $data ) = @_;
  my $text = q{};
  for my $family ( $self->_families($data) ) {
    my ( $name, $help, $samples ) = @$family;
    next unless @$samples;
    $text .= '# HELP '.$name.' '.$self->_escape_help($help)."\n".'# TYPE '.$name." gauge\n";
    for my $sample (@$samples) {
      my ( $labels, $value ) = @$sample;
      my @pairs = map { $_.'="'.$self->_escape_label( $labels->{$_} ).'"' } $self->_label_order($labels);
      $text .= $name.( @pairs ? '{'.join( ',', @pairs ).'}' : q{} ).' '.( 0 + $value )."\n";
    }
  }
  return $text;
}

=method prometheus

    my $text = $report->prometheus( $report->check( \@states ) );

The result of L</check> in the text exposition format of Prometheus, every
metric a gauge with C<HELP> and C<TYPE>, label values escaped (backslash,
double quote, newline):

    sick_check_timestamp_seconds                       when check looked
    sick_ca_up                                         1 or 0; absent for selfsigned
    sick_ca_certificate_not_after_seconds{role,subject}  role root or intermediate
    sick_device_info{device,type,status}               1
    sick_device_reachable{device}                      0 for unreachable; absent for error
    sick_device_renew_due{device}                      absent when unknown
    sick_certificate_not_after_seconds{device}         \
    sick_certificate_remaining_seconds{device}          > of the live certificate; absent without one
    sick_certificate_lifetime_seconds{device}          /
    sick_device_renew_before_seconds{device}
    sick_chain_not_after_seconds{device}               absent without a chain to the root
    sick_device_matches_last_issue{device}             absent where matches_last_issue is null
    sick_device_consecutive_failures{device}
    sick_device_last_success_timestamp_seconds{device} absent when unknown

Of two certificates of the CA with the same role and subject, the one that
ends first is reported: a series appears once.

=cut

#### internals

sub _label_order {
  my ( $self, $labels ) = @_;
  my %rank = ( device => 0, role => 0, type => 1, subject => 1, status => 2 );
  return sort { ( $rank{$a} // 9 ) <=> ( $rank{$b} // 9 ) || $a cmp $b } keys %$labels;
}

sub _escape_label {
  my ( $self, $value ) = @_;
  $value = q{} unless defined $value;
  $value =~ s/\\/\\\\/g;
  $value =~ s/"/\\"/g;
  $value =~ s/\n/\\n/g;
  return $value;
}

sub _escape_help {
  my ( $self, $text ) = @_;
  $text =~ s/\\/\\\\/g;
  $text =~ s/\n/\\n/g;
  return $text;
}

sub _ca_samples {
  my ( $self, $ca ) = @_;
  my %earliest;
  for my $entry ( ( $ca->{root} ? [ root => $ca->{root} ] : () ), map { [ intermediate => $_ ] } @{ $ca->{intermediates} } ) {
    my ( $role, $cert ) = @$entry;
    my $key = $role."\0".$cert->{subject};
    $earliest{$key} = [ { role => $role, subject => $cert->{subject} }, $cert->{not_after_epoch} ]
      if !$earliest{$key} || $cert->{not_after_epoch} < $earliest{$key}[1];
  }
  return [ map { $earliest{$_} } sort keys %earliest ];
}

sub _bool {
  my ( $self, $value ) = @_;
  return undef unless defined $value;
  return $value ? JSON::MaybeXS::true : JSON::MaybeXS::false;
}

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

# name => ISO, name_epoch => epoch
sub _time {
  my ( $self, $name, $epoch ) = @_;
  return ( $name => $self->_iso($epoch), $name.'_epoch' => defined $epoch ? 0 + $epoch : undef );
}

sub _ca_type {
  my ( $self ) = @_;
  my $type = eval { $self->config->ca->{type} };
  $type = 'step-ca' unless defined $type && length $type;
  ( my $plain = lc $type ) =~ s/[^a-z0-9]//g;
  return $plain eq 'stepca' ? 'step-ca' : $plain eq 'selfsigned' ? 'selfsigned' : $type;
}

# Root and intermediates of the CA as bundles; what cannot be read is left
# out - the devices report it.
sub _ca_certificates {
  my ( $self ) = @_;
  my $root = eval { SICK::Bundle->new( cert => $self->issuer->root_pem ) };
  $root = undef unless $root && eval { $root->not_after; 1 };
  my $pem = $root && $self->issuer->can('intermediates_pem') ? eval { $self->issuer->intermediates_pem } : undef;
  my @intermediates = grep { eval { $_->not_after; 1 } }
    map { SICK::Bundle->new( cert => $_ ) } $self->_blocks($pem);
  @intermediates = grep { $_->fingerprint_sha256 ne $root->fingerprint_sha256 } @intermediates if $root;
  return { root => $root, intermediates => \@intermediates };
}

sub _blocks {
  my ( $self, $pem ) = @_;
  return () unless defined $pem;
  return $pem =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg;
}

sub _ca_entry {
  my ( $self, $cert, $with_fingerprint ) = @_;
  return {
    subject => $cert->subject_dn,
    $self->_time( not_after => $cert->not_after ),
    ( $with_fingerprint ? ( fingerprint_sha256 => $cert->fingerprint_sha256 ) : () )
  };
}

# ( $record, $problem ): {} and undef without a state
sub _record {
  my ( $self, $name ) = @_;
  return ( {}, undef ) unless $self->has_state;
  my ( $record, $problem ) = $self->state->read($name);
  return ( $record, $problem );
}

sub _failures {
  my ( $self, $record ) = @_;
  my $count = $record->{consecutive_failures};
  return defined $count && !ref $count && $count =~ /\A[0-9]{1,6}\z/ ? $count + 0 : 0;
}

sub _last_issue {
  my ( $self, $record ) = @_;
  return ref $record->{last_issue} eq 'HASH' ? $record->{last_issue} : undef;
}

sub _live {
  my ( $self, $cert, $now ) = @_;
  return undef unless $cert;
  return {
    fingerprint_sha256 => $cert->fingerprint_sha256,
    serial             => $cert->serial,
    issuer             => $cert->issuer_dn,
    $self->_time( not_before => $cert->not_before ),
    $self->_time( not_after  => $cert->not_after ),
    remaining_seconds => $cert->not_after - $now,
    lifetime_seconds  => $cert->not_after - $cert->not_before
  };
}

# The earliest end along the path from the leaf to the root, by names.
sub _chain_not_after {
  my ( $self, $leaf, $ca ) = @_;
  return undef unless $leaf && $ca->{root};
  my @candidates = (
    ( map { SICK::Bundle->new( cert => $_ ) } $self->_blocks( $leaf->chain ) ),
    @{ $ca->{intermediates} },
    $ca->{root}
  );
  my ( $current, $earliest, %seen ) = ($leaf);
  $seen{ $leaf->fingerprint_sha256 } = 1;
  while ( !$current->is_self_signed ) {
    my @next = sort { $a->not_after <=> $b->not_after }
      grep { !$seen{ $_->fingerprint_sha256 } && $_->subject_dn eq $current->issuer_dn } @candidates;
    last unless @next;
    $current = $next[0];
    $seen{ $current->fingerprint_sha256 } = 1;
    $earliest = $current->not_after if !defined $earliest || $current->not_after < $earliest;
  }
  return $earliest;
}

sub _device_check {
  my ( $self, $state, $now, $ca, $record, $problem ) = @_;
  my $name   = $state->{device};
  my $device = $self->config->device($name);
  my $issue  = $self->_last_issue($record);
  my $live   = $state->{presented};
  my $judged = $state->{reason} ne 'unreachable' && $state->{reason} ne 'error';
  my $ours   = $state->{reason} =~ /\A(?:ok|names|expiring)\z/;
  my $issued = $issue && defined $issue->{fingerprint_sha256} ? $issue->{fingerprint_sha256} : undef;
  return {
    device               => $name,
    type                 => $device ? $device->type : undef,
    status               => $state->{reason},
    renew                => $self->_bool( $state->{renew} ),
    detail               => $state->{detail},
    names                => $device ? $device->names : undef,
    host                 => $device ? $device->host : undef,
    port                 => $device ? 0 + $device->port : undef,
    live                 => $self->_live( $live, $now ),
    renew_before_seconds => $device ? 0 + $device->renew_before : undef,
    $self->_time( chain_not_after => $ours ? $self->_chain_not_after( $live, $ca ) : undef ),
    matches_last_issue => !defined $issued || !$judged ? undef
      : $self->_bool( $live && $live->fingerprint_sha256 eq $issued ),
    last_issue => $issue,
    $self->_time( last_success => $self->_epoch( $record->{last_success} ) ),
    consecutive_failures => $self->_failures($record),
    $self->_time( next_attempt => $self->_epoch( $record->{next_attempt} ) ),
    state_error => $problem,
  };
}

sub _device_inventory {
  my ( $self, $name, $record, $problem ) = @_;
  my $device = $self->config->device($name);
  my $issue  = $self->_last_issue($record) || {};
  my $deploy = ref $record->{last_deploy} eq 'HASH' ? $record->{last_deploy} : undef;
  my $check  = ref $record->{last_check} eq 'HASH' ? $record->{last_check} : {};
  my $fingerprint = defined $issue->{fingerprint_sha256} && !ref $issue->{fingerprint_sha256} ? $issue->{fingerprint_sha256} : undef;

  my @seen = (
    ( $deploy && defined $deploy->{result} && $deploy->{result} eq 'ok' ? $self->_epoch( $deploy->{time} ) : () ),
    ( defined $fingerprint && defined $check->{fingerprint_sha256} && $check->{fingerprint_sha256} eq $fingerprint
      ? $self->_epoch( $check->{time} ) : () )
  );
  my ($verified) = sort { $b <=> $a } grep { defined } @seen;

  return {
    device             => $name,
    type               => $device ? $device->type : undef,
    names              => ref $issue->{names} eq 'ARRAY' ? $issue->{names} : undef,
    issuer             => $issue->{issuer},
    serial             => $issue->{serial},
    fingerprint_sha256 => $fingerprint,
    $self->_time( not_after => $self->_epoch( $issue->{not_after} ) ),
    issued             => $self->_iso( $self->_epoch( $issue->{time} ) ),
    last_deploy        => $deploy ? {
      time   => $self->_iso( $self->_epoch( $deploy->{time} ) ),
      result => $deploy->{result},
      error  => $deploy->{error}
    } : undef,
    last_verified      => $self->_iso($verified),
    last_status        => $check->{status},
    last_checked       => $self->_iso( $self->_epoch( $check->{time} ) ),
    state_error        => $problem,
  };
}

1;
