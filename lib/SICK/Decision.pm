package SICK::Decision;
# ABSTRACT: Decide whether the certificate a device presents has to be renewed

use strict;
use warnings;
use Carp qw( croak );
use POSIX qw( strftime );
use SICK::Names;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Decision;

    my $decision = SICK::Decision::evaluate(
      device            => $device,                      # SICK::Device
      presented         => $target->presented_cert,      # SICK::Bundle or undef
      root_pem          => $issuer->root_pem,
      intermediates_pem => $issuer->intermediates_pem,   # or undef
      now               => time,
    );

    if ( $decision->{renew} ) {
      print $device->name, ': ', $decision->{reason}, ' (', $decision->{detail}, ")\n";
    }

=head1 DESCRIPTION

The first step of every run, and the last: look at the certificate a device
presents and say whether it is the one it should have. Nothing is exported,
nothing is changed, and nothing but the arguments decides the answer - the
clock included.

=cut

sub evaluate {
  my ( %arg ) = @_;
  my $device = $arg{device};
  croak 'evaluate needs a device' unless ref $device && eval { $device->can('names') };
  croak 'evaluate needs root_pem' unless defined $arg{root_pem} && length $arg{root_pem};
  croak 'evaluate: intermediates_pem must be PEM text' if ref $arg{intermediates_pem};
  my $now       = defined $arg{now} ? $arg{now} : time;
  my $presented = $arg{presented};

  return _answer( 1, 'missing', 'the device presents no certificate' )
    unless defined $presented;

  return _answer( 1, 'foreign-ca', 'issued by '._readable_dn( $presented->issuer_dn ) )
    unless $presented->is_issued_by( $arg{root_pem}, $arg{intermediates_pem} );

  my ( $want_dns, $want_ip ) = SICK::Names::split_names( $device->names );
  my @differences = (
    _difference( 'DNS name', 'DNS names', $want_dns, $presented->dns_names ),
    _difference( 'IP address', 'IP addresses', $want_ip, $presented->ip_names )
  );
  return _answer( 1, 'names', join( '; ', @differences ) ) if @differences;

  my $left = $presented->not_after - $now;
  my $end  = strftime( '%Y-%m-%d %H:%M:%S UTC', gmtime $presented->not_after );
  return _answer( 1, 'expiring', 'expired '.$end ) if $left <= 0;
  return _answer( 1, 'expiring', 'valid until '.$end.', '._span($left).' left' )
    if $left < $device->renew_before;

  return _answer( 0, 'ok', 'valid until '.$end.', '._span($left).' left' );
}

=func evaluate

    my $decision = SICK::Decision::evaluate(
      device            => $device,
      presented         => $bundle_or_undef,
      root_pem          => $pem,
      intermediates_pem => $pem_or_undef,
      now               => $epoch,
    );

Returns C<< { renew => 0|1, reason => $reason, detail => $text } >>. The
checks run in this order and the first one that applies is the answer:

=over 4

=item C<missing>

C<presented> is C<undef>: the device has no certificate to show.

=item C<foreign-ca>

The certificate is not issued by the CA of C<root_pem>
(L<SICK::Bundle/is_issued_by>): no chain of signatures leads from it to that
root. The chain is built from what the device sent along and from
C<intermediates_pem>, the intermediate certificates of the CA
(L<SICK::Issuer/intermediates_pem>). A CA like step-ca signs with an
intermediate, and a device that presents its certificate alone would be
C<foreign-ca> forever without them. C<detail> names the issuer; parts of
its name that hold nothing but blanks are left out.

=item C<names>

The certificate does not carry exactly the names of the device. Case and
order do not matter; one name too few or one too many does. Host names are
compared with the DNS SANs and IP addresses with the IP SANs: an address
that only stands in a DNS SAN, or in the common name of a certificate
without SANs, is not there.

=item C<expiring>

Less than C<renew_before> of the device is left until the certificate ends,
or it has ended.

=item C<ok>

None of the above. This is the only answer with C<< renew => 0 >>.

=back

C<detail> is one line for a human: who issued it, which names differ, until
when it is valid.

C<now> defaults to the current time. A device that could not be reached is
not a case for this function: there is no certificate to judge, and "no
answer" is not "no certificate" (see L<SICK::Target/presented_cert>).

=cut

sub _answer {
  my ( $renew, $reason, $detail ) = @_;
  return { renew => $renew, reason => $reason, detail => $detail };
}

# An RFC 2253 name for a table cell: without the relative names whose value
# is nothing but blanks (some devices fill every field of a subject they
# were not given, "C=\ \ ,O=\ "), and without the backslash in front of a
# blank that stays.
sub _readable_dn {
  my ( $dn ) = @_;
  return '(no name)' unless defined $dn && $dn =~ /\S/;
  my @shown;
  for my $rdn ( $dn =~ /((?:\\.|[^\\,])+)/sg ) {
    my ( $type, $value ) = $rdn =~ /\A\s*([^=]+)=(.*)\z/s or next;
    $value =~ s/\\ / /g;
    $value =~ s/\A\s+//;
    $value =~ s/\s+\z//;
    push @shown, $type.'='.$value if length $value;
  }
  return @shown ? join( ',', @shown ) : '(a name of blanks)';
}

sub _difference {
  my ( $one, $many, $want, $have ) = @_;
  my %want = map { $_ => 1 } @$want;
  my %have = map { $_ => 1 } @$have;
  my @missing    = grep { !$have{$_} } @$want;
  my @unexpected = grep { !$want{$_} } @$have;
  return (
    ( @missing    ? 'missing '.( @missing == 1       ? $one : $many ).' '.join( ', ', @missing )       : () ),
    ( @unexpected ? 'unexpected '.( @unexpected == 1 ? $one : $many ).' '.join( ', ', @unexpected ) : () )
  );
}

sub _span {
  my ( $seconds ) = @_;
  return int( $seconds / 86400 ).' days'    if $seconds >= 2 * 86400;
  return int( $seconds / 3600 ).' hours'    if $seconds >= 2 * 3600;
  return int( $seconds / 60 ).' minutes'    if $seconds >= 2 * 60;
  return $seconds.' seconds';
}

1;
