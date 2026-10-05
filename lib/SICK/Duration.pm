package SICK::Duration;
# ABSTRACT: Parse the durations of a SICK device list into seconds

use strict;
use warnings;
use Carp qw( croak );

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Duration;

    my $lifetime = SICK::Duration::parse('397d');   # 34300800
    my $renew    = SICK::Duration::parse('12h');    # 43200
    my $seconds  = SICK::Duration::parse('90');     # 90

=head1 DESCRIPTION

The C<lifetime> and C<renew_before> settings of a device list are written as
a number with a unit. This module turns them into seconds, which is what the
rest of SICK computes with. Nothing is exported.

=cut

my %SECONDS = (
  d   => 86400,
  h   => 3600,
  m   => 60,
  s   => 1,
  q{} => 1
);

sub parse {
  my ( $text ) = @_;
  $text = '' unless defined $text;
  croak 'invalid duration \''.$text.'\''
    if ref $text || $text !~ /\A([0-9]+)([dhms]?)\z/;
  return $1 * $SECONDS{$2};
}

=func parse

    my $seconds = SICK::Duration::parse($text);

Takes a whole number followed by one unit - C<d> for days, C<h> for hours,
C<m> for minutes, C<s> for seconds - or a bare number, which is seconds:
C<30d>, C<12h>, C<45m>, C<90s>, C<3600>. Units are lower case and are not
combined; there is no C<1d12h>.

Croaks with C<< invalid duration '<text>' >> for everything else, including
an empty or undefined value, fractions, signs and surrounding whitespace.

=cut

1;
