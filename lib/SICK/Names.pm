package SICK::Names;
# ABSTRACT: Normalize and compare the DNS names and IP addresses of a certificate

use strict;
use warnings;
use Socket qw( AF_INET AF_INET6 inet_ntop inet_pton );

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Names;

    SICK::Names::is_ip('192.0.2.199');             # 4
    SICK::Names::is_ip('2001:DB8::1');             # 6
    SICK::Names::is_ip('ant.example.internal');    # 0

    SICK::Names::normalize('Ant.Example.Internal');     # 'ant.example.internal'
    SICK::Names::normalize('2001:DB8:0:0:0:0:0:1');     # '2001:db8::1'

    my $sorted = SICK::Names::canonical( [ 'B.example', 'a.example', 'b.example' ] );
    # [ 'a.example', 'b.example' ]

=head1 DESCRIPTION

The names of a device are written by a person, the names of a certificate
are printed by C<openssl>. Before the two can be compared they need one
spelling: lower case, and one text form per IP address. These are the
functions the device list, the issuers and L<SICK::Decision> share for that.
Nothing is exported.

=cut

sub is_ip {
  my ( $name ) = @_;
  return 0 if !defined $name || ref $name;
  return 4
    if $name =~ /\A[0-9]{1,3}(?:\.[0-9]{1,3}){3}\z/
    && defined inet_pton( AF_INET, $name );
  return 6
    if $name =~ /:/
    && $name =~ /\A[0-9A-Fa-f:.]+\z/
    && defined inet_pton( AF_INET6, $name );
  return 0;
}

=func is_ip

    my $family = SICK::Names::is_ip($name);

C<4> for an IPv4 address, C<6> for an IPv6 address, C<0> for everything
else. An IP address belongs into an IP SAN of a certificate, not into a DNS
SAN, so this is what decides between the two.

=cut

sub normalize {
  my ( $name ) = @_;
  return q{} if !defined $name || ref $name;
  $name =~ s/\A\s+//;
  $name =~ s/\s+\z//;
  my $family = is_ip($name);
  return inet_ntop( AF_INET,  inet_pton( AF_INET,  $name ) ) if $family == 4;
  return inet_ntop( AF_INET6, inet_pton( AF_INET6, $name ) ) if $family == 6;
  return lc $name;
}

=func normalize

    my $name = SICK::Names::normalize($name);

Lower case without surrounding whitespace; an IP address in the one form the
system prints it in (C<2001:db8::1>, not C<2001:DB8:0:0:0:0:0:1>).

=cut

sub is_valid {
  my ( $name ) = @_;
  return 0 if !defined $name || ref $name || !length $name || length $name > 253;
  return 1 if is_ip($name);
  return 0 if $name =~ /\A[0-9.]+\z/;    # looks like an address, is none
  return $name =~ /\A(?:\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\z/
    ? 1
    : 0;
}

=func is_valid

    my $bool = SICK::Names::is_valid($name);

True for an IP address and for a host name: labels of letters, digits,
hyphens and underscores separated by dots, optionally with a leading C<*.>.
Everything a name is later handed to - a command line, an OpenSSL
configuration value - relies on this: no whitespace, no comma, no slash.

=cut

sub canonical {
  my ( $names ) = @_;
  my %seen;
  return [ sort grep { length && !$seen{$_}++ } map { normalize($_) } @{ $names || [] } ];
}

=func canonical

    my $names = SICK::Names::canonical( \@names );

A new array reference with the normalized names, sorted, without duplicates.

=cut

sub split_names {
  my ( $names ) = @_;
  my ( @dns, @ip );
  for my $name ( @{ canonical($names) } ) {
    if ( is_ip($name) ) { push @ip, $name }
    else                { push @dns, $name }
  }
  return ( \@dns, \@ip );
}

=func split_names

    my ( $dns, $ip ) = SICK::Names::split_names( \@names );

The canonical names in two array references: host names and IP addresses.

=cut

sub san_from_text {
  my ( $text ) = @_;
  my ( @dns, @ip );
  my @lines = split /\r?\n/, defined $text ? $text : q{};
  while ( defined( my $line = shift @lines ) ) {
    next unless $line =~ /X509v3 Subject Alternative Name:/;
    my $list = shift @lines;
    last unless defined $list;
    for my $entry ( split /,\s*/, $list ) {
      $entry =~ s/\A\s+//;
      $entry =~ s/\s+\z//;
      if    ( $entry =~ /\ADNS:(.+)\z/ )          { push @dns, $1 }
      elsif ( $entry =~ /\AIP Address:(.+)\z/ )   { push @ip,  $1 }
    }
    last;
  }
  return ( canonical( \@dns ), canonical( \@ip ) );
}

=func san_from_text

    my ( $dns, $ip ) = SICK::Names::san_from_text($openssl_text);

Reads the I<Subject Alternative Name> extension out of what
C<openssl x509 -text> or C<openssl req -text> prints and returns the DNS
names and the IP addresses, each canonical. Other kinds of names (e-mail,
URI) are skipped. Two empty lists when there is no such extension.

=cut

sub cn_from_text {
  my ( $text ) = @_;
  my $cn;
  for my $line ( split /\r?\n/, defined $text ? $text : q{} ) {
    $cn = $1 if $line =~ /\A\s*commonName\s*=\s*(.*?)\s*\z/;
  }
  return $cn;
}

=func cn_from_text

    my $cn = SICK::Names::cn_from_text($openssl_text);

The common name out of a subject printed with C<-nameopt multiline>, as
C<openssl> printed it, or C<undef> when the subject has none.

=cut

1;
