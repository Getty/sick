#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use lib 't/lib';

use SICK::Bundle;
use SICK::Decision;
use SICK::Device;
use SICK::OpenSSL;
use Test::SICK::PKI qw( new_ca new_cert );

# SICK::Decision::evaluate: renew or not, and why. The certificates are made
# here; the clock is an argument.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp     = tempdir( CLEANUP => 1 );
my $root    = new_ca( dir => $tmp, name => 'root',    cn => 'Decision Root' );
my $foreign = new_ca( dir => $tmp, name => 'foreign', cn => 'Factory Default CA' );
my $inter   = new_ca( dir => $tmp, name => 'inter',   cn => 'Decision Intermediate', issuer => $root );

my $DAY   = 86400;
my $count = 0;

sub device {
  my ( @names ) = @_;
  return SICK::Device->new(
    name         => 'web',
    type         => 'files',
    names        => \@names,
    lifetime     => 90 * $DAY,
    renew_before => 30 * $DAY,
    key          => 'rsa2048'
  );
}

sub presented {
  my ( %arg ) = @_;
  my $cert = new_cert( dir => $tmp, name => 'cert'.++$count, ca => $root, days => 90, %arg );
  return SICK::Bundle->new( cert => $cert->{cert_pem} );
}

sub decide {
  my ( $device, $presented, %arg ) = @_;
  return SICK::Decision::evaluate(
    device    => $device,
    presented => $presented,
    root_pem  => $root->{pem},
    now       => time,
    %arg,
  );
}

my $web      = device( 'web.example.internal', '192.0.2.7' );
my $web_cert = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:192.0.2.7' );

subtest 'ok' => sub {
  my $decision = decide( $web, $web_cert, now => $web_cert->not_before + 3600 );
  is_deeply [ sort keys %$decision ], [qw( detail reason renew )], 'renew, reason and detail';
  is $decision->{renew},  0,    'nothing to do';
  is $decision->{reason}, 'ok', 'reason ok';
  like $decision->{detail}, qr/^valid until \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC, 89 days left$/, 'detail says until when';
};

subtest 'missing' => sub {
  my $decision = decide( $web, undef );
  is $decision->{renew},  1,         'renew';
  is $decision->{reason}, 'missing', 'reason missing';
  like $decision->{detail}, qr/no certificate/, 'detail';
};

subtest 'foreign-ca' => sub {
  my $decision = decide( $web, presented( ca => $foreign, cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:192.0.2.7' ) );
  is $decision->{renew},  1,            'renew';
  is $decision->{reason}, 'foreign-ca', 'reason foreign-ca';
  is $decision->{detail}, 'issued by CN=Factory Default CA', 'detail names the issuer';
};

subtest 'names' => sub {
  my $decision = decide( $web, presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,DNS:old.example.internal' ) );
  is $decision->{renew},  1,       'renew';
  is $decision->{reason}, 'names', 'reason names';
  is $decision->{detail}, 'unexpected DNS name old.example.internal; missing IP address 192.0.2.7', 'detail lists what differs';
};

subtest 'expiring' => sub {
  my $end = $web_cert->not_after;

  my $decision = decide( $web, $web_cert, now => $end - 30 * $DAY + 1 );
  is $decision->{renew},  1,          'renew when less than renew_before is left';
  is $decision->{reason}, 'expiring', 'reason expiring';
  like $decision->{detail}, qr/^valid until .+ UTC, 29 days left$/, 'detail says how long';

  $decision = decide( $web, $web_cert, now => $end - 30 * $DAY );
  is $decision->{reason}, 'ok', 'exactly renew_before left is not yet less';

  $decision = decide( $web, $web_cert, now => $end - 3 * 3600 );
  is $decision->{reason}, 'expiring', 'hours before the end';
  like $decision->{detail}, qr/, 3 hours left$/, '... counted in hours';

  $decision = decide( $web, $web_cert, now => $end + 5 * $DAY );
  is_deeply [ @$decision{qw( renew reason )} ], [ 1, 'expiring' ], 'a certificate of ours that has expired is expiring, not foreign';
  like $decision->{detail}, qr/^expired \d{4}-\d\d-\d\d/, '... and the detail says expired';

  my $short = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:192.0.2.7', days => 10 );
  is decide( $web, $short )->{reason}, 'expiring', 'a certificate that never had renew_before to live';
};

subtest 'the order of the checks' => sub {
  my $foreign_wrong_short = presented( ca => $foreign, cn => 'other.example.internal', san => 'DNS:other.example.internal', days => 1 );
  is decide( $web, $foreign_wrong_short )->{reason}, 'foreign-ca', 'foreign CA before names and expiry';

  my $wrong_short = presented( cn => 'other.example.internal', san => 'DNS:other.example.internal', days => 1 );
  is decide( $web, $wrong_short )->{reason}, 'names', 'names before expiry';
};

subtest 'names: case and order do not matter' => sub {
  my $device = device( 'Zeta.Example.Internal', 'alpha.EXAMPLE.internal', '192.0.2.7' );
  my $cert = presented( cn => 'ALPHA.example.internal', san => 'IP:192.0.2.7,DNS:ALPHA.Example.Internal,DNS:zeta.example.INTERNAL' );
  is decide( $device, $cert )->{reason}, 'ok', 'same names in another order and spelling';

  my $twice = device( 'web.example.internal', 'WEB.example.internal', '192.0.2.7' );
  is decide( $twice, $web_cert )->{reason}, 'ok', 'a name listed twice is one name';
};

subtest 'names: one too many or one too few' => sub {
  my $extra = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:192.0.2.7,DNS:extra.example.internal' );
  my $decision = decide( $web, $extra );
  is $decision->{reason}, 'names', 'an additional name in the certificate';
  is $decision->{detail}, 'unexpected DNS name extra.example.internal', '... is named';

  my $fewer = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal' );
  $decision = decide( $web, $fewer );
  is $decision->{reason}, 'names', 'a name missing from the certificate';
  is $decision->{detail}, 'missing IP address 192.0.2.7', '... is named';

  my $extra_ip = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:192.0.2.7,IP:192.0.2.8' );
  is decide( $web, $extra_ip )->{detail}, 'unexpected IP address 192.0.2.8', 'an additional address';

  my $several = presented( cn => 'web.example.internal', san => 'DNS:b.example.internal,DNS:a.example.internal,IP:192.0.2.7' );
  is decide( $web, $several )->{detail},
    'missing DNS name web.example.internal; unexpected DNS names a.example.internal, b.example.internal',
    'several differences at once';
};

subtest 'names: an IP address is an IP SAN' => sub {
  is decide( $web, $web_cert )->{reason}, 'ok', 'the address of the device is found in the IP SAN';

  my $as_dns = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,DNS:192.0.2.7' );
  my $decision = decide( $web, $as_dns );
  is $decision->{reason}, 'names', 'an address in a DNS SAN is not an IP SAN';
  is $decision->{detail}, 'unexpected DNS name 192.0.2.7; missing IP address 192.0.2.7', '... and the detail shows both sides';

  my $v6_device = device( 'web.example.internal', '2001:0DB8:0000:0000:0000:0000:0000:0007' );
  my $v6_cert = presented( cn => 'web.example.internal', san => 'DNS:web.example.internal,IP:2001:db8::7' );
  is decide( $v6_device, $v6_cert )->{reason}, 'ok', 'IPv6 addresses match however they are written';

  my $only_ip = device('192.0.2.7');
  is decide( $only_ip, presented( cn => '192.0.2.7', san => 'IP:192.0.2.7' ) )->{reason}, 'ok', 'a device that is only an address';
};

subtest 'names: certificates without SAN' => sub {
  my $single = device('legacy.example.internal');
  is decide( $single, presented( cn => 'Legacy.Example.Internal' ) )->{reason}, 'ok',
    'the common name stands in for a missing SAN';
  is decide( $web, presented( cn => 'web.example.internal' ) )->{reason}, 'names',
    '... but it is only one name';
  is decide( device('192.0.2.7'), presented( cn => '192.0.2.7' ) )->{reason}, 'names',
    'an address as common name is not an IP SAN';
};

subtest 'intermediates' => sub {
  my $leaf = new_cert( dir => $tmp, name => 'deep', ca => $inter, cn => 'web.example.internal',
    san => 'DNS:web.example.internal,IP:192.0.2.7', days => 90 );

  my $with_chain = SICK::Bundle->new( cert => $leaf->{cert_pem}, chain => $inter->{pem} );
  is decide( $web, $with_chain )->{reason}, 'ok', 'a device that sends the intermediate along';

  my $bare = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  is decide( $web, $bare )->{reason}, 'foreign-ca', 'a device that does not: the root alone cannot vouch for it';
  is decide( $web, $bare, root_pem => $root->{pem}.$inter->{pem} )->{reason}, 'ok',
    '... unless root_pem carries the intermediate';
};

subtest 'arguments' => sub {
  my $decision = SICK::Decision::evaluate( device => $web, presented => $web_cert, root_pem => $root->{pem} );
  is $decision->{reason}, 'ok', 'now defaults to the current time';

  my $ok = eval { SICK::Decision::evaluate( presented => $web_cert, root_pem => $root->{pem} ); 1 };
  ok !$ok, 'dies without a device';
  $ok = eval { SICK::Decision::evaluate( device => $web, presented => $web_cert ); 1 };
  ok !$ok, 'dies without root_pem';
  like $@, qr/^evaluate needs root_pem/, '... saying so';
};

done_testing;
