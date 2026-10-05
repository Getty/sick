#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use SICK::Names;

# SICK::Names: one spelling for the names of devices and certificates.

subtest 'is_ip' => sub {
  is SICK::Names::is_ip('192.0.2.199'),          4, 'IPv4';
  is SICK::Names::is_ip('2001:db8::1'),          6, 'IPv6';
  is SICK::Names::is_ip('2001:DB8:0:0:0:0:0:1'), 6, 'IPv6 the way openssl prints it';
  is SICK::Names::is_ip('::ffff:192.0.2.1'),     6, 'IPv4-mapped IPv6';
  is SICK::Names::is_ip($_), 0, 'not an address: '.( defined $_ ? $_ : 'undef' )
    for 'ant.example.internal', '999.1.1.1', '1.2.3', '1.2.3.4.5', 'dead:beef', q{}, undef;
};

subtest 'normalize' => sub {
  is SICK::Names::normalize('Ant.Example.INTERNAL'),   'ant.example.internal', 'lower case';
  is SICK::Names::normalize('  ant.example  '),        'ant.example',          'trimmed';
  is SICK::Names::normalize('2001:DB8:0:0:0:0:0:1'),   '2001:db8::1',          'IPv6 in its short form';
  is SICK::Names::normalize('2001:0db8::0001'),        '2001:db8::1',          '... whatever the long form was';
  is SICK::Names::normalize('192.0.2.199'),            '192.0.2.199',          'IPv4 as it is';
  is SICK::Names::normalize(undef),                    q{},                    'undef is empty';
};

subtest 'is_valid' => sub {
  ok SICK::Names::is_valid($_), 'valid: '.$_
    for 'ant.example.internal', 'ANT', 'a-b.example', 'under_score.example', '*.example.internal',
    'xn--bcher-kva.example', '192.0.2.199', '2001:db8::1', '3com.example';
  ok !SICK::Names::is_valid($_), 'invalid: '.( defined $_ ? $_ : 'undef' )
    for q{}, undef, 'two words', 'a,b', 'a/b', '-a.example', 'a-.example', 'a..b', '.a', 'a.', '*.*.example',
    'a*.example', '999.1.1.1', '1.2.3', "a\nb", 'a;b', 'DNS:a', 'x' x 64, join( '.', ('abcdefgh') x 30 );
};

subtest 'canonical and split_names' => sub {
  is_deeply SICK::Names::canonical( [ 'B.example', 'a.example', 'b.example', '10.0.0.2', '10.0.0.10' ] ),
    [ '10.0.0.10', '10.0.0.2', 'a.example', 'b.example' ], 'normalized, unique, sorted as text';
  is_deeply SICK::Names::canonical( [] ),    [], 'empty list';
  is_deeply SICK::Names::canonical(undef), [], 'no list';

  my ( $dns, $ip ) = SICK::Names::split_names( [ 'b.example', '2001:DB8::1', 'A.example', '10.0.0.1' ] );
  is_deeply $dns, [ 'a.example', 'b.example' ], 'host names';
  is_deeply $ip,  [ '10.0.0.1', '2001:db8::1' ], 'addresses';
};

subtest 'what openssl prints' => sub {
  my $text = <<'TEXT';
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Alternative Name:
                DNS:Ant.example, DNS:b.example, IP Address:192.0.2.199, IP Address:2001:DB8:0:0:0:0:0:1, email:a@b.example, URI:https://b.example/
            X509v3 Subject Key Identifier:
                5C:DF:7A:1F
TEXT
  my ( $dns, $ip ) = SICK::Names::san_from_text($text);
  is_deeply $dns, [ 'ant.example', 'b.example' ], 'DNS names';
  is_deeply $ip,  [ '192.0.2.199', '2001:db8::1' ], 'IP addresses; e-mail and URI are skipped';

  ( $dns, $ip ) = SICK::Names::san_from_text("        X509v3 extensions:\n            X509v3 Subject Key Identifier: \n                5C\n");
  is_deeply [ $dns, $ip ], [ [], [] ], 'no SAN extension';
  ( $dns, $ip ) = SICK::Names::san_from_text(undef);
  is_deeply [ $dns, $ip ], [ [], [] ], 'no text';

  is SICK::Names::cn_from_text("subject=\n    organizationName          = Probe, Inc\n    commonName                = Probe CA\n"),
    'Probe CA', 'common name from a multiline subject';
  is SICK::Names::cn_from_text("subject=\n    organizationName          = Probe\n"), undef, 'a subject without one';
};

done_testing;
