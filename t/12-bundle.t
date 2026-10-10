#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use lib 't/lib';

use SICK::Bundle;
use SICK::OpenSSL;
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# SICK::Bundle: PEM in, and what openssl reads from the certificate out.
# All certificates are made here, into a temporary directory.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

my $root    = new_ca( dir => $tmp, name => 'root',    cn => 'SICK Test Root' );
my $foreign = new_ca( dir => $tmp, name => 'foreign', cn => 'Somebody Else' );
my $inter   = new_ca( dir => $tmp, name => 'inter',   cn => 'SICK Test Intermediate', issuer => $root );

my $leaf = new_cert(
  ca   => $root,
  dir  => $tmp,
  name => 'leaf',
  cn   => 'Ant.Example.Internal',
  san  => 'DNS:Zebra.Example.Internal,DNS:Ant.Example.Internal,IP:192.0.2.199,IP:2001:db8::1',
  days => 10,
);
my $cn_only = new_cert( ca => $root, dir => $tmp, name => 'cnonly', cn => 'Legacy.Example.Internal' );
my $deep    = new_cert( ca => $inter, dir => $tmp, name => 'deep', cn => 'deep.example.internal',
  san => 'DNS:deep.example.internal' );

subtest 'parts' => sub {
  my $bundle = SICK::Bundle->new( cert => $leaf->{cert_pem}, key => $leaf->{key_pem} );
  isa_ok $bundle, 'SICK::Bundle';
  like $bundle->cert, qr/\A-----BEGIN CERTIFICATE-----\n.+\n-----END CERTIFICATE-----\n\z/s, 'cert is one PEM block';
  is $bundle->chain, undef, 'no chain';
  like $bundle->key, qr/\A-----BEGIN [A-Z ]*PRIVATE KEY-----\n.+PRIVATE KEY-----\n\z/s, 'key is a PEM block';
  is $bundle->fullchain, $bundle->cert, 'fullchain without a chain is the certificate';

  my $no_key = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  is $no_key->key, undef, 'a bundle without a key';

  my $chained = SICK::Bundle->new( cert => $deep->{cert_pem}, chain => $inter->{pem} );
  is $chained->chain, $inter->{pem}, 'chain';
  is $chained->fullchain, $deep->{cert_pem}.$inter->{pem}, 'fullchain is certificate plus chain';

  my $from_fullchain = SICK::Bundle->new( cert => "junk before\n".$deep->{cert_pem}."\n\n".$inter->{pem}, chain => $root->{pem} );
  is $from_fullchain->cert,  $deep->{cert_pem}, 'several certificates in cert: the first is the certificate';
  is $from_fullchain->chain, $inter->{pem}.$root->{pem}, '... the others go in front of the chain';

  ( my $crlf = $leaf->{cert_pem} ) =~ s/\n/\r\n/g;
  is( SICK::Bundle->new( cert => $crlf )->cert, $leaf->{cert_pem}, 'CRLF line ends are normalized' );
};

subtest 'names from the SAN, DNS and IP mixed' => sub {
  my $bundle = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  is_deeply $bundle->names,
    [ '192.0.2.199', '2001:db8::1', 'ant.example.internal', 'zebra.example.internal' ],
    'lower case, sorted, IPv6 in its short form';
  is_deeply $bundle->dns_names, [ 'ant.example.internal', 'zebra.example.internal' ], 'dns_names';
  is_deeply $bundle->ip_names, [ '192.0.2.199', '2001:db8::1' ], 'ip_names';

  push @{ $bundle->names }, 'tampered';
  is scalar @{ $bundle->names }, 4, 'names returns a copy';
};

subtest 'names fall back to the CN without a SAN' => sub {
  my $bundle = SICK::Bundle->new( cert => $cn_only->{cert_pem} );
  is_deeply $bundle->names,     ['legacy.example.internal'], 'the common name, lower case';
  is_deeply $bundle->dns_names, ['legacy.example.internal'], '... counts as a DNS name';
  is_deeply $bundle->ip_names,  [], '... and never as an IP SAN';
};

subtest 'validity, fingerprint, subject and issuer' => sub {
  my $bundle = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  my $now    = time;

  cmp_ok abs( $bundle->not_before - $now ), '<', 300, 'not_before is about now';
  is $bundle->not_after - $bundle->not_before, 10 * 86400, 'not_after is ten days later';

  my ($enddate) = SICK::OpenSSL::run( [ 'x509', '-noout', '-enddate', '-in', $leaf->{cert} ] );
  my @utc = gmtime $bundle->not_after;
  my $year = $utc[5] + 1900;
  like $enddate, qr/\b$utc[3] \Q${\ sprintf '%02d:%02d:%02d', @utc[ 2, 1, 0 ] }\E $year GMT/,
    'not_after is the moment openssl prints';

  my $fingerprint = $bundle->fingerprint_sha256;
  like $fingerprint, qr/\A[0-9a-f]{64}\z/, 'fingerprint: 64 lower-case hex digits';
  is( SICK::Bundle->new( cert => $leaf->{cert_pem} )->fingerprint_sha256, $fingerprint, 'stable across objects' );
  isnt( SICK::Bundle->new( cert => $cn_only->{cert_pem} )->fingerprint_sha256, $fingerprint,
    'another certificate has another one' );

  my ($der) = SICK::OpenSSL::run( [ 'x509', '-in', $leaf->{cert}, '-outform', 'DER' ] );
  my ($digest) = SICK::OpenSSL::run( [ 'dgst', '-sha256', '-r' ], stdin => $der );
  is $fingerprint, ( split /\s/, $digest )[0], 'it is the SHA-256 of the DER certificate';

  is $bundle->subject_dn, 'CN=Ant.Example.Internal', 'subject_dn';
  is $bundle->issuer_dn,  'CN=SICK Test Root',       'issuer_dn';

  is $bundle->common_name, 'Ant.Example.Internal', 'common_name, as written in the certificate';
  is( SICK::Bundle->new( cert => $root->{pem} )->common_name, 'SICK Test Root', '... of a CA' );
  ok !$bundle->is_self_signed, 'a certificate of a CA is not self-signed';
  ok !SICK::Bundle->new( cert => $inter->{pem} )->is_self_signed, '... nor is an intermediate';
  ok( SICK::Bundle->new( cert => $root->{pem} )->is_self_signed, 'a root certificate is' );
};

subtest 'is_ca and signs_itself' => sub {
  my $lone = new_ca( dir => $tmp, name => 'lone', cn => 'lone.example.internal', extensions => 'leaf_ext' );
  ok( SICK::Bundle->new( cert => $root->{pem} )->is_ca,  'a root is a CA' );
  ok( SICK::Bundle->new( cert => $inter->{pem} )->is_ca, '... and so is an intermediate' );
  ok !SICK::Bundle->new( cert => $leaf->{cert_pem} )->is_ca, 'a leaf is not';
  ok !SICK::Bundle->new( cert => $lone->{pem} )->is_ca, '... self-signed or not';

  ok( SICK::Bundle->new( cert => $root->{pem} )->signs_itself, 'a root signs itself' );
  ok !SICK::Bundle->new( cert => $inter->{pem} )->signs_itself, 'an intermediate does not';
  ok !SICK::Bundle->new( cert => $leaf->{cert_pem} )->signs_itself, '... nor does a leaf';
  SKIP: {
    skip 'a certificate without key identifiers needs OpenSSL 3', 2 unless SICK::OpenSSL::major() >= 3;
    my $signer = new_ca( dir => $tmp, name => 'twin-signer', cn => 'Twin' );
    my $forged = SICK::Bundle->new(
      cert => new_ca( dir => $tmp, name => 'twin', cn => 'Twin', issuer => $signer, extensions => 'forged_ca_ext' )->{pem} );
    ok $forged->is_self_signed, 'a certificate signed by another key under the same name looks self-signed';
    ok !$forged->signs_itself, '... but does not sign itself';
  }
};

subtest 'key_matches' => sub {
  my $other = new_cert( ca => $root, dir => $tmp, name => 'other-key', cn => 'other.example.internal' );
  ok( SICK::Bundle->new( cert => $leaf->{cert_pem}, key => $leaf->{key_pem} )->key_matches,
    'the key of the certificate matches' );
  ok( SICK::Bundle->from_files( cert => $deep->{cert}, chain => $inter->{cert}, key => $deep->{key} )->key_matches,
    '... also with a chain' );
  my $mixed = SICK::Bundle->new( cert => $leaf->{cert_pem}, key => $other->{key_pem} );
  ok !$mixed->key_matches, 'the key of another certificate does not';

  my $ok = eval { SICK::Bundle->new( cert => $leaf->{cert_pem} )->key_matches; 1 };
  ok !$ok, 'key_matches dies for a bundle without a key';
  like $@, qr/^key_matches: the bundle has no key/, '... saying so';

  # a key block openssl cannot read: the message holds no key material
  ( my $broken = $leaf->{key_pem} ) =~ s/(-----\n)[A-Za-z0-9+\/]{8}/${1}AAAAAAAA/;
  $ok = eval { SICK::Bundle->new( cert => $leaf->{cert_pem}, key => $broken )->key_matches; 1 };
  ok !$ok, 'key_matches dies for a key openssl cannot read';
  like $@, qr/^cannot read the private key of the bundle: openssl/, '... saying so';
  unlike $@, qr/PRIVATE KEY|AAAAAAAA/, '... without the key';
};

subtest 'is_issued_by' => sub {
  my $bundle = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  ok $bundle->is_issued_by( $root->{pem} ), 'true for the CA that signed it';
  ok !$bundle->is_issued_by( $foreign->{pem} ), 'false for another CA';

  my $same_name = new_ca( dir => $tmp, name => 'imposter', cn => 'SICK Test Root' );
  ok !$bundle->is_issued_by( $same_name->{pem} ), 'false for another CA of the same name';

  my $bare    = SICK::Bundle->new( cert => $deep->{cert_pem} );
  my $chained = SICK::Bundle->new( cert => $deep->{cert_pem}, chain => $inter->{pem} );
  ok $chained->is_issued_by( $root->{pem} ), 'true through the intermediate of the chain';
  ok !$bare->is_issued_by( $root->{pem} ), 'false when the intermediate is missing';
  ok $bare->is_issued_by( $root->{pem}.$inter->{pem} ), 'true when the intermediate comes with the CA';
  ok !$chained->is_issued_by( $foreign->{pem} ), 'the chain does not make a foreign CA ours';

  # what a device that sends its certificate alone needs: the intermediates
  # of the CA as a second argument, helping but not trusted
  ok $bare->is_issued_by( $root->{pem}, $inter->{pem} ), 'true with the intermediates handed over';
  ok $bare->is_issued_by( $root->{pem}, $foreign->{pem}.$inter->{pem} ), '... also among others';
  ok $bundle->is_issued_by( $root->{pem}, $inter->{pem} ), '... and they do no harm where none is needed';
  ok $bare->is_issued_by( $root->{pem}, undef ) == 0, 'undef is no intermediates';
  ok !$bare->is_issued_by( $root->{pem}, q{} ),        '... and so is the empty string';
  ok !$bare->is_issued_by( $foreign->{pem}, $inter->{pem} ), 'intermediates are no trust anchors: the chain has to end at the CA';
  ok !$bare->is_issued_by( $foreign->{pem}, $inter->{pem}.$root->{pem} ), '... even with the real root among them';
  my $lived = eval { $bare->is_issued_by( $root->{pem}, 'nonsense' ); 1 };
  ok !$lived, 'dies for intermediates that are no certificates';
  like $@, qr/^is_issued_by: the intermediates are not PEM certificates/, '... saying so';

  my $ok = eval { $bundle->is_issued_by('nonsense'); 1 };
  ok !$ok, 'dies without a CA certificate';
  like $@, qr/^is_issued_by needs the PEM certificate of a CA/, '... saying so';
};

subtest 'is_issued_by ignores the trust store of the system' => sub {
  my ($where) = SICK::OpenSSL::run( [ 'version', '-d' ] );
  my ($dir) = $where =~ /"(.+)"/;
  my ($public) = defined $dir ? grep { -f && -r } glob( $dir.'/certs/*.pem' ) : ();
  plan skip_all => 'no certificate found in the default trust store' unless defined $public;

  my $bundle = eval { SICK::Bundle->from_files( cert => $public ) };
  plan skip_all => 'cannot read '.$public unless $bundle;
  ok !$bundle->is_issued_by( $root->{pem} ), 'a publicly trusted certificate is not issued by our CA';
};

subtest 'is_issued_by ignores the validity period' => sub {
  my $expired = new_cert( ca => $root, dir => $tmp, name => 'expired', cn => 'old.example.internal',
    san => 'DNS:old.example.internal', days => 0 );
  my $bundle = SICK::Bundle->new( cert => $expired->{cert_pem} );
  sleep 2;
  cmp_ok $bundle->not_after, '<', time, 'the certificate is expired';
  ok $bundle->is_issued_by( $root->{pem} ), '... and still issued by its CA';
};

subtest 'from_files' => sub {
  my $bundle = SICK::Bundle->from_files( cert => $deep->{cert}, chain => $inter->{cert}, key => $deep->{key} );
  is $bundle->cert,  $deep->{cert_pem}, 'cert';
  is $bundle->chain, $inter->{pem},     'chain';
  is $bundle->key,   $deep->{key_pem},  'key';

  my $cert_only = SICK::Bundle->from_files( cert => $deep->{cert} );
  is $cert_only->key, undef, 'chain and key are optional';

  for my $part (qw( cert chain key )) {
    my %files = ( cert => $deep->{cert}, chain => $inter->{cert}, key => $deep->{key} );
    $files{$part} = $tmp.'/does-not-exist.pem';
    my $label = $part eq 'cert' ? 'certificate' : $part;
    my $ok = eval { SICK::Bundle->from_files(%files); 1 };
    ok !$ok, 'dies when the '.$part.' file is missing';
    like $@, qr/^cannot read $label file '\Q$tmp\E\/does-not-exist\.pem': \S/, '... with path and reason';
  }

  my $ok = eval { SICK::Bundle->from_files( cert => $tmp ); 1 };
  ok !$ok, 'dies for a directory';
  like $@, qr/^cannot read certificate file '\Q$tmp\E': Is a directory/, '... saying so';
};

subtest 'bad input' => sub {
  my $ok = eval { SICK::Bundle->new( cert => 'no certificate here' ); 1 };
  ok !$ok, 'dies when cert has no PEM certificate';
  like $@, qr/^cert is not a PEM certificate/, '... saying so';

  $ok = eval { SICK::Bundle->new( key => $leaf->{key_pem} ); 1 };
  ok !$ok, 'dies without cert';

  $ok = eval { SICK::Bundle->new( cert => $leaf->{cert_pem}, chain => 'nonsense' ); 1 };
  ok !$ok, 'dies when a given chain has no PEM certificate';
  like $@, qr/^chain is not a list of PEM certificates/, '... saying so';

  my $marker = 'KEY-MATERIAL-MARKER';
  $ok = eval { SICK::Bundle->new( cert => $leaf->{cert_pem}, key => $marker ); 1 };
  ok !$ok, 'dies when key is no PEM private key';
  like $@, qr/^key is not a PEM private key/, '... saying so';
  unlike $@, qr/$marker/, '... without repeating what it was given';

  my $broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
  my $bundle = SICK::Bundle->new( cert => $broken );
  $ok = eval { $bundle->names; 1 };
  ok !$ok, 'a PEM block that is no certificate dies when it is read';
  like $@, qr/^cannot read the certificate: openssl x509 failed/, '... with the reason of openssl';
  $ok = eval { $bundle->not_after; 1 };
  ok !$ok, '... for every derived value';
};

done_testing;
