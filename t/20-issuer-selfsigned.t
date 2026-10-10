#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use lib 't/lib';

use SICK::Bundle;
use SICK::Issuer;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use Test::SICK::PKI qw( new_csr slurp spew );

# SICK::Issuer::SelfSigned: a CA out of nothing but openssl.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

sub mode_of { sprintf '%04o', ( stat $_[0] )[2] & 07777 }

sub public_key_of {
  my ( $kind, $pem ) = @_;
  my %args = (
    key  => [ 'pkey', '-pubout' ],
    cert => [ 'x509', '-noout', '-pubkey' ],
    csr  => [ 'req',  '-noout', '-pubkey' ]
  );
  my ( $out, $err, $exit ) = SICK::OpenSSL::run( $args{$kind}, stdin => $pem );
  die 'cannot read public key of '.$kind.': '.$err if $exit;
  return $out;
}

my $ca_dir = $tmp.'/ca/nested';
my $issuer = SICK::Issuer::SelfSigned->new( dir => $ca_dir );

subtest 'construction' => sub {
  isa_ok $issuer, 'SICK::Issuer';
  is $issuer->dir, $ca_dir, 'dir';
  ok !-e $ca_dir, 'nothing is created before the first use';

  my $ok = eval { SICK::Issuer::SelfSigned->new; 1 };
  ok !$ok, 'dies without dir';
  like $@, qr/^ca: missing 'dir'/, '... in the words of the device list';

  $ok = eval { SICK::Issuer::SelfSigned->new( dir => $ca_dir, colour => 'blue' ); 1 };
  ok !$ok, 'dies for an unknown argument';
  like $@, qr/^ca: unknown key 'colour'/, '... naming it';

  isa_ok( SICK::Issuer::SelfSigned->new( type => 'selfsigned', dir => $ca_dir ), 'SICK::Issuer::SelfSigned',
    'the type key of the ca section is accepted' );
};

subtest 'the base class is abstract' => sub {
  my $base = SICK::Issuer->new;
  for my $method (qw( issue sign root_pem )) {
    my $ok = eval { $base->$method; 1 };
    ok !$ok, $method.' dies';
    like $@, qr/^SICK::Issuer does not implement $method/, '... saying so';
  }
  is_deeply $base->key_params('rsa2048'), { type => 'rsa', bits => 2048 }, 'rsa2048';
  is_deeply $base->key_params('rsa3072'), { type => 'rsa', bits => 3072 }, 'rsa3072';
  is_deeply $base->key_params('rsa4096'), { type => 'rsa', bits => 4096 }, 'rsa4096';
  is_deeply $base->key_params('ec256'), { type => 'ec', curve => 'P-256' }, 'ec256';
};

my $root_pem;

subtest 'the CA appears on first use' => sub {
  $root_pem = $issuer->root_pem;
  like $root_pem, qr/\A-----BEGIN CERTIFICATE-----\n.+-----END CERTIFICATE-----\n\z/s, 'root_pem is one PEM certificate';
  ok -d $ca_dir, 'the directory was created';
  is mode_of($ca_dir), '0700', '... for the owner only';
  ok -s $ca_dir.'/ca.crt', 'ca.crt';
  ok -s $ca_dir.'/ca.key', 'ca.key';
  is mode_of( $ca_dir.'/ca.key' ), '0600', 'the CA key is mode 0600';
  is_deeply [ sort map { s{.*/}{}r } glob( $ca_dir.'/{.,}*' ) ], [ '.', '..', 'ca.crt', 'ca.key' ], 'nothing else is left there';

  my $root = SICK::Bundle->new( cert => $root_pem );
  is $root->subject_dn, $root->issuer_dn, 'the root is self-signed';
  ok $root->is_issued_by($root_pem), '... and verifies against itself';
  my ($text) = SICK::OpenSSL::run( [ 'x509', '-noout', '-text' ], stdin => $root_pem );
  like $text, qr/CA:TRUE/, '... and is a CA';

  is $issuer->root_pem, $root_pem, 'asking again does not make a new one';
  is( SICK::Issuer::SelfSigned->new( dir => $ca_dir )->root_pem, $root_pem, 'another object on the same dir uses the same CA' );
  isnt( SICK::Issuer::SelfSigned->new( dir => $tmp.'/other-ca' )->root_pem, $root_pem, 'another dir is another CA' );

  my $blocked = $tmp.'/blocked-ca';
  mkdir $blocked, 0700 or die $!;
  mkdir $blocked.'/ca.key', 0700 or die $!;
  my $ok = eval { SICK::Issuer::SelfSigned->new( dir => $blocked )->root_pem; 1 };
  ok !$ok, 'a directory in the place of ca.key is an error';
  like $@, qr/^cannot create the CA in '\Q$blocked\E': cannot write '\Q$blocked\E\/ca\.key': \S/, '... naming it';
  is_deeply [ glob( $blocked.'/ca.key/{.,}*' ) ], [ $blocked.'/ca.key/.', $blocked.'/ca.key/..' ], '... and the key is not moved into it';
};

subtest 'issue' => sub {
  my $lifetime = 36 * 3600;
  my $before   = time;
  my $bundle   = $issuer->issue( {
      names    => [ 'Web.Example.Internal', '192.0.2.7', 'alias.example.internal', '2001:db8::7' ],
      lifetime => $lifetime,
      key      => 'rsa2048'
  } );
  my $after = time;

  isa_ok $bundle, 'SICK::Bundle';
  is_deeply $bundle->names, [ '192.0.2.7', '2001:db8::7', 'alias.example.internal', 'web.example.internal' ],
    'the certificate carries exactly the names';
  is_deeply $bundle->dns_names, [ 'alias.example.internal', 'web.example.internal' ], 'host names are DNS SANs';
  is_deeply $bundle->ip_names, [ '192.0.2.7', '2001:db8::7' ], 'addresses are IP SANs';
  is $bundle->subject_dn, 'CN=web.example.internal', 'the first name is the subject';

  is $bundle->not_after - $bundle->not_before, $lifetime, 'valid for exactly the lifetime';
  cmp_ok $bundle->not_before, '>=', $before, 'starting now';
  cmp_ok $bundle->not_before, '<=', $after,  '... not later';

  ok $bundle->is_issued_by($root_pem), 'signed by root_pem';
  is $bundle->chain, undef, 'no chain: the root signs directly';

  like $bundle->key, qr/PRIVATE KEY-----/, 'the bundle has a key';
  is public_key_of( key => $bundle->key ), public_key_of( cert => $bundle->cert ), '... the one of the certificate';
  my ($key_text) = SICK::OpenSSL::run( [ 'pkey', '-noout', '-text' ], stdin => $bundle->key );
  like $key_text, qr/2048 bit/, '... RSA 2048 as requested';

  my ($text) = SICK::OpenSSL::run( [ 'x509', '-noout', '-text' ], stdin => $bundle->cert );
  like $text, qr/CA:FALSE/, 'not a CA';
  like $text, qr/TLS Web Server Authentication/, 'for server authentication';

  my $second = $issuer->issue( { names => ['web.example.internal'], lifetime => 86400, key => 'rsa2048' } );
  isnt $second->fingerprint_sha256, $bundle->fingerprint_sha256, 'a second certificate is another certificate';
  isnt public_key_of( key => $second->key ), public_key_of( key => $bundle->key ), '... with another key';
};

subtest 'issue with an EC key and the default key type' => sub {
  my $bundle = $issuer->issue( { names => ['ec.example.internal'], lifetime => 86400, key => 'ec256' } );
  my ($key_text) = SICK::OpenSSL::run( [ 'pkey', '-noout', '-text' ], stdin => $bundle->key );
  like $key_text, qr/prime256v1|P-256/, 'ec256 is a P-256 key';
  is public_key_of( key => $bundle->key ), public_key_of( cert => $bundle->cert ), 'key and certificate belong together';
  ok $bundle->is_issued_by($root_pem), 'signed by root_pem';

  my $default = $issuer->issue( { names => ['default.example.internal'], lifetime => 86400 } );
  ($key_text) = SICK::OpenSSL::run( [ 'pkey', '-noout', '-text' ], stdin => $default->key );
  like $key_text, qr/2048 bit/, 'without a key type it is rsa2048';
};

subtest 'sign' => sub {
  my $request = new_csr( dir => $tmp, name => 'device', cn => 'Device.Example.Internal',
    san => 'DNS:something.else.example,IP:192.0.2.77' );
  my $csr_pem = $request->{csr_pem};

  my $bundle = $issuer->sign( $csr_pem, { names => [ 'device.example.internal', '192.0.2.9' ], lifetime => 7 * 86400 } );
  isa_ok $bundle, 'SICK::Bundle';
  is $bundle->key, undef, 'no key in the bundle';
  is public_key_of( cert => $bundle->cert ), public_key_of( csr => $csr_pem ), 'the certificate is for the key of the request';
  is_deeply $bundle->names, [ '192.0.2.9', 'device.example.internal' ], 'the names are those of the spec, not of the request';
  is $bundle->subject_dn, 'CN=Device.Example.Internal', 'the subject is that of the request';
  is $bundle->not_after - $bundle->not_before, 7 * 86400, 'valid for the lifetime';
  ok $bundle->is_issued_by($root_pem), 'signed by root_pem';

  my $ok = eval { $issuer->sign( 'no request', { names => ['a.example'], lifetime => 60 } ); 1 };
  ok !$ok, 'dies for something that is no request';
  like $@, qr/^not a PEM certificate request/, '... saying so';

  is_deeply $issuer->csr_names($csr_pem), [ '192.0.2.77', 'something.else.example' ], 'csr_names reads the SANs of a request';
  my $plain = new_csr( dir => $tmp, name => 'plain', cn => 'Plain.Example.Internal' );
  is_deeply $issuer->csr_names( $plain->{csr_pem} ), ['plain.example.internal'],
    'csr_names falls back to the common name';
};

subtest 'invalid specs' => sub {
  my %bad = (
    'no spec'           => undef,
    'no names'          => { lifetime => 60 },
    'empty names'       => { names => [], lifetime => 60 },
    'an invalid name'   => { names => ['two words'], lifetime => 60 },
    'a name with comma' => { names => ['a.example,IP:192.0.2.66'], lifetime => 60 },
    'no lifetime'       => { names => ['a.example'] },
    'lifetime zero'     => { names => ['a.example'], lifetime => 0 },
    'a text lifetime'   => { names => ['a.example'], lifetime => '30d' },
    'an unknown key'    => { names => ['a.example'], lifetime => 60, key => 'rsa1024' }
  );
  for my $case ( sort keys %bad ) {
    my $ok = eval { $issuer->issue( $bad{$case} ); 1 };
    ok !$ok, 'issue dies for '.$case;
    like $@, qr/^spec/, '... blaming the spec';
  }
};

subtest 'keys on disk: private while they exist, gone afterwards' => sub {
  my $real    = SICK::OpenSSL::bin();
  my $log     = $tmp.'/openssl-calls.log';
  my $wrapper = $tmp.'/openssl-wrapper';
  spew( $wrapper, <<"WRAPPER" );
#!$^X
use strict;
use warnings;
my \@args = \@ARGV;
open my \$log, '>>', \$ENV{SICK_TEST_LOG} or die \$!;
for my \$i ( 0 .. \$#args - 1 ) {
  next unless \$args[\$i] eq '-key' || \$args[\$i] eq '-in';
  my \$file = \$args[ \$i + 1 ];
  ( my \$dir = \$file ) =~ s{/[^/]+\\z}{};
  printf {\$log} "%s %s %04o %04o\\n", \$args[0], \$file, ( stat \$file )[2] & 07777, ( stat \$dir )[2] & 07777;
}
close \$log;
if ( ( \$ENV{SICK_TEST_FAIL_ON} || '' ) eq \$args[0] ) {
  print STDERR "simulated failure\\n";
  exit 9;
}
exec { '$real' } '$real', \@args;
WRAPPER
  chmod 0755, $wrapper or die 'chmod: '.$!;

  local $ENV{SICK_OPENSSL}  = $wrapper;
  local $ENV{SICK_TEST_LOG} = $log;

  my $bundle = $issuer->issue( { names => ['tmp.example.internal'], lifetime => 86400, key => 'ec256' } );
  ok $bundle->key, 'issue works through the wrapper';

  my @seen = grep { m{/key\.pem } } split /\n/, slurp($log);
  ok scalar @seen, 'the key was a file while openssl used it';
  for my $line (@seen) {
    my ( $command, $file, $file_mode, $dir_mode ) = split / /, $line;
    is $file_mode, '0600', 'key file had mode 0600 during '.$command;
    is $dir_mode,  '0700', '... in a directory of mode 0700';
    ( my $dir = $file ) =~ s{/[^/]+\z}{};
    ok !-e $dir, '... which no longer exists';
  }

  unlink $log;
  local $ENV{SICK_TEST_FAIL_ON} = 'ca';
  my $ok = eval { $issuer->issue( { names => ['fail.example.internal'], lifetime => 86400, key => 'ec256' } ); 1 };
  ok !$ok, 'issue dies when openssl fails half way';
  like $@, qr/^openssl ca failed \(exit 9\): simulated failure/, '... with the message of openssl';
  my ($key_line) = grep { m{/key\.pem } } split /\n/, slurp($log);
  ok $key_line, 'a key had been generated by then';
  ( my $dir = ( split / /, $key_line )[1] ) =~ s{/[^/]+\z}{};
  ok !-e $dir, '... and its directory is gone all the same';
};

done_testing;
