#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use JSON::PP;
use lib 't/lib';

use SICK::Bundle;
use SICK::Issuer::StepCA;
use SICK::OpenSSL;
use Test::SICK::PKI qw( new_ca new_cert new_csr slurp spew );

# SICK::Issuer::StepCA against t/bin/fake-step: what is on the command line,
# what comes back, and what happens to the files in between. No step-ca.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp = tempdir( CLEANUP => 1 );

# The fake step, runnable by the perl that runs this test.
my $step = $tmp.'/step';
( my $source = slurp('t/bin/fake-step') ) =~ s/\A#![^\n]*\n/#!$^X\n/;
spew( $step, $source );
chmod 0755, $step or die 'chmod: '.$!;

# A test CA with an intermediate, and what the fake step hands out.
my $root  = new_ca( dir => $tmp, name => 'root',  cn => 'Fake Step Root' );
my $inter = new_ca( dir => $tmp, name => 'inter', cn => 'Fake Step Intermediate', issuer => $root );
my $leaf  = new_cert( ca => $inter, dir => $tmp, name => 'leaf', cn => 'switch.example.internal',
  san => 'DNS:switch.example.internal,DNS:switch.hq.example.org,IP:192.0.2.199' );

my $fixtures = $tmp.'/fixtures';
mkdir $fixtures or die 'mkdir: '.$!;
spew( $fixtures.'/fullchain.pem', $leaf->{cert_pem}.$inter->{pem} );
spew( $fixtures.'/key.pem',       $leaf->{key_pem} );
spew( $fixtures.'/signed.pem',    $leaf->{cert_pem}.$inter->{pem} );

my $secret        = 'placeholder-'.$$.'-not-a-real-password';
my $password_file = spew( $tmp.'/provisioner.pw', $secret."\n" );
my $log           = $tmp.'/step.log';

local $ENV{FAKE_STEP_LOG}      = $log;
local $ENV{FAKE_STEP_FIXTURES} = $fixtures;

my %ca = (
  url           => 'https://ca.example.internal:9000',
  root          => $root->{cert},
  provisioner   => 'sick',
  password_file => $password_file,
  step          => $step
);
my $issuer = SICK::Issuer::StepCA->new(%ca);

my %spec = (
  names    => [ 'Switch.Example.Internal', 'switch.hq.example.org', '192.0.2.199' ],
  lifetime => 397 * 86400,
  key      => 'rsa2048'
);

# the calls the fake step recorded since the last look
sub calls {
  return () unless -e $log;
  my $raw = slurp($log);
  unlink $log;
  return ( $raw, map { JSON::PP->new->decode($_) } split /\n/, $raw );
}

subtest 'construction' => sub {
  isa_ok $issuer, 'SICK::Issuer';
  is $issuer->step, $step, 'step as given';
  is( SICK::Issuer::StepCA->new( %ca, step => undef )->step, 'step', 'step defaults to step from the PATH' );
  isa_ok( SICK::Issuer::StepCA->new( %ca, type => 'step-ca' ), 'SICK::Issuer::StepCA', 'the type key is accepted' );

  for my $required (qw( url root provisioner password_file )) {
    my %incomplete = %ca;
    delete $incomplete{$required};
    my $ok = eval { SICK::Issuer::StepCA->new(%incomplete); 1 };
    ok !$ok, 'dies without '.$required;
    like $@, qr/^ca: missing '$required'/, '... in the words of the device list';
  }

  my $ok = eval { SICK::Issuer::StepCA->new( %ca, dir => '/somewhere' ); 1 };
  ok !$ok, 'dies for a key of another issuer';
  like $@, qr/^ca: unknown key 'dir'/, '... naming it';

  is $issuer->root_pem, $root->{pem}, 'root_pem is the content of the root file';
};

subtest 'intermediates' => sub {
  is $issuer->intermediates,     undef, 'no intermediates unless configured';
  is $issuer->intermediates_pem, undef, '... and intermediates_pem is undef then';

  my $with = SICK::Issuer::StepCA->new( %ca, intermediates => $inter->{cert} );
  is $with->intermediates,     $inter->{cert}, 'the path as given';
  is $with->intermediates_pem, $inter->{pem},  'intermediates_pem is the content of the file';
  is $with->root_pem,          $root->{pem},   '... and root_pem stays the root alone';

  my $second = new_ca( dir => $tmp, name => 'inter2', cn => 'Fake Step Intermediate 2', issuer => $root );
  my $both   = spew( $tmp.'/intermediates.pem', $inter->{pem}."\n".$second->{pem} );
  is( SICK::Issuer::StepCA->new( %ca, intermediates => $both )->intermediates_pem,
    $inter->{pem}.$second->{pem}, 'a file with several intermediates' );

  my $missing = $tmp.'/missing-intermediate.crt';
  my $ok = eval { SICK::Issuer::StepCA->new( %ca, intermediates => $missing )->intermediates_pem; 1 };
  ok !$ok, 'intermediates_pem dies when the file is missing';
  like $@, qr/^cannot read ca\.intermediates '\Q$missing\E': \S/, '... with path and reason';

  $ok = eval { SICK::Issuer::StepCA->new( %ca, intermediates => $password_file )->intermediates_pem; 1 };
  ok !$ok, 'intermediates_pem dies when the file holds no certificate';
  like $@, qr/^ca\.intermediates '\Q$password_file\E' is not a PEM certificate/, '... saying so';
  unlike $@, qr/\Q$secret\E/, '... without showing the file';

  # the leaf alone, as a switch presents it
  my $alone = SICK::Bundle->new( cert => $leaf->{cert_pem} );
  ok !$alone->is_issued_by( $with->root_pem ), 'the certificate alone does not lead to the root';
  ok $alone->is_issued_by( $with->root_pem, $with->intermediates_pem ), '... with the intermediates it does';
};

subtest 'a root file with the intermediate in it' => sub {
  # what step itself says to such a file: "error decoding <file>: contains
  # more than one PEM encoded block"
  my $bundle = spew( $tmp.'/root-and-intermediate.pem', $root->{pem}.$inter->{pem} );
  my $crowded = SICK::Issuer::StepCA->new( %ca, root => $bundle );
  my $ok = eval { $crowded->root_pem; 1 };
  ok !$ok, 'root_pem dies';
  like $@, qr/^ca\.root '\Q$bundle\E' holds more than one certificate; step needs the root alone/, '... saying why';
  like $@, qr/ca\.intermediates/, '... and where the intermediate belongs';
  $ok = eval { $crowded->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies the same way';
  is scalar( () = calls() ), 0, '... before step is called';
};

subtest 'a root file with something else than the root in it' => sub {
  # step trusts whatever is in --root as an anchor; SICK would judge the
  # devices against it and sick trust would hand it to the clients
  my $other     = new_ca( dir => $tmp, name => 'other-root', cn => 'Other Root' );
  my $root_leaf = new_cert( ca => $root, dir => $tmp, name => 'root-leaf', cn => 'device.example.internal' );
  my $lone_leaf = new_ca( dir => $tmp, name => 'lone-leaf', cn => 'lone.example.internal', extensions => 'leaf_ext' );

  my @cases = (
    [ 'the intermediate', $inter->{cert}, qr/issued by CN=Fake Step Root(?: at |\z)/ ],
    [ 'a leaf of the CA', $root_leaf->{cert}, qr/issued by CN=Fake Step Root(?: at |\z)/ ],
    [ 'a self-signed leaf', $lone_leaf->{cert}, qr/basicConstraints does not say CA:TRUE(?: at |\z)/ ],
  );
  if ( SICK::OpenSSL::major() >= 3 ) {
    my $twin   = new_ca( dir => $tmp, name => 'twin-signer', cn => 'Twin Root' );
    my $forged = new_ca( dir => $tmp, name => 'twin', cn => 'Twin Root', issuer => $twin, extensions => 'forged_ca_ext' );
    push @cases, [ 'a certificate that names itself as issuer and is signed by another key',
      $forged->{cert}, qr/its signature does not verify with its own key(?: at |\z)/ ];
  }

  for my $case (@cases) {
    my ( $what, $path, $reason ) = @$case;
    my $wrong = SICK::Issuer::StepCA->new( %ca, root => $path );
    my $ok = eval { $wrong->root_pem; 1 };
    ok !$ok, 'root_pem dies for '.$what;
    like $@, qr/^ca\.root '\Q$path\E' is not a self-signed CA certificate: /, '... naming ca.root and the path';
    like $@, $reason, '... and the reason';
    $ok = eval { $wrong->issue( {%spec} ); 1 };
    ok !$ok, '... issue dies the same way';
    is scalar( () = calls() ), 0, '... before step is called';
  }

  is( SICK::Issuer::StepCA->new( %ca, root => $other->{cert} )->root_pem, $other->{pem},
    'the root of another CA is a root: which CA it is, step finds out' );
};

subtest 'an intermediates file with something else than intermediates in it' => sub {
  my $foreign_root  = new_ca( dir => $tmp, name => 'foreign-root',  cn => 'Foreign Root' );
  my $foreign_inter = new_ca( dir => $tmp, name => 'foreign-inter', cn => 'Foreign Intermediate', issuer => $foreign_root );
  my $leaf_of_root  = new_cert( ca => $root, dir => $tmp, name => 'inter-leaf', cn => 'device.example.internal' );

  my @cases = (
    [ 'a leaf of the CA', $leaf_of_root->{cert_pem}, 'CN=device.example.internal',
      qr/is not a CA certificate \(basicConstraints does not say CA:TRUE\)(?: at |\z)/ ],
    [ 'the leaf the CA hands out', $leaf->{cert_pem}, 'CN=switch.example.internal',
      qr/is not a CA certificate \(basicConstraints does not say CA:TRUE\)(?: at |\z)/ ],
    [ 'an intermediate of another CA', $foreign_inter->{pem}, 'CN=Foreign Intermediate',
      qr/does not lead to ca\.root '\Q$root->{cert}\E' \(CN=Fake Step Root\)(?: at |\z)/ ],
    [ 'the root of another CA', $foreign_root->{pem}, 'CN=Foreign Root',
      qr/does not lead to ca\.root '\Q$root->{cert}\E' \(CN=Fake Step Root\)(?: at |\z)/ ],
    [ 'a good intermediate followed by an intermediate of another CA', $inter->{pem}.$foreign_inter->{pem},
      'CN=Foreign Intermediate', qr/does not lead to ca\.root/ ],
  );
  my $n = 0;
  for my $case (@cases) {
    my ( $what, $pem, $subject, $reason ) = @$case;
    my $path = spew( $tmp.'/wrong-intermediates-'.++$n.'.pem', $pem );
    my $ok = eval { SICK::Issuer::StepCA->new( %ca, intermediates => $path )->intermediates_pem; 1 };
    ok !$ok, 'intermediates_pem dies for '.$what;
    like $@, qr/^ca\.intermediates '\Q$path\E': the certificate '\Q$subject\E' /,
      '... naming ca.intermediates, the path and the subject';
    like $@, $reason, '... and the reason';
  }

  my $with_root = spew( $tmp.'/intermediates-and-root.pem', $inter->{pem}.$root->{pem} );
  is( SICK::Issuer::StepCA->new( %ca, intermediates => $with_root )->intermediates_pem,
    $inter->{pem}.$root->{pem}, 'a bundle of intermediate and root is taken as it is' );

  my $deep  = new_ca( dir => $tmp, name => 'inter-deep', cn => 'Fake Step Intermediate Deep', issuer => $inter );
  my $chain = spew( $tmp.'/intermediates-deep.pem', $deep->{pem}.$inter->{pem} );
  is( SICK::Issuer::StepCA->new( %ca, intermediates => $chain )->intermediates_pem,
    $deep->{pem}.$inter->{pem}, 'an intermediate below an intermediate leads to the root through the other' );
};

subtest 'issue: the command line' => sub {
  my $bundle = $issuer->issue( {%spec} );
  my ( $raw, @calls ) = calls();
  is scalar @calls, 1, 'step was called once';
  my $call = $calls[0];

  is $call->{command}, 'certificate', 'step ca certificate';
  is_deeply [ @{ $call->{argv} }[ 0, 1 ] ], [ 'ca', 'certificate' ], '... as the first two arguments';
  is_deeply $call->{flags}{'--san'}, [ 'switch.example.internal', 'switch.hq.example.org', '192.0.2.199' ],
    'every name is a --san, the first one included';
  is_deeply $call->{flags}{'--not-after'}, [ ( 397 * 86400 ).'s' ], 'the lifetime as --not-after in seconds';
  is_deeply $call->{flags}{'--provisioner'}, ['sick'], '--provisioner';
  is_deeply $call->{flags}{'--provisioner-password-file'}, [$password_file], '--provisioner-password-file is the path';
  is_deeply $call->{flags}{'--ca-url'}, ['https://ca.example.internal:9000'], '--ca-url';
  is_deeply $call->{flags}{'--root'},   [ $root->{cert} ], '--root';
  is_deeply $call->{flags}{'--kty'},    ['RSA'],  '--kty RSA';
  is_deeply $call->{flags}{'--size'},   ['2048'], '--size 2048';
  ok !exists $call->{flags}{'--curve'}, 'no --curve for RSA';
  is $call->{positional}[0], 'switch.example.internal', 'the first name is the subject';
  is $call->{password_file_readable}, 1, 'step could read the password file';

  unlike $raw, qr/\Q$secret\E/, 'the password is nowhere on the command line';
  unlike join( "\n", %ENV ), qr/\Q$secret\E/, '... and not in the environment';
};

subtest 'issue: what comes back' => sub {
  my $bundle = $issuer->issue( {%spec} );
  calls();
  isa_ok $bundle, 'SICK::Bundle';
  is $bundle->cert,  $leaf->{cert_pem}, 'the first certificate step wrote is the certificate';
  is $bundle->chain, $inter->{pem},     'the rest is the chain';
  is $bundle->key,   $leaf->{key_pem},  'the key';
  is_deeply $bundle->names, [ '192.0.2.199', 'switch.example.internal', 'switch.hq.example.org' ], 'names';
  ok $bundle->is_issued_by( $issuer->root_pem ), 'issued by root_pem, through the chain';
};

subtest 'issue: key types' => sub {
  my %expect = (
    rsa3072 => { '--kty' => ['RSA'], '--size'  => ['3072'] },
    rsa4096 => { '--kty' => ['RSA'], '--size'  => ['4096'] },
    ec256   => { '--kty' => ['EC'],  '--curve' => ['P-256'] }
  );
  for my $key ( sort keys %expect ) {
    $issuer->issue( { %spec, key => $key } );
    my ( $raw, $call ) = calls();
    is_deeply { map { $_ => $call->{flags}{$_} } grep { /kty|size|curve/ } keys %{ $call->{flags} } },
      $expect{$key}, $key;
  }
  $issuer->issue( { names => ['a.example.internal'], lifetime => 3600 } );
  my ( $raw, $call ) = calls();
  is_deeply [ $call->{flags}{'--kty'}, $call->{flags}{'--size'} ], [ ['RSA'], ['2048'] ], 'rsa2048 without a key type';
  is_deeply $call->{flags}{'--not-after'}, ['3600s'], 'another lifetime';
};

subtest 'issue: the files in between' => sub {
  $issuer->issue( {%spec} );
  my ( $raw, $call ) = calls();
  is $call->{umask},    '0077', 'step runs with umask 077';
  is $call->{key_mode}, '0600', 'the key file has mode 0600 while it exists';
  is $call->{dir_mode}, '0700', '... in a directory of mode 0700';
  like $call->{dir}, qr{\A/.+}, '... which step was given';
  is $call->{positional}[2], $call->{key_file}, '... as the place for the key';
  ok !-e $call->{dir}, 'no temporary directory is left after issue';
};

subtest 'the CA refuses' => sub {
  # the words of step 0.30.2; its progress lines come in front of them
  local $ENV{FAKE_STEP_EXIT}   = 1;
  local $ENV{FAKE_STEP_STDERR} = "The request was forbidden by the certificate authority: requested duration of 9528h1m0s is more than the authorized maximum certificate duration of 24h1m0s.\nRe-run with STEPDEBUG=1 for more info.\n";

  my $ok = eval { $issuer->issue( {%spec} ); 1 };
  my $error = $@;
  ok !$ok, 'issue dies';
  like $error, qr/^step failed \(exit 1\): The request was forbidden by the certificate authority: requested duration of 9528h1m0s is more than the authorized maximum certificate duration of 24h1m0s\. at /,
    'step failed (exit N): what step said, and nothing else';
  unlike $error, qr/\e|\xe2\x9c\x94|Provisioner|STEPDEBUG/, '... without its colours, its progress lines and its hint';
  unlike $error, qr/\Q$secret\E/, '... and no password';

  my ( $raw, $call ) = calls();
  ( my $dir = $call->{positional}[2] ) =~ s{/[^/]+\z}{};
  like $dir, qr{\A/.+}, 'step had been given a temporary directory';
  ok !-e $dir, '... which is gone after the failure';

  my $request = new_csr( dir => $tmp, name => 'refused', cn => 'switch.example.internal',
    san => 'DNS:switch.example.internal,DNS:switch.hq.example.org,IP:192.0.2.199' );
  $ok = eval { $issuer->sign( $request->{csr_pem}, {%spec} ); 1 };
  ok !$ok, 'sign dies';
  like $@, qr/^step failed \(exit 1\): The request was forbidden/, '... the same way';
  calls();

  local $ENV{FAKE_STEP_STDERR} = q{};
  $ok = eval { $issuer->issue( {%spec} ); 1 };
  like $@, qr/^step failed \(exit 1\): it did not say why at /, 'a step that fails with nothing but progress lines';
  calls();
};

subtest 'a wrong password' => sub {
  local $ENV{FAKE_STEP_EXIT}   = 1;
  local $ENV{FAKE_STEP_STDERR} = "failed to decrypt JWE: invalid password\n";
  my $ok = eval { $issuer->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies';
  like $@, qr/^step failed \(exit 1\): failed to decrypt JWE: invalid password at /, '... with the words of step';
  calls();
};

subtest 'files step needs' => sub {
  my $missing = $tmp.'/missing.pw';
  my $ok = eval { SICK::Issuer::StepCA->new( %ca, password_file => $missing )->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies when the password file is missing';
  like $@, qr/^cannot read secret file '\Q$missing\E': \S/, '... with path and reason';
  unlike $@, qr/\n.*\n/s, '... on one line';
  is scalar( () = calls() ), 0, '... and step is not called';

SKIP: {
    skip 'root reads every file', 3 unless $>;
    my $locked = spew( $tmp.'/locked.pw', $secret."\n" );
    chmod 0000, $locked or die 'chmod: '.$!;
    $ok = eval { SICK::Issuer::StepCA->new( %ca, password_file => $locked )->issue( {%spec} ); 1 };
    ok !$ok, 'issue dies when the password file is unreadable';
    like $@, qr/^cannot read secret file '\Q$locked\E': \S/, '... with path and reason';
    unlike $@, qr/\Q$secret\E/, '... and without its content';
    chmod 0600, $locked;
  }

  my $no_root = $tmp.'/missing-root.crt';
  $ok = eval { SICK::Issuer::StepCA->new( %ca, root => $no_root )->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies when the root file is missing';
  like $@, qr/^cannot read ca\.root '\Q$no_root\E': \S/, '... with path and reason';
  is scalar( () = calls() ), 0, '... and step is not called';

  $ok = eval { SICK::Issuer::StepCA->new( %ca, root => $password_file )->root_pem; 1 };
  ok !$ok, 'root_pem dies when the root file is no certificate';
  like $@, qr/^ca\.root '\Q$password_file\E' is not a PEM certificate/, '... saying so';
  unlike $@, qr/\Q$secret\E/, '... without showing the file';

  my $no_step = $tmp.'/not-installed/step';
  $ok = eval { SICK::Issuer::StepCA->new( %ca, step => $no_step )->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies when step is not installed';
  like $@, qr/^cannot run '\Q$no_step\E': \S/, '... naming the missing program';
};

subtest 'an encrypted key is refused' => sub {
  my $encrypted = $tmp.'/encrypted-fixtures';
  mkdir $encrypted or die 'mkdir: '.$!;
  spew( $encrypted.'/fullchain.pem', $leaf->{cert_pem} );
  spew( $encrypted.'/key.pem', "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n" );
  local $ENV{FAKE_STEP_FIXTURES} = $encrypted;
  my $ok = eval { $issuer->issue( {%spec} ); 1 };
  ok !$ok, 'issue dies';
  like $@, qr/^step wrote an encrypted private key/, '... saying why';
  calls();
};

subtest 'sign' => sub {
  my $request = new_csr( dir => $tmp, name => 'device', cn => 'Switch.Example.Internal',
    san => 'DNS:Switch.HQ.Example.Org,IP:192.0.2.199,DNS:switch.example.internal' );

  my $bundle = $issuer->sign( $request->{csr_pem}, {%spec} );
  my ( $raw, @calls ) = calls();
  is scalar @calls, 1, 'step was called once';
  my $call = $calls[0];

  is $call->{command}, 'sign', 'step ca sign';
  is_deeply $call->{flags}{'--not-after'},  [ ( 397 * 86400 ).'s' ], '--not-after';
  is_deeply $call->{flags}{'--provisioner'}, ['sick'], '--provisioner';
  is_deeply $call->{flags}{'--provisioner-password-file'}, [$password_file], '--provisioner-password-file';
  is_deeply $call->{flags}{'--ca-url'}, ['https://ca.example.internal:9000'], '--ca-url';
  is_deeply $call->{flags}{'--root'},   [ $root->{cert} ], '--root';
  ok !exists $call->{flags}{$_}, 'no '.$_.': step ca sign does not have it' for qw( --san --kty --size --curve );
  is $call->{csr_is_pem}, 1, 'the request reached step as a file';
  is $call->{dir_mode}, '0700', '... in a private directory';
  ok !-e $call->{dir}, '... which is gone afterwards';
  unlike $raw, qr/\Q$secret\E/, 'the password is nowhere on the command line';

  isa_ok $bundle, 'SICK::Bundle';
  is $bundle->key,   undef,             'no key in the bundle';
  is $bundle->cert,  $leaf->{cert_pem}, 'the certificate';
  is $bundle->chain, $inter->{pem},     'the chain';
};

subtest 'sign refuses a request with other names' => sub {
  my %requests = (
    'fewer names'      => new_csr( dir => $tmp, name => 'fewer', cn => 'switch.example.internal',
      san => 'DNS:switch.example.internal' ),
    'more names'       => new_csr( dir => $tmp, name => 'more', cn => 'switch.example.internal',
      san => 'DNS:switch.example.internal,DNS:switch.hq.example.org,IP:192.0.2.199,DNS:extra.example.internal' ),
    'only a common name' => new_csr( dir => $tmp, name => 'cnonly', cn => 'switch.example.internal' )
  );
  for my $case ( sort keys %requests ) {
    my $ok = eval { $issuer->sign( $requests{$case}{csr_pem}, {%spec} ); 1 };
    ok !$ok, 'dies for a request with '.$case;
    like $@, qr/^the certificate request is for \[.*\], not for \[192\.0\.2\.199, switch\.example\.internal, switch\.hq\.example\.org\]/,
      '... naming both sets';
    is scalar( () = calls() ), 0, '... before step is called';
  }

  my $single = new_csr( dir => $tmp, name => 'single', cn => 'Single.Example.Internal' );
  my $bundle = eval { $issuer->sign( $single->{csr_pem}, { names => ['single.example.internal'], lifetime => 3600 } ) };
  ok $bundle, 'a request with only a common name is fine when that is the one name wanted';
  calls();

  my $ok = eval { $issuer->sign( 'no request', {%spec} ); 1 };
  ok !$ok, 'dies for something that is no request';
  like $@, qr/^not a PEM certificate request/, '... saying so';
};

subtest 'additional roots: published, not handed to step, checked like the root' => sub {
  # the next root before the switch, the previous one after it
  my $next = new_ca( dir => $tmp, name => 'next-root', cn => 'Fake Step Root 2' );
  my $old  = new_ca( dir => $tmp, name => 'old-root',  cn => 'Fake Step Root 0' );

  is_deeply $issuer->additional_roots, [], 'no additional roots unless configured';
  is $issuer->additional_roots_pem, undef, '... and additional_roots_pem is undef then';

  my $with = SICK::Issuer::StepCA->new( %ca, additional_roots => [ $next->{cert}, $old->{cert} ] );
  is_deeply $with->additional_roots, [ $next->{cert}, $old->{cert} ], 'the paths as given';
  is $with->additional_roots_pem, $next->{pem}.$old->{pem}, 'additional_roots_pem: the certificates, in the order of the list';
  is $with->root_pem, $root->{pem}, '... and root_pem stays the root alone';
  is $with->intermediates_pem, undef, '... and they are no intermediates';
  is_deeply( SICK::Issuer::StepCA->new( %ca, additional_roots => [] )->additional_roots_pem, undef, 'an empty list is none' );

  calls();
  $with->issue( {%spec} );
  my ( $raw, @calls ) = calls();
  is scalar @calls, 1, 'issue calls step once';
  is_deeply $calls[0]{flags}{'--root'}, [ $root->{cert} ], '... with the root as --root';
  unlike $raw, qr/\Q$_\E/, '... and '.( $_ =~ s{.*/}{}r ).' nowhere on its command line' for $next->{cert}, $old->{cert};

  my $ok = eval { SICK::Issuer::StepCA->new( %ca, additional_roots => $next->{cert} ); 1 };
  ok !$ok, 'a path that is no list dies';
  like $@, qr/^ca\.additional_roots: must be a list of paths/, '... in the words of the device list';
  $ok = eval { SICK::Issuer::StepCA->new( %ca, additional_roots => [ $next->{cert}, [] ] ); 1 };
  ok !$ok, 'a list with something else than a path in it dies';
  like $@, qr/^ca\.additional_roots: must be a list of paths/, '... the same way';

  my $missing   = $tmp.'/missing-root-2.crt';
  my $crowded   = spew( $tmp.'/two-roots.pem', $next->{pem}.$old->{pem} );
  my $root_copy = spew( $tmp.'/root-again.crt', $root->{pem} );
  my $next_copy = spew( $tmp.'/next-again.crt', $next->{pem} );
  my $lone_leaf = new_ca( dir => $tmp, name => 'lone-leaf-2', cn => 'lone2.example.internal', extensions => 'leaf_ext' );
  my @cases = (
    [ 'a missing file', [$missing], qr/^cannot read ca\.additional_roots '\Q$missing\E': \S/ ],
    [ 'a file without a certificate', [$password_file],
      qr/^ca\.additional_roots '\Q$password_file\E' is not a PEM certificate/ ],
    [ 'a file with two certificates', [$crowded],
      qr/^ca\.additional_roots '\Q$crowded\E' holds more than one certificate; name each root as an entry of its own/ ],
    [ 'the intermediate', [ $inter->{cert} ],
      qr/^ca\.additional_roots '\Q$inter->{cert}\E' is not a self-signed CA certificate: issued by CN=Fake Step Root(?: at |\z)/ ],
    [ 'a self-signed leaf', [ $lone_leaf->{cert} ],
      qr/^ca\.additional_roots '\Q$lone_leaf->{cert}\E' is not a self-signed CA certificate: basicConstraints does not say CA:TRUE(?: at |\z)/ ],
    [ 'the root under another name', [$root_copy],
      qr/^ca\.additional_roots '\Q$root_copy\E' is the root of this CA \(CN=Fake Step Root\); list only the next or the previous root(?: at |\z)/ ],
    [ 'one root twice under two names', [ $next->{cert}, $next_copy ],
      qr/^ca\.additional_roots '\Q$next_copy\E' is the same certificate as '\Q$next->{cert}\E'(?: at |\z)/ ],
  );
  for my $case (@cases) {
    my ( $what, $paths, $message ) = @$case;
    my $ok = eval { SICK::Issuer::StepCA->new( %ca, additional_roots => $paths )->additional_roots_pem; 1 };
    ok !$ok, 'additional_roots_pem dies for '.$what;
    like $@, $message, '... naming ca.additional_roots, the path and the reason';
    unlike $@, qr/\Q$secret\E/, '... without showing a file' if $what eq 'a file without a certificate';
  }
};

done_testing;
