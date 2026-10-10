#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use MIME::Base64 qw( decode_base64 );
use lib 't/lib';

use SICK::Bundle;
use SICK::Command;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Trust;
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# SICK::Trust: the root certificate as PEM, DER and Apple profile, and the
# page around them.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp   = tempdir( CLEANUP => 1 );
my $root  = new_ca( dir => $tmp, name => 'root', cn => 'Example Internal Root CA' );
my $inter = new_ca( dir => $tmp, name => 'inter', cn => 'Example Internal Intermediate', issuer => $root );
my $other = new_ca( dir => $tmp, name => 'other', cn => 'Another Root' );
my $facts = SICK::Bundle->new( cert => $root->{pem} );

sub files_in {
  my ( $dir ) = @_;
  opendir my $dh, $dir or return [];
  return [ sort grep { !/\A\.\.?\z/ } readdir $dh ];
}

sub raw {
  my ( $path ) = @_;
  open my $fh, '<:raw', $path or die 'cannot read '.$path.': '.$!;
  local $/;
  return scalar <$fh>;
}

# Is this well-formed XML? Enough of a parser for a property list: one
# declaration, one doctype, properly nested elements without attributes
# that could hide something, text without stray markup. Returns the problem
# or nothing.
sub xml_problem {
  my ( $xml ) = @_;
  $xml =~ s/\A<\?xml version="1\.0" encoding="UTF-8"\?>\n// or return 'no XML declaration';
  $xml =~ s/\A<!DOCTYPE plist PUBLIC "[^"<>]*" "[^"<>]*">\n// or return 'no doctype';
  my @open;
  my $roots = 0;
  pos($xml) = 0;
  while ( pos($xml) < length $xml ) {
    if ( $xml =~ /\G<([A-Za-z][A-Za-z0-9]*)((?:\s+[A-Za-z][A-Za-z0-9]*="[^"<&]*")*)\s*(\/?)>/gc ) {
      return 'more than one root element' if !@open && $roots++;
      push @open, $1 unless $3;
    }
    elsif ( $xml =~ /\G<\/([A-Za-z][A-Za-z0-9]*)>/gc ) {
      my $expected = pop @open;
      return 'closing '.$1.' without opening it' unless defined $expected;
      return 'closing '.$1.' inside '.$expected unless $expected eq $1;
    }
    elsif ( $xml =~ /\G([^<]+)/gc ) {
      my $text = $1;
      return 'text outside of the root element' if !@open && $text =~ /\S/;
      ( my $rest = $text ) =~ s/&(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9A-Fa-f]+);//g;
      return 'a stray ampersand' if $rest =~ /&/;
    }
    else {
      return 'markup that is none at offset '.pos($xml);
    }
  }
  return 'unclosed '.$open[-1] if @open;
  return 'no root element' unless $roots;
  return;
}

subtest 'the checker of this test knows broken XML when it sees it' => sub {
  my $head = qq{<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "a" "b">\n};
  is xml_problem( $head.'<plist version="1.0"><dict><key>a</key><true/></dict></plist>'."\n" ), undef, 'well-formed';
  ok xml_problem( $head.'<plist><dict></plist>' ),              'wrong nesting';
  ok xml_problem( $head.'<plist><string>a & b</string></plist>' ), 'a bare ampersand';
  ok xml_problem( $head.'<plist><string>a < b</string></plist>' ), 'a bare less-than';
  ok xml_problem( $head.'<plist></plist><plist></plist>' ),     'two roots';
  ok xml_problem( $head.'<plist>' ),                            'unclosed';
  ok xml_problem('<plist></plist>'),                            'no declaration';
};

my $dir = $tmp.'/site/trust';
my @written;

subtest 'the four files' => sub {
  ok !-e $dir, 'the directory does not exist yet';
  @written = SICK::Trust->write( $dir, root_pem => $root->{pem}, name => 'Example Internal CA' );

  is_deeply [ SICK::Trust->files ], [qw( root_ca.pem root_ca.crt root_ca.mobileconfig index.html )], 'files';
  is_deeply \@written, [ map { $dir.'/'.$_ } SICK::Trust->files ], 'write returns the paths';
  is_deeply files_in($dir), [qw( index.html root_ca.crt root_ca.mobileconfig root_ca.pem )],
    'exactly the four files are there, no temporary ones';
  is sprintf( '%04o', ( stat $_ )[2] & 07777 ), '0644', $_ =~ s{.*/}{}r.' is readable for everybody' for @written;
  ok -s $_, $_ =~ s{.*/}{}r.' is not empty' for @written;
};

subtest 'root_ca.pem and root_ca.crt' => sub {
  is slurp( $dir.'/root_ca.pem' ), $root->{pem}, 'the PEM file is the root certificate';

  my $der = raw( $dir.'/root_ca.crt' );
  unlike $der, qr/BEGIN CERTIFICATE/, 'the .crt file is not PEM';
  my ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'x509', '-inform', 'der', '-in', $dir.'/root_ca.crt', '-noout', '-fingerprint', '-sha256' ] );
  is $exit, 0, 'openssl x509 -inform der reads it';
  my ($fingerprint) = $out =~ /Fingerprint=([0-9A-Fa-f:]+)/;
  ( my $plain = lc( $fingerprint || q{} ) ) =~ tr/://d;
  is $plain, $facts->fingerprint_sha256, '... and it has the fingerprint of the root certificate';
};

subtest 'root_ca.mobileconfig' => sub {
  my $profile = slurp( $dir.'/root_ca.mobileconfig' );
  is xml_problem($profile), undef, 'well-formed XML';
  like $profile, qr/\A<\?xml version="1\.0" encoding="UTF-8"\?>\n<!DOCTYPE plist PUBLIC "-\/\/Apple\/\/DTD PLIST 1\.0\/\/EN" /, 'a property list';

SKIP: {
    my $lint = eval { ( SICK::Command::run( [ 'xmllint', '--version' ] ) )[2] };
    skip 'xmllint is not installed', 1 unless defined $lint && $lint == 0;
    my ( $out, $err, $exit ) = SICK::Command::run( [ 'xmllint', '--noout', '--nonet', $dir.'/root_ca.mobileconfig' ] );
    is $exit, 0, 'xmllint agrees' or diag $err;
  }

  like $profile, qr{<key>PayloadType</key>\s*<string>com\.apple\.security\.root</string>}, 'the certificate is a com.apple.security.root payload';
  like $profile, qr{<key>PayloadType</key>\s*<string>Configuration</string>}, '... inside a configuration profile';
  my ($data) = $profile =~ m{<key>PayloadContent</key>\s*<data>\s*(.*?)\s*</data>}s;
  ok defined $data, 'the payload has data';
  is decode_base64( $data || q{} ), raw( $dir.'/root_ca.crt' ), '... which is the certificate in DER';
  is scalar( () = $profile =~ m{<string>Example Internal CA</string>}g ), 2, 'profile and payload carry the display name';

  my @uuids = $profile =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g;
  is scalar @uuids, 2, 'two UUIDs';
  like $_, qr/\A[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/, $_.' has the form of one' for @uuids;
  isnt $uuids[0], $uuids[1], 'payload and profile have different ones';

  my $elsewhere = $tmp.'/other-trust';
  SICK::Trust->write( $elsewhere, root_pem => $other->{pem} );
  my @others = slurp( $elsewhere.'/root_ca.mobileconfig' ) =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g;
  isnt $others[1], $uuids[1], 'another root certificate is another profile';
};

subtest 'index.html' => sub {
  my $page = slurp( $dir.'/index.html' );
  like $page, qr/\A<!DOCTYPE html>\n<html lang="en">/, 'an HTML page';
  like $page, qr/<meta charset="utf-8">/, '... that declares its encoding';
  like $page, qr{<title>Trust Example Internal CA</title>}, 'the name is in the title';

  my $colons = join ':', map { uc } $facts->fingerprint_sha256 =~ /(..)/g;
  ( my $shown = $page ) =~ s/<br>//g;
  like $shown, qr/\Q$colons\E/, 'the SHA-256 fingerprint, the way devices show it';
  like $page, qr/SHA-1 fingerprint.*?(?:[0-9A-F]{2}:){19}[0-9A-F]{2}/s, 'the SHA-1 fingerprint, which is what Windows shows';
  my @end = gmtime $facts->not_after;
  my $until = sprintf '%04d-%02d-%02d', $end[5] + 1900, $end[4] + 1, $end[3];
  like $page, qr/Valid until<\/dt><dd>\Q$until\E \d\d:\d\d UTC</, 'the date it expires';
  like $page, qr/CN=Example Internal Root CA/, 'the subject of the certificate';

  like $page, qr/<a href="\Q$_\E"/, 'a link to '.$_ for qw( root_ca.pem root_ca.crt root_ca.mobileconfig );
  like $page, qr/<h2 id="[a-z]+">[^<]*\Q$_\E/, 'instructions for '.$_ for qw( Firefox Chrome Linux macOS Windows iPhone Android );

  my @references = $page =~ /(?:href|src|action)\s*=\s*"([^"]*)"/g;
  ok scalar @references, 'the page has links';
  is_deeply [ grep { !/\A(?:#[a-z]+|root_ca\.(?:pem|crt|mobileconfig))\z/ } @references ], [],
    '... only to its own sections and the three files';
  unlike $page, qr/<(?:script|link|img|iframe|object|embed)\b/i, 'no script, no style sheet, no image from anywhere';
  unlike $page, qr/url\(|\@import/i, '... and none in the style either';
  unlike $page, qr/[ \t]\n/, 'no trailing blanks';
};

subtest 'writing twice produces the same bytes' => sub {
  my %before = map { $_ => raw($_) } @written;
  my %inode  = map { $_ => ( stat $_ )[1] } @written;
  sleep 1;
  SICK::Trust->write( $dir, root_pem => $root->{pem}, name => 'Example Internal CA' );
  is raw($_), $before{$_}, $_ =~ s{.*/}{}r.' is byte for byte the same' for @written;
  isnt( ( stat $written[0] )[1], $inode{ $written[0] }, 'the files are replaced, not rewritten in place' );
  is_deeply files_in($dir), [qw( index.html root_ca.crt root_ca.mobileconfig root_ca.pem )], 'and nothing else appeared';

  my $again = $tmp.'/again';
  SICK::Trust->write( $again, root_pem => "some text around it\n".$root->{pem}."\n", name => 'Example Internal CA' );
  is raw( $again.'/'.$_ ), $before{ $dir.'/'.$_ }, $_.' is the same in another directory' for SICK::Trust->files;
};

subtest 'the name' => sub {
  my $unnamed = $tmp.'/unnamed';
  SICK::Trust->write( $unnamed, root_pem => $root->{pem} );
  like slurp( $unnamed.'/index.html' ), qr{<h1>Trust Example Internal Root CA</h1>},
    'without a name it is the common name of the root certificate';
  like slurp( $unnamed.'/root_ca.mobileconfig' ), qr{<string>Example Internal Root CA</string>}, '... in the profile as well';
  SICK::Trust->write( $unnamed, root_pem => $root->{pem}, name => '  ' );
  like slurp( $unnamed.'/index.html' ), qr{<h1>Trust Example Internal Root CA</h1>}, 'a blank name is no name';

  my $awkward = $tmp.'/awkward';
  my $name    = qq{R&D <"Lab"> 'CA' \x{e4}\x{f6}\x{fc} \x{2713}};
  {
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    SICK::Trust->write( $awkward, root_pem => $root->{pem}, name => $name );
    is_deeply \@warnings, [], 'a name with markup and wide characters is written without a warning';
  }
  my $page    = raw( $awkward.'/index.html' );
  my $profile = raw( $awkward.'/root_ca.mobileconfig' );
  my $escaped = 'R&amp;D &lt;&quot;Lab&quot;&gt; &#39;CA&#39; '."\xc3\xa4\xc3\xb6\xc3\xbc \xe2\x9c\x93";
  like $page,    qr{<h1>Trust \Q$escaped\E</h1>},   'the page has it escaped, as UTF-8';
  like $profile, qr{<string>\Q$escaped\E</string>}, '... and so has the profile';
  is xml_problem($profile), undef, '... which is still well-formed';
  unlike $page, qr/<"Lab">/, 'the markup of the name is nowhere in the page';

  my $bytes = $tmp.'/bytes';
  SICK::Trust->write( $bytes, root_pem => $root->{pem}, name => "Stra\xc3\x9fe" );
  like raw( $bytes.'/index.html' ), qr{<h1>Trust Stra\xc3\x9fe</h1>}, 'a name that is UTF-8 bytes already, as the device list delivers it, stays as it is';
};

subtest 'which certificate is the root' => sub {
  my $both = $tmp.'/both';
  SICK::Trust->write( $both, root_pem => $inter->{pem}.$root->{pem} );
  is slurp( $both.'/root_ca.pem' ), $root->{pem}, 'of a root file with the intermediate in it, the self-signed one is published';

  my $issuer = SICK::Issuer::SelfSigned->new( dir => $tmp.'/ca' );
  my @paths = SICK::Trust->write( $tmp.'/selfsigned', root_pem => $issuer->root_pem );
  is slurp( $paths[0] ), $issuer->root_pem, 'the root of an issuer';

  my %bad = (
    'no root_pem'           => [ [], qr/^SICK::Trust->write needs root_pem/ ],
    'text that is no PEM'   => [ [ root_pem => "not a certificate\n" ], qr/^root_pem is not a PEM certificate/ ],
    'only an intermediate'  => [ [ root_pem => $inter->{pem} ], qr/^root_pem holds no root certificate: the certificate in it is self-signed/ ],
    'two roots'             => [ [ root_pem => $root->{pem}.$other->{pem} ], qr/^root_pem holds 2 root certificates; exactly one can be published/ ],
    'an unknown argument'   => [ [ root_pem => $root->{pem}, title => 'x' ], qr/^SICK::Trust->write: unknown argument 'title'/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $args, $message ) = @{ $bad{$case} };
    my $target = $tmp.'/bad-'.( $case =~ tr/a-z//cdr );
    ok !eval { SICK::Trust->write( $target, @$args ); 1 }, 'dies for '.$case;
    like $@, $message, '... saying so';
    ok !-e $target, '... and writes nothing';
  }
  ok !eval { SICK::Trust->write( undef, root_pem => $root->{pem} ); 1 }, 'dies without a directory';
  like $@, qr/^SICK::Trust->write needs a directory/, '... saying so';

  my $blocked = spew( $tmp.'/a-file', "in the way\n" );
  ok !eval { SICK::Trust->write( $blocked.'/site', root_pem => $root->{pem} ); 1 }, 'a directory that cannot be made';
  like $@, qr/^cannot create directory '\Q$blocked\E\/site': \S/, '... is named with the reason';

SKIP: {
    skip 'root writes everywhere', 3 unless $>;
    my $locked = $tmp.'/locked';
    SICK::Trust->write( $locked, root_pem => $root->{pem} );
    my $before = raw( $locked.'/root_ca.pem' );
    chmod 0555, $locked or die 'chmod: '.$!;
    my $ok = eval { SICK::Trust->write( $locked, root_pem => $other->{pem} ); 1 };
    my $error = $@;
    chmod 0755, $locked;
    ok !$ok, 'a directory that cannot be written';
    like $error, qr/^cannot write '\Q$locked\E\/root_ca\.pem': \S/, '... names the file and the reason';
    is raw( $locked.'/root_ca.pem' ), $before, '... and leaves what was there';
  }
};

#### a CA that signs through an intermediate

# What a device presents that has room for one certificate: the leaf, alone.
my $leaf    = new_cert( ca => $inter, dir => $tmp, name => 'switch', cn => 'switch.example.internal',
  san => 'DNS:switch.example.internal,IP:192.0.2.199' );
my $foreign = new_cert( ca => $other, dir => $tmp, name => 'stranger', cn => 'stranger.example.internal' );

# openssl verify with nothing but the given files to go by: no directory and
# no store of the system, the way SICK::Bundle keeps them out. Returns
# ( true or false, what openssl said ).
my $nowhere = $tmp.'/no-certificates-here';
mkdir $nowhere or die 'mkdir: '.$!;

sub verifies {
  my ( $anchors, $cert, @more ) = @_;
  my @args = ( 'verify', @$anchors );
  if ( SICK::OpenSSL::major() >= 1 ) {
    push @args, '-no-CAfile' unless grep { $_ eq '-CAfile' } @$anchors;
    push @args, '-no-CApath' unless grep { $_ eq '-CApath' } @$anchors;
  }
  push @args, '-no-CAstore' if SICK::OpenSSL::major() >= 3;
  my ( $out, $err, $exit ) = SICK::OpenSSL::run(
    [ @args, @more, $cert ],
    env => { SSL_CERT_DIR => $nowhere, SSL_CERT_FILE => $nowhere.'/none.pem' },
  );
  return ( $exit == 0 ? 1 : 0, $out.$err );
}

sub fingerprint_of_der {
  my ( $path ) = @_;
  my ( $out ) = SICK::OpenSSL::run( [ 'x509', '-inform', 'der', '-in', $path, '-noout', '-fingerprint', '-sha256' ] );
  my ($fingerprint) = $out =~ /Fingerprint=([0-9A-Fa-f:]+)/;
  ( my $plain = lc( $fingerprint || q{} ) ) =~ tr/://d;
  return $plain;
}

my $chained     = $tmp.'/site/chained';
my $inter_facts = SICK::Bundle->new( cert => $inter->{pem} );
my @with        = qw( root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca.crt ca_bundle.pem root_ca.mobileconfig index.html );
my @chained_paths;

subtest 'with an intermediate: seven files' => sub {
  @chained_paths = SICK::Trust->write( $chained, root_pem => $root->{pem}, intermediates_pem => $inter->{pem}, name => 'Example Internal CA' );

  is_deeply [ SICK::Trust->files(1) ], \@with, 'files(1): the names with one intermediate';
  is_deeply [ SICK::Trust->files(0) ], [ SICK::Trust->files ], 'files(0) is files()';
  is_deeply \@chained_paths, [ map { $chained.'/'.$_ } @with ], 'write returns the paths, the page last';
  is_deeply files_in($chained), [ sort @with ], 'exactly these files are there';
  is sprintf( '%04o', ( stat $_ )[2] & 07777 ), '0644', $_ =~ s{.*/}{}r.' is readable for everybody' for @chained_paths;

  is raw( $chained.'/'.$_ ), raw( $dir.'/'.$_ ), $_.' is what it is without an intermediate' for qw( root_ca.pem root_ca.crt );
  is slurp( $chained.'/intermediate_ca.pem' ), $inter->{pem}, 'intermediate_ca.pem is the intermediate certificate';
  unlike raw( $chained.'/intermediate_ca.crt' ), qr/BEGIN CERTIFICATE/, 'intermediate_ca.crt is not PEM';
  is fingerprint_of_der( $chained.'/intermediate_ca.crt' ), $inter_facts->fingerprint_sha256, '... but the same certificate in DER';
  is slurp( $chained.'/ca_bundle.pem' ), $root->{pem}.$inter->{pem}, 'ca_bundle.pem is the root followed by the intermediate';
  unlike join( q{}, map { raw($_) } @chained_paths ), qr/PRIVATE KEY/, 'no key in any of them';
};

subtest 'a certificate presented alone validates with what was written, and with nothing less' => sub {
  # Everything openssl gets here is a file SICK::Trust wrote, and the leaf.
  my ( $ok, $said ) = verifies( [ '-CAfile', $chained.'/ca_bundle.pem' ], $leaf->{cert} );
  ok $ok, 'ca_bundle.pem as the only CA file: the leaf is accepted' or diag $said;

  ( $ok, $said ) = verifies( [ '-CAfile', $chained.'/root_ca.pem' ], $leaf->{cert} );
  ok !$ok, 'root_ca.pem alone: the leaf is refused';
  like $said, qr/unable to get local issuer certificate/, '... because nothing leads to the root';

  ( $ok, $said ) = verifies( [ '-CAfile', $chained.'/root_ca.pem' ], $leaf->{cert}, '-untrusted', $chained.'/intermediate_ca.pem' );
  ok $ok, 'root_ca.pem as the anchor and intermediate_ca.pem as a mere help: accepted' or diag $said;

  ( $ok, $said ) = verifies( [ '-CAfile', $chained.'/intermediate_ca.pem' ], $leaf->{cert} );
  ok !$ok, 'intermediate_ca.pem alone is no anchor: refused';

  ( $ok, $said ) = verifies( [ '-CAfile', $chained.'/ca_bundle.pem' ], $foreign->{cert} );
  ok !$ok, 'the certificate of another CA is refused with the bundle';

  # The system store of a Linux machine: one file per certificate in a
  # directory, found by the hash of the subject.
SKIP: {
    my $store = $tmp.'/system-store';
    mkdir $store or die 'mkdir: '.$!;
    spew( $store.'/internal-root-ca.crt',         slurp( $chained.'/root_ca.pem' ) );
    spew( $store.'/internal-intermediate-ca.crt', slurp( $chained.'/intermediate_ca.pem' ) );
    my ( $out, $err, $exit ) = SICK::OpenSSL::run( [ 'rehash', $store ] );
    skip 'openssl rehash does not work here', 2 if $exit;
    ( $ok, $said ) = verifies( [ '-CApath', $store ], $leaf->{cert} );
    ok $ok, 'both files in a certificate directory: accepted' or diag $said;
    unlink $store.'/internal-intermediate-ca.crt' or die 'unlink: '.$!;
    SICK::OpenSSL::run( [ 'rehash', $store ] );
    ( $ok, $said ) = verifies( [ '-CApath', $store ], $leaf->{cert} );
    ok !$ok, '... the root alone in it: refused';
  }
};

subtest 'the profile carries the root as root and the intermediate as a certificate' => sub {
  my $profile = slurp( $chained.'/root_ca.mobileconfig' );
  is xml_problem($profile), undef, 'well-formed XML';

  my @payloads = $profile =~ m{<dict>\s*(<key>PayloadCertificateFileName</key>.*?)</dict>}sg;
  is scalar @payloads, 2, 'two certificate payloads';
  my %by_type;
  for my $payload (@payloads) {
    my ($type) = $payload =~ m{<key>PayloadType</key>\s*<string>([^<]+)</string>};
    my ($data) = $payload =~ m{<key>PayloadContent</key>\s*<data>\s*(.*?)\s*</data>}s;
    my ($file) = $payload =~ m{<key>PayloadCertificateFileName</key>\s*<string>([^<]+)</string>};
    my ($id)   = $payload =~ m{<key>PayloadIdentifier</key>\s*<string>([^<]+)</string>};
    my ($uuid) = $payload =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>};
    $by_type{ $type || q{} } = { der => decode_base64( $data || q{} ), file => $file, id => $id, uuid => $uuid };
  }
  is_deeply [ sort keys %by_type ], [qw( com.apple.security.pkcs1 com.apple.security.root )],
    'one com.apple.security.root, one com.apple.security.pkcs1';
  is $by_type{'com.apple.security.root'}{der}, raw( $chained.'/root_ca.crt' ), 'the root payload is the root certificate in DER';
  is $by_type{'com.apple.security.pkcs1'}{der}, raw( $chained.'/intermediate_ca.crt' ), 'the other one is the intermediate in DER';
  is $by_type{'com.apple.security.pkcs1'}{file}, 'intermediate_ca.crt', '... under the name of its file';
  is $by_type{$_}{id}, $_.'.'.$by_type{$_}{uuid}, 'the identifier of the '.$_.' payload ends in its UUID' for sort keys %by_type;
  like $profile, qr{<string>Example Internal Intermediate</string>}, 'the intermediate is called by its common name';

  my @uuids = $profile =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g;
  is scalar @uuids, 3, 'three UUIDs';
  like $_, qr/\A[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/, $_.' has the form of one' for @uuids;
  my %distinct = map { $_ => 1 } @uuids;
  is scalar keys %distinct, 3, 'all different';

  # A device that has the profile of the root alone has to take this one as
  # its successor, not as a second profile.
  my $alone        = slurp( $dir.'/root_ca.mobileconfig' );
  my @alone_uuids  = $alone =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g;
  my ($alone_id)   = $alone =~ m{<key>PayloadIdentifier</key>\s*<string>(sick\.trust\.[^<]+)</string>};
  my ($chained_id) = $profile =~ m{<key>PayloadIdentifier</key>\s*<string>(sick\.trust\.[^<]+)</string>};
  ok defined $alone_id, 'the profile has an identifier of its own';
  is $chained_id, $alone_id, '... which is the same with and without the intermediate: one replaces the other';
  is $by_type{'com.apple.security.root'}{uuid}, $alone_uuids[0], 'the root payload is the same payload';
  isnt $uuids[-1], $alone_uuids[-1], 'the profile as a whole has another UUID: its content is another';
};

subtest 'the page with an intermediate' => sub {
  my $page = slurp( $chained.'/index.html' );
  like $page, qr/\A<!DOCTYPE html>\n<html lang="en">/, 'an HTML page';
  like $page, qr/<a href="\Q$_\E"/, 'a link to '.$_ for grep { $_ ne 'index.html' } @with;
  like $page, qr/<h2 id="[a-z]+">[^<]*\Q$_\E/, 'instructions for '.$_ for qw( Firefox Chrome Linux macOS Windows iPhone Android );

  my @references = $page =~ /(?:href|src|action)\s*=\s*"([^"]*)"/g;
  my %written = map { $_ => 1 } @with;
  is_deeply [ grep { !/\A#[a-z]+\z/ && !$written{$_} } @references ], [],
    'every link leads to a section of the page or to a file that was written';
  my %anchor = map { $_ => 1 } $page =~ /\bid="([a-z]+)"/g;
  is_deeply [ grep { /\A#/ && !$anchor{ substr $_, 1 } } @references ], [], '... and every section that is linked exists';
  unlike $page, qr/<(?:script|link|img|iframe|object|embed)\b/i, 'no script, no style sheet, no image from anywhere';
  unlike $page, qr/url\(|\@import/i, '... and none in the style either';
  unlike $page, qr/[ \t]\n/, 'no trailing blanks';
  unlike $page, qr/<!--/, 'no comment, no placeholder left';
  unlike $page, qr/\n\n\n/, 'no hole where a part was left out';

  ( my $shown = $page ) =~ s/<br>//g;
  for my $facts ( $facts, $inter_facts ) {
    my $colons = join ':', map { uc } $facts->fingerprint_sha256 =~ /(..)/g;
    like $shown, qr/\Q$colons\E/, 'the SHA-256 fingerprint of '.$facts->subject_dn;
  }
  like $page, qr/CN=Example Internal Intermediate/, 'the subject of the intermediate';

  # what is to be done where
  my %section = map { /\A<h2 id="([a-z]+)">/ ? ( $1 => $_ ) : () } split /(?=<h2 id=")/, $page;
  like $section{ios}, qr/root_ca\.mobileconfig/, 'iPhone: the profile';
  like $section{ios}, qr/Certificate Trust\s+Settings/, '... and full trust for the root';
  unlike $section{ios}, qr/href="intermediate_ca/, '... and no second file: the profile has the intermediate';
  like $section{android}, qr/href="root_ca\.crt"/, 'Android: the root';
  unlike $section{android}, qr/intermediate_ca/, '... and no intermediate: its CA list is a list of anchors';
  like $section{android}, qr/not accepted on Android/, '... which a device without the chain is told';
  like $section{macos}, qr/add-trusted-cert -d -r trustRoot[^<]*root_ca\.pem/, 'macOS: the root is trusted as a root';
  like $section{macos}, qr/security add-certificates[^<]*intermediate_ca\.crt/, '... the intermediate is added, not trusted';
  like $section{windows}, qr/certutil -addstore -f Root root_ca\.crt/, 'Windows: the root into the root store';
  like $section{windows}, qr/certutil -addstore -f CA intermediate_ca\.crt/, '... the intermediate into the store of intermediates';
  like $section{windows}, qr/Intermediate Certification Authorities/, '... which the page calls by its name';
  like $section{linux}, qr{cp root_ca\.pem /usr/local/share/ca-certificates/[a-z-]+\.crt\nsudo update-ca-certificates}, 'Debian: the root, then update-ca-certificates';
  like $section{linux}, qr{cp root_ca\.pem /etc/pki/ca-trust/source/anchors/[a-z-]+\.pem\nsudo update-ca-trust}, 'Fedora: the root, then update-ca-trust';
  like $section{linux}, qr{trust anchor --store root_ca\.pem</pre>}, 'p11-kit: the root alone';
  # An intermediate in a store of anchors stays trusted when the root is gone
  # (docs/findings/trust-anchors.md): no system store, no p11-kit anchor.
  unlike $page, qr{intermediate[^\n<]*(?:/usr/local/share/ca-certificates|/etc/pki/ca-trust|/etc/ssl/certs)}, 'no intermediate is copied into a system store';
  unlike $page, qr{trust anchor --store[^\n<]*intermediate}, '... nor stored as a p11-kit anchor';
  like $section{linux}, qr/--cacert ca_bundle\.pem/, 'the bundle for a program that takes one file';
  like $section{linux}, qr/http\.sslCAInfo [^\n<]*ca_bundle\.pem/, '... git as well';
  like $section{linux}, qr/take the intermediate as a\s+trust anchor/, '... saying that the intermediate is an anchor inside it';
  like $section{linux}, qr/replace the file/, '... and that the file goes when the intermediate goes';
  like $section{firefox}, qr/pick <code>intermediate_ca\.pem<\/code> and tick nothing/, 'Firefox: the intermediate without trust';
  like $section{firefox}, qr/href="\Q$_\E"/, 'Firefox: '.$_ for qw( root_ca.pem intermediate_ca.pem );
  like $section{firefox}, qr/Firefox for Android/, '... and Firefox for Android';
  like $section{chrome}, qr/href="\Q$_\E"/, 'Chrome on Linux: '.$_ for qw( root_ca.pem intermediate_ca.pem );
  like $section{chrome}, qr/Intermediate certificates/, '... the intermediate where Chrome keeps intermediates';
};

subtest 'without an intermediate nothing is different' => sub {
  my %before = map { $_ => raw( $dir.'/'.$_ ) } SICK::Trust->files;
  my %cases  = ( 'undef' => undef, 'an empty string' => q{}, 'blank lines' => "\n \n" );
  for my $case ( sort keys %cases ) {
    my $target = $tmp.'/none-'.( $case =~ tr/a-z//cdr );
    my @paths  = SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $cases{$case}, name => 'Example Internal CA' );
    is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], $case.' as intermediates_pem: the four files';
    is raw( $target.'/'.$_ ), $before{$_}, '... '.$_.' byte for byte what it is without the argument' for SICK::Trust->files;
  }
  unlike $before{'index.html'}, qr/intermediate|ca_bundle/i, 'the page of a CA without an intermediate does not speak of one';
  unlike $before{'root_ca.mobileconfig'}, qr/pkcs1/, '... and its profile has the root alone';
};

subtest 'writing twice with an intermediate produces the same bytes' => sub {
  my %before = map { $_ => raw($_) } @chained_paths;
  sleep 1;
  SICK::Trust->write( $chained, root_pem => $root->{pem}, intermediates_pem => $inter->{pem}, name => 'Example Internal CA' );
  is raw($_), $before{$_}, $_ =~ s{.*/}{}r.' is byte for byte the same' for @chained_paths;

  # the root in the file of intermediates, the intermediate twice: the same
  my $again = $tmp.'/chained-again';
  SICK::Trust->write( $again, root_pem => $root->{pem}, name => 'Example Internal CA',
    intermediates_pem => "the chain of the CA\n".$inter->{pem}.$root->{pem}."\n".$inter->{pem} );
  is_deeply files_in($again), [ sort @with ], 'the root among the intermediates and a certificate given twice count once';
  is raw( $again.'/'.$_ ), $before{ $chained.'/'.$_ }, $_.' is the same' for @with;
};

subtest 'several intermediates' => sub {
  my $issuing = new_ca( dir => $tmp, name => 'issuing', cn => 'Example Internal Issuing CA', issuer => $inter );
  my $deep    = new_cert( ca => $issuing, dir => $tmp, name => 'deep', cn => 'deep.example.internal' );
  my $target  = $tmp.'/site/deep';
  my @names   = qw( root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca_1.pem intermediate_ca_1.crt
    intermediate_ca_2.pem intermediate_ca_2.crt ca_bundle.pem root_ca.mobileconfig index.html );
  my @paths = SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $inter->{pem}.$issuing->{pem} );

  is_deeply [ SICK::Trust->files(2) ], \@names, 'files(2)';
  is_deeply \@paths, [ map { $target.'/'.$_ } @names ], 'the paths';
  is_deeply files_in($target), [ sort @names ], 'the files';
  is slurp( $target.'/intermediate_ca.pem' ), $inter->{pem}.$issuing->{pem}, 'intermediate_ca.pem has all of them, in the order they were given';
  is slurp( $target.'/intermediate_ca_1.pem' ), $inter->{pem},   'intermediate_ca_1.pem is the first one alone';
  is slurp( $target.'/intermediate_ca_2.pem' ), $issuing->{pem}, 'intermediate_ca_2.pem the second';
  is fingerprint_of_der( $target.'/intermediate_ca_2.crt' ), SICK::Bundle->new( cert => $issuing->{pem} )->fingerprint_sha256,
    'intermediate_ca_2.crt is the second one in DER';
  is slurp( $target.'/ca_bundle.pem' ), $root->{pem}.$inter->{pem}.$issuing->{pem}, 'ca_bundle.pem has the root and both';

  my ( $ok, $said ) = verifies( [ '-CAfile', $target.'/ca_bundle.pem' ], $deep->{cert} );
  ok $ok, 'a certificate two steps below the root validates with the bundle' or diag $said;
  ( $ok ) = verifies( [ '-CAfile', $chained.'/ca_bundle.pem' ], $deep->{cert} );
  ok !$ok, '... and not with the bundle that lacks the second step';

  my $profile = slurp( $target.'/root_ca.mobileconfig' );
  is xml_problem($profile), undef, 'the profile is well-formed';
  is scalar( () = $profile =~ m{<string>com\.apple\.security\.pkcs1</string>}g ), 2, '... with two intermediate payloads';
  is scalar( () = $profile =~ m{<string>com\.apple\.security\.root</string>}g ), 1, '... and one root';
  like $profile, qr{<string>intermediate_ca_2\.crt</string>}, '... named like their files';

  my $page    = slurp( $target.'/index.html' );
  my %written = map { $_ => 1 } @names;
  my @files   = grep { !/\A#/ } $page =~ /href="([^"]*)"/g;
  is_deeply [ grep { !$written{$_} } @files ], [], 'the page links to nothing that was not written';
  like $page, qr/<a href="\Q$_\E"/, '... and to '.$_ for grep { $_ ne 'index.html' } @names;
  like $page, qr/certutil -addstore -f CA intermediate_ca_1\.crt\ncertutil -addstore -f CA intermediate_ca_2\.crt/,
    'a command for each of them';
  unlike $page, qr{intermediate[^\n<]*(?:/usr/local/share/ca-certificates|/etc/pki/ca-trust|/etc/ssl/certs)|trust anchor --store[^\n<]*intermediate},
    'none of them into a system store or a p11-kit anchor';
  unlike $page, qr/[ \t]\n|<!--|\n\n\n/, 'no trailing blanks, no placeholder, no hole';
};

subtest 'what an earlier write left and this one does not write is removed' => sub {
  my $target = $tmp.'/site/shrinking';
  SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $inter->{pem} );
  spew( $target.'/robots.txt',             "User-agent: *\n" );
  spew( $target.'/intermediate_ca_7.crt',  "left by a CA with more of them\n" );
  spew( $target.'/intermediate_ca.pem.bak', "somebody's copy\n" );

  SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $inter->{pem} );
  is_deeply files_in($target), [ sort @with, 'intermediate_ca.pem.bak', 'robots.txt' ],
    'with the intermediate: the stale numbered file is gone, files of others stay';

  my @paths = SICK::Trust->write( $target, root_pem => $root->{pem} );
  is_deeply files_in($target), [ sort SICK::Trust->files, 'intermediate_ca.pem.bak', 'robots.txt' ],
    'the CA has no intermediate any more: nothing of it is offered any longer';
  is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], '... and the four files are returned';
  is raw( $target.'/index.html' ), raw( $tmp.'/unnamed/index.html' ), '... with the page of a CA without one';
};

subtest 'intermediates that are none' => sub {
  my $stranger = new_ca( dir => $tmp, name => 'stranger-inter', cn => 'Intermediate Of Another', issuer => $other );
  my %bad = (
    'text that is no PEM'            => [ "not a certificate\n", qr/^intermediates_pem is not a PEM certificate/ ],
    'an intermediate of another CA'  => [ $stranger->{pem}, qr/^the intermediate certificate 'CN=Intermediate Of Another' does not lead to the root certificate 'CN=Example Internal Root CA'/ ],
    'another root'                   => [ $other->{pem}, qr/^the intermediate certificate 'CN=Another Root' does not lead to the root certificate/ ],
    'one good and one of another CA' => [ $inter->{pem}.$stranger->{pem}, qr/^the intermediate certificate 'CN=Intermediate Of Another' does not lead/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $pem, $message ) = @{ $bad{$case} };
    my $target = $tmp.'/badinter-'.( $case =~ tr/a-z//cdr );
    ok !eval { SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $pem ); 1 }, 'dies for '.$case;
    like $@, $message, '... saying so';
    ok !-e $target, '... and writes nothing';
  }
};

done_testing;
