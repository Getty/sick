#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use Digest::SHA qw( sha1_hex );
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
my @scripts = qw( trust-linux.sh trust-macos.sh trust-windows.ps1 trust-nss.sh );

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

subtest 'the root, the scripts, the profile and the page' => sub {
  ok !-e $dir, 'the directory does not exist yet';
  @written = SICK::Trust->write( $dir, root_pem => $root->{pem}, name => 'Example Internal CA' );

  is_deeply [ SICK::Trust->files ], [ qw( root_ca.pem root_ca.crt ), @scripts, qw( root_ca.mobileconfig index.html ) ], 'files';
  is_deeply \@written, [ map { $dir.'/'.$_ } SICK::Trust->files ], 'write returns the paths';
  is_deeply files_in($dir), [ sort qw( index.html root_ca.crt root_ca.mobileconfig root_ca.pem ), @scripts ],
    'exactly these files are there, no temporary ones';
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
  is_deeply [ grep { !/\A(?:#[a-z]+|root_ca\.(?:pem|crt|mobileconfig)|trust-(?:linux|macos|nss)\.sh|trust-windows\.ps1)\z/ } @references ], [],
    '... only to its own sections, the three files and the four scripts';
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
  is_deeply files_in($dir), [ sort qw( index.html root_ca.crt root_ca.mobileconfig root_ca.pem ), @scripts ], 'and nothing else appeared';

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
my @with        = ( qw( root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca.crt ca_bundle.pem ), @scripts, qw( root_ca.mobileconfig index.html ) );
my @chained_paths;

subtest 'with an intermediate: three files more' => sub {
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
    is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], $case.' as intermediates_pem: the files without one';
    is raw( $target.'/'.$_ ), $before{$_}, '... '.$_.' byte for byte what it is without the argument' for SICK::Trust->files;
  }
  unlike $before{'index.html'}, qr/intermediate|(?<!REQUESTS_)ca_bundle/i, 'the page of a CA without an intermediate does not speak of one';
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
  my @names   = ( qw( root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca_1.pem intermediate_ca_1.crt
    intermediate_ca_2.pem intermediate_ca_2.crt ca_bundle.pem ), @scripts, qw( root_ca.mobileconfig index.html ) );
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
  is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], '... and the files without them are returned';
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

subtest 'a certificate that is no CA is no intermediate' => sub {
  # with an issuer other than StepCA nothing else stops a leaf of the root
  my $root_leaf = new_cert( ca => $root, dir => $tmp, name => 'root-leaf', cn => 'leaf.example.internal' );
  for my $case ( [ 'a leaf of the root', $root_leaf->{cert_pem} ], [ 'a leaf next to the intermediate', $inter->{pem}.$root_leaf->{cert_pem} ] ) {
    my ( $what, $pem ) = @$case;
    my $target = $tmp.'/badinter-noca-'.( $what =~ tr/a-z//cdr );
    ok !eval { SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $pem ); 1 }, 'dies for '.$what;
    like $@, qr/^the intermediate certificate 'CN=leaf\.example\.internal' is not a CA certificate \(basicConstraints does not say CA:TRUE\)/,
      '... naming its subject and the reason';
    ok !-e $target, '... and writes nothing';
  }
};

#### a replacement of the root: further roots next to the current one

my $next      = new_ca( dir => $tmp, name => 'next', cn => 'Example Internal Root CA 2' );
my $previous  = new_ca( dir => $tmp, name => 'previous', cn => 'Example Internal Root CA 0' );
my $next_leaf = new_cert( ca => $next, dir => $tmp, name => 'renewed', cn => 'renewed.example.internal',
  san => 'DNS:renewed.example.internal' );
my $next_facts     = SICK::Bundle->new( cert => $next->{pem} );
my $previous_facts = SICK::Bundle->new( cert => $previous->{pem} );
my $rollover       = $tmp.'/site/rollover';
my @rollover_names = ( qw( root_ca.pem root_ca.crt root_ca_2.pem root_ca_2.crt ca_bundle.pem ), @scripts, qw( root_ca.mobileconfig index.html ) );
my @rollover_paths;

subtest 'with an additional root: its files and the bundle' => sub {
  @rollover_paths = SICK::Trust->write( $rollover, root_pem => $root->{pem}, additional_roots_pem => $next->{pem},
    name => 'Example Internal CA' );

  is_deeply [ SICK::Trust->files( 0, 1 ) ], \@rollover_names, 'files(0, 1): the names with one additional root';
  is_deeply [ SICK::Trust->files( 1, 0 ) ], [ SICK::Trust->files(1) ], 'files(1, 0) is files(1)';
  is_deeply \@rollover_paths, [ map { $rollover.'/'.$_ } @rollover_names ], 'write returns the paths, the page last';
  is_deeply files_in($rollover), [ sort @rollover_names ], 'exactly these files are there';
  is sprintf( '%04o', ( stat $_ )[2] & 07777 ), '0644', $_ =~ s{.*/}{}r.' is readable for everybody' for @rollover_paths;

  is raw( $rollover.'/'.$_ ), raw( $dir.'/'.$_ ), $_.' is the current root, as without an additional one' for qw( root_ca.pem root_ca.crt );
  is slurp( $rollover.'/root_ca_2.pem' ), $next->{pem}, 'root_ca_2.pem is the additional root';
  unlike raw( $rollover.'/root_ca_2.crt' ), qr/BEGIN CERTIFICATE/, 'root_ca_2.crt is not PEM';
  is fingerprint_of_der( $rollover.'/root_ca_2.crt' ), $next_facts->fingerprint_sha256, '... but the same certificate in DER';
  is slurp( $rollover.'/ca_bundle.pem' ), $root->{pem}.$next->{pem}, 'ca_bundle.pem is the current root followed by the additional one';

  my ( $ok, $said ) = verifies( [ '-CAfile', $rollover.'/ca_bundle.pem' ], $next_leaf->{cert} );
  ok $ok, 'a certificate of the next root validates with the bundle' or diag $said;
  ( $ok, $said ) = verifies( [ '-CAfile', $rollover.'/root_ca_2.pem' ], $next_leaf->{cert} );
  ok $ok, '... and with root_ca_2.pem' or diag $said;
  ( $ok ) = verifies( [ '-CAfile', $rollover.'/root_ca.pem' ], $next_leaf->{cert} );
  ok !$ok, 'a client with the current root alone refuses it';

  my $target = $tmp.'/site/rollover-chained';
  my @names  = ( qw( root_ca.pem root_ca.crt root_ca_2.pem root_ca_2.crt root_ca_3.pem root_ca_3.crt
    intermediate_ca.pem intermediate_ca.crt ca_bundle.pem ), @scripts, qw( root_ca.mobileconfig index.html ) );
  my @paths = SICK::Trust->write( $target, root_pem => $root->{pem}, intermediates_pem => $inter->{pem},
    additional_roots_pem => $next->{pem}.$previous->{pem} );
  is_deeply [ SICK::Trust->files( 1, 2 ) ], \@names, 'files(1, 2): the roots first, then the intermediate';
  is_deeply \@paths, [ map { $target.'/'.$_ } @names ], '... and that is what write returns';
  is_deeply files_in($target), [ sort @names ], '... and what is there';
  is slurp( $target.'/root_ca_2.pem' ), $next->{pem},     'root_ca_2.pem is the first additional root';
  is slurp( $target.'/root_ca_3.pem' ), $previous->{pem}, 'root_ca_3.pem the second';
  is slurp( $target.'/ca_bundle.pem' ), $root->{pem}.$next->{pem}.$previous->{pem}.$inter->{pem},
    'ca_bundle.pem: the current root, the additional ones in their order, then the intermediate';
  is slurp( $target.'/intermediate_ca.pem' ), $inter->{pem}, 'intermediate_ca.pem is the intermediate alone';
  ( $ok, $said ) = verifies( [ '-CAfile', $target.'/ca_bundle.pem' ], $leaf->{cert} );
  ok $ok, 'the leaf under the intermediate still validates with the bundle' or diag $said;
  unlike join( q{}, map { raw($_) } @rollover_paths, @paths ), qr/PRIVATE KEY/, 'no key in any of them';
};

subtest 'the profile carries each additional root as a root' => sub {
  my $profile = slurp( $rollover.'/root_ca.mobileconfig' );
  is xml_problem($profile), undef, 'well-formed XML';

  my @payloads = $profile =~ m{<dict>\s*(<key>PayloadCertificateFileName</key>.*?)</dict>}sg;
  is scalar @payloads, 2, 'two certificate payloads';
  my %by_file;
  for my $payload (@payloads) {
    my ($type) = $payload =~ m{<key>PayloadType</key>\s*<string>([^<]+)</string>};
    my ($data) = $payload =~ m{<key>PayloadContent</key>\s*<data>\s*(.*?)\s*</data>}s;
    my ($file) = $payload =~ m{<key>PayloadCertificateFileName</key>\s*<string>([^<]+)</string>};
    my ($name) = $payload =~ m{<key>PayloadDisplayName</key>\s*<string>([^<]+)</string>};
    $by_file{ $file || q{} } = { type => $type, der => decode_base64( $data || q{} ), name => $name };
  }
  is_deeply [ sort keys %by_file ], [qw( root_ca.crt root_ca_2.crt )], 'one for root_ca.crt, one for root_ca_2.crt';
  is $by_file{$_}{type}, 'com.apple.security.root', $_.' is a com.apple.security.root' for sort keys %by_file;
  is $by_file{$_}{der}, raw( $rollover.'/'.$_ ), '... '.$_.' carries that file' for sort keys %by_file;
  is $by_file{'root_ca_2.crt'}{name}, 'Example Internal Root CA 2', 'the additional root is called by its common name';
  like $profile, qr{<key>PayloadDescription</key>\s*<string>Makes this device trust[^<]*root replacement[^<]*</string>},
    'the description of the profile speaks of the replacement';

  my ($alone_id)    = slurp( $dir.'/root_ca.mobileconfig' ) =~ m{<string>(sick\.trust\.[^<]+)</string>};
  my ($rollover_id) = $profile =~ m{<string>(sick\.trust\.[^<]+)</string>};
  is $rollover_id, $alone_id, 'the identifier stays with the current root: this profile replaces the one without';
  my @uuids = $profile =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g;
  my %distinct = map { $_ => 1 } @uuids;
  is scalar keys %distinct, 3, 'three UUIDs, all different';
  isnt $uuids[-1], ( slurp( $dir.'/root_ca.mobileconfig' ) =~ m{<key>PayloadUUID</key>\s*<string>([^<]+)</string>}g )[-1],
    'the profile as a whole has another UUID than the one without';

  my $chained_profile = slurp( $tmp.'/site/rollover-chained/root_ca.mobileconfig' );
  is xml_problem($chained_profile), undef, 'with two additional roots and an intermediate: well-formed';
  is scalar( () = $chained_profile =~ m{<string>com\.apple\.security\.root</string>}g ), 3, '... three roots';
  is scalar( () = $chained_profile =~ m{<string>com\.apple\.security\.pkcs1</string>}g ), 1, '... and the intermediate';
};

subtest 'the page with an additional root' => sub {
  my $page = slurp( $rollover.'/index.html' );
  like $page, qr/\A<!DOCTYPE html>\n<html lang="en">/, 'an HTML page';
  like $page, qr/<a href="\Q$_\E"/, 'a link to '.$_ for grep { $_ ne 'index.html' } @rollover_names;
  my @references = $page =~ /(?:href|src|action)\s*=\s*"([^"]*)"/g;
  my %written = map { $_ => 1 } @rollover_names;
  is_deeply [ grep { !/\A#[a-z]+\z/ && !$written{$_} } @references ], [],
    'every link leads to a section of the page or to a file that was written';
  my %anchor = map { $_ => 1 } $page =~ /\bid="([a-z]+)"/g;
  is_deeply [ grep { /\A#/ && !$anchor{ substr $_, 1 } } @references ], [], '... and every section that is linked exists';
  unlike $page, qr/[ \t]\n|<!--|\n\n\n/, 'no trailing blanks, no placeholder, no hole';
  unlike $page, qr/intermediate/i, 'no word about an intermediate the CA does not have';
  like $page, qr/the current root and the further root in one file/, 'the bundle says what it holds';

  ( my $shown = $page ) =~ s/<br>//g;
  for my $facts ( $facts, $next_facts ) {
    my $colons = join ':', map { uc } $facts->fingerprint_sha256 =~ /(..)/g;
    like $shown, qr/\Q$colons\E/, 'the SHA-256 fingerprint of '.$facts->subject_dn;
  }
  like $page, qr/CN=Example Internal Root CA 2/, 'the subject of the additional root';
  like $page, qr/<strong>current root<\/strong>[^<]*<\/p>\n<dl>\n  <dt>Certificate<\/dt><dd>CN=Example Internal Root CA<\/dd>/,
    'the page says which one is the current root';
  ( my $text = $page ) =~ s/\s+/ /g;
  like $text, qr/roots of the same organisation during a replacement/, 'what the further roots are';
  like $text, qr/install them the same way as the current root/i, '... how to install them';
  like $text, qr/remove the one that is no longer listed on this page/, '... and what to do once the replacement is over';

  my %section = map { /\A<h2 id="([a-z]+)">/ ? ( $1 => $_ ) : () } split /(?=<h2 id=")/, $page;
  like $section{macos},   qr/add-trusted-cert -d -r trustRoot[^<]*root_ca\.pem\nsudo security add-trusted-cert -d -r trustRoot \\\n  -k \S+ root_ca_2\.pem/,
    'macOS: the additional root is trusted as a root';
  like $section{windows}, qr/certutil -addstore -f Root root_ca\.crt\ncertutil -addstore -f Root root_ca_2\.crt/,
    'Windows: the additional root into the root store';
  like $section{linux},   qr/openssl x509 -in root_ca_2\.pem -noout -fingerprint -sha256/, 'Linux: its fingerprint can be checked';
  like $section{linux},   qr/internal-root-ca-2/, '... and it gets a file of its own in the system store';
  like $section{ios},     qr/full trust for it in the same place/, 'iPhone: full trust for the further root of the profile';

  my $chained_page = slurp( $tmp.'/site/rollover-chained/index.html' );
  unlike $chained_page, qr/[ \t]\n|<!--|\n\n\n/, 'with an intermediate as well: no trailing blanks, no placeholder, no hole';
  ( $shown = $chained_page ) =~ s/<br>//g;
  for my $facts ( $facts, $next_facts, $previous_facts, $inter_facts ) {
    my $colons = join ':', map { uc } $facts->fingerprint_sha256 =~ /(..)/g;
    like $shown, qr/\Q$colons\E/, '... the SHA-256 fingerprint of '.$facts->subject_dn;
  }
  like $chained_page, qr/full trust for each of them in the same place/, '... full trust for each further root on the iPhone';
  like $chained_page, qr/the current root, the further roots and the intermediate in one file/, '... and the bundle says what it holds';
  like $chained_page, qr/certutil -addstore -f Root root_ca\.crt\ncertutil -addstore -f Root root_ca_2\.crt\ncertutil -addstore -f Root root_ca_3\.crt\ncertutil -addstore -f CA intermediate_ca\.crt/,
    '... the roots into the root store, then the intermediate into its own';
};

subtest 'without an additional root nothing is different' => sub {
  my %cases = ( 'undef' => undef, 'an empty string' => q{}, 'blank lines' => "\n \n", 'the root itself' => $root->{pem} );
  for my $case ( sort keys %cases ) {
    my $target = $tmp.'/noroots-'.( $case =~ tr/a-z//cdr );
    my @paths  = SICK::Trust->write( $target, root_pem => $root->{pem}, additional_roots_pem => $cases{$case}, name => 'Example Internal CA' );
    is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], $case.' as additional_roots_pem: the files with one root';
    is raw( $target.'/'.$_ ), raw( $dir.'/'.$_ ), '... '.$_.' byte for byte what it is without the argument' for SICK::Trust->files;

    my $chained_target = $target.'-chained';
    SICK::Trust->write( $chained_target, root_pem => $root->{pem}, intermediates_pem => $inter->{pem},
      additional_roots_pem => $cases{$case}, name => 'Example Internal CA' );
    is raw( $chained_target.'/'.$_ ), raw( $chained.'/'.$_ ), '... with an intermediate: '.$_.' the same as without the argument' for @with;
  }
  unlike raw( $dir.'/index.html' ), qr/current root|root_ca_2|further root/i, 'the page of a CA with one root does not speak of others';
};

subtest 'writing twice with an additional root produces the same bytes' => sub {
  my %before = map { $_ => raw($_) } @rollover_paths;
  sleep 1;
  SICK::Trust->write( $rollover, root_pem => $root->{pem}, additional_roots_pem => $next->{pem}, name => 'Example Internal CA' );
  is raw($_), $before{$_}, $_ =~ s{.*/}{}r.' is byte for byte the same' for @rollover_paths;

  my $again = $tmp.'/rollover-again';
  SICK::Trust->write( $again, root_pem => $root->{pem}, name => 'Example Internal CA',
    additional_roots_pem => "the next root\n".$next->{pem}.$root->{pem}."\n".$next->{pem} );
  is_deeply files_in($again), [ sort @rollover_names ], 'the current root among them and a root given twice count once';
  is raw( $again.'/'.$_ ), $before{ $rollover.'/'.$_ }, $_.' is the same' for @rollover_names;
};

subtest 'the files of additional roots go when the replacement is over' => sub {
  my $target = $tmp.'/site/replaced';
  SICK::Trust->write( $target, root_pem => $root->{pem}, additional_roots_pem => $next->{pem}.$previous->{pem} );
  spew( $target.'/robots.txt',       "User-agent: *\n" );
  spew( $target.'/root_ca_9.crt',    "left by a replacement with more roots\n" );
  spew( $target.'/root_ca_2.pem.bak', "somebody's copy\n" );

  SICK::Trust->write( $target, root_pem => $root->{pem}, additional_roots_pem => $next->{pem} );
  is_deeply files_in($target), [ sort @rollover_names, 'robots.txt', 'root_ca_2.pem.bak' ],
    'one additional root less: root_ca_3 and the stale numbered file are gone, files of others stay';

  my @paths = SICK::Trust->write( $target, root_pem => $root->{pem} );
  is_deeply files_in($target), [ sort SICK::Trust->files, 'robots.txt', 'root_ca_2.pem.bak' ],
    'the key is removed again: no additional root and no bundle is offered any longer';
  is_deeply \@paths, [ map { $target.'/'.$_ } SICK::Trust->files ], '... and the files without them are returned';
  is raw( $target.'/'.$_ ), raw( $tmp.'/unnamed/'.$_ ), '... '.$_.' that of a CA with one root' for SICK::Trust->files;
};

subtest 'additional roots that are none' => sub {
  my $root_leaf = new_cert( ca => $root, dir => $tmp, name => 'root-leaf-2', cn => 'leaf2.example.internal' );
  my %bad = (
    'text that is no PEM' => [ "not a certificate\n", qr/^additional_roots_pem is not a PEM certificate/ ],
    'an intermediate'     => [ $inter->{pem}, qr/^the additional root certificate 'CN=Example Internal Intermediate' is not a self-signed CA certificate/ ],
    'a leaf'              => [ $root_leaf->{cert_pem}, qr/^the additional root certificate 'CN=leaf2\.example\.internal' is not a self-signed CA certificate/ ],
    'one good, one not'   => [ $next->{pem}.$inter->{pem}, qr/^the additional root certificate 'CN=Example Internal Intermediate' is not/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $pem, $message ) = @{ $bad{$case} };
    my $target = $tmp.'/badroot-'.( $case =~ tr/a-z//cdr );
    ok !eval { SICK::Trust->write( $target, root_pem => $root->{pem}, additional_roots_pem => $pem ); 1 }, 'dies for '.$case;
    like $@, $message, '... saying so';
    ok !-e $target, '... and writes nothing';
  }
};

#### the install and remove scripts

# Four scripts carry the certificates themselves and install them only when
# the operator gives the SHA-256 fingerprint of every root, as got by another
# channel. The shell scripts run here in a sandbox: SICK_TRUST_ROOT puts their
# paths below a directory of the test, and the programs they call
# (update-ca-certificates, update-ca-trust, trust, certutil, security) are
# recording fakes earlier in the PATH. Nothing touches a store of this machine.

my $sandbox = $tmp.'/script-sandbox';
my $fakebin = $sandbox.'/bin';
my $log     = $sandbox.'/calls.log';
mkdir $_ or die 'mkdir '.$_.': '.$! for $sandbox, $fakebin;

sub fake {
  my ( $name, $body ) = @_;
  my $path = spew( $fakebin.'/'.$name, "#!/bin/sh\nprintf '%s\\n' \"$name\${1+ \$*}\" >> \"\$SICK_TEST_LOG\"\n".$body );
  chmod 0755, $path or die 'chmod: '.$!;
  return $path;
}

# a SHA of a PEM file, the way the fakes find a certificate again
my $fake_hash = 'openssl x509 -in "$1" -outform DER | openssl dgst -$2 -r | cut -d" " -f1';

fake( 'update-ca-certificates', "exit 0\n" );
fake( 'update-ca-trust',        "exit 0\n" );
# p11-kit: trust anchor --store FILE / --remove FILE and trust list
# --filter=ca-anchors, kept below $SICK_TRUST_ROOT/p11kit. Like p11-kit 0.26.5
# (docs/findings/trust-os.md), --remove exits 0 also when nothing matched, and
# list prints one pkcs11: URI per anchor stored.
fake( 'trust', <<"SH" );
h() { $fake_hash; }
dir="\$SICK_TRUST_ROOT/p11kit"; mkdir -p "\$dir"
if [ "\$1" = list ]; then
  [ "\$2" = --filter=ca-anchors ] || exit 3
  for f in "\$dir"/*.pem; do
    [ -f "\$f" ] || continue
    n=\${f##*/}
    printf 'pkcs11:id=%s;type=cert\n    type: certificate\n    trust: anchor\n\n' "\${n%.pem}"
  done
  exit 0
fi
[ "\$1" = anchor ] || exit 3
entry="\$dir/\$(h "\$3" sha256).pem"
case \$2 in
  --store)  [ ! -f "\$entry" ] || exit 1; cp "\$3" "\$entry";;
  --remove) rm -f "\$entry";;
  *) exit 3;;
esac
SH
# NSS certutil: -A/-M/-D/-L on sql:DIR, one file per nickname
fake( 'certutil', <<'SH' );
op=''; db=''; nick=''; trust=''; file=''
while [ $# -gt 0 ]; do
  case $1 in
    -A|-M|-D|-L) op=$1;;
    -d) db=${2#sql:}; shift;;
    -n) nick=$2; shift;;
    -t) trust=$2; shift;;
    -i) file=$2; shift;;
  esac
  shift
done
entry="$db/fake-$(printf %s "$nick" | tr -c 'A-Za-z0-9\n' _)"
case $op in
  -A) [ ! -f "$entry.pem" ] || exit 1; cp "$file" "$entry.pem"; printf '%s\n' "$trust" > "$entry.trust";;
  -M) [ -f "$entry.pem" ] || exit 1; printf '%s\n' "$trust" > "$entry.trust";;
  -D) [ -f "$entry.pem" ] || exit 1; rm -f "$entry.pem" "$entry.trust";;
  -L) [ -f "$entry.pem" ] || exit 1;;
  *) exit 3;;
esac
SH
# macOS security: the keychain is a directory next to the keychain path
fake( 'security', <<"SH" );
h() { $fake_hash; }
cmd=\$1; shift
kc=''; hash=''; trusted=''
while [ \$# -gt 1 ]; do
  case \$1 in
    -k) kc=\$2; shift;;
    -Z) hash=\$2; shift;;
    -r) trusted=\$2; shift;;
  esac
  shift
done
last=\$1
dir="\$SICK_TRUST_ROOT/keychain"; mkdir -p "\$dir"
case \$cmd in
  add-trusted-cert)    [ "\$kc" = "\$SICK_TRUST_ROOT/Library/Keychains/System.keychain" ] || exit 4
                       s=\$(h "\$last" sha1 | tr a-f A-F); cp "\$last" "\$dir/\$s.pem"; printf '%s\\n' "\$trusted" > "\$dir/\$s.trust";;
  add-certificates)    [ "\$kc" = "\$SICK_TRUST_ROOT/Library/Keychains/System.keychain" ] || exit 4
                       s=\$(h "\$last" sha1 | tr a-f A-F); [ ! -f "\$dir/\$s.pem" ] || exit 1; cp "\$last" "\$dir/\$s.pem";;
  find-certificate)    for f in "\$dir"/*.pem; do [ -f "\$f" ] && printf 'SHA-1 hash: %s\\n' "\$(basename "\$f" .pem)"; done; exit 0;;
  remove-trusted-cert) s=\$(h "\$last" sha1 | tr a-f A-F); [ -f "\$dir/\$s.trust" ] || exit 1; rm -f "\$dir/\$s.trust";;
  delete-certificate)  [ -f "\$dir/\$hash.pem" ] || exit 1; rm -f "\$dir/\$hash.pem";;
  *) exit 3;;
esac
SH

my $site = $tmp.'/site/scripts';
SICK::Trust->write( $site, root_pem => $root->{pem}, intermediates_pem => $inter->{pem},
  additional_roots_pem => $next->{pem}, name => q{Example 'Internal' CA} );
my @site_roots = ( $facts, $next_facts );
my $sha        = sub { my ( $f ) = @_; return $f->fingerprint_sha256 };
my $colons_of  = sub { join ':', map { uc } $_[0] =~ /(..)/g };
my $others_sha = SICK::Bundle->new( cert => $other->{pem} )->fingerprint_sha256;

# ( exit code, stdout, stderr ) of a shell script in the sandbox
sub script {
  my ( $file, $root_dir, @args ) = @_;
  my ( $out, $err, $exit ) = SICK::Command::run(
    [ 'sh', $file, @args ],
    env => {
      PATH            => $fakebin.':'.$ENV{PATH},
      SICK_TRUST_ROOT => $root_dir,
      SICK_TEST_LOG   => $log,
    },
    timeout => 60,
  );
  return ( $exit, $out, $err );
}

sub pem_blocks {
  my ( $text ) = @_;
  return [ map { $_."\n" } $text =~ /(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----)/sg ];
}

sub tree {
  my ( $top ) = @_;
  return [] unless -d $top;
  my @found;
  my @todo = ($top);
  while ( my $d = shift @todo ) {
    opendir my $dh, $d or die 'opendir '.$d.': '.$!;
    for my $e ( sort grep { !/\A\.\.?\z/ } readdir $dh ) {
      my $p = $d.'/'.$e;
      if   ( -d $p ) { push @todo, $p }
      else           { push @found, substr( $p, length($top) + 1 ) }
    }
  }
  return [ sort @found ];
}

subtest 'the scripts are written, and carry exactly the certificates they install' => sub {
  for my $where ( $dir, $chained, $site ) {
    ok -s $where.'/'.$_, $where =~ s{.*/}{}r.': '.$_.' is there' for @scripts;
  }
  my $linux = slurp( $site.'/trust-linux.sh' );
  is_deeply pem_blocks($linux), [ $root->{pem}, $next->{pem} ],
    'trust-linux.sh: the root and the additional root, and no intermediate - the system store is a store of anchors';
  for my $file (qw( trust-macos.sh trust-nss.sh )) {
    is_deeply pem_blocks( slurp( $site.'/'.$file ) ), [ $root->{pem}, $next->{pem}, $inter->{pem} ],
      $file.': the roots, then the intermediate';
  }
  is_deeply pem_blocks( slurp( $dir.'/trust-linux.sh' ) ), [ $root->{pem} ], 'one root: that root alone';
  is_deeply pem_blocks( slurp( $dir.'/trust-nss.sh' ) ),   [ $root->{pem} ], '... in trust-nss.sh as well';

  my $ps1 = raw( $site.'/trust-windows.ps1' );
  unlike $ps1, qr/[^\x09\x0a\x0d\x20-\x7e]/, 'trust-windows.ps1 is plain ASCII, whatever the name of the CA';
  my ($roots_block) = $ps1 =~ /^\$Roots = \@\(\n(.*?)^\)/ms;
  my ($inter_block) = $ps1 =~ /^\$Intermediates = \@\(\n(.*?)^\)/ms;
  my @root_der  = map { decode_base64($_) } ( $roots_block || q{} ) =~ /'([A-Za-z0-9+\/=]+)'/g;
  my @inter_der = map { decode_base64($_) } ( $inter_block || q{} ) =~ /'([A-Za-z0-9+\/=]+)'/g;
  is_deeply \@root_der,  [ raw( $site.'/root_ca.crt' ), raw( $site.'/root_ca_2.crt' ) ], 'trust-windows.ps1: the roots in DER';
  is_deeply \@inter_der, [ raw( $site.'/intermediate_ca.crt' ) ], '... and the intermediate, for the store of intermediates';
  like $ps1, qr/Cert:\\LocalMachine\\Root/, '... roots into LocalMachine\Root';
  like $ps1, qr/Cert:\\LocalMachine\\CA/,   '... intermediates into LocalMachine\CA';
  like $ps1, qr/Import-Certificate/,        '... with Import-Certificate';

  my $alone = raw( $dir.'/trust-windows.ps1' );
  my ($none) = $alone =~ /^\$Intermediates = \@\(\n(.*?)^\)/ms;
  is $none, q{}, 'without an intermediate the list of intermediates is empty';
  like raw( $dir.'/'.$_ ), qr/^INTERMEDIATES=0$/m, $_.' of a CA without an intermediate knows of none' for grep { /\.sh\z/ } @scripts;
  like raw( $site.'/'.$_ ), qr/^INTERMEDIATES=1$/m, $_.' of a CA with one knows of one' for qw( trust-macos.sh trust-nss.sh );
  like raw( $site.'/trust-linux.sh' ), qr/^INTERMEDIATES=0$/m, '... but trust-linux.sh does not carry it';
  unlike join( q{}, map { raw( $site.'/'.$_ ) } @scripts ), qr/PRIVATE KEY/, 'no key in any script';
  unlike raw( $_ ), qr/[ \t]\n/, $_ =~ s{.*/}{}r.' has no trailing blanks' for map { $site.'/'.$_ } @scripts;

  my %before = map { $_ => raw( $site.'/'.$_ ) } @scripts;
  SICK::Trust->write( $site, root_pem => $root->{pem}, intermediates_pem => $inter->{pem},
    additional_roots_pem => $next->{pem}, name => q{Example 'Internal' CA} );
  is raw( $site.'/'.$_ ), $before{$_}, $_.' is byte for byte the same when written again' for @scripts;
};

subtest 'the shell scripts are valid sh' => sub {
  for my $file ( grep { /\.sh\z/ } @scripts ) {
    for my $where ( $dir, $site ) {
      my ( $out, $err, $exit ) = SICK::Command::run( [ 'sh', '-n', $where.'/'.$file ] );
      is $exit, 0, 'sh -n '.$file.' ('.( $where =~ s{.*/}{}r ).')' or diag $err;
    }
  }
SKIP: {
    my $pwsh = eval { ( SICK::Command::run( [ 'pwsh', '-NoProfile', '-Command', 'exit 0' ] ) )[2] };
    skip 'pwsh is not installed: the syntax of trust-windows.ps1 is not checked', 2 unless defined $pwsh && $pwsh == 0;
    for my $where ( $dir, $site ) {
      my $check = spew( $tmp.'/parse-check.ps1', '$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$e); if ($e.Count) { $e | ForEach-Object { $_.ToString() }; exit 1 }'."\n" );
      my ( $out, $err, $exit ) = SICK::Command::run( [ 'pwsh', '-NoProfile', '-NonInteractive', '-File', $check, $where.'/trust-windows.ps1' ] );
      is $exit, 0, 'pwsh parses trust-windows.ps1 ('.( $where =~ s{.*/}{}r ).')' or diag $out.$err;
    }
  }
};

subtest 'the command line of the scripts' => sub {
  my $box = $sandbox.'/usage';
  for my $file ( grep { /\.sh\z/ } @scripts ) {
    my ( $exit, $out, $err ) = script( $site.'/'.$file, $box );
    is $exit, 2, $file.' without an action: exit code 2';
    like $err, qr/Usage:/, '... with the usage';
    ( $exit, $out, $err ) = script( $site.'/'.$file, $box, 'erase' );
    is $exit, 2, $file.' with an unknown action: exit code 2';
    ( $exit, $out, $err ) = script( $site.'/'.$file, $box, 'remove', '--fingerprint', $sha->($facts), ( $file eq 'trust-nss.sh' ? $box : () ) );
    is $exit, 2, $file.' remove with a fingerprint: exit code 2, remove needs none';
    ( $exit, $out, $err ) = script( $site.'/'.$file, $box, '--help' );
    is $exit, 0, $file.' --help: exit code 0';
    like $out, qr/\Q$file\E install --fingerprint <sha256> \[--fingerprint <sha256> \.\.\.\]/, '... and the usage names --fingerprint';
  }
  ok !-e $box, 'none of this wrote anything';
};

# The families of trust-linux.sh: what /etc/os-release says, where the root
# goes and which program updates the store.
my %family = (
  debian => [ "ID=debian\n",                              'usr/local/share/ca-certificates', '.crt', 'update-ca-certificates' ],
  ubuntu => [ "ID=ubuntu\nID_LIKE=debian\n",              'usr/local/share/ca-certificates', '.crt', 'update-ca-certificates' ],
  alpine => [ "ID=alpine\n",                              'usr/local/share/ca-certificates', '.crt', 'update-ca-certificates' ],
  rocky  => [ "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", 'etc/pki/ca-trust/source/anchors', '.pem', 'update-ca-trust extract' ],
  fedora => [ "ID=fedora\n",                              'etc/pki/ca-trust/source/anchors', '.pem', 'update-ca-trust extract' ],
);

for my $os ( sort keys %family ) {
  subtest 'trust-linux.sh on '.$os.': refuses without the right fingerprints, installs the roots, removes them' => sub {
    my ( $release, $store, $ext, $update ) = @{ $family{$os} };
    my $box = $sandbox.'/linux-'.$os;
    mkdir $box; mkdir $box.'/etc';
    spew( $box.'/etc/os-release', $release );
    my $file = $site.'/trust-linux.sh';
    unlink $log;

    my ( $exit, $out, $err ) = script( $file, $box, 'install' );
    is $exit, 1, 'no fingerprint: refused with exit code 1';
    like $err, qr/refused/, '... saying so';
    like $err, qr/from the person who runs/, '... and where the fingerprint comes from';
    like $out, qr/\Q${\ $colons_of->( $sha->($_) ) }\E/, '... printing the fingerprint it computed for '.$_->subject_dn for @site_roots;

    ( $exit, $out, $err ) = script( $file, $box, 'install', '--fingerprint', $others_sha, '--fingerprint', $sha->($next_facts) );
    is $exit, 1, 'the fingerprint of another root instead of the current one: refused';
    like $err, qr/refused/, '... saying so';
    like $out, qr/\Q${\ $colons_of->($others_sha) }\E/, '... and naming the fingerprint that fits no certificate';

    ( $exit, $out, $err ) = script( $file, $box, 'install', '--fingerprint', $sha->($facts) );
    is $exit, 1, 'only one of the two roots: refused, the set has to match';
    ( $exit, $out, $err ) = script( $file, $box, 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots, $facts );
    is $exit, 0, 'a fingerprint given twice is still the same set' or diag $err;
    script( $file, $box, 'remove' );
    unlink $log;
    ( $exit, $out, $err ) = script( $file, $box, 'install', ( map { ( '--fingerprint', $sha->($_) ) } @site_roots ), '--fingerprint', $others_sha );
    is $exit, 1, 'one fingerprint too many: refused';
    ( $exit, $out, $err ) = script( $file, $box, 'install', '--fingerprint', 'not-a-fingerprint' );
    is $exit, 1, 'something that is no fingerprint: refused';
    like $err, qr/not a SHA-256 fingerprint/, '... saying so';
    is_deeply tree( $box.'/'.$store ), [], 'after all refusals nothing is in the store';
    ok !-e $log, '... and no program was called';

    ( $exit, $out, $err ) = script( $file, $box, 'install',
      '--fingerprint', $colons_of->( $sha->($facts) ), '--fingerprint', uc $sha->($next_facts) );
    is $exit, 0, 'both fingerprints, one with colons, one in capitals: installed' or diag $err;
    my @stored = @{ tree( $box.'/'.$store ) };
    is scalar @stored, 2, '... two files in /'.$store;
    like $_, qr/\Asick-root-[0-9a-f]{16}\Q$ext\E\z/, '... '.$_.' named by its fingerprint' for @stored;
    is_deeply [ sort map { slurp( $box.'/'.$store.'/'.$_ ) } @stored ], [ sort $root->{pem}, $next->{pem} ],
      '... holding exactly the two roots';
    unlike join( q{}, map { slurp($_) } map { $box.'/'.$store.'/'.$_ } @stored ), qr/\Q${\ substr( $inter->{pem}, 30, 60 ) }\E/,
      '... and never the intermediate';
    is_deeply [ grep { !m{\A\Q$store\E/} && $_ ne 'etc/os-release' } @{ tree($box) } ], [], '... and nothing anywhere else';
    like slurp($log), qr/^\Q$update\E$/m, '... then '.$update;
    like $out, qr/restart/i, '... and it says what still needs a restart';

    spew( $box.'/'.$store.'/somebody-else.crt', "not ours\n" );
    unlink $log;
    ( $exit, $out, $err ) = script( $file, $box, 'remove' );
    is $exit, 0, 'remove: exit code 0' or diag $err;
    is_deeply tree( $box.'/'.$store ), ['somebody-else.crt'], '... both roots are gone, the file of somebody else stays';
    like $out, qr/removed/, '... saying what it removed';
    like slurp($log), qr/^\Q$update\E$/m, '... and the store is updated';

    unlink $log;
    ( $exit, $out, $err ) = script( $file, $box, 'remove' );
    is $exit, 0, 'remove again: exit code 0, nothing to do is no error';
    like $out, qr/not installed/, '... saying so';
    is_deeply tree( $box.'/'.$store ), ['somebody-else.crt'], '... and touching nothing';
  };
}

subtest 'trust-linux.sh with p11-kit (Arch and others)' => sub {
  my $box = $sandbox.'/linux-arch';
  mkdir $box; mkdir $box.'/etc';
  spew( $box.'/etc/os-release', "ID=arch\n" );
  my $file = $site.'/trust-linux.sh';
  unlink $log;
  my ( $exit, $out, $err ) = script( $file, $box, 'install', '--fingerprint', $others_sha );
  is $exit, 1, 'a wrong fingerprint: refused';
  ok !-e $log, '... and trust was not called';

  ( $exit, $out, $err ) = script( $file, $box, 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots );
  is $exit, 0, 'the right ones: exit code 0' or diag $err;
  is_deeply tree( $box.'/p11kit' ), [ sort map { $sha->($_).'.pem' } @site_roots ], '... trust anchor --store for each root, and for nothing else';
  like slurp($log), qr/^trust anchor --store /m, '... called as trust anchor --store';
  ( $exit, $out, $err ) = script( $file, $box, 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots );
  is $exit, 0, 'installing again: exit code 0' or diag $err;

  ( $exit, $out, $err ) = script( $file, $box, 'remove' );
  is $exit, 0, 'remove: exit code 0' or diag $err;
  is_deeply tree( $box.'/p11kit' ), [], '... both anchors gone';
  like $out, qr/^removed: root certificate 1, a p11-kit anchor$/m, '... saying what it removed';
  ( $exit, $out, $err ) = script( $file, $box, 'remove' );
  is $exit, 0, 'remove again: exit code 0';
  like $out, qr/not installed/, '... saying so';
  # trust anchor --remove exits 0 when nothing matched: its exit code alone
  # does not tell whether an anchor was there.
  unlike $out, qr/^removed:/m, '... and claiming no removal';
  unlike $out, qr/no longer trusts/, '... nor a changed store';
};

subtest 'trust-linux.sh on a system it does not know, and as somebody who is not root' => sub {
  my @real = grep { -x } map { my $d = $_; map { $d.'/'.$_ } qw( trust update-ca-trust update-ca-certificates ) } qw( /usr/bin /bin );
  my ( $out, $err, $exit );
SKIP: {
    skip 'this machine has '.$real[0].' in /usr/bin:/bin, which the script would find', 2 if @real;
    my $box = $sandbox.'/linux-unknown';
    mkdir $box; mkdir $box.'/etc';
    spew( $box.'/etc/os-release', "ID=plan9\n" );
    ( $out, $err, $exit ) = SICK::Command::run(
      [ 'sh', $site.'/trust-linux.sh', 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots ],
      env => { PATH => '/usr/bin:/bin', SICK_TRUST_ROOT => $box, SICK_TEST_LOG => $log } );
    is $exit, 1, 'an unknown family without update-ca-certificates, update-ca-trust or trust: refused';
    like $err, qr/do not know the trust store/, '... saying so';
  }

SKIP: {
    skip 'this test runs as root', 2 unless $>;
    ( $out, $err, $exit ) = SICK::Command::run( [ 'sh', $site.'/trust-linux.sh', 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots ],
      env => { PATH => $fakebin.':'.$ENV{PATH}, SICK_TRUST_ROOT => undef, SICK_TEST_LOG => $log } );
    is $exit, 1, 'not root and no sandbox: refused';
    like $err, qr/as root/, '... saying it needs root';
  }
};

subtest 'trust-nss.sh: roots trusted as CA, intermediates without trust, removed again' => sub {
  my $db = $sandbox.'/nssdb';
  mkdir $db or die 'mkdir: '.$!;
  my $file = $site.'/trust-nss.sh';

  my ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'install', ( map { ( '--fingerprint', $sha->($_) ) } @site_roots ), $db );
  is $exit, 1, 'a directory without cert9.db: refused';
  like $err, qr/cert9\.db/, '... saying what is missing';
  like $err, qr{made with: mkdir -p \$HOME/\.pki/nssdb && certutil -N -d sql:\$HOME/\.pki/nssdb --empty-password},
    '... and the hint makes the directory before certutil -N, which fails in one that is not there';
  spew( $db.'/cert9.db', q{} );

  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'install', '--fingerprint', $sha->($facts), $db );
  is $exit, 1, 'one root of two: refused';
  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'install', $db );
  is $exit, 1, 'no fingerprint: refused';
  is_deeply tree($db), ['cert9.db'], '... nothing added';

  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'install', ( map { ( '--fingerprint', $sha->($_) ) } @site_roots ), $db );
  is $exit, 0, 'both fingerprints: installed' or diag $err;
  my @entries = grep { /\.trust\z/ } @{ tree($db) };
  is scalar @entries, 3, '... three certificates in the database';
  my %trust = map { ( slurp( $db.'/'.( s/\.trust\z/.pem/r ) ) => slurp( $db.'/'.$_ ) ) } @entries;
  is $trust{ $root->{pem} },  "C,,\n", '... the root trusted as a CA for websites (C,,)';
  is $trust{ $next->{pem} },  "C,,\n", '... the additional root as well';
  is $trust{ $inter->{pem} }, ",,\n",  '... the intermediate without any trust (,,)';
  like $out, qr/restart/i, '... and it says Firefox needs a restart';

  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'install', ( map { ( '--fingerprint', $sha->($_) ) } @site_roots ), $db );
  is $exit, 0, 'installing again: exit code 0' or diag $err;

  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'remove', $db );
  is $exit, 0, 'remove: exit code 0' or diag $err;
  is_deeply tree($db), ['cert9.db'], '... all three gone';
  ( $exit, $out, $err ) = script( $file, $sandbox.'/none', 'remove', $db );
  is $exit, 0, 'remove again: exit code 0';
  like $out, qr/not installed/, '... saying so';
};

subtest 'trust-macos.sh: roots trusted in the System keychain, intermediates added without trust' => sub {
  my $box  = $sandbox.'/macos';
  my $file = $site.'/trust-macos.sh';
  my ( $exit, $out, $err ) = script( $file, $box, 'install', '--fingerprint', $others_sha, '--fingerprint', $sha->($facts) );
  is $exit, 1, 'a wrong fingerprint: refused';
  is_deeply tree( $box.'/keychain' ), [], '... nothing in the keychain';

  ( $exit, $out, $err ) = script( $file, $box, 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots );
  is $exit, 0, 'the right ones: installed' or diag $err;
  my %der_of = ( $root->{pem} => 'root_ca.crt', $next->{pem} => 'root_ca_2.crt', $inter->{pem} => 'intermediate_ca.crt' );
  my $sha1 = sub { my ( $pem ) = @_; uc sha1_hex( raw( $site.'/'.$der_of{$pem} ) ) };
  my %in = map { $_ => 1 } @{ tree( $box.'/keychain' ) };
  ok $in{ $sha1->( $_->[1] ).'.pem' },   '... '.$_->[0].' is in the keychain' for [ 'the root', $root->{pem} ], [ 'the additional root', $next->{pem} ], [ 'the intermediate', $inter->{pem} ];
  ok $in{ $sha1->( $_->[1] ).'.trust' }, '... '.$_->[0].' is trusted as a root' for [ 'the root', $root->{pem} ], [ 'the additional root', $next->{pem} ];
  ok !$in{ $sha1->( $inter->{pem} ).'.trust' }, '... the intermediate has no trust setting';
  is slurp( $box.'/keychain/'.$sha1->( $root->{pem} ).'.trust' ), "trustRoot\n", '... the roots with -r trustRoot';

  ( $exit, $out, $err ) = script( $file, $box, 'install', map { ( '--fingerprint', $sha->($_) ) } @site_roots );
  is $exit, 0, 'installing again: exit code 0' or diag $err;

  ( $exit, $out, $err ) = script( $file, $box, 'remove' );
  is $exit, 0, 'remove: exit code 0' or diag $err;
  is_deeply tree( $box.'/keychain' ), [], '... certificates and trust settings gone';
  ( $exit, $out, $err ) = script( $file, $box, 'remove' );
  is $exit, 0, 'remove again: exit code 0';
  like $out, qr/not installed/, '... saying so';
};

subtest 'the page: the fingerprint from another channel first, the scripts, removal, the limits' => sub {
  my $page = slurp( $site.'/index.html' );
  ( my $text = $page ) =~ s/\s+/ /g;
  my $oob = index $text, 'not from this page';
  ok $oob > 0, 'the page says the fingerprint does not come from this page';
  ok $oob < index( $text, '<dl>' ), '... before it shows any fingerprint';
  ok $oob < index( $text, 'href="root_ca' ), '... and before it offers any file';
  like $text, qr/this page is not authenticated/i, '... because the page is not authenticated';

  like $page, qr/<a href="\Q$_\E"/, 'a link to '.$_ for @scripts;
  my %section = map { /\A<h2 id="([a-z]+)">/ ? ( $1 => $_ ) : () } split /(?=<h2 id=")/, $page;
  my $two = '--fingerprint &lt;from your admin&gt; --fingerprint &lt;from your admin&gt;';
  like $section{linux},   qr/sudo sh trust-linux\.sh install \Q$two\E/,  'Linux: the script, one placeholder per root';
  like $section{macos},   qr/sudo sh trust-macos\.sh install \Q$two\E/,  'macOS: the script';
  like $section{windows}, qr/trust-windows\.ps1 install \Q$two\E/,       'Windows: the script';
  like $section{firefox}, qr/sh trust-nss\.sh install \Q$two\E/,         'Firefox: trust-nss.sh';
  like $section{chrome},  qr/trust-nss\.sh/,                             'Chrome on Linux: trust-nss.sh';
  unlike $text, qr/--fingerprint [0-9A-Fa-f]{2}:/, 'no command on the page carries a fingerprint';
  my $one = slurp( $dir.'/index.html' );
  like $one, qr/trust-linux\.sh install --fingerprint &lt;from your admin&gt;<\/pre>/, 'one root: one placeholder';

  for my $platform (qw( ios android macos windows linux firefox chrome )) {
    like $section{$platform}, qr/<h3>Remove<\/h3>/, $platform.': how to remove it again';
  }
  like $section{linux},   qr/trust-linux\.sh remove/,   'Linux: the script removes';
  like $section{macos},   qr/trust-macos\.sh remove/,   'macOS: the script removes';
  like $section{windows}, qr/trust-windows\.ps1 remove/, 'Windows: the script removes';
  like $section{firefox}, qr/trust-nss\.sh remove/,     'Firefox: the script removes';

  ( my $android = $section{android} ) =~ s/\s+/ /g;
  like $android, qr/Network Security Config/, 'Android: apps opt in through the Network Security Configuration';
  like $android, qr/API level 24/, '... from API level 24 on';
  like $android, qr/Chrome/, '... Chrome uses them';
  ( my $ios = $section{ios} ) =~ s/\s+/ /g;
  like $ios, qr/Not Verified/, 'iPhone: the profile is unsigned and shows Not Verified';
  like $ios, qr/compare/i, '... so the fingerprint is compared after the installation';
  like $section{macos}, qr/Not Verified/, 'macOS: the same';
  like $section{$_}, qr/[Nn]ot tried/, $_.': not tried on a device yet' for qw( ios android macos windows );

  ok $section{runtimes}, 'a section for programs with a store of their own';
  ( my $runtimes = $section{runtimes} ) =~ s/\s+/ /g;
  like $runtimes, qr/\Q$_\E/, '... '.$_ for qw( keytool certifi SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS --use-system-ca Go curl http.sslCAInfo /etc/docker/certs.d Dockerfile Kubernetes );
  like $runtimes, qr/does not make every program trust the root/, '... saying first that the system store is not enough';
  my @lines = $runtimes =~ /<li>(.*?)<\/li>/g;
  is scalar( grep { !/<em>(?:Tested in containers|Not tried)\.?<\/em>/ } @lines ), 0, '... every line marked tested in containers or not tried';
  like $_, qr/Not tried/, '... Docker certs.d not tried' for grep { /certs\.d/ } @lines;
  like $runtimes, qr/docs\/findings\/trust-runtimes\.md/, '... pointing to the findings';
  like $runtimes, qr/requests<\/code> uses only <code>certifi<\/code>/, '... requests: certifi only';
  like $runtimes, qr/subPath<\/code> it never follows/, '... a subPath mount never follows';
  like $text, qr/2026-10-10/, 'the date the dated claims were checked';

  unlike $page, qr/[ \t]\n|<!--|\n\n\n/, 'no trailing blanks, no placeholder, no hole';
  my %anchor = map { $_ => 1 } $page =~ /\bid="([a-z]+)"/g;
  is_deeply [ grep { /\A#/ && !$anchor{ substr $_, 1 } } $page =~ /href="([^"]*)"/g ], [], 'every section that is linked exists';
};

done_testing;
