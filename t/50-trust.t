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

done_testing;
