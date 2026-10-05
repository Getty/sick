package SICK::Trust;
# ABSTRACT: Write the root certificate in the forms clients want, and a page that explains them

use strict;
use warnings;
use Carp qw( croak );
use Digest::SHA qw( sha1_hex sha256_hex );
use File::Path qw( make_path );
use File::Temp ();
use MIME::Base64 qw( encode_base64 );
use POSIX qw( strftime );
use SICK::Bundle;
use SICK::OpenSSL;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Trust;

    my @files = SICK::Trust->write(
      '/srv/www/trust',
      root_pem => $issuer->root_pem,
      name     => 'Example Internal CA',
    );

On the command line:

    sick trust /srv/www/trust

=head1 DESCRIPTION

A certificate of an internal CA is worth as much as the number of machines
that trust the CA. This module writes what it takes to get there into one
directory, ready to be put behind any web server:

    root_ca.pem            the root certificate as PEM
    root_ca.crt            the same as DER, the form Windows and Android open
    root_ca.mobileconfig   a configuration profile for iOS, iPadOS and macOS
    index.html             one page: fingerprints, the three downloads, and
                           how to install the certificate on each platform

The page is self-contained - no script, no style sheet, no image from
anywhere else. Everything is derived from the certificate and the name
alone: writing twice produces the same bytes, so the command can run after
every C<sick run> without touching what did not change. The identifiers of
the profile come from the fingerprint of the certificate, so a device
recognizes a profile it has installed.

Only the root certificate is published. Its key is not here and never was.

=cut

my @FILES = qw( root_ca.pem root_ca.crt root_ca.mobileconfig index.html );

sub files { @FILES }

=method files

    my @names = SICK::Trust->files;

The names of the four files, in the order they are written.

=cut

sub write {
  my ( $class, $dir, %arg ) = @_;
  croak 'SICK::Trust->write needs a directory' unless defined $dir && !ref $dir && length $dir;
  my @unknown = sort grep { !/\A(?:root_pem|name)\z/ } keys %arg;
  croak 'SICK::Trust->write: unknown argument \''.$unknown[0].'\'' if @unknown;

  my $root = $class->_root( $arg{root_pem} );
  my $der  = $class->_der($root);

  my $name = $arg{name};
  $name = $root->common_name unless defined $name && !ref $name && $name =~ /\S/;
  $name = 'Internal CA'      unless defined $name && $name =~ /\S/;
  utf8::encode($name) if utf8::is_utf8($name);
  $name =~ s/[\x00-\x1f\x7f]+/ /g;
  $name =~ s/\A\s+//;
  $name =~ s/\s+\z//;

  my %fact = (
    name       => $name,
    sha256     => $root->fingerprint_sha256,
    sha1       => sha1_hex($der),
    subject    => $root->subject_dn,
    not_before => strftime( '%Y-%m-%d %H:%M UTC', gmtime $root->not_before ),
    not_after  => strftime( '%Y-%m-%d %H:%M UTC', gmtime $root->not_after ),
  );
  croak 'the DER form of the root certificate does not have its fingerprint'
    unless sha256_hex($der) eq $fact{sha256};

  my %content = (
    'root_ca.pem'          => $root->cert,
    'root_ca.crt'          => $der,
    'root_ca.mobileconfig' => $class->_profile( $der, %fact ),
    'index.html'           => $class->_page(%fact)
  );

  unless ( -d $dir ) {
    make_path( $dir, { mode => 0755, error => \my $errors } );
    croak 'cannot create directory \''.$dir.'\': '.( values %{ $errors->[0] } )[0]
      if $errors && @$errors;
  }
  $class->_put( $dir.'/'.$_, $content{$_} ) for @FILES;
  return map { $dir.'/'.$_ } @FILES;
}

=method write

    my @paths = SICK::Trust->write( $directory, root_pem => $pem, name => $display_name );

Writes the four files into C<$directory>, which is created when it is
missing, and returns their paths. Every file is written aside and renamed
into place (mode C<0644>), so a web server never serves half of one.

C<root_pem> is the root certificate as PEM, as L<SICK::Issuer/root_pem>
returns it. It may hold more certificates - the root file of a step-ca
setup sometimes carries the intermediate as well; the one that is
self-signed is the root. C<name> is what the CA is called on the page and
in the profile; without it, the common name of the root certificate.

Croaks when C<root_pem> holds no root certificate or more than one, and
with C<< cannot write '<path>': <reason> >> when a file cannot be written.

=cut

#### internals

# The one self-signed certificate in the PEM.
sub _root {
  my ( $class, $pem ) = @_;
  croak 'SICK::Trust->write needs root_pem' unless defined $pem && !ref $pem && length $pem;
  my @blocks = $pem =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg;
  croak 'root_pem is not a PEM certificate' unless @blocks;
  my @roots = grep { $_->is_self_signed } map { SICK::Bundle->new( cert => $_ ) } @blocks;
  croak 'root_pem holds no root certificate: '
    .( @blocks == 1 ? 'the certificate in it is' : 'none of the '.@blocks.' certificates in it is' )
    .' self-signed'
    unless @roots;
  croak 'root_pem holds '.@roots.' root certificates; exactly one can be published' if @roots > 1;
  return $roots[0];
}

sub _der {
  my ( $class, $root ) = @_;
  my $der = eval { SICK::OpenSSL::run_checked( [ 'x509', '-outform', 'DER' ], stdin => $root->cert ) };
  return $der if defined $der && length $der;
  my $error = $@;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  croak 'cannot convert the root certificate to DER: '.( length $error ? $error : 'openssl printed nothing' );
}

sub _put {
  my ( $class, $path, $content ) = @_;
  ( my $dir = $path ) =~ s{/[^/]+\z}{};
  my $tmp = eval { File::Temp->new( DIR => $dir, TEMPLATE => '.sick-XXXXXXXX', UNLINK => 0 ) }
    or croak 'cannot write \''.$path.'\': '.( $! ? $! : 'cannot create a temporary file' );
  my $aside = $tmp->filename;
  binmode $tmp;
  my $ok = chmod( 0644, $aside ) && print( {$tmp} $content ) && close($tmp) && rename( $aside, $path );
  unless ($ok) {
    my $reason = q{}.$!;
    unlink $aside;
    croak 'cannot write \''.$path.'\': '.$reason;
  }
  return $path;
}

# For text between tags and inside double-quoted attributes, XML and HTML.
sub _escape {
  my ( $text ) = @_;
  $text =~ s/&/&amp;/g;
  $text =~ s/</&lt;/g;
  $text =~ s/>/&gt;/g;
  $text =~ s/"/&quot;/g;
  $text =~ s/'/&#39;/g;
  return $text;
}

# A UUID that is the same for the same certificate and purpose.
sub _uuid {
  my ( $purpose, $fingerprint ) = @_;
  my $hex = substr sha256_hex( 'SICK::Trust '.$purpose.' '.$fingerprint ), 0, 32;
  substr( $hex, 12, 1 ) = '5';
  substr( $hex, 16, 1 ) = sprintf '%x', ( hex( substr $hex, 16, 1 ) & 0x3 ) | 0x8;
  return uc join '-', unpack 'A8 A4 A4 A4 A12', $hex;
}

sub _colons {
  my ( $hex ) = @_;
  return join ':', map { uc } $hex =~ /(..)/g;
}

sub _profile {
  my ( $class, $der, %fact ) = @_;
  my $name         = _escape( $fact{name} );
  my $profile_uuid = _uuid( 'profile', $fact{sha256} );
  my $payload_uuid = _uuid( 'payload', $fact{sha256} );
  my $data         = encode_base64( $der, q{} );
  $data =~ s/(.{1,52})/\t\t\t$1\n/g;

  return <<"PLIST";
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>root_ca.crt</string>
			<key>PayloadContent</key>
			<data>
$data			</data>
			<key>PayloadDescription</key>
			<string>Adds the root certificate of $name.</string>
			<key>PayloadDisplayName</key>
			<string>$name</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.security.root.$payload_uuid</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>$payload_uuid</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Makes this device trust the certificates of $name. SHA-256 fingerprint of the root certificate: $fact{sha256}</string>
	<key>PayloadDisplayName</key>
	<string>$name</string>
	<key>PayloadIdentifier</key>
	<string>sick.trust.$profile_uuid</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>$profile_uuid</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
PLIST
}

sub _page {
  my ( $class, %fact ) = @_;
  my $name    = _escape( $fact{name} );
  my $subject = _escape( $fact{subject} );
  my $sha256  = _colons( $fact{sha256} );
  my $sha1    = _colons( $fact{sha1} );
  # two lines of sixteen bytes read better than one of thirty-two
  ( my $sha256_html = $sha256 ) =~ s/\A(.{47}):/$1:<br>/;

  return <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trust $name</title>
<style>
  :root { color-scheme: light dark; --fg: #1c1c1c; --bg: #fdfdfb; --soft: #5f6368; --line: #d8d8d2; --box: #f1f1ec; --link: #0b57d0; }
  \@media (prefers-color-scheme: dark) {
    :root { --fg: #e6e6e3; --bg: #18191b; --soft: #a0a4a8; --line: #3a3c40; --box: #232528; --link: #8ab4f8; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 1.5rem 1rem 4rem; background: var(--bg); color: var(--fg);
         font: 1rem/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 44rem; margin: 0 auto; }
  h1 { font-size: 1.6rem; line-height: 1.25; margin: 0 0 .5rem; }
  h2 { font-size: 1.15rem; margin: 2.2rem 0 .6rem; padding-top: 1rem; border-top: 1px solid var(--line); }
  h3 { font-size: 1rem; margin: 1.4rem 0 .3rem; }
  p, ol, ul { margin: .5rem 0; }
  ol, ul { padding-left: 1.4rem; }
  li { margin: .25rem 0; }
  a { color: var(--link); }
  code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88em; }
  pre { background: var(--box); border: 1px solid var(--line); border-radius: 6px; padding: .7rem .8rem;
        overflow-x: auto; margin: .5rem 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1rem; background: var(--box);
       border: 1px solid var(--line); border-radius: 6px; padding: .8rem 1rem; margin: 1rem 0; }
  dt { color: var(--soft); }
  dd { margin: 0; overflow-wrap: anywhere; }
  .downloads { list-style: none; padding: 0; }
  .downloads li { margin: .5rem 0; }
  .downloads a { font-weight: 600; }
  .soft { color: var(--soft); }
  nav { margin: 1rem 0 0; }
  nav a { display: inline-block; margin: 0 .7rem .3rem 0; }
  \@media (max-width: 30rem) { dl { grid-template-columns: 1fr; gap: 0 0; } dd { margin-bottom: .5rem; } }
</style>
</head>
<body>
<main>
<h1>Trust $name</h1>
<p>The devices and services here use certificates issued by <strong>$name</strong>, a private
certificate authority. Your browser warns about them until this device trusts the root certificate
of that authority. Install it once and the warnings are gone.</p>

<dl>
  <dt>Certificate</dt><dd>$subject</dd>
  <dt>SHA-256 fingerprint</dt><dd class="mono">$sha256_html</dd>
  <dt>SHA-1 fingerprint</dt><dd class="mono">$sha1</dd>
  <dt>Valid from</dt><dd>$fact{not_before}</dd>
  <dt>Valid until</dt><dd>$fact{not_after}</dd>
</dl>

<p>Whoever holds the key of a root certificate you trust can issue a certificate for any name. Compare
the fingerprint your device shows during the installation with the one above, and when you reached this
page over a connection you have no reason to trust, ask the person who runs the authority for it.</p>

<h2 id="download">Download</h2>
<ul class="downloads">
  <li><a href="root_ca.crt" download>root_ca.crt</a> <span class="soft">&ndash; binary (DER). Windows, Android.</span></li>
  <li><a href="root_ca.pem" download>root_ca.pem</a> <span class="soft">&ndash; text (PEM). Linux, Firefox, macOS, tools.</span></li>
  <li><a href="root_ca.mobileconfig">root_ca.mobileconfig</a> <span class="soft">&ndash; configuration profile. iPhone, iPad, Mac.</span></li>
</ul>

<nav>
  <a href="#ios">iPhone and iPad</a>
  <a href="#android">Android</a>
  <a href="#macos">macOS</a>
  <a href="#windows">Windows</a>
  <a href="#linux">Linux</a>
  <a href="#firefox">Firefox</a>
  <a href="#chrome">Chrome</a>
</nav>

<h2 id="ios">iPhone and iPad</h2>
<ol>
  <li>Open this page in Safari and tap <a href="root_ca.mobileconfig">root_ca.mobileconfig</a>. Allow the download.</li>
  <li>Open <em>Settings</em>. Tap <em>Profile Downloaded</em> near the top (or <em>General &rarr; VPN &amp; Device
      Management</em>), choose the profile <em>$name</em> and tap <em>Install</em>.</li>
  <li>The profile alone is not enough. Go to <em>Settings &rarr; General &rarr; About &rarr; Certificate Trust
      Settings</em> and switch on full trust for <em>$name</em>.</li>
</ol>

<h2 id="android">Android</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a>.</li>
  <li>Open <em>Settings</em> and search for <em>CA certificate</em>. The entry is usually found under
      <em>Security &rarr; More security settings &rarr; Encryption &amp; credentials &rarr; Install a certificate
      &rarr; CA certificate</em>; the names differ between manufacturers.</li>
  <li>Confirm the warning with <em>Install anyway</em> and pick the downloaded file.</li>
</ol>
<p class="soft">Chrome and most browsers use certificates installed this way. Other apps only do so when their
developers allowed it.</p>

<h2 id="macos">macOS</h2>
<p>With the profile: open <a href="root_ca.mobileconfig">root_ca.mobileconfig</a>, then <em>System Settings &rarr;
Privacy &amp; Security &rarr; Profiles</em> (on older versions <em>System Preferences &rarr; Profiles</em>),
select <em>$name</em> and choose <em>Install</em>.</p>
<p>Or in a terminal, with the PEM file:</p>
<pre>sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain root_ca.pem</pre>
<p>Safari and Chrome use the keychain. Firefox has its own list, see <a href="#firefox">below</a>.</p>

<h2 id="windows">Windows</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a> and open it.</li>
  <li>Choose <em>Install Certificate&hellip;</em>, then <em>Local Machine</em> (for all users; needs an
      administrator) or <em>Current User</em>.</li>
  <li>Select <em>Place all certificates in the following store</em>, browse to <em>Trusted Root Certification
      Authorities</em> and finish. Windows shows the SHA-1 fingerprint as <em>thumbprint</em>.</li>
</ol>
<p>Or in a terminal that runs as administrator:</p>
<pre>certutil -addstore -f Root root_ca.crt</pre>
<p>Edge and Chrome use the Windows store. Firefox has its own list, see <a href="#firefox">below</a>.</p>

<h2 id="linux">Linux</h2>
<p>The system store wants the PEM file. Debian, Ubuntu and relatives:</p>
<pre>sudo cp root_ca.pem /usr/local/share/ca-certificates/internal-root-ca.crt
sudo update-ca-certificates</pre>
<p>Fedora, RHEL, Rocky and relatives:</p>
<pre>sudo cp root_ca.pem /etc/pki/ca-trust/source/anchors/internal-root-ca.pem
sudo update-ca-trust</pre>
<p>Arch and others with <code>p11-kit</code>:</p>
<pre>sudo trust anchor --store root_ca.pem</pre>
<p>Check the fingerprint of what you downloaded before you install it:</p>
<pre>openssl x509 -in root_ca.pem -noout -fingerprint -sha256</pre>
<p class="soft">That covers <code>curl</code>, <code>git</code>, <code>wget</code> and most programs. Browsers keep
their own lists on Linux, see below.</p>

<h2 id="firefox">Firefox</h2>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>.</li>
  <li>Open <em>Settings &rarr; Privacy &amp; Security</em>, scroll to <em>Certificates</em> and choose
      <em>View Certificates&hellip;</em>.</li>
  <li>On the tab <em>Authorities</em> choose <em>Import&hellip;</em>, pick the file and tick <em>Trust this CA to
      identify websites</em>.</li>
</ol>
<p class="soft">On Windows and macOS, Firefox can use the certificates of the system instead: open
<code>about:config</code> and set <code>security.enterprise_roots.enabled</code> to <code>true</code>.</p>

<h2 id="chrome">Chrome, Chromium, Edge</h2>
<p>On Windows, macOS, Android and iOS these browsers use the certificates of the system: follow the
instructions for the platform above and restart the browser.</p>
<p>On Linux they keep their own list:</p>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>.</li>
  <li>Open <code>chrome://certificate-manager</code> (older versions: <code>chrome://settings/certificates</code>).</li>
  <li>Under <em>Local certificates &rarr; Installed by you</em> (older versions: tab <em>Authorities</em>) import
      the file as a trusted certificate for websites.</li>
</ol>
</main>
</body>
</html>
HTML
}

1;
