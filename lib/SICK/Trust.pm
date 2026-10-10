package SICK::Trust;
# ABSTRACT: Write the certificates of the CA in the forms clients want, and a page that explains them

use strict;
use warnings;
use Carp qw( croak );
use Digest::SHA qw( sha1_hex sha256_hex );
use MIME::Base64 qw( encode_base64 );
use POSIX qw( strftime );
use Path::Tiny ();
use SICK::Bundle;
use SICK::OpenSSL;
use SICK::Trust::Scripts;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Trust;

    my @files = SICK::Trust->write(
      '/srv/www/trust',
      root_pem          => $issuer->root_pem,
      intermediates_pem    => $issuer->intermediates_pem,       # or undef
      additional_roots_pem => $issuer->additional_roots_pem,    # or undef
      name                 => 'Example Internal CA',
    );

On the command line:

    sick trust /srv/www/trust

=head1 DESCRIPTION

A certificate of an internal CA is worth as much as the number of machines
that trust the CA. This module writes what it takes to get there into one
directory, ready to be put behind any web server:

    root_ca.pem            the root certificate as PEM
    root_ca.crt            the same as DER, the form Windows and Android open
    trust-linux.sh         install and remove scripts, one per platform,
    trust-macos.sh         with the certificates in them
    trust-windows.ps1      (L<SICK::Trust::Scripts>)
    trust-nss.sh
    root_ca.mobileconfig   a configuration profile for iOS, iPadOS and macOS
    index.html             one page: fingerprints, the downloads, and how to
                           install and remove them on each platform

A CA like step-ca does not sign with its root but through an intermediate
certificate, and a device with room for exactly one certificate - a switch -
presents its certificate without it. A client that knows the root alone
cannot build the chain and keeps refusing such a device. When the CA has
intermediates (L<SICK::Issuer/intermediates_pem>), they are published as
well:

    intermediate_ca.pem    the intermediate certificate as PEM
    intermediate_ca.crt    the same as DER
    ca_bundle.pem          root and intermediate in one PEM file, for
                           programs that take one file with their CAs

The profile then carries the root as a root (C<com.apple.security.root>)
and the intermediate as a plain certificate (C<com.apple.security.pkcs1>),
so that one installation is enough on an Apple device, and the page says
for every platform where the root goes, where the intermediate goes and
whether that takes a trust setting. The root is what a client trusts; the
intermediate only has to be known to it.

An intermediate never goes where every certificate is a trust anchor: the
system stores of Linux and the CA list of Android get the root alone. An
intermediate there would be trusted by itself and stay trusted after the
root is removed (F<docs/findings/trust-anchors.md> in the repository). The
page names three ways to the intermediate instead: the device sends the
chain, which is the better one; a program takes F<ca_bundle.pem> as its own
CA file, where the intermediate is an anchor inside that one file; or a
place that keeps it without trust - Firefox and Chrome on Linux with nothing
ticked, the store of intermediates of Windows, the keychain of macOS, the
profile.

While the CA replaces its root, clients have to trust more than one root
for a while: the next one before the switch, the previous one after it
(L<SICK::Issuer/additional_roots>). Each of these additional roots is
published in the order it was given:

    root_ca_2.pem          the first additional root as PEM
    root_ca_2.crt          the same as DER
    root_ca_3.pem, ...     the next one, and so on
    ca_bundle.pem          the current root, the additional roots and the
                           intermediates, in that order

The profile carries each of them as a trusted root, and the page names the
current root - the one in F<root_ca.pem> - lists the others with their
fingerprints, says that they are roots of the same organisation during a
replacement, to be installed the same way, and that the one no longer listed
is to be removed once the replacement is over. Without additional roots
nothing on the page or in the profile speaks of them.

With more than one intermediate, F<intermediate_ca.pem> holds all of them
in the order they were given, and each one has files of its own for the
programs that take a single certificate: F<intermediate_ca_1.pem>,
F<intermediate_ca_1.crt>, F<intermediate_ca_2.pem> and so on.

The page is served over whatever the web server offers, and a client that
does not trust the CA yet cannot tell a forged page from this one. So the
page says first that the fingerprint comes from the person who runs the CA,
by another channel, and not from the page; and the scripts install nothing
unless they are given the SHA-256 fingerprint of every root they carry,
checked against what they compute themselves (L<SICK::Trust::Scripts>).
The page shows the commands with placeholders, never with a fingerprint.

For every platform the page has the script, the steps by hand and how to
remove it again; for Android that apps targeting API level 24 or newer use
the CA list only when they opt in (Network Security Configuration), for iOS
and macOS that the unsigned profile shows as I<Not Verified>, and a short
section on programs with a store of their own (Java, Python, Node, Go, curl,
git, Docker, container images, Kubernetes). What it says about Firefox 120,
C<chrome://certificate-manager> (Chrome 134), Android's Network Security
Configuration, Node's C<--use-system-ca> and C<NODE_EXTRA_CA_CERTS>, the
C<security> commands of macOS and C<Import-Certificate> was checked against
the documentation of the vendors on 2026-10-10; Windows, macOS, iOS and
Android are marked as not tried on a device.

The page is self-contained - no script, no style sheet, no image from
anywhere else. Everything is derived from the certificates and the name
alone: writing twice produces the same bytes, so the command can run after
every C<sick run> without touching what did not change. The identifiers of
the profile come from the fingerprints of the certificates, so a device
recognizes a profile it has installed, and the profile with the
intermediate replaces the one without.

Only certificates are published. No key is here and none ever was.

=cut

my @FIRST = qw( root_ca.pem root_ca.crt );
my @LAST  = qw( root_ca.mobileconfig index.html );

# What write puts into a directory when the CA has intermediates or
# additional roots - and what it takes away again when the CA has fewer of
# them than last time.
my $CHAIN_FILE = qr/\A(?:intermediate_ca(?:_[0-9]+)?\.(?:pem|crt)|root_ca_[0-9]+\.(?:pem|crt)|ca_bundle\.pem)\z/;

# The files of each single intermediate, without their extension.
sub _single {
  my ( $count ) = @_;
  return $count == 1 ? ('intermediate_ca') : map { 'intermediate_ca_'.$_ } 1 .. $count;
}

# The files of each additional root, without their extension: the current
# root is root_ca, the first additional one root_ca_2.
sub _additional {
  my ( $count ) = @_;
  return map { 'root_ca_'.$_ } 2 .. $count + 1;
}

sub files {
  my ( $class, $count, $roots ) = @_;
  $count = 0 unless defined $count && !ref $count && $count =~ /\A[0-9]+\z/;
  $roots = 0 unless defined $roots && !ref $roots && $roots =~ /\A[0-9]+\z/;
  my @scripts = SICK::Trust::Scripts->files;
  return ( @FIRST, @scripts, @LAST ) unless $count || $roots;
  return (
    @FIRST,
    ( map { ( $_.'.pem', $_.'.crt' ) } _additional($roots) ),
    ( $count > 1 ? 'intermediate_ca.pem' : () ),
    ( $count ? map { ( $_.'.pem', $_.'.crt' ) } _single($count) : () ),
    'ca_bundle.pem',
    @scripts,
    @LAST,
  );
}

=method files

    my @names = SICK::Trust->files;                   # a CA without intermediates
    my @names = SICK::Trust->files($intermediates);   # with that many
    my @names = SICK::Trust->files( $intermediates, $additional_roots );

The names of the files, in the order they are written: eight without
intermediates, eleven with one; the files of the additional roots come right
after those of the root, the four scripts right before the profile. The page
comes last, so that it never links to a file that is not there yet.

=cut

sub write {
  my ( $class, $dir, %arg ) = @_;
  croak 'SICK::Trust->write needs a directory' unless defined $dir && !ref $dir && length $dir;
  my @unknown = sort grep { !/\A(?:root_pem|intermediates_pem|additional_roots_pem|name)\z/ } keys %arg;
  croak 'SICK::Trust->write: unknown argument \''.$unknown[0].'\'' if @unknown;

  my $root  = $class->_root( $arg{root_pem} );
  my $der   = $class->_der( $root, 'root' );
  my @chain = $class->_intermediates( $root, $arg{intermediates_pem} );
  my @extra = $class->_additional_roots( $root, $arg{additional_roots_pem} );

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

  my @single        = _single( scalar @chain );
  my @intermediates = map { $class->_published( $chain[$_], 'intermediate', $single[$_], $name.' intermediate' ) } 0 .. $#chain;
  my @additional    = _additional( scalar @extra );
  my @roots         = map { $class->_published( $extra[$_], 'additional root', $additional[$_], $name.' root' ) } 0 .. $#extra;

  my $scripts = SICK::Trust::Scripts->new(
    name          => $name,
    roots         => [ { pem => $root->cert, der => $der }, map { { pem => $_->{pem}, der => $_->{der} } } @roots ],
    intermediates => [ map { { pem => $_->{pem}, der => $_->{der} } } @intermediates ],
  );

  my %content = (
    ( map { $_ => $scripts->content($_) } SICK::Trust::Scripts->files ),
    'root_ca.pem'          => $root->cert,
    'root_ca.crt'          => $der,
    'root_ca.mobileconfig' => $class->_profile( $der, %fact, intermediates => \@intermediates, roots => \@roots ),
    'index.html'           => $class->_page( %fact, intermediates => \@intermediates, roots => \@roots )
  );
  if ( @intermediates || @roots ) {
    $content{'intermediate_ca.pem'} = join q{}, map { $_->{pem} } @intermediates;
    $content{'ca_bundle.pem'}       = join q{}, $root->cert, map { $_->{pem} } @roots, @intermediates;
    for my $cert ( @roots, @intermediates ) {
      $content{ $cert->{pem_file} } = $cert->{pem};
      $content{ $cert->{der_file} } = $cert->{der};
    }
  }
  my @files = $class->files( scalar @intermediates, scalar @roots );

  unless ( Path::Tiny::path($dir)->is_dir ) {
    eval { Path::Tiny::path($dir)->mkdir( { mode => 0755 } ); 1 }
      or croak 'cannot create directory \''.$dir.'\': '.$class->_reason($@);
  }
  $class->_put( $dir.'/'.$_, $content{$_} ) for @files;
  $class->_sweep( $dir, @files );
  return map { $dir.'/'.$_ } @files;
}

=method write

    my @paths = SICK::Trust->write(
      $directory,
      root_pem             => $pem,
      intermediates_pem    => $pem,    # optional
      additional_roots_pem => $pem,    # optional
      name                 => $display_name,
    );

Writes the files into C<$directory>, which is created when it is missing,
and returns their paths. Every file is written aside and renamed into place
(mode C<0644>), so a web server never serves half of one.

C<root_pem> is the root certificate as PEM, as L<SICK::Issuer/root_pem>
returns it. It may hold more certificates - the root file of a step-ca
setup sometimes carries the intermediate as well; the one that is
self-signed is the root, and the others are ignored.

C<intermediates_pem> is what L<SICK::Issuer/intermediates_pem> returns: the
intermediate certificates of the CA as PEM, or C<undef> (or nothing but
blanks) when it has none - the files are then exactly what they are
without the argument. Every intermediate has to lead to the root, through
the others if need be: this page tells people to install what it offers,
so a certificate of some other CA is refused and not published. The root
itself and a certificate that is given twice are passed over.

C<additional_roots_pem> is what L<SICK::Issuer/additional_roots_pem>
returns: further root certificates as PEM, during a replacement of the
root, or C<undef> (or nothing but blanks) when there are none - the files
are then exactly what they are without the argument. Each has to be a
self-signed CA certificate; the root itself and a certificate that is given
twice are passed over.

C<name> is what the CA is called on the page and in the profile; without
it, the common name of the root certificate.

The files with the intermediates and the additional roots belong to this
module (F<ca_bundle.pem> and everything called F<intermediate_ca.pem>,
F<intermediate_ca.crt>, F<intermediate_ca_E<lt>nE<gt>.pem>,
F<intermediate_ca_E<lt>nE<gt>.crt>, F<root_ca_E<lt>nE<gt>.pem> or
F<root_ca_E<lt>nE<gt>.crt>): those an earlier call left in the directory
and this one does not write are removed, so that a directory never offers
the intermediate of a CA that has none any more, nor a root whose
replacement is over. Nothing else in the directory is touched.

Croaks when C<root_pem> holds no root certificate or more than one, with
C<< the intermediate certificate '<subject>' does not lead to the root
certificate '<subject>' >> for an intermediate that is none of this CA,
with C<< the intermediate certificate '<subject>' is not a CA certificate
(basicConstraints does not say CA:TRUE) >> for one that leads to the root
but is no CA - a device certificate of the root, which an issuer other than
L<SICK::Issuer::StepCA> does not stop on its way here, with
C<< the additional root certificate '<subject>' is not a self-signed CA
certificate >> for an additional root that is none,
and with C<< cannot write '<path>': <reason> >> when a file cannot be
written. Nothing is written when the certificates are not in order.

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

# The certificates of intermediates_pem that are not the root, each one
# once, each one a CA and leading to the root.
sub _intermediates {
  my ( $class, $root, $pem ) = @_;
  return unless defined $pem && !ref $pem && $pem =~ /\S/;
  my @blocks = $pem =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg;
  croak 'intermediates_pem is not a PEM certificate' unless @blocks;

  my %seen  = ( $root->fingerprint_sha256 => 1 );
  my @chain = grep { !$seen{ $_->fingerprint_sha256 }++ } map { SICK::Bundle->new( cert => $_ ) } @blocks;
  my $all   = join q{}, map { $_->cert } @chain;
  for my $cert (@chain) {
    croak 'the intermediate certificate \''.$cert->subject_dn.'\' does not lead to the root certificate \''
      .$root->subject_dn.'\''
      unless !$cert->is_self_signed && $cert->is_issued_by( $root->cert, $all );
    croak 'the intermediate certificate \''.$cert->subject_dn
      .'\' is not a CA certificate (basicConstraints does not say CA:TRUE)'
      unless $cert->is_ca;
  }
  return @chain;
}

# The certificates of additional_roots_pem that are not the root, each one
# once, each one a root of its own: self-signed, of a CA.
sub _additional_roots {
  my ( $class, $root, $pem ) = @_;
  return unless defined $pem && !ref $pem && $pem =~ /\S/;
  my @blocks = $pem =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg;
  croak 'additional_roots_pem is not a PEM certificate' unless @blocks;

  my %seen  = ( $root->fingerprint_sha256 => 1 );
  my @roots = grep { !$seen{ $_->fingerprint_sha256 }++ } map { SICK::Bundle->new( cert => $_ ) } @blocks;
  for my $cert (@roots) {
    croak 'the additional root certificate \''.$cert->subject_dn.'\' is not a self-signed CA certificate'
      unless $cert->is_self_signed && $cert->is_ca && $cert->signs_itself;
  }
  return @roots;
}

# What the page and the profile need of a certificate other than the root:
# its files (without extension in $file), its forms and its facts.
sub _published {
  my ( $class, $cert, $what, $file, $fallback ) = @_;
  my $der = $class->_der( $cert, $what );
  croak 'the DER form of an '.$what.' certificate does not have its fingerprint'
    unless sha256_hex($der) eq $cert->fingerprint_sha256;
  my $label = $cert->common_name;
  $label = q{} unless defined $label;
  $label =~ s/[\x00-\x1f\x7f]+/ /g;
  $label =~ s/\A\s+//;
  $label =~ s/\s+\z//;
  return {
    pem_file  => $file.'.pem',
    der_file  => $file.'.crt',
    pem       => $cert->cert,
    der       => $der,
    label     => length $label ? $label : $fallback,
    sha256    => $cert->fingerprint_sha256,
    sha1      => sha1_hex($der),
    subject   => $cert->subject_dn,
    not_after => strftime( '%Y-%m-%d %H:%M UTC', gmtime $cert->not_after )
  };
}

sub _der {
  my ( $class, $cert, $what ) = @_;
  my $der = eval { SICK::OpenSSL::run_checked( [ 'x509', '-outform', 'DER' ], stdin => $cert->cert ) };
  return $der if defined $der && length $der;
  my $error = $@;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  croak 'cannot convert the '.$what.' certificate to DER: '.( length $error ? $error : 'openssl printed nothing' );
}

# Take away the chain files of an earlier call that this one did not write.
sub _sweep {
  my ( $class, $dir, @written ) = @_;
  my %written = map { $_ => 1 } @written;
  my @children = eval { Path::Tiny::path($dir)->children($CHAIN_FILE) } or return;
  my @stale = sort grep { !$written{$_} } map { $_->basename } @children;
  for my $name (@stale) {
    my $path = $dir.'/'.$name;
    next unless -l $path || -f _;
    eval { Path::Tiny::path($path)->remove; 1 }
      or croak 'cannot remove \''.$path.'\': '.$class->_reason($@);
  }
  return;
}

# One file, written aside in the same directory and renamed into place. The
# file aside is created by File::Temp and filled in place, raw; it is
# published with CORE rename, because Path::Tiny's move copies when renaming
# fails, and a web server would serve half a file.
sub _put {
  my ( $class, $path, $content ) = @_;
  my $dir = Path::Tiny::path($path)->parent->stringify;
  my $aside = eval { Path::Tiny->tempfile( DIR => $dir, TEMPLATE => '.sick-XXXXXXXX', UNLINK => 0 ) }
    or croak 'cannot write \''.$path.'\': '.( $! ? $! : 'cannot create a temporary file' );
  my $reason = eval { $aside->chmod(0644); $aside->append_raw($content); 1 } ? undef : $class->_reason($@);
  $reason = q{}.$! if !defined $reason && !rename( $aside->stringify, $path );
  if ( defined $reason ) {
    eval { $aside->remove };
    croak 'cannot write \''.$path.'\': '.$reason;
  }
  return $path;
}

# The reason of the system out of a Path::Tiny exception.
sub _reason {
  my ( $class, $error ) = @_;
  return $error->{err} if ref $error eq 'Path::Tiny::Error';
  ( $error = defined $error ? $error : q{} ) =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  return length $error ? $error : 'unknown error';
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

# One certificate of the profile. The root is a com.apple.security.root, an
# intermediate a com.apple.security.pkcs1: a certificate the device gets to
# know without being asked to trust it.
sub _payload {
  my ( %payload ) = @_;
  my $data = encode_base64( $payload{der}, q{} );
  $data =~ s/(.{1,52})/\t\t\t$1\n/g;

  return <<"DICT";
\t\t<dict>
\t\t\t<key>PayloadCertificateFileName</key>
\t\t\t<string>$payload{file}</string>
\t\t\t<key>PayloadContent</key>
\t\t\t<data>
$data\t\t\t</data>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>$payload{description}</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>$payload{name}</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>$payload{type}.$payload{uuid}</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>$payload{type}</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>$payload{uuid}</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
DICT
}

sub _profile {
  my ( $class, $der, %fact ) = @_;
  my $name  = _escape( $fact{name} );
  my @chain = @{ $fact{intermediates} || [] };
  my @roots = @{ $fact{roots} || [] };

  # The identifier is what a device knows a profile by: it stays with the
  # root, so that the profile with the intermediate replaces the one
  # without. The UUID is that of this very content.
  my $profile_id   = _uuid( 'profile', $fact{sha256} );
  my $profile_uuid = _uuid( 'profile', join q{ }, $fact{sha256}, map { $_->{sha256} } @roots, @chain );
  my $also         = !@chain ? q{}
    : @chain == 1 ? '. The intermediate certificate comes with it.'
    :               '. The '.@chain.' intermediate certificates come with it.';
  $also = ( @roots == 1
    ? '. For the time of a root replacement the further root certificate comes with it'
    : '. For the time of a root replacement the '.@roots.' further root certificates come with it' )
    .( length $also ? $also : '.' )
    if @roots;

  my $payloads = _payload(
    type        => 'com.apple.security.root',
    file        => 'root_ca.crt',
    der         => $der,
    description => 'Adds the root certificate of '.$name.'.',
    name        => $name,
    uuid        => _uuid( 'payload', $fact{sha256} ),
  );
  $payloads .= _payload(
    type        => 'com.apple.security.root',
    file        => $_->{der_file},
    der         => $_->{der},
    description => 'Adds a further root certificate of '.$name.', for the time of a root replacement.',
    name        => _escape( $_->{label} ),
    uuid        => _uuid( 'payload', $_->{sha256} ),
  ) for @roots;
  $payloads .= _payload(
    type        => 'com.apple.security.pkcs1',
    file        => $_->{der_file},
    der         => $_->{der},
    description => 'Adds an intermediate certificate of '.$name.'. It is not trusted by itself.',
    name        => _escape( $_->{label} ),
    uuid        => _uuid( 'payload', $_->{sha256} ),
  ) for @chain;

  return <<"PLIST";
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadContent</key>
\t<array>
$payloads\t</array>
\t<key>PayloadDescription</key>
\t<string>Makes this device trust the certificates of $name. SHA-256 fingerprint of the root certificate: $fact{sha256}$also</string>
\t<key>PayloadDisplayName</key>
\t<string>$name</string>
\t<key>PayloadIdentifier</key>
\t<string>sick.trust.$profile_id</string>
\t<key>PayloadRemovalDisallowed</key>
\t<false/>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>$profile_uuid</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
</dict>
</plist>
PLIST
}

# What the page says beyond the root when the CA signs through intermediates:
# the words that go into its sentences (%$t) and the parts that are put
# where the page names them (%$part).
sub _chain_parts {
  my ( $class, $t, $part, @chain ) = @_;
  my $many  = @chain > 1;
  my $the   = $many ? 'the intermediates' : 'the intermediate';
  my $The   = ucfirst $the;
  my $is    = $many ? 'are'               : 'is';
  my $needs = $many ? 'need'              : 'needs';
  my $it    = $many ? 'them'              : 'it';
  my $that  = $many ? 'those'             : 'that';
  my $certs = $many ? @chain.' <strong>intermediate certificates</strong>' : 'an <strong>intermediate certificate</strong>';
  my @pem   = map { $_->{pem_file} } @chain;
  my @der   = map { $_->{der_file} } @chain;

  my $link = sub { '<a href="'.$_[0].'" download>'.$_[0].'</a>' };
  my $code = sub { '<code>'.$_[0].'</code>' };
  my $and  = sub { @_ > 1 ? join( ', ', @_[ 0 .. $#_ - 1 ] ).' and '.$_[-1] : $_[0] };
  # ... continuing a list that began with the file of the root
  my $more = sub { join( q{}, map { ', '.$_ } @_[ 0 .. $#_ - 1 ] ).' and '.$_[-1] };

  %$t = (
    %$t,
    profile_holds => ' with the root and '.$the,
    and_pem       => $more->( map { $link->($_) } @pem ),
    terminal      => 'the root as PEM and '.$the.' as DER',
    mac_more      => join( q{}, map { "\nsudo security add-certificates \\\n  -k /Library/Keychains/System.keychain ".$_ } @der ),
    windows_more  => join( q{}, map { "\ncertutil -addstore -f CA ".$_ } @der ),
    check_more    => join( q{}, map { "\nopenssl x509 -in ".$_.' -noout -fingerprint -sha256' } @pem ),
    the_file      => '<code>root_ca.pem</code>',
    from_system   => ' On Windows, macOS and iOS they find '.$the.' there as well; on Android they do not.',
    windows_less  => ', and for '.$the.' <code>certutil -delstore CA &lt;thumbprint&gt;</code>',
    mac_less      => ' (the same for '.$the.', without the first command)',
  );

  $part->{INTRO} = <<"HTML";
<p>This authority does not sign with its root but through $certs, and a device normally hands
$that to your browser together with its own certificate. That is the better way, and such a device needs
nothing but the root. Some devices cannot: a switch has room for exactly one certificate and presents it
alone, and nothing in it leads to the root. For those, this page offers $the as well. The root is what you
trust; $the $is the link between a device and the root and only $needs to be known. So $the $is never
put where every certificate is trusted by itself &ndash; the system store of Linux, the CA certificates of
Android &ndash; but only into <a href="ca_bundle.pem" download>ca_bundle.pem</a> for a program, or where a
platform keeps $it without trust.</p>

HTML

  $part->{FACTS} = join q{}, map {
    my $subject = _escape( $_->{subject} );
    my $sha1    = _colons( $_->{sha1} );
    ( my $sha256 = _colons( $_->{sha256} ) ) =~ s/\A(.{47}):/$1:<br>/;
    <<"HTML" } @chain;
<dl>
  <dt>Intermediate certificate</dt><dd>$subject</dd>
  <dt>SHA-256 fingerprint</dt><dd class="mono">$sha256</dd>
  <dt>SHA-1 fingerprint</dt><dd class="mono">$sha1</dd>
  <dt>Valid until</dt><dd>$_->{not_after}</dd>
</dl>

HTML
  $part->{FACTS} .= <<'HTML';
<p class="soft">Installed without trust, an intermediate certificate is no second root: it counts only because the
root signed it, and gives nobody a power the root has not given already. That holds for the steps below for
Windows, macOS, iPhone and iPad, Firefox and Chrome. In a store that knows nothing but trusted certificates it is a
second root, trusted by itself and still trusted when the root is gone. The only such place this page names is
<code>ca_bundle.pem</code>, one file for the programs you give it to, see <a href="#linux">Linux</a>.</p>

HTML

  $part->{DOWNLOADS} = join q{},
    ( map { '  <li>'.$link->( $_->{der_file} ).' <span class="soft">&ndash; '._escape( $_->{label} )
          .', the intermediate certificate, binary (DER). Windows, macOS.</span></li>'."\n"
          .'  <li>'.$link->( $_->{pem_file} ).' <span class="soft">&ndash; the same as text (PEM). Firefox, Chrome on Linux.</span></li>'."\n" }
      @chain ),
    ( $many
      ? '  <li>'.$link->('intermediate_ca.pem').' <span class="soft">&ndash; '.( @chain == 2 ? 'both' : 'all '.@chain )
        .' intermediate certificates in one file (PEM). Tools.</span></li>'."\n"
      : () );
  $part->{BUNDLE} = '  <li>'.$link->('ca_bundle.pem').' <span class="soft">&ndash; the root and '.$the
    .' in one file (PEM). Programs that take one file with their CAs, see <a href="#linux">Linux</a>.</span></li>'."\n";

  $part->{IOS} = <<"HTML";
<p class="soft">The profile holds $the as well, as a plain certificate, so this one installation also covers the
devices that present their certificate alone. Full trust is switched on for the root only; $the $needs no
setting.</p>
HTML

  $part->{ANDROID} = <<"HTML";
<p class="soft">Only the root goes here, not $the. Android keeps one list of CA certificates, and every certificate
in it is trusted by itself: $the would stay trusted even after the root is removed. So a device that presents its
certificate without $the is not accepted on Android; only one that sends the chain is.</p>
HTML

  $part->{MACOS} = <<"HTML";
<p class="soft">Only the root is marked as trusted. $The $is added to the keychain and $needs no trust setting.
The profile and the script install $it along with the root.</p>
HTML

  $part->{WINDOWS} = '<p>Then '.$the.': download '.$and->( map { $link->($_) } @der ).' and install '.$it
    .' the same way, but into the store'."\n"
    .'<em>Intermediate Certification Authorities</em>. A certificate in that store is trusted for nothing; it only helps'."\n"
    .'Windows to find the way from a device to the root. The script puts '.$it.' there as well.</p>'."\n";

  $part->{LINUX} = <<"HTML";
<p class="soft">Only the root goes into these stores. They know nothing but trusted certificates: $the would be
trusted there without the root, and stay trusted after the root is removed or replaced.</p>
<p>A device that sends $the along with its own certificate needs nothing more. For a device that presents its
certificate alone, a switch with room for one certificate, give the program
<a href="ca_bundle.pem" download>ca_bundle.pem</a>, the root and $the together, as its own CA file:</p>
<pre>curl --cacert ca_bundle.pem https://device.example.internal/
git config http.sslCAInfo /path/to/ca_bundle.pem
openssl s_client -connect device.example.internal:443 -CAfile ca_bundle.pem</pre>
<p class="soft">Inside that one file, programs built on OpenSSL or GnuTLS, curl among them, take $the as a
trust anchor: they accept what $the signed even without the root. That stays within the file and the programs you
give it to. When this authority replaces $the, replace the file as well.</p>
HTML

  $part->{FIREFOXSTEP} = '  <li>Choose <em>Import&hellip;</em> again, pick '.$and->( map { $code->($_) } @pem )
    .' and tick nothing: Firefox has to know'."\n"
    .'      '.$the.', the trust stays with the root.</li>'."\n";

  $part->{FIREFOX} = <<"HTML";
<p class="soft">What Firefox takes from Windows and macOS are the root certificates. Do not count on it for $the: when
a device that presents its certificate alone still gets a warning (<code>SEC_ERROR_UNKNOWN_ISSUER</code>), import
$the as in the last step, or use the script, which does so.</p>
<p><strong>Firefox for Android</strong> has no list of its own and no import. It uses the CA certificates installed
in Android, see <a href="#android">Android</a> above &ndash; since version 120 by itself. Older versions have to be told:
<em>Settings &rarr; About Firefox</em>, tap the logo until the debug menu is announced, then <em>Settings &rarr; Secret
Settings &rarr; Use third party CA certificates</em>.</p>
HTML

  $part->{CHROMESTEP} = '  <li>Import '.$and->( map { $code->($_) } @pem )
    .' in the same place under <em>Intermediate certificates</em> (older versions: tab'."\n"
    .'      <em>Authorities</em> again, without ticking a trust setting). Chrome keeps '.$it.' in NSS, as Firefox'."\n"
    .'      does; not tried yet.</li>'."\n";

  return;
}

# What the page says when the CA is replacing its root: the current root is
# named as such, the others are listed with their fingerprints and files,
# and the commands get a line for each. Called after _chain_parts, whose
# words it extends.
sub _roots_parts {
  my ( $class, $t, $part, $roots, $count ) = @_;
  my @roots = @$roots;
  my $the   = !$count ? q{} : $count > 1 ? 'the intermediates' : 'the intermediate';
  my @pem   = map { $_->{pem_file} } @roots;
  my @der   = map { $_->{der_file} } @roots;
  my $link  = sub { '<a href="'.$_[0].'" download>'.$_[0].'</a>' };
  my $store = sub { my ( $file ) = @_; ( my $name = $file ) =~ s/\Aroot_ca_([0-9]+)\.pem\z/internal-root-ca-$1/; $name };

  $t->{profile_holds} = ' with '.( @roots == 1 ? 'both roots' : 'all '.( @roots + 1 ).' roots' )
    .( $count ? ' and '.$the : q{} );
  $t->{terminal}     = $count ? 'the roots as PEM and '.$the.' as DER' : 'with the PEM files';
  $t->{mac_more}     = join( q{}, map { "\nsudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain ".$_ } @pem )
    .$t->{mac_more};
  $t->{windows_more} = join( q{}, map { "\ncertutil -addstore -f Root ".$_ } @der ).$t->{windows_more};
  $t->{check_more}   = join( q{}, map { "\nopenssl x509 -in ".$_.' -noout -fingerprint -sha256' } @pem ).$t->{check_more};

  $part->{CURRENT} = <<'HTML';
<p>This authority is replacing its root certificate, and for that time this page lists more than one. This is the
<strong>current root</strong>, the one the certificates here lead to today:</p>
HTML

  $part->{ROOTS} = <<'HTML';
<p>The further root certificates below are roots of the same organisation during a replacement: the next one before
the switch, the previous one after it. Install them the same way as the current root, after the same comparison of the
fingerprint. Once the replacement is over, remove the one that is no longer listed on this page.</p>
HTML
  $part->{ROOTS} .= join q{}, map {
    my $subject = _escape( $_->{subject} );
    my $sha1    = _colons( $_->{sha1} );
    ( my $sha256 = _colons( $_->{sha256} ) ) =~ s/\A(.{47}):/$1:<br>/;
    <<"HTML" } @roots;
<dl>
  <dt>Further root certificate</dt><dd>$subject</dd>
  <dt>SHA-256 fingerprint</dt><dd class="mono">$sha256</dd>
  <dt>SHA-1 fingerprint</dt><dd class="mono">$sha1</dd>
  <dt>Valid until</dt><dd>$_->{not_after}</dd>
</dl>
HTML
  $part->{ROOTS} .= "\n";

  $part->{ROOTDOWNLOADS} = join q{}, map {
    '  <li>'.$link->( $_->{der_file} ).' <span class="soft">&ndash; '._escape( $_->{label} )
      .', a further root certificate, binary (DER). Windows, Android.</span></li>'."\n"
      .'  <li>'.$link->( $_->{pem_file} ).' <span class="soft">&ndash; the same as text (PEM). Linux, Firefox, macOS, tools.</span></li>'."\n"
  } @roots;

  $part->{BUNDLE} = '  <li>'.$link->('ca_bundle.pem').' <span class="soft">&ndash; the current root'
    .( $count ? ', ' : ' and ' ).( @roots == 1 ? 'the further root' : 'the further roots' )
    .( $count ? ' and '.$the : q{} )
    .' in one file (PEM). Programs that take one file with their CAs'
    .( $count ? ', see <a href="#linux">Linux</a>' : q{} ).'.</span></li>'."\n";

  $part->{IOS} = ( defined $part->{IOS} ? $part->{IOS} : q{} )
    .( @roots == 1
    ? '<p class="soft">The profile holds the further root as well. Switch on full trust for it in the same place,'
    : '<p class="soft">The profile holds the further roots as well. Switch on full trust for each of them in the same place,' )
    ."\nwhere ".( @roots == 1 ? 'it is' : 'they are' ).' listed by '.( @roots == 1 ? 'its name' : 'their names' ).".</p>\n";

  $part->{LINUXROOTS} = '<p>Each further root goes in under a name of its own, so that it does not replace the current'
    .' one. Debian, Ubuntu and relatives:</p>'."\n"
    .'<pre>'.join( q{}, map { 'sudo cp '.$_.' /usr/local/share/ca-certificates/'.$store->($_).".crt\n" } @pem )
    ."sudo update-ca-certificates</pre>\n"
    ."<p>Fedora, RHEL, Rocky and relatives:</p>\n"
    .'<pre>'.join( q{}, map { 'sudo cp '.$_.' /etc/pki/ca-trust/source/anchors/'.$store->($_).".pem\n" } @pem )
    ."sudo update-ca-trust</pre>\n"
    ."<p>With <code>p11-kit</code>:</p>\n"
    .'<pre>'.join( "\n", map { 'sudo trust anchor --store '.$_ } @pem )."</pre>\n"
    .'<p class="soft">Once the replacement is over, delete the file of the root this page no longer lists and run the'
    ."\nupdate again; with <code>p11-kit</code>, <code>sudo trust anchor --remove</code> and that file.</p>\n";

  return;
}

sub _page {
  my ( $class, %fact ) = @_;
  my $name    = _escape( $fact{name} );
  my $subject = _escape( $fact{subject} );
  my $sha256  = _colons( $fact{sha256} );
  my $sha1    = _colons( $fact{sha1} );
  # two lines of sixteen bytes read better than one of thirty-two
  ( my $sha256_html = $sha256 ) =~ s/\A(.{47}):/$1:<br>/;

  # Without an intermediate these are all there is to say, and the lines
  # that only name a part (<!--PART-->) leave nothing behind.
  my $roots = 1 + @{ $fact{roots} || [] };
  my %t = (
    profile_holds => q{},
    and_pem       => q{},
    terminal      => 'with the PEM file',
    mac_more      => q{},
    windows_more  => q{},
    check_more    => q{},
    the_file      => 'the file',
    from_system   => q{},
    windows_less  => q{},
    mac_less      => q{},
    # one placeholder per root: the scripts want the set, and the page has none to give
    fps           => join( ' ', ( '--fingerprint &lt;from your admin&gt;' ) x $roots ),
    every_root    => $roots > 1 ? 'every one of the '.$roots.' root certificates' : 'the root certificate',
    roots_word    => $roots > 1 ? 'the root certificates' : 'the root certificate',
    one_file      => @{ $fact{intermediates} || [] } || $roots > 1 ? 'ca_bundle.pem' : 'root_ca.pem',
  );
  my %part;
  $class->_chain_parts( \%t, \%part, @{ $fact{intermediates} } ) if @{ $fact{intermediates} || [] };
  $class->_roots_parts( \%t, \%part, $fact{roots}, scalar @{ $fact{intermediates} || [] } ) if @{ $fact{roots} || [] };

  my $html = <<"HTML";
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

<p><strong>First get the fingerprint from the person who runs this authority</strong> &ndash; in person, on paper,
by phone or in a chat you already trust &ndash; not from this page. This page is not authenticated: whoever can change
it can change the certificates and the fingerprints on it as well, and whoever holds the key of a root certificate you
trust can issue a certificate for any name. Compare before you install, and stop when they differ.</p>

<!--INTRO-->
<!--CURRENT-->
<dl>
  <dt>Certificate</dt><dd>$subject</dd>
  <dt>SHA-256 fingerprint</dt><dd class="mono">$sha256_html</dd>
  <dt>SHA-1 fingerprint</dt><dd class="mono">$sha1</dd>
  <dt>Valid from</dt><dd>$fact{not_before}</dd>
  <dt>Valid until</dt><dd>$fact{not_after}</dd>
</dl>

<p>That is what this page says the fingerprint is. The scripts below install nothing unless you give them the one
you got from the person who runs the authority; with the steps by hand, compare that one with what your device shows.</p>

<!--ROOTS-->
<!--FACTS-->
<h2 id="download">Download</h2>
<ul class="downloads">
  <li><a href="root_ca.crt" download>root_ca.crt</a> <span class="soft">&ndash; binary (DER). Windows, Android.</span></li>
  <li><a href="root_ca.pem" download>root_ca.pem</a> <span class="soft">&ndash; text (PEM). Linux, Firefox, macOS, tools.</span></li>
<!--ROOTDOWNLOADS-->
<!--DOWNLOADS-->
<!--BUNDLE-->
  <li><a href="root_ca.mobileconfig">root_ca.mobileconfig</a> <span class="soft">&ndash; configuration profile$t{profile_holds}. iPhone, iPad, Mac.</span></li>
  <li><a href="trust-linux.sh" download>trust-linux.sh</a> <span class="soft">&ndash; script: installs and removes $t{roots_word} in the system store of Linux.</span></li>
  <li><a href="trust-macos.sh" download>trust-macos.sh</a> <span class="soft">&ndash; the same for macOS.</span></li>
  <li><a href="trust-windows.ps1" download>trust-windows.ps1</a> <span class="soft">&ndash; the same for Windows.</span></li>
  <li><a href="trust-nss.sh" download>trust-nss.sh</a> <span class="soft">&ndash; the same for a Firefox profile, or Chrome on Linux.</span></li>
</ul>

<p>The scripts carry the certificates themselves; the one file is enough. Each refuses to install unless you give it
the SHA-256 fingerprint of $t{every_root} with <code>--fingerprint</code>, the way you got it from the person who
runs the authority; colons and case do not matter. <code>remove</code> takes out again what <code>install</code> put in.
They restart nothing and say what still needs a restart.</p>

<nav>
  <a href="#ios">iPhone and iPad</a>
  <a href="#android">Android</a>
  <a href="#macos">macOS</a>
  <a href="#windows">Windows</a>
  <a href="#linux">Linux</a>
  <a href="#firefox">Firefox</a>
  <a href="#chrome">Chrome</a>
  <a href="#runtimes">Other programs</a>
</nav>

<h2 id="ios">iPhone and iPad</h2>
<ol>
  <li>Open this page in Safari and tap <a href="root_ca.mobileconfig">root_ca.mobileconfig</a>. Allow the download.</li>
  <li>Open <em>Settings</em>. Tap <em>Profile Downloaded</em> near the top (or <em>General &rarr; VPN &amp; Device
      Management</em>), choose the profile <em>$name</em> and tap <em>Install</em>.</li>
  <li>The profile alone is not enough. Go to <em>Settings &rarr; General &rarr; About &rarr; Certificate Trust
      Settings</em> and switch on full trust for <em>$name</em>.</li>
</ol>
<p class="soft">The profile is not signed, so iOS calls it <em>Not Verified</em>. That says nothing about the certificate
in it; the fingerprint does. After the installation, open the profile under <em>Settings &rarr; General &rarr; VPN &amp;
Device Management</em>, tap the certificate (<em>More Details</em>) and compare its SHA-256 fingerprint with the one
you got from the person who runs the authority. When they differ, remove the profile. Not tried on a device yet.</p>
<!--IOS-->
<h3>Remove</h3>
<p><em>Settings &rarr; General &rarr; VPN &amp; Device Management</em>, choose the profile <em>$name</em> and tap
<em>Remove Profile</em>. That takes away everything it brought.</p>

<h2 id="android">Android</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a>.</li>
  <li>Open <em>Settings</em> and search for <em>CA certificate</em>. The entry is usually found under
      <em>Security &rarr; More security settings &rarr; Encryption &amp; credentials &rarr; Install a certificate
      &rarr; CA certificate</em>; the names differ between manufacturers.</li>
  <li>Confirm the warning with <em>Install anyway</em> and pick the downloaded file.</li>
</ol>
<!--ANDROID-->
<p class="soft">Only root certificates belong in this list. Apps that target Android 7 (API level 24) or newer ignore
certificates installed this way unless their developers opted in with a <em>Network Security Configuration</em>
(<code>&lt;certificates src=&quot;user&quot;/&gt;</code>). Chrome uses them, and Firefox does since version 120 (checked
2026-10-10). Not tried on a device yet.</p>
<h3>Remove</h3>
<p><em>Settings &rarr; Security &rarr; More security settings &rarr; Encryption &amp; credentials &rarr; Trusted
credentials</em>, tab <em>User</em>: choose the certificate and <em>Remove</em>. The names differ between
manufacturers, as above.</p>

<h2 id="macos">macOS</h2>
<p>With the profile: open <a href="root_ca.mobileconfig">root_ca.mobileconfig</a>, then <em>System Settings &rarr;
Privacy &amp; Security &rarr; Profiles</em> (on older versions <em>System Preferences &rarr; Profiles</em>),
select <em>$name</em> and choose <em>Install</em>. The profile is not signed, so macOS
shows it as <em>Not Verified</em>; compare the SHA-256 fingerprint of the certificate in it with the one you got
before you install it.</p>
<p>With the script, in a terminal:</p>
<pre>sudo sh trust-macos.sh install $t{fps}</pre>
<p>Or in a terminal by hand, $t{terminal}:</p>
<pre>sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain root_ca.pem$t{mac_more}</pre>
<!--MACOS-->
<p>Safari and Chrome use the keychain. Firefox has its own list, see <a href="#firefox">below</a>. Not tried on a Mac
yet.</p>
<h3>Remove</h3>
<pre>sudo sh trust-macos.sh remove</pre>
<p>Installed with the profile: remove <em>$name</em> under <em>System Settings &rarr; Privacy &amp; Security &rarr;
Profiles</em>. By hand: <code>sudo security remove-trusted-cert -d root_ca.pem</code>, then
<code>sudo security delete-certificate -Z &lt;SHA-1 fingerprint&gt; /Library/Keychains/System.keychain</code>$t{mac_less}.
Restart the browsers.</p>

<h2 id="windows">Windows</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a> and open it.</li>
  <li>Choose <em>Install Certificate&hellip;</em>, then <em>Local Machine</em> (for all users; needs an
      administrator) or <em>Current User</em>.</li>
  <li>Select <em>Place all certificates in the following store</em>, browse to <em>Trusted Root Certification
      Authorities</em> and finish. Windows shows the SHA-1 fingerprint as <em>thumbprint</em>.</li>
</ol>
<!--WINDOWS-->
<p>With the script, in a PowerShell that runs as administrator:</p>
<pre>powershell -ExecutionPolicy Bypass -File trust-windows.ps1 install $t{fps}</pre>
<p>Or by hand, in a terminal that runs as administrator:</p>
<pre>certutil -addstore -f Root root_ca.crt$t{windows_more}</pre>
<p>Edge and Chrome use the Windows store. Firefox has its own list, see <a href="#firefox">below</a>. Not tried on
Windows yet.</p>
<h3>Remove</h3>
<pre>powershell -ExecutionPolicy Bypass -File trust-windows.ps1 remove</pre>
<p>By hand, as administrator, with the SHA-1 fingerprint (the thumbprint) without colons:
<code>certutil -delstore Root &lt;thumbprint&gt;</code>$t{windows_less}. Restart the browsers.</p>

<h2 id="linux">Linux</h2>
<p>With the script, which finds out by itself which kind of Linux it runs on:</p>
<pre>sudo sh trust-linux.sh install $t{fps}</pre>
<p>Or by hand. The system store wants the PEM file. Debian, Ubuntu and relatives:</p>
<pre>sudo cp root_ca.pem /usr/local/share/ca-certificates/internal-root-ca.crt
sudo update-ca-certificates</pre>
<p>Fedora, RHEL, Rocky and relatives:</p>
<pre>sudo cp root_ca.pem /etc/pki/ca-trust/source/anchors/internal-root-ca.pem
sudo update-ca-trust</pre>
<p>Arch and others with <code>p11-kit</code>:</p>
<pre>sudo trust anchor --store root_ca.pem</pre>
<!--LINUXROOTS-->
<p>Check the fingerprint of what you downloaded before you install it:</p>
<pre>openssl x509 -in root_ca.pem -noout -fingerprint -sha256$t{check_more}</pre>
<p class="soft">That covers <code>curl</code>, <code>git</code>, <code>wget</code> and most programs. Browsers keep
their own lists on Linux, see below.</p>
<!--LINUX-->
<h3>Remove</h3>
<pre>sudo sh trust-linux.sh remove</pre>
<p>By hand: delete the file you copied and run the update again (<code>sudo update-ca-certificates --fresh</code>,
<code>sudo update-ca-trust</code>), or <code>sudo trust anchor --remove root_ca.pem</code>. A program that read the
store when it started trusts the root until it is restarted.</p>

<h2 id="firefox">Firefox</h2>
<p>With the script, Firefox closed, for one profile (<code>about:profiles</code> shows its directory):</p>
<pre>sh trust-nss.sh install $t{fps} /path/to/profile</pre>
<p>Or by hand:</p>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>$t{and_pem}.</li>
  <li>Open <em>Settings &rarr; Privacy &amp; Security</em>, scroll to <em>Certificates</em> and choose
      <em>View Certificates&hellip;</em>.</li>
  <li>On the tab <em>Authorities</em> choose <em>Import&hellip;</em>, pick $t{the_file} and tick <em>Trust this CA to
      identify websites</em>.</li>
<!--FIREFOXSTEP-->
</ol>
<p class="soft">On Windows, macOS and Android, Firefox 120 and newer use the root certificates installed in the system
as well, unless that is switched off under <em>Settings &rarr; Privacy &amp; Security &rarr; Certificates</em>
(<code>security.enterprise_roots.enabled</code>; checked 2026-10-10). On Linux it does not.</p>
<!--FIREFOX-->
<h3>Remove</h3>
<pre>sh trust-nss.sh remove /path/to/profile</pre>
<p>By hand: <em>View Certificates&hellip;</em>, tab <em>Authorities</em>, select the certificate and choose <em>Delete
or Distrust&hellip;</em>. Restart Firefox.</p>

<h2 id="chrome">Chrome, Chromium, Edge</h2>
<p>On Windows, macOS, Android and iOS these browsers use the certificates of the system: follow the
instructions for the platform above and restart the browser.$t{from_system}</p>
<p>On Linux they keep their own list:</p>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>$t{and_pem}.</li>
  <li>Open <code>chrome://certificate-manager</code> (Chrome 134 and newer, checked 2026-10-10; older versions:
      <code>chrome://settings/certificates</code>).</li>
  <li>Under <em>Local certificates &rarr; Installed by you</em> (older versions: tab <em>Authorities</em>) import
      $t{the_file} as a trusted certificate for websites.</li>
<!--CHROMESTEP-->
</ol>
<p>Or with the script: Chrome on Linux keeps them in the NSS database in <code>~/.pki/nssdb</code>. Not tried yet.</p>
<pre>sh trust-nss.sh install $t{fps} ~/.pki/nssdb</pre>
<h3>Remove</h3>
<p>On Windows, macOS, Android and iOS: remove it from the system as above. On Linux:
<code>sh trust-nss.sh remove ~/.pki/nssdb</code>, or delete it in the certificate manager. Restart the browser.</p>

<h2 id="runtimes">Programs with a store of their own</h2>
<p>Many programs do not read the system store, and a system store makes every program on the machine trust the root.
Where one program needs it, give that program the file instead. Each of them reads its certificates when it starts:
restart it after a change.</p>
<ul>
  <li><strong>Java</strong> has its own <code>cacerts</code>: <code>keytool -importcert -cacerts -alias internal-root-ca
      -file root_ca.pem</code>, removed with <code>keytool -delete -cacerts -alias internal-root-ca</code>. The JDK
      packages of Debian and Fedora build theirs from the system store.</li>
  <li><strong>Python</strong>: <code>requests</code> and many others use <code>certifi</code>, not the system store.
      <code>REQUESTS_CA_BUNDLE</code> (requests) and <code>SSL_CERT_FILE</code> (the <code>ssl</code> module) point
      them at a file, which then replaces their list: give them one with everything they need.</li>
  <li><strong>Node</strong>: <code>NODE_EXTRA_CA_CERTS=/path/to/$t{one_file}</code> adds to its own list, read once at
      start; <code>node --use-system-ca</code> (Node 23.8, on Linux since 23.9) or <code>NODE_USE_SYSTEM_CA=1</code>
      (22.19, 24.6) uses the system store (checked 2026-10-10).</li>
  <li><strong>Go</strong> programs read the system store on Linux, or <code>SSL_CERT_FILE</code> and
      <code>SSL_CERT_DIR</code>; one built into an empty image has none.</li>
  <li><strong>curl</strong> uses the system store; for one call <code>curl --cacert $t{one_file}</code>.</li>
  <li><strong>git</strong>: <code>git config --global http.sslCAInfo /path/to/$t{one_file}</code>, or
      <code>http.&lt;url&gt;.sslCAInfo</code> for one server; the file replaces the list of git.</li>
  <li><strong>Docker</strong> pulling from a registry with a certificate of this authority: the root as
      <code>/etc/docker/certs.d/&lt;registry&gt;:&lt;port&gt;/ca.crt</code> on every host that pulls.</li>
  <li><strong>Container images</strong> do not see the store of the host. In the Dockerfile:
      <code>COPY root_ca.pem /usr/local/share/ca-certificates/internal-root-ca.crt</code>, then
      <code>RUN update-ca-certificates</code> (Debian, Ubuntu, Alpine). That is baked in: removing it means building
      the image again.</li>
  <li><strong>Kubernetes pods</strong>: the root from a ConfigMap (or a trust-manager Bundle) mounted into the pod, and
      the program pointed at it as above; restart the pods after a change.</li>
</ul>
<p class="soft">Not tried from this page yet. The handbook has the full table.</p>
</main>
</body>
</html>
HTML
  $html =~ s/^<!--([A-Z]+)-->\n/defined $part{$1} ? $part{$1} : q{}/mge;
  return $html;
}

1;
