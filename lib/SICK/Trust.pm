package SICK::Trust;
# ABSTRACT: Write the certificates of the CA in the forms clients want, and a page that explains them

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
      root_pem          => $issuer->root_pem,
      intermediates_pem => $issuer->intermediates_pem,    # or undef
      name              => 'Example Internal CA',
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
    index.html             one page: fingerprints, the downloads, and how to
                           install them on each platform

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

With more than one intermediate, F<intermediate_ca.pem> holds all of them
in the order they were given, and each one has files of its own for the
programs that take a single certificate: F<intermediate_ca_1.pem>,
F<intermediate_ca_1.crt>, F<intermediate_ca_2.pem> and so on.

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

# What write puts into a directory when the CA has intermediates - and what
# it takes away again when the CA has fewer of them than last time.
my $CHAIN_FILE = qr/\A(?:intermediate_ca(?:_[0-9]+)?\.(?:pem|crt)|ca_bundle\.pem)\z/;

# The files of each single intermediate, without their extension.
sub _single {
  my ( $count ) = @_;
  return $count == 1 ? ('intermediate_ca') : map { 'intermediate_ca_'.$_ } 1 .. $count;
}

sub files {
  my ( $class, $count ) = @_;
  $count = 0 unless defined $count && !ref $count && $count =~ /\A[0-9]+\z/;
  return ( @FIRST, @LAST ) unless $count;
  return (
    @FIRST,
    ( $count > 1 ? 'intermediate_ca.pem' : () ),
    ( map { ( $_.'.pem', $_.'.crt' ) } _single($count) ),
    'ca_bundle.pem',
    @LAST,
  );
}

=method files

    my @names = SICK::Trust->files;                   # a CA without intermediates
    my @names = SICK::Trust->files($intermediates);   # with that many

The names of the files, in the order they are written: four without
intermediates, seven with one. The page comes last, so that it never links
to a file that is not there yet.

=cut

sub write {
  my ( $class, $dir, %arg ) = @_;
  croak 'SICK::Trust->write needs a directory' unless defined $dir && !ref $dir && length $dir;
  my @unknown = sort grep { !/\A(?:root_pem|intermediates_pem|name)\z/ } keys %arg;
  croak 'SICK::Trust->write: unknown argument \''.$unknown[0].'\'' if @unknown;

  my $root  = $class->_root( $arg{root_pem} );
  my $der   = $class->_der( $root, 'root' );
  my @chain = $class->_intermediates( $root, $arg{intermediates_pem} );

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

  my @single = _single( scalar @chain );
  my @intermediates;
  for my $i ( 0 .. $#chain ) {
    my $cert     = $chain[$i];
    my $cert_der = $class->_der( $cert, 'intermediate' );
    croak 'the DER form of an intermediate certificate does not have its fingerprint'
      unless sha256_hex($cert_der) eq $cert->fingerprint_sha256;
    my $label = $cert->common_name;
    $label = q{} unless defined $label;
    $label =~ s/[\x00-\x1f\x7f]+/ /g;
    $label =~ s/\A\s+//;
    $label =~ s/\s+\z//;
    push @intermediates, {
      pem_file  => $single[$i].'.pem',
      der_file  => $single[$i].'.crt',
      pem       => $cert->cert,
      der       => $cert_der,
      label     => length $label ? $label : $name.' intermediate',
      sha256    => $cert->fingerprint_sha256,
      sha1      => sha1_hex($cert_der),
      subject   => $cert->subject_dn,
      not_after => strftime( '%Y-%m-%d %H:%M UTC', gmtime $cert->not_after )
    };
  }

  my %content = (
    'root_ca.pem'          => $root->cert,
    'root_ca.crt'          => $der,
    'root_ca.mobileconfig' => $class->_profile( $der, %fact, intermediates => \@intermediates ),
    'index.html'           => $class->_page( %fact, intermediates => \@intermediates )
  );
  if (@intermediates) {
    $content{'intermediate_ca.pem'} = join q{}, map { $_->{pem} } @intermediates;
    $content{'ca_bundle.pem'}       = $root->cert.$content{'intermediate_ca.pem'};
    for my $intermediate (@intermediates) {
      $content{ $intermediate->{pem_file} } = $intermediate->{pem};
      $content{ $intermediate->{der_file} } = $intermediate->{der};
    }
  }
  my @files = $class->files( scalar @intermediates );

  unless ( -d $dir ) {
    make_path( $dir, { mode => 0755, error => \my $errors } );
    croak 'cannot create directory \''.$dir.'\': '.( values %{ $errors->[0] } )[0]
      if $errors && @$errors;
  }
  $class->_put( $dir.'/'.$_, $content{$_} ) for @files;
  $class->_sweep( $dir, @files );
  return map { $dir.'/'.$_ } @files;
}

=method write

    my @paths = SICK::Trust->write(
      $directory,
      root_pem          => $pem,
      intermediates_pem => $pem,    # optional
      name              => $display_name,
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
blanks) when it has none - the four files are then exactly what they are
without the argument. Every intermediate has to lead to the root, through
the others if need be: this page tells people to install what it offers,
so a certificate of some other CA is refused and not published. The root
itself and a certificate that is given twice are passed over.

C<name> is what the CA is called on the page and in the profile; without
it, the common name of the root certificate.

The files with the intermediates belong to this module (F<ca_bundle.pem>
and everything called F<intermediate_ca.pem>, F<intermediate_ca.crt>,
F<intermediate_ca_E<lt>nE<gt>.pem> or F<intermediate_ca_E<lt>nE<gt>.crt>):
those an earlier call left in the directory and this one does not write
are removed, so that a directory never offers the intermediate of a CA
that has none any more. Nothing else in the directory is touched.

Croaks when C<root_pem> holds no root certificate or more than one, with
C<< the intermediate certificate '<subject>' does not lead to the root
certificate '<subject>' >> for an intermediate that is none of this CA,
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
# once, each one leading to the root.
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
  }
  return @chain;
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
  opendir my $dh, $dir or return;
  my @stale = sort grep { $_ =~ $CHAIN_FILE && !$written{$_} } readdir $dh;
  closedir $dh;
  for my $name (@stale) {
    my $path = $dir.'/'.$name;
    next unless -l $path || -f _;
    unlink $path or croak 'cannot remove \''.$path.'\': '.$!;
  }
  return;
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

  # The identifier is what a device knows a profile by: it stays with the
  # root, so that the profile with the intermediate replaces the one
  # without. The UUID is that of this very content.
  my $profile_id   = _uuid( 'profile', $fact{sha256} );
  my $profile_uuid = _uuid( 'profile', join q{ }, $fact{sha256}, map { $_->{sha256} } @chain );
  my $also         = !@chain ? q{}
    : @chain == 1 ? '. The intermediate certificate comes with it.'
    :               '. The '.@chain.' intermediate certificates come with it.';

  my $payloads = _payload(
    type        => 'com.apple.security.root',
    file        => 'root_ca.crt',
    der         => $der,
    description => 'Adds the root certificate of '.$name.'.',
    name        => $name,
    uuid        => _uuid( 'payload', $fact{sha256} ),
  );
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
  # the name a certificate file gets in a system store
  my $stored = sub { 'internal-intermediate-ca'.( $many ? '-'.( $_[0] + 1 ) : q{} ) };

  %$t = (
    %$t,
    profile_holds => ' with the root and '.$the,
    and_der       => $more->( map { $link->($_) } @der ),
    and_pem       => $more->( map { $link->($_) } @pem ),
    terminal      => 'the root as PEM and '.$the.' as DER',
    mac_more      => join( q{}, map { "\nsudo security add-certificates \\\n  -k /Library/Keychains/System.keychain ".$_ } @der ),
    windows_more  => join( q{}, map { "\ncertutil -addstore -f CA ".$_ } @der ),
    pem_files     => 'PEM files',
    arch_more     => join( q{}, map { q{ }.$_ } @pem ),
    check_more    => join( q{}, map { "\nopenssl x509 -in ".$_.' -noout -fingerprint -sha256' } @pem ),
    the_file      => '<code>root_ca.pem</code>',
    from_system   => ' They find '.$the.' there as well.',
  );

  $part->{INTRO} = <<"HTML";
<p>This authority does not sign with its root but through $certs, and a device normally hands
$that to your browser together with its own certificate. Some devices cannot: a switch has room for exactly one
certificate and presents it alone, and nothing in it leads to the root. For those, this page offers $the as
well, and the steps below install $it. The root is what you trust; $the $is the link between a device and the
root and only $needs to be known.</p>

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
<p class="soft">An intermediate certificate is no second root. It counts only because the root signed it, and
installing it gives nobody a power the root has not given already.</p>

HTML

  $part->{DOWNLOADS} = join q{},
    ( map { '  <li>'.$link->( $_->{der_file} ).' <span class="soft">&ndash; '._escape( $_->{label} )
          .', the intermediate certificate, binary (DER). Windows, Android, macOS.</span></li>'."\n"
          .'  <li>'.$link->( $_->{pem_file} ).' <span class="soft">&ndash; the same as text (PEM). Linux, Firefox, Chrome.</span></li>'."\n" }
      @chain ),
    ( $many
      ? '  <li>'.$link->('intermediate_ca.pem').' <span class="soft">&ndash; '.( @chain == 2 ? 'both' : 'all '.@chain )
        .' intermediate certificates in one file (PEM). Tools.</span></li>'."\n"
      : () ),
    '  <li>'.$link->('ca_bundle.pem').' <span class="soft">&ndash; the root and '.$the
      .' in one file (PEM). Programs that take one file with their CAs.</span></li>'."\n";

  $part->{IOS} = <<"HTML";
<p class="soft">The profile holds $the as well, so this one installation also covers the devices that present
their certificate alone. Full trust is switched on for the root only; $the $needs no setting.</p>
HTML

  $part->{ANDROID} = '  <li>Do the same for '.$and->( map { $code->($_) } @der )
    .': Android takes one certificate at a time, and '.$the.' '.( $many ? 'go' : 'goes' )
    .' into the same list of CA certificates as the root.</li>'."\n";

  $part->{MACOS} = <<"HTML";
<p class="soft">Only the root is marked as trusted. $The $is added to the keychain and $needs no trust setting.
The profile installs $it along with the root.</p>
HTML

  $part->{WINDOWS} = '<p>Then '.$the.': download '.$and->( map { $link->($_) } @der ).' and install '.$it
    .' the same way, but into the store'."\n"
    .'<em>Intermediate Certification Authorities</em>. A certificate in that store is trusted for nothing; it only helps'."\n"
    .'Windows to find the way from a device to the root.</p>'."\n";

  $part->{DEBIAN} = join q{},
    map { 'sudo cp '.$pem[$_].' /usr/local/share/ca-certificates/'.$stored->($_).'.crt'."\n" } 0 .. $#pem;
  $part->{FEDORA} = join q{},
    map { 'sudo cp '.$pem[$_].' /etc/pki/ca-trust/source/anchors/'.$stored->($_).'.pem'."\n" } 0 .. $#pem;

  $part->{LINUX} = <<"HTML";
<p class="soft">Every file is one certificate; these stores take them one by one. They also know nothing but trusted
certificates: $the $is trusted there directly, next to the root. Take $it out again together with the
root.</p>
<p>A program that wants its CA certificates as one file gets <a href="ca_bundle.pem" download>ca_bundle.pem</a>,
the root and $the together:</p>
<pre>curl --cacert ca_bundle.pem https://device.example.internal/
openssl s_client -connect device.example.internal:443 -CAfile ca_bundle.pem</pre>
HTML

  $part->{FIREFOXSTEP} = '  <li>Choose <em>Import&hellip;</em> again, pick '.$and->( map { $code->($_) } @pem )
    .' and tick nothing: Firefox has to know'."\n"
    .'      '.$the.', the trust stays with the root.</li>'."\n";

  $part->{FIREFOX} = <<"HTML";
<p class="soft">Since version 120 Firefox does that by itself for the root certificates you installed on Windows and
macOS. Do not count on it for $the: when a device that presents its certificate alone still gets a warning
(<code>SEC_ERROR_UNKNOWN_ISSUER</code>), import $the as in the last step.</p>
<p><strong>Firefox for Android</strong> has no list of its own and no import. It uses the CA certificates installed
in Android, see <a href="#android">Android</a> above &ndash; since version 120 by itself. Older versions have to be told:
<em>Settings &rarr; About Firefox</em>, tap the logo until the debug menu is announced, then <em>Settings &rarr; Secret
Settings &rarr; Use third party CA certificates</em>.</p>
HTML

  $part->{CHROMESTEP} = '  <li>Import '.$and->( map { $code->($_) } @pem )
    .' in the same place under <em>Intermediate certificates</em> (older versions: tab'."\n"
    .'      <em>Authorities</em> again, without ticking a trust setting).</li>'."\n";

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
  my %t = (
    profile_holds => q{},
    and_der       => q{},
    and_pem       => q{},
    terminal      => 'with the PEM file',
    mac_more      => q{},
    windows_more  => q{},
    pem_files     => 'PEM file',
    arch_more     => q{},
    check_more    => q{},
    the_file      => 'the file',
    from_system   => q{},
  );
  my %part;
  $class->_chain_parts( \%t, \%part, @{ $fact{intermediates} } ) if @{ $fact{intermediates} || [] };

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

<!--INTRO-->
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

<!--FACTS-->
<h2 id="download">Download</h2>
<ul class="downloads">
  <li><a href="root_ca.crt" download>root_ca.crt</a> <span class="soft">&ndash; binary (DER). Windows, Android.</span></li>
  <li><a href="root_ca.pem" download>root_ca.pem</a> <span class="soft">&ndash; text (PEM). Linux, Firefox, macOS, tools.</span></li>
<!--DOWNLOADS-->
  <li><a href="root_ca.mobileconfig">root_ca.mobileconfig</a> <span class="soft">&ndash; configuration profile$t{profile_holds}. iPhone, iPad, Mac.</span></li>
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
<!--IOS-->

<h2 id="android">Android</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a>$t{and_der}.</li>
  <li>Open <em>Settings</em> and search for <em>CA certificate</em>. The entry is usually found under
      <em>Security &rarr; More security settings &rarr; Encryption &amp; credentials &rarr; Install a certificate
      &rarr; CA certificate</em>; the names differ between manufacturers.</li>
  <li>Confirm the warning with <em>Install anyway</em> and pick the downloaded file.</li>
<!--ANDROID-->
</ol>
<p class="soft">Chrome and most browsers use certificates installed this way. Other apps only do so when their
developers allowed it.</p>

<h2 id="macos">macOS</h2>
<p>With the profile: open <a href="root_ca.mobileconfig">root_ca.mobileconfig</a>, then <em>System Settings &rarr;
Privacy &amp; Security &rarr; Profiles</em> (on older versions <em>System Preferences &rarr; Profiles</em>),
select <em>$name</em> and choose <em>Install</em>.</p>
<p>Or in a terminal, $t{terminal}:</p>
<pre>sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain root_ca.pem$t{mac_more}</pre>
<!--MACOS-->
<p>Safari and Chrome use the keychain. Firefox has its own list, see <a href="#firefox">below</a>.</p>

<h2 id="windows">Windows</h2>
<ol>
  <li>Download <a href="root_ca.crt" download>root_ca.crt</a> and open it.</li>
  <li>Choose <em>Install Certificate&hellip;</em>, then <em>Local Machine</em> (for all users; needs an
      administrator) or <em>Current User</em>.</li>
  <li>Select <em>Place all certificates in the following store</em>, browse to <em>Trusted Root Certification
      Authorities</em> and finish. Windows shows the SHA-1 fingerprint as <em>thumbprint</em>.</li>
</ol>
<!--WINDOWS-->
<p>Or in a terminal that runs as administrator:</p>
<pre>certutil -addstore -f Root root_ca.crt$t{windows_more}</pre>
<p>Edge and Chrome use the Windows store. Firefox has its own list, see <a href="#firefox">below</a>.</p>

<h2 id="linux">Linux</h2>
<p>The system store wants the $t{pem_files}. Debian, Ubuntu and relatives:</p>
<pre>sudo cp root_ca.pem /usr/local/share/ca-certificates/internal-root-ca.crt
<!--DEBIAN-->
sudo update-ca-certificates</pre>
<p>Fedora, RHEL, Rocky and relatives:</p>
<pre>sudo cp root_ca.pem /etc/pki/ca-trust/source/anchors/internal-root-ca.pem
<!--FEDORA-->
sudo update-ca-trust</pre>
<p>Arch and others with <code>p11-kit</code>:</p>
<pre>sudo trust anchor --store root_ca.pem$t{arch_more}</pre>
<p>Check the fingerprint of what you downloaded before you install it:</p>
<pre>openssl x509 -in root_ca.pem -noout -fingerprint -sha256$t{check_more}</pre>
<p class="soft">That covers <code>curl</code>, <code>git</code>, <code>wget</code> and most programs. Browsers keep
their own lists on Linux, see below.</p>
<!--LINUX-->

<h2 id="firefox">Firefox</h2>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>$t{and_pem}.</li>
  <li>Open <em>Settings &rarr; Privacy &amp; Security</em>, scroll to <em>Certificates</em> and choose
      <em>View Certificates&hellip;</em>.</li>
  <li>On the tab <em>Authorities</em> choose <em>Import&hellip;</em>, pick $t{the_file} and tick <em>Trust this CA to
      identify websites</em>.</li>
<!--FIREFOXSTEP-->
</ol>
<p class="soft">On Windows and macOS, Firefox can use the certificates of the system instead: open
<code>about:config</code> and set <code>security.enterprise_roots.enabled</code> to <code>true</code>.</p>
<!--FIREFOX-->

<h2 id="chrome">Chrome, Chromium, Edge</h2>
<p>On Windows, macOS, Android and iOS these browsers use the certificates of the system: follow the
instructions for the platform above and restart the browser.$t{from_system}</p>
<p>On Linux they keep their own list:</p>
<ol>
  <li>Download <a href="root_ca.pem" download>root_ca.pem</a>$t{and_pem}.</li>
  <li>Open <code>chrome://certificate-manager</code> (older versions: <code>chrome://settings/certificates</code>).</li>
  <li>Under <em>Local certificates &rarr; Installed by you</em> (older versions: tab <em>Authorities</em>) import
      $t{the_file} as a trusted certificate for websites.</li>
<!--CHROMESTEP-->
</ol>
</main>
</body>
</html>
HTML
  $html =~ s/^<!--([A-Z]+)-->\n/defined $part{$1} ? $part{$1} : q{}/mge;
  return $html;
}

1;
