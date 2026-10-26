package SICK::Trust::Scripts;
# ABSTRACT: Install and remove scripts for the certificates of the CA, one per platform

use Moo;
use Carp qw( croak );
use MIME::Base64 qw( encode_base64 );
use Types::Standard qw( ArrayRef HashRef Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Trust::Scripts;

    my $scripts = SICK::Trust::Scripts->new(
      name          => 'Example Internal CA',
      roots         => [ { pem => $pem, der => $der }, ... ],    # the current root first
      intermediates => [ { pem => $pem, der => $der }, ... ],    # or []
    );
    my %content = map { $_ => $scripts->content($_) } SICK::Trust::Scripts->files;

=head1 DESCRIPTION

What L<SICK::Trust> writes next to the certificates for the people who
install them: one script per platform, each with the certificates in it, so
that the one downloaded file is enough.

    trust-linux.sh      the system store of Linux: Debian, Ubuntu and Alpine
                        (update-ca-certificates), Fedora, RHEL, Rocky
                        (update-ca-trust), Arch and others (p11-kit trust)
    trust-macos.sh      the System keychain of macOS (security)
    trust-windows.ps1   the stores of the local machine of Windows
                        (Import-Certificate)
    trust-nss.sh        an NSS database: a Firefox profile, or the one of
                        Chrome on Linux (certutil)

Each takes C<install> or C<remove>:

    sudo sh trust-linux.sh install --fingerprint <sha256> [--fingerprint <sha256> ...]
    sudo sh trust-linux.sh remove

    sudo sh trust-macos.sh install --fingerprint <sha256> [--fingerprint <sha256> ...]
    sudo sh trust-macos.sh remove

    powershell -ExecutionPolicy Bypass -File trust-windows.ps1 install --fingerprint <sha256> [--fingerprint <sha256> ...]
    powershell -ExecutionPolicy Bypass -File trust-windows.ps1 remove

    sh trust-nss.sh install --fingerprint <sha256> [--fingerprint <sha256> ...] <profile or database directory>
    sh trust-nss.sh remove <profile or database directory>

The page these scripts are served from is not authenticated, so a script
does not trust itself either. C<install> refuses - exit code 1, nothing
changed - unless it is given the SHA-256 fingerprint of every root
certificate it carries, and no other: the fingerprint the operator got from
whoever runs the CA, by another channel. Colons, blanks and case do not
matter. The script computes the fingerprints itself (C<openssl>, or
C<base64> and C<sha256sum> or C<shasum> where there is no C<openssl>;
C<Get-FileHash> on Windows) and prints them.

C<remove> needs no fingerprint, takes out what C<install> put in - the files
it names after the fingerprints, the nicknames, the thumbprints - and
nothing else, says what it removed, and is content when there is nothing to
remove. Neither restarts anything; both say what still needs a restart.

Where they put what, by the rules of L<SICK::Trust>: a store in which every
certificate is a trust anchor - the system stores of Linux - gets the roots
alone, so F<trust-linux.sh> carries no intermediate. The others carry the
intermediates as well and keep them without trust: in the System keychain
without a trust setting, in C<LocalMachine\CA>, in NSS with the trust flags
C<,,> (the roots get C<C,,>). No script replaces a whole system bundle.

Exit codes of every script: C<0> done, C<1> refused or failed, C<2> the
command line is wrong.

The shell scripts know one variable for tests, and only for tests:
C<SICK_TRUST_ROOT=E<lt>directoryE<gt>> puts every path that
F<trust-linux.sh> and F<trust-macos.sh> read or write below that directory
and lifts their checks for root and for the platform; the programs they
call are found through C<PATH> as always. It is not a way to install for
real. F<trust-nss.sh> works on the directory it is given and needs no such
variable.

The scripts are derived from the certificates and the name alone, so
writing them twice gives the same bytes. F<trust-windows.ps1> is plain
ASCII: Windows PowerShell reads a file without byte order mark in the code
page of the system, so the name of the CA travels in it as Base64.

=cut

my @FILES = qw( trust-linux.sh trust-macos.sh trust-windows.ps1 trust-nss.sh );

sub files { @FILES }

=method files

    my @names = SICK::Trust::Scripts->files;

The names of the scripts, in the order L<SICK::Trust> writes them.

=cut

has name => ( is => 'ro', isa => Str, required => 1 );

=attr name

Required. What the CA is called in the messages of the scripts.

=cut

has roots => (
  is       => 'ro',
  isa      => ArrayRef [HashRef],
  required => 1,
  coerce   => sub { ref $_[0] eq 'ARRAY' ? [ @{ $_[0] } ] : $_[0] }
);

=attr roots

Required. The root certificates, the current one first, each a hash with
C<pem> and C<der>.

=cut

has intermediates => (
  is      => 'ro',
  isa     => ArrayRef [HashRef],
  default => sub { [] },
  coerce  => sub { ref $_[0] eq 'ARRAY' ? [ @{ $_[0] } ] : $_[0] }
);

=attr intermediates

The intermediate certificates, each a hash with C<pem> and C<der>; empty by
default.

=cut

sub BUILD {
  my ( $self ) = @_;
  croak 'SICK::Trust::Scripts->new needs at least one root' unless @{ $self->roots };
  for my $cert ( @{ $self->roots }, @{ $self->intermediates } ) {
    croak 'SICK::Trust::Scripts->new: every certificate needs pem and der'
      unless defined $cert->{pem} && $cert->{pem} =~ /\A-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+-----END CERTIFICATE-----\n?\z/
      && defined $cert->{der} && length $cert->{der};
  }
  return;
}

sub content {
  my ( $self, $file ) = @_;
  my %method = (
    'trust-linux.sh'    => '_linux',
    'trust-macos.sh'    => '_macos',
    'trust-windows.ps1' => '_windows',
    'trust-nss.sh'      => '_nss',
  );
  croak 'SICK::Trust::Scripts: no script \''.( defined $file ? $file : 'undef' ).'\'' unless defined $file && $method{$file};
  my $method = $method{$file};
  return $self->$method;
}

=method content

    my $text = $scripts->content('trust-linux.sh');

The script of that name as bytes. Croaks with C<< no script '<name>' >> for
a name that is not one of L</files>.

=cut

#### internals

# The name for a comment and for a single-quoted string of sh: one line,
# a quote closed, escaped and opened again.
sub _sh_name {
  my ( $self ) = @_;
  ( my $name = $self->name ) =~ s/[\x00-\x1f\x7f]+/ /g;
  ( my $quoted = $name ) =~ s/'/'\\''/g;
  return ( $name, $quoted );
}

sub _pem {
  my ( $self, $cert ) = @_;
  my $pem = $cert->{pem};
  $pem .= "\n" unless $pem =~ /\n\z/;
  return $pem;
}

# The certificates of a shell script, as functions that print them.
sub _sh_certs {
  my ( $self, $with_intermediates ) = @_;
  my $text = q{};
  my $n = 0;
  $text .= 'root_'.++$n."() {\n  cat <<'SICK_PEM'\n".$self->_pem($_)."SICK_PEM\n}\n\n" for @{ $self->roots };
  return $text unless $with_intermediates;
  $n = 0;
  $text .= 'intermediate_'.++$n."() {\n  cat <<'SICK_PEM'\n".$self->_pem($_)."SICK_PEM\n}\n\n" for @{ $self->intermediates };
  return $text;
}

# What every shell script has: its head, the certificates, the helpers, the
# command line and the check of the fingerprints. %arg: file, purpose,
# usage (lines), what (the extra argument of the usage), test (whether
# SICK_TRUST_ROOT applies), intermediates (whether they are carried).
sub _sh {
  my ( $self, %arg ) = @_;
  my ( $name, $quoted ) = $self->_sh_name;
  my $roots = @{ $self->roots };
  my $inter = $arg{intermediates} ? scalar @{ $self->intermediates } : 0;
  my $file  = $arg{file};
  my $usage = join q{}, map { ( '#   '.$_ ) =~ s/\s+\z//r ."\n" } @{ $arg{usage} };
  my $plain = join q{}, map { ( '  '.$_ ) =~ s/\s+\z//r ."\n" } @{ $arg{usage} };
  my $test  = $arg{test} ? <<'SH' : q{};
#
# For tests only: SICK_TRUST_ROOT=<directory> puts every path this script
# reads or writes below that directory and lifts the checks for root and for
# the platform. It is not a way to install for real.
SH
  my $root_var = $arg{test} ? "ROOT=\${SICK_TRUST_ROOT-}\n" : q{};
  my $positional = $arg{what}
    ? '[ -z "$DIR" ] || misuse "one directory only: '."'".'$1'."'".'"; DIR=$1; shift;;'
    : 'misuse "unexpected argument '."'".'$1'."'".'";;';
  my $certs = $self->_sh_certs( $arg{intermediates} );

  return <<"SH";
#!/bin/sh
# $file - $arg{purpose}
# Written by sick trust for $name.
#
# Usage:
$usage#
# install refuses unless it is given the SHA-256 fingerprint of every root
# certificate in this script, one --fingerprint for each, as you got it from
# the person who runs the CA - not from the page this script came from, which
# is not authenticated. Colons, blanks and case do not matter. remove takes
# out exactly what install put in and needs no fingerprint. Nothing is
# restarted; the script says what still needs a restart.
#
# Exit codes: 0 done, 1 refused or failed, 2 wrong command line.
$test
set -u
umask 022

ME=$file
NAME='$quoted'
ROOTS=$roots
INTERMEDIATES=$inter
$root_var
usage() {
  cat <<'SICK_USAGE'
Usage:
${plain}SICK_USAGE
}

fail() {
  printf '%s: %s\\n' "\$ME" "\$1" >&2
  exit 1
}

misuse() {
  printf '%s: %s\\n' "\$ME" "\$1" >&2
  usage >&2
  exit 2
}

say() {
  printf '%s\\n' "\$1"
}

${certs}# A SHA of standard input as lower-case hex; \$1 is 256 or 1.
hash_of() {
  if command -v "sha\${1}sum" >/dev/null 2>&1; then
    "sha\${1}sum"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a "\$1"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst "-sha\$1" -r
  fi | cut -d ' ' -f 1 | tr 'ABCDEF' 'abcdef'
}

# PEM file \$1 to DER file \$2.
der_of() {
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "\$1" -outform DER -out "\$2" 2>/dev/null
  else
    sed -e '/^-----/d' "\$1" | base64 -d > "\$2" 2>/dev/null
  fi
  [ -s "\$2" ]
}

colons() {
  printf '%s\\n' "\$1" | sed -e 's/../&:/g' -e 's/:\$//' | tr 'abcdef' 'ABCDEF'
}

subject_of() {
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "\$TMP/\$1.pem" -noout -subject 2>/dev/null | sed -e 's/^subject= *//'
  fi
}

GIVEN=''
add_fingerprint() {
  fp=\$(printf '%s' "\$1" | tr -d ': \\t' | tr 'ABCDEF' 'abcdef')
  case \$fp in
    ''|*[!0-9a-f]*) fail "refused: '\$1' is not a SHA-256 fingerprint" ;;
  esac
  [ \${#fp} -eq 64 ] || fail "refused: '\$1' is not a SHA-256 fingerprint (64 hex digits)"
  GIVEN="\$GIVEN\$fp
"
}

[ \$# -gt 0 ] || misuse 'install or remove?'
ACTION=\$1
shift
case \$ACTION in
  install|remove) ;;
  -h|--help) usage; exit 0 ;;
  *) misuse "unknown action '\$ACTION'" ;;
esac
DIR=''
while [ \$# -gt 0 ]; do
  case \$1 in
    --fingerprint=*) add_fingerprint "\${1#--fingerprint=}"; shift ;;
    --fingerprint)
      [ \$# -ge 2 ] || misuse '--fingerprint needs a value'
      add_fingerprint "\$2"
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) misuse "unknown option '\$1'" ;;
    *) $positional
  esac
done
[ "\$ACTION" = install ] || [ -z "\$GIVEN" ] || misuse 'remove takes no --fingerprint'

TMP=\$(mktemp -d 2>/dev/null) || fail 'cannot create a temporary directory'
trap 'rm -rf "\$TMP"' EXIT
trap 'exit 1' HUP INT TERM

# Every certificate into \$TMP, as PEM and DER, with its SHA-256 and SHA-1.
prepare() {
  for kind in root intermediate; do
    count=\$ROOTS
    [ "\$kind" = root ] || count=\$INTERMEDIATES
    i=1
    while [ "\$i" -le "\$count" ]; do
      "\${kind}_\$i" > "\$TMP/\${kind}_\$i.pem"
      der_of "\$TMP/\${kind}_\$i.pem" "\$TMP/\${kind}_\$i.der" \\
        || fail "cannot read the \$kind certificate \$i: this needs openssl, or base64"
      for bits in 256 1; do
        sum=\$(hash_of "\$bits" < "\$TMP/\${kind}_\$i.der")
        case \$sum in
          ''|*[!0-9a-f]*) fail 'cannot compute a fingerprint: this needs sha256sum, shasum or openssl' ;;
        esac
        printf '%s\\n' "\$sum" > "\$TMP/\${kind}_\$i.sha\$bits"
      done
      i=\$((i + 1))
    done
  done
}

sha256_of() {
  cat "\$TMP/\$1.sha256"
}

sha1_of() {
  cat "\$TMP/\$1.sha1"
}

# Refuses unless the fingerprints given are exactly those of the roots here.
check_fingerprints() {
  bad=0
  say "Root certificates in this script, SHA-256:"
  i=1
  while [ "\$i" -le "\$ROOTS" ]; do
    sum=\$(sha256_of "root_\$i")
    if printf '%s' "\$GIVEN" | grep -qx "\$sum"; then
      mark='matches'
    else
      mark='NOT GIVEN'
      bad=1
    fi
    say "  \$(colons "\$sum")  \$mark"
    subject=\$(subject_of "root_\$i")
    [ -z "\$subject" ] || say "    \$subject"
    i=\$((i + 1))
  done
  for given in \$GIVEN; do
    if ! cat "\$TMP"/root_*.sha256 | grep -qx "\$given"; then
      say "  given, but no certificate here has it: \$(colons "\$given")"
      bad=1
    fi
  done
  if [ -z "\$GIVEN" ]; then
    fail "refused: install needs the SHA-256 fingerprint of each root certificate, as --fingerprint, from the person who runs \$NAME - not from the page this script came from, and not from the lines above."
  fi
  [ "\$bad" -eq 0 ] || fail "refused: the fingerprints given are not those of the root certificates in this script. Nothing was installed. Ask the person who runs \$NAME again."
}

prepare
SH
}

sub _linux {
  my ( $self ) = @_;
  my $chain = @{ $self->intermediates }
    ? <<'SH'
  say 'No intermediate certificate went into the store: every certificate there'
  say 'is trusted by itself. For a device that presents its certificate without'
  say 'the chain, give the program ca_bundle.pem from the same page as its CA file.'
SH
    : q{};
  my $head = $self->_sh(
    file    => 'trust-linux.sh',
    purpose => 'install or remove the root certificates of a CA in the system store of Linux',
    usage   => [
      'sudo sh trust-linux.sh install --fingerprint <sha256> [--fingerprint <sha256> ...]',
      'sudo sh trust-linux.sh remove'
    ],
    test => 1,
  );
  return $head.<<'SH'.$chain.<<'SH';

# Which store: Debian, Ubuntu and Alpine (update-ca-certificates), the
# Fedora and RHEL family (update-ca-trust), or p11-kit (trust anchor).
FAMILY=''
release="$ROOT/etc/os-release"
if [ -r "$release" ]; then
  words=$(sed -n -e 's/^ID=//p' -e 's/^ID_LIKE=//p' "$release" | tr -d '"'"'")
  for word in $words; do
    case $word in
      debian|ubuntu|alpine) FAMILY=debian; break ;;
      fedora|rhel|centos|rocky|almalinux|ol|amzn) FAMILY=rhel; break ;;
      arch) FAMILY=p11kit; break ;;
    esac
  done
fi
if [ -z "$FAMILY" ]; then
  if [ -d "$ROOT/etc/pki/ca-trust/source/anchors" ] && command -v update-ca-trust >/dev/null 2>&1; then
    FAMILY=rhel
  elif [ -d "$ROOT/usr/local/share/ca-certificates" ] && command -v update-ca-certificates >/dev/null 2>&1; then
    FAMILY=debian
  elif command -v trust >/dev/null 2>&1; then
    FAMILY=p11kit
  else
    fail 'do not know the trust store of this system: no update-ca-certificates, update-ca-trust or trust (p11-kit)'
  fi
fi

case $FAMILY in
  debian)
    STORE="$ROOT/usr/local/share/ca-certificates"; EXT=crt
    command -v update-ca-certificates >/dev/null 2>&1 \
      || fail 'update-ca-certificates is missing: apt-get install ca-certificates (Debian, Ubuntu) or apk add ca-certificates (Alpine)' ;;
  rhel)
    STORE="$ROOT/etc/pki/ca-trust/source/anchors"; EXT=pem
    command -v update-ca-trust >/dev/null 2>&1 || fail 'update-ca-trust is missing: dnf install ca-certificates' ;;
  p11kit)
    STORE=''; EXT=''
    command -v trust >/dev/null 2>&1 || fail 'trust (p11-kit) is missing' ;;
esac

if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  fail "run it as root: sudo sh $ME $ACTION ..."
fi

update_store() {
  case $FAMILY in
    debian) update-ca-certificates || fail 'update-ca-certificates failed' ;;
    rhel)   update-ca-trust extract || fail 'update-ca-trust extract failed' ;;
  esac
}

store_file() {
  printf '%s/sick-root-%s.%s' "$STORE" "$(printf '%s' "$1" | cut -c 1-16)" "$EXT"
}

if [ "$ACTION" = install ]; then
  check_fingerprints
  [ -z "$STORE" ] || mkdir -p "$STORE" || fail "cannot create $STORE"
  i=1
  while [ "$i" -le "$ROOTS" ]; do
    if [ "$FAMILY" = p11kit ]; then
      trust anchor --remove "$TMP/root_$i.pem" >/dev/null 2>&1
      trust anchor --store "$TMP/root_$i.pem" || fail "trust anchor --store failed for root certificate $i"
      say "installed: root certificate $i as a p11-kit anchor"
    else
      file=$(store_file "$(sha256_of "root_$i")")
      cp "$TMP/root_$i.pem" "$file.sick-new" && chmod 644 "$file.sick-new" && mv -f "$file.sick-new" "$file" \
        || fail "cannot write $file"
      say "installed: $file"
    fi
    i=$((i + 1))
  done
  update_store
  say "Done: the system store trusts the root certificates of $NAME."
SH
  say 'Nothing was restarted. Still to do:'
  say '- restart what reads the store only when it starts: long-running services,'
  say '  anything started before, and Java from the Debian packages, whose cacerts'
  say '  follows this store (ca-certificates-java);'
  say '- Firefox and Chrome on Linux keep a store of their own: trust-nss.sh;'
  say '- Temurin and other JDKs keep their own cacerts (keytool), and Python with'
  say '  certifi, Node without --use-system-ca and container images do not read this'
  say '  store either: see the page.'
  exit 0
fi

removed=0
i=1
while [ "$i" -le "$ROOTS" ]; do
  if [ "$FAMILY" = p11kit ]; then
    # trust anchor --remove exits 0 also when nothing matched: whether the
    # anchor was there shows in the list of anchors before and after.
    before=$(trust list --filter=ca-anchors) || fail 'trust list --filter=ca-anchors failed'
    trust anchor --remove "$TMP/root_$i.pem" >/dev/null 2>&1
    after=$(trust list --filter=ca-anchors) || fail 'trust list --filter=ca-anchors failed'
    if [ "$before" != "$after" ]; then
      say "removed: root certificate $i, a p11-kit anchor"
      removed=1
    else
      say "not installed: root certificate $i as a p11-kit anchor"
    fi
  else
    file=$(store_file "$(sha256_of "root_$i")")
    if [ -e "$file" ]; then
      rm -f "$file" || fail "cannot remove $file"
      say "removed: $file"
      removed=1
    else
      say "not installed: $file"
    fi
  fi
  i=$((i + 1))
done
if [ "$removed" -eq 1 ]; then
  update_store
  say "Done: the system store no longer trusts the root certificates of $NAME."
  say 'Nothing was restarted: what read the store before goes on trusting them until it restarts.'
fi
exit 0
SH
}

sub _macos {
  my ( $self ) = @_;
  my $head = $self->_sh(
    file    => 'trust-macos.sh',
    purpose => 'install or remove the certificates of a CA in the System keychain of macOS',
    usage   => [
      'sudo sh trust-macos.sh install --fingerprint <sha256> [--fingerprint <sha256> ...]',
      'sudo sh trust-macos.sh remove'
    ],
    test          => 1,
    intermediates => 1,
  );
  my $chain = @{ $self->intermediates } ? <<'SH' : q{};
  i=1
  while [ "$i" -le "$INTERMEDIATES" ]; do
    if in_keychain "intermediate_$i"; then
      say "already there: intermediate certificate $i"
    else
      security add-certificates -k "$KEYCHAIN" "$TMP/intermediate_$i.pem" \
        || fail "security add-certificates failed for intermediate certificate $i"
      say "installed: intermediate certificate $i, without a trust setting"
    fi
    i=$((i + 1))
  done
SH
  return $head.<<'SH'.$chain.<<'SH';

KEYCHAIN="$ROOT/Library/Keychains/System.keychain"
if [ -z "$ROOT" ]; then
  [ "$(uname -s)" = Darwin ] || fail 'this script is for macOS'
  [ "$(id -u)" -eq 0 ] || fail "run it as root: sudo sh $ME $ACTION ..."
fi
command -v security >/dev/null 2>&1 || fail 'the program security is missing'

in_keychain() {
  security find-certificate -a -Z "$KEYCHAIN" 2>/dev/null | grep -qi "SHA-1 hash: *$(sha1_of "$1")\$"
}

if [ "$ACTION" = install ]; then
  check_fingerprints
  i=1
  while [ "$i" -le "$ROOTS" ]; do
    security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$TMP/root_$i.pem" \
      || fail "security add-trusted-cert failed for root certificate $i"
    say "installed: root certificate $i, trusted as a root"
    i=$((i + 1))
  done
SH
  say "Done: macOS trusts the root certificates of $NAME."
  say 'Nothing was restarted: restart browsers and long-running programs to be sure'
  say 'they see it. Firefox uses these roots since version 120, unless that is turned off.'
  exit 0
fi

removed=0
for kind in root intermediate; do
  count=$ROOTS
  [ "$kind" = root ] || count=$INTERMEDIATES
  i=1
  while [ "$i" -le "$count" ]; do
    if [ "$kind" = root ] && security remove-trusted-cert -d "$TMP/root_$i.pem" >/dev/null 2>&1; then
      say "removed: the trust setting of root certificate $i"
      removed=1
    fi
    if in_keychain "${kind}_$i"; then
      security delete-certificate -Z "$(sha1_of "${kind}_$i" | tr 'abcdef' 'ABCDEF')" "$KEYCHAIN" >/dev/null \
        || fail "security delete-certificate failed for $kind certificate $i"
      say "removed: $kind certificate $i"
      removed=1
    else
      say "not installed: $kind certificate $i"
    fi
    i=$((i + 1))
  done
done
if [ "$removed" -eq 1 ]; then
  say "Done: the certificates of $NAME are gone from the System keychain."
  say 'Nothing was restarted: restart browsers and long-running programs.'
fi
exit 0
SH
}

sub _nss {
  my ( $self ) = @_;
  my $head = $self->_sh(
    file    => 'trust-nss.sh',
    purpose => 'install or remove the certificates of a CA in an NSS database (Firefox, Chrome on Linux)',
    usage   => [
      'sh trust-nss.sh install --fingerprint <sha256> [--fingerprint <sha256> ...] <directory>',
      'sh trust-nss.sh remove <directory>',
      '',
      '<directory> is a Firefox profile (about:profiles) or an NSS database,',
      'such as $HOME/.pki/nssdb for Chrome on Linux.'
    ],
    what          => 1,
    intermediates => 1,
  );
  return $head.<<'SH';

[ -n "$DIR" ] || misuse 'name the Firefox profile or the NSS database'
command -v certutil >/dev/null 2>&1 \
  || fail 'certutil is missing: apt-get install libnss3-tools (Debian, Ubuntu), dnf install nss-tools (Fedora), pacman -S nss (Arch)'
[ -f "$DIR/cert9.db" ] \
  || fail "no NSS database (cert9.db) in '$DIR'. Firefox: the profile directory from about:profiles. Chrome on Linux: \$HOME/.pki/nssdb, made with: mkdir -p \$HOME/.pki/nssdb && certutil -N -d sql:\$HOME/.pki/nssdb --empty-password"
DB="sql:$DIR"

nickname() {
  printf 'sick %s %s' "$1" "$(sha256_of "$2" | cut -c 1-16)"
}

if [ "$ACTION" = install ]; then
  check_fingerprints
  for kind in root intermediate; do
    count=$ROOTS
    flags='C,,'
    if [ "$kind" = intermediate ]; then
      count=$INTERMEDIATES
      flags=',,'
    fi
    i=1
    while [ "$i" -le "$count" ]; do
      nick=$(nickname "$kind" "${kind}_$i")
      if certutil -L -d "$DB" -n "$nick" >/dev/null 2>&1; then
        certutil -M -d "$DB" -n "$nick" -t "$flags" || fail "certutil -M failed for '$nick'"
      else
        certutil -A -d "$DB" -n "$nick" -t "$flags" -i "$TMP/${kind}_$i.pem" || fail "certutil -A failed for '$nick'"
      fi
      say "installed: '$nick', trust flags '$flags'"
      i=$((i + 1))
    done
  done
  say "Done: the database in $DIR trusts the root certificates of $NAME."
  say 'Nothing was restarted: restart Firefox or Chrome to be sure they see it.'
  exit 0
fi

removed=0
for kind in root intermediate; do
  count=$ROOTS
  [ "$kind" = root ] || count=$INTERMEDIATES
  i=1
  while [ "$i" -le "$count" ]; do
    nick=$(nickname "$kind" "${kind}_$i")
    if certutil -L -d "$DB" -n "$nick" >/dev/null 2>&1; then
      certutil -D -d "$DB" -n "$nick" || fail "certutil -D failed for '$nick'"
      say "removed: '$nick'"
      removed=1
    else
      say "not installed: '$nick'"
    fi
    i=$((i + 1))
  done
done
[ "$removed" -eq 0 ] || say 'Done. Nothing was restarted: restart Firefox or Chrome.'
exit 0
SH
}

sub _windows {
  my ( $self ) = @_;
  ( my $name = $self->name ) =~ s/[\x00-\x1f\x7f]+/ /g;
  my $name64 = encode_base64( $name, q{} );
  my $list = sub { join q{}, map { "  '".encode_base64( $_->{der}, q{} )."'\n" } @_ };
  my $roots = $list->( @{ $self->roots } );
  my $inter = $list->( @{ $self->intermediates } );
  my $about_chain = @{ $self->intermediates }
    ? "# Roots go to Cert:\\LocalMachine\\Root, intermediates to Cert:\\LocalMachine\\CA\n"
     ."# (Intermediate Certification Authorities), where they are trusted for nothing.\n"
    : "# The roots go to Cert:\\LocalMachine\\Root.\n";

  return <<'PS1'.$about_chain.<<"PS1".<<'PS1';
# trust-windows.ps1 - install or remove the certificates of a CA in the
# certificate stores of the local machine of Windows. Written by sick trust.
#
# Usage, in a PowerShell that runs as administrator:
#   powershell -ExecutionPolicy Bypass -File trust-windows.ps1 install --fingerprint <sha256> [--fingerprint <sha256> ...]
#   powershell -ExecutionPolicy Bypass -File trust-windows.ps1 remove
#
# install refuses unless it is given the SHA-256 fingerprint of every root
# certificate in this script, one --fingerprint for each, as you got it from
# the person who runs the CA - not from the page this script came from, which
# is not authenticated. Colons, blanks and case do not matter. remove takes
# out exactly what install put in, by thumbprint, and needs no fingerprint.
# Nothing is restarted; the script says what still needs a restart.
#
PS1
#
# Exit codes: 0 done, 1 refused or failed, 2 wrong command line.

\$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

\$Me   = 'trust-windows.ps1'
\$Name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$name64'))

\$Roots = \@(
$roots)

\$Intermediates = \@(
$inter)
PS1

$Usage = @'
Usage, in a PowerShell that runs as administrator:
  powershell -ExecutionPolicy Bypass -File trust-windows.ps1 install --fingerprint <sha256> [--fingerprint <sha256> ...]
  powershell -ExecutionPolicy Bypass -File trust-windows.ps1 remove
'@

function Stop-Misuse([string]$Message) {
  [Console]::Error.WriteLine($Me + ': ' + $Message)
  [Console]::Error.WriteLine($Usage)
  exit 2
}

function Stop-Refused([string]$Message) {
  [Console]::Error.WriteLine($Me + ': ' + $Message)
  exit 1
}

function ConvertTo-Colons([string]$Hex) {
  return (($Hex.ToUpperInvariant() -split '(..)' | Where-Object { $_ }) -join ':')
}

$Given = New-Object 'System.Collections.Generic.List[string]'

function Add-Fingerprint([string]$Text) {
  foreach ($part in ($Text -split ',')) {
    $plain = ($part -replace '[:\s]', '').ToLowerInvariant()
    if ($plain -eq '') { continue }
    if ($plain -notmatch '^[0-9a-f]{64}$') {
      Stop-Refused ("refused: '" + $part + "' is not a SHA-256 fingerprint (64 hex digits)")
    }
    $Given.Add($plain)
  }
}

$Action = $null
$i = 0
while ($i -lt $args.Count) {
  $arg = [string]$args[$i]
  if ($arg -eq '--fingerprint' -or $arg -eq '-fingerprint') {
    if ($i + 1 -ge $args.Count) { Stop-Misuse '--fingerprint needs a value' }
    Add-Fingerprint ([string]$args[$i + 1])
    $i += 2
    continue
  }
  if ($arg -like '--fingerprint=*') {
    Add-Fingerprint $arg.Substring(14)
    $i += 1
    continue
  }
  if ($arg -eq '-h' -or $arg -eq '--help') {
    Write-Output $Usage
    exit 0
  }
  if ($null -eq $Action -and ($arg -eq 'install' -or $arg -eq 'remove')) {
    $Action = $arg
    $i += 1
    continue
  }
  Stop-Misuse ("unexpected argument '" + $arg + "'")
}
if ($null -eq $Action) { Stop-Misuse 'install or remove?' }
if ($Action -eq 'remove' -and $Given.Count -gt 0) { Stop-Misuse 'remove takes no --fingerprint' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Stop-Refused 'run this in a PowerShell that runs as administrator'
}

$Temp = Join-Path ([IO.Path]::GetTempPath()) ('sick-trust-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
  $certs = @()
  foreach ($kind in @('root', 'intermediate')) {
    $list  = $Roots
    $store = 'Cert:\LocalMachine\Root'
    if ($kind -eq 'intermediate') {
      $list  = $Intermediates
      $store = 'Cert:\LocalMachine\CA'
    }
    $n = 0
    foreach ($base64 in $list) {
      $n += 1
      $file = Join-Path $Temp ($kind + '_' + $n + '.cer')
      [IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($base64))
      $x509 = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $file
      $certs += New-Object PSObject -Property @{
        Kind       = $kind
        Number     = $n
        File       = $file
        Store      = $store
        Subject    = $x509.Subject
        Sha256     = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        Thumbprint = $x509.Thumbprint.ToUpperInvariant()
      }
    }
  }

  if ($Action -eq 'install') {
    $roots = @($certs | Where-Object { $_.Kind -eq 'root' })
    $bad = $false
    Write-Output 'Root certificates in this script, SHA-256:'
    foreach ($cert in $roots) {
      $mark = 'matches'
      if (-not $Given.Contains($cert.Sha256)) {
        $mark = 'NOT GIVEN'
        $bad = $true
      }
      Write-Output ('  ' + (ConvertTo-Colons $cert.Sha256) + '  ' + $mark)
      Write-Output ('    ' + $cert.Subject)
    }
    $known = @($roots | ForEach-Object { $_.Sha256 })
    foreach ($fingerprint in $Given) {
      if ($known -notcontains $fingerprint) {
        Write-Output ('  given, but no certificate here has it: ' + (ConvertTo-Colons $fingerprint))
        $bad = $true
      }
    }
    if ($Given.Count -eq 0) {
      Stop-Refused ('refused: install needs the SHA-256 fingerprint of each root certificate, as --fingerprint, from the person who runs ' + $Name + ' - not from the page this script came from, and not from the lines above.')
    }
    if ($bad) {
      Stop-Refused ('refused: the fingerprints given are not those of the root certificates in this script. Nothing was installed. Ask the person who runs ' + $Name + ' again.')
    }

    foreach ($cert in $certs) {
      $path = $cert.Store + '\' + $cert.Thumbprint
      if (Test-Path -Path $path) {
        Write-Output ('already there: ' + $path + '  ' + $cert.Subject)
        continue
      }
      Import-Certificate -FilePath $cert.File -CertStoreLocation $cert.Store | Out-Null
      Write-Output ('installed: ' + $path + '  ' + $cert.Subject)
    }
    Write-Output ('Done: Windows trusts the root certificates of ' + $Name + '.')
    Write-Output 'Nothing was restarted. Edge and Chrome use the Windows store; restart them, Firefox'
    Write-Output '(which uses these roots since version 120 unless that is turned off) and long-running'
    Write-Output 'services to be sure they see it. Java, Python with certifi and Node without'
    Write-Output '--use-system-ca keep stores of their own: see the page.'
    exit 0
  }

  $removed = $false
  foreach ($cert in $certs) {
    $path = $cert.Store + '\' + $cert.Thumbprint
    if (Test-Path -Path $path) {
      Remove-Item -Path $path
      Write-Output ('removed: ' + $path + '  ' + $cert.Subject)
      $removed = $true
    }
    else {
      Write-Output ('not installed: ' + $path + '  ' + $cert.Subject)
    }
  }
  if ($removed) {
    Write-Output ('Done: Windows no longer trusts the root certificates of ' + $Name + '.')
    Write-Output 'Nothing was restarted: restart browsers and long-running services.'
  }
  exit 0
}
finally {
  Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
PS1
}

1;
