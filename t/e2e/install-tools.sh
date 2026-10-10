#!/bin/bash
#
# Installs the programs the full test suite and the local end-to-end run
# need, in pinned versions, without root: step, step-ca and acme.sh.
#
#   t/e2e/install-tools.sh [prefix]        (default: $SICK_TOOLS_PREFIX or $HOME/.local)
#
# Programs are linked into <prefix>/bin, unpacked trees live in
# <prefix>/share/<name>-<version>. Every download is checked against the
# SHA-256 recorded below BEFORE anything is unpacked; a mismatch stops the
# script and installs nothing. When the right version is already in place
# the script changes nothing and says so. Nothing is "installed" in the
# sense of the tools themselves: acme.sh is unpacked only (acme.sh,
# deploy/, LICENSE.md - like docker/Dockerfile does), never run with
# --install, so there is no cron entry and no ~/.acme.sh.
#
# Needs curl, tar, sha256sum. Make sure <prefix>/bin is in the PATH.
#
# Run on agent-lab (Linux x86_64, no sudo) on 2026-10-10 with the prefix
# $HOME/.local; the SHA-256 of the step and step-ca archives are those of
# the checksums.txt of the two releases.

set -euo pipefail

#### versions and hashes: the one place

STEP_VERSION=0.30.2
STEP_SHA256_amd64=abf5ffe9a39c01c7b4e777d50a96f30f33f5bd8eeafa2dfeef22b8a4abeee14a
STEP_SHA256_arm64=7d66fa62949d64142b053db1c86ee29037088919cd329ac7966b15b09e914230

STEP_CA_VERSION=0.30.2
STEP_CA_SHA256_amd64=126615795bafe3f2d3f890e2d628fa6e2857315fb48d0671d34b23047cc37d73
STEP_CA_SHA256_arm64=43f79d1b0b8cab9895dbadd46b0a014006f682a6b1341e1fadf0be31d4b9f4b4

# the same version and hash as ARG ACME_SH_VERSION / ACME_SH_SHA256 in docker/Dockerfile
ACME_SH_VERSION=3.1.6
ACME_SH_SHA256=0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486

####

prefix=${1:-${SICK_TOOLS_PREFIX:-$HOME/.local}}
bin=$prefix/bin
share=$prefix/share

say() { printf 'install-tools: %s\n' "$*"; }
die() { printf 'install-tools: %s\n' "$*" >&2; exit 1; }

for program in curl tar sha256sum; do
  command -v "$program" >/dev/null || die "$program is not installed"
done

case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "no pinned archive for $(uname -m)" ;;
esac
[ "$(uname -s)" = Linux ] || die 'only Linux archives are pinned'

mkdir -p "$bin" "$share"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# fetch <url> <sha256> <file>: download, verify, nothing unpacked yet
fetch() {
  local url=$1 sha=$2 file=$3
  say "downloading $url"
  curl -fsSL -o "$file" "$url" || die "cannot download $url"
  echo "$sha  $file" | sha256sum -c --status - \
    || die "SHA-256 of $url is $(sha256sum "$file" | cut -d' ' -f1), expected $sha: refusing to unpack"
}

# linked <link> <target>: is <link> a symbolic link to <target> that exists?
linked() { [ -L "$1" ] && [ "$(readlink "$1")" = "$2" ] && [ -x "$2" ]; }

# install_tool <name> <version> <sha256> <url> <member in the archive> <file in the tree>
install_tool() {
  local name=$1 version=$2 sha=$3 url=$4 member=$5 file=$6
  local tree=$share/$name-$version
  if linked "$bin/$file" "$tree/$file"; then
    say "$name $version is already in place ($bin/$file)"
    return 0
  fi
  fetch "$url" "$sha" "$work/$name.tar.gz"
  rm -rf "$tree"
  mkdir -p "$tree"
  tar -xzf "$work/$name.tar.gz" -C "$tree" --strip-components="$(awk -F/ '{print NF-1}' <<<"$member")" "$member" \
    || die "cannot unpack $member from the $name archive"
  chmod 755 "$tree/$file"
  ln -sfn "$tree/$file" "$bin/$file"
  say "installed $name $version: $bin/$file -> $tree/$file"
}

install_tool step "$STEP_VERSION" "$(eval echo "\$STEP_SHA256_$arch")" \
  "https://github.com/smallstep/cli/releases/download/v$STEP_VERSION/step_linux_${STEP_VERSION}_$arch.tar.gz" \
  "step_$STEP_VERSION/bin/step" step

install_tool step-ca "$STEP_CA_VERSION" "$(eval echo "\$STEP_CA_SHA256_$arch")" \
  "https://github.com/smallstep/certificates/releases/download/v$STEP_CA_VERSION/step-ca_linux_${STEP_CA_VERSION}_$arch.tar.gz" \
  step-ca step-ca

# acme.sh: unpacked beside its deploy/ directory, linked into bin/
acme_tree=$share/acme.sh-$ACME_SH_VERSION
if linked "$bin/acme.sh" "$acme_tree/acme.sh" && [ -r "$acme_tree/deploy/localcopy.sh" ]; then
  say "acme.sh $ACME_SH_VERSION is already in place ($bin/acme.sh)"
else
  fetch "https://github.com/acmesh-official/acme.sh/archive/refs/tags/$ACME_SH_VERSION.tar.gz" \
    "$ACME_SH_SHA256" "$work/acme.sh.tar.gz"
  rm -rf "$acme_tree"
  mkdir -p "$acme_tree"
  tar -xzf "$work/acme.sh.tar.gz" -C "$acme_tree" --strip-components=1 \
    "acme.sh-$ACME_SH_VERSION/acme.sh" \
    "acme.sh-$ACME_SH_VERSION/deploy" \
    "acme.sh-$ACME_SH_VERSION/LICENSE.md" \
    || die 'cannot unpack the acme.sh archive'
  chmod 755 "$acme_tree/acme.sh"
  ln -sfn "$acme_tree/acme.sh" "$bin/acme.sh"
  say "installed acme.sh $ACME_SH_VERSION: $bin/acme.sh -> $acme_tree/acme.sh"
fi

case ":$PATH:" in
  *":$bin:"*) ;;
  *) say "note: $bin is not in your PATH" ;;
esac
