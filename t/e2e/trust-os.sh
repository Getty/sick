#!/bin/bash
#
# Does the REAL install script of "sick trust" do what it says on each operating system? (k37, P4c)
#
# The scripts are written by `sick trust` (lib/SICK/Trust/Scripts.pm) against a throwaway CA and
# then run as they are, as root, in a container per distribution, without SICK_TRUST_ROOT. This
# script asks what the clients on that system think afterwards.
#
# The PKI is made with openssl at run time into a private directory: root R, an intermediate I
# name-constrained to DNS:example.internal, and leaves (see trust-runtimes.sh, same layout):
#
#   4431 good: service.example.internal by I, chain sent       4432 wrong name (wrong.example.internal)
#   4433 outside.example.org by I: out of the constraint       4434 service.example.internal, unrelated CA
#   4435 outside.example.org by an unconstrained I2: control   4436 good leaf, chain NOT sent (a switch)
#
# Containers (each one `docker run --rm`, named sick-e2e-trust-os-<distro>): debian, ubuntu, fedora,
# rocky, arch, alpine. Per container, with clients curl, openssl s_client and gnutls-cli:
#
#   S   the four scripts pass `sh -n` (the shell of that distro: dash, bash, busybox ash)
#   0   controls: the servers and the PKI do what they are meant to; the store holds none of our certificates
#   1   refused before the install
#   2   install with a wrong fingerprint, with none, and with the right one plus a wrong one: exit 1,
#       nothing written (the store files are byte-identical), still refused
#   3   install with the right fingerprint: exit 0, the clients accept the service that sends its chain
#   4   wrong name, out of the constraint and unrelated CA refused; 4k the unconstrained control accepted
#   5   the intermediate is NOT an anchor: not in the anchor directory or p11-kit, not in the generated bundle,
#       and a service that sends its leaf alone (4436) is refused
#   6   remove: exit 0, the files and the bundle entry are gone, refused again
#   7   remove again: exit 0, "not installed", nothing changes
#   N   (where certutil exists; the client checks where tstclnt exists too: not Alpine, not Arch) trust-nss.sh into a fresh NSS database: wrong fingerprint
#       refused and nothing written; roots C,,, intermediate ,,; the same positives and negatives with
#       tstclnt; remove; remove again
#
# Also, on the host: `sh -n` of the Windows PowerShell script is replaced by the PowerShell parser in
# mcr.microsoft.com/powershell (--rm) when the image can be pulled. The BEHAVIOUR of trust-macos.sh and
# trust-windows.ps1 is not tried.
#
# A line is CONTROL (must hold, else exit 1), PASS/FAIL (a claim; FAIL is a finding, the run goes on) or
# RECORD (no verdict). Exit 0 when the harness worked, 1 when it did not.
#
# Everything created carries --label sick=1 and --label sick-e2e=trust-os, is run with --rm and removed
# by those labels at the end, also after a failure. Nothing is pruned; pulled images stay as a cache.
# No volume, no network is created. Keys and certificates live in the private temporary directory (0700)
# and are mounted read-only.
#
#   SICK_E2E_OS_ONLY   comma list of: debian ubuntu fedora rocky arch alpine pwsh   (all of them)
#   SICK_E2E_OS_<DISTRO>  image (DEBIAN debian:trixie, UBUNTU ubuntu:latest, FEDORA fedora:latest,
#                         ROCKY rockylinux:9, ARCH archlinux:latest, ALPINE alpine:3, PWSH mcr.microsoft.com/powershell)

set -uo pipefail

LABEL=sick-e2e=trust-os
HOST_GOOD=service.example.internal
HOST_OUT=outside.example.org
DISTROS="debian ubuntu fedora rocky arch alpine"
declare -A IMG=(
  [debian]=${SICK_E2E_OS_DEBIAN:-debian:trixie}
  [ubuntu]=${SICK_E2E_OS_UBUNTU:-ubuntu:latest}
  [fedora]=${SICK_E2E_OS_FEDORA:-fedora:latest}
  [rocky]=${SICK_E2E_OS_ROCKY:-rockylinux:9}
  [arch]=${SICK_E2E_OS_ARCH:-archlinux:latest}
  [alpine]=${SICK_E2E_OS_ALPINE:-alpine:3}
  [pwsh]=${SICK_E2E_OS_PWSH:-mcr.microsoft.com/powershell}
)
ONLY=${SICK_E2E_OS_ONLY:-debian,ubuntu,fedora,rocky,arch,alpine,pwsh}
want() { [[ ",$ONLY," == *",$1,"* ]]; }

#### inside the container #####################################################

inside() {
  local distro=$1 fam
  local -A SF=()          # step -> number of failures
  local -A SN=()          # step -> number of assertions
  local npass=0 nfail=0 nrecord=0
  local OUT='' RC=0 OBSV='' WHY=''

  say()  { printf '%s\n' "$*"; }
  note() { printf -- '--- %s\n' "$*"; }
  die()  { printf 'ERROR %s\n' "$*" >&2; exit 1; }
  case $distro in
    debian|ubuntu|alpine) fam=deb ;;
    fedora|rocky) fam=rhel ;;
    arch) fam=p11 ;;
    *) die "unknown distribution $distro" ;;
  esac

  #### packages
  note "installing the clients ($distro)"
  case $distro in
    debian|ubuntu)
      export DEBIAN_FRONTEND=noninteractive
      { apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl curl gnutls-bin libnss3-tools ca-certificates; } \
        >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log >&2; die apt-get; } ;;
    fedora|rocky)
      dnf -y -q install --allowerasing openssl curl gnutls-utils nss-tools ca-certificates p11-kit p11-kit-trust \
        >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log >&2; die dnf; } ;;
    arch)
      pacman -Sy --noconfirm --needed openssl curl gnutls nss ca-certificates p11-kit >/tmp/install.log 2>&1 \
        || { tail -20 /tmp/install.log >&2; die pacman; } ;;
    alpine)
      apk add --no-cache openssl curl gnutls-utils nss-tools ca-certificates >/tmp/install.log 2>&1 \
        || { tail -20 /tmp/install.log >&2; die apk; } ;;
  esac
  for p in /usr/lib64/nss/unsupported-tools /usr/lib/nss/unsupported-tools; do [ -d "$p" ] && PATH=$PATH:$p; done
  for c in openssl curl gnutls-cli; do command -v "$c" >/dev/null || die "$c is not installed"; done
  local nss=no nsscli=no
  command -v certutil >/dev/null && nss=yes
  command -v tstclnt >/dev/null && nsscli=yes
  echo "127.0.0.1 $HOST_GOOD $HOST_OUT" >>/etc/hosts
  unset SICK_TRUST_ROOT

  #### the servers (127.0.0.1 only, inside this container)
  local -A PORT=()
  cleanup() { kill $(jobs -p) 2>/dev/null; }
  trap cleanup EXIT
  serve() { # name port cert [s_server args]
    local n=$1 port=$2 cert=$3; shift 3
    openssl s_server -accept "127.0.0.1:$port" -www -no-CAfile -no-CApath -no-CAstore \
      -cert "/pki/$cert.pem" -key "/pki/$cert.key" "$@" >"/tmp/srv-$n.log" 2>&1 &
    PORT[$n]=$port
  }
  serve good  4431 good       -cert_chain /pki/inter.pem
  serve wrong 4432 wrong      -cert_chain /pki/inter.pem
  serve out   4433 outside    -cert_chain /pki/inter.pem
  serve other 4434 other-leaf
  serve free  4435 free       -cert_chain /pki/inter2.pem
  serve bare  4436 good
  local i
  for i in $(seq 50); do
    local up=0 n
    for n in good wrong out other free bare; do grep -q '^ACCEPT' "/tmp/srv-$n.log" && up=$((up+1)); done
    [ $up -eq 6 ] && break
    sleep 0.2
  done
  [ $up -eq 6 ] || die 'the servers did not start'

  #### recording
  step_ok() { [ "${SN[$1]:-0}" -gt 0 ] && [ "${SF[$1]:-0}" -eq 0 ]; }
  # t <step> <description> <command...>: PASS when the command succeeds
  t() {
    local step=$1 desc=$2; shift 2
    SN[$step]=$(( ${SN[$step]:-0} + 1 ))
    if "$@"; then say "PASS     [$distro] $step  $desc"; npass=$((npass+1))
    else say "FAIL     [$distro] $step  $desc  <== NOT AS EXPECTED"; nfail=$((nfail+1)); SF[$step]=$(( ${SF[$step]:-0} + 1 )); fi
  }
  record() { say "RECORD   [$distro] $*"; nrecord=$((nrecord+1)); }

  #### clients; the NSS database is $NSSDB when the client is nss
  local NSSDB=/tmp/nssdb
  # attempt <client> <port> [host]: sets OBSV accepted|refused and WHY
  attempt() {
    local client=$1 port=${PORT[$2]} host=${3:-$HOST_GOOD} out rc
    case $client in
      curl)
        out=$(curl -sS -o /dev/null --max-time 10 "https://$host:$port/" 2>&1); rc=$?
        case $rc in
          0)  OBSV=accepted; WHY='' ;;
          60) OBSV=refused; WHY=$(sed -n 's/^curl: ([0-9]*) //p' <<<"$out" | head -n 1) ;;
          *)  die "curl ended with $rc: $out" ;;
        esac ;;
      s_client)
        out=$(openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" </dev/null 2>&1); rc=$?
        if grep -q '^Verification: OK' <<<"$out"; then OBSV=accepted; WHY=''
        elif grep -q '^Verification error' <<<"$out"; then OBSV=refused; WHY=$(sed -n 's/^Verification error: //p' <<<"$out" | head -n 1)
        else die "openssl s_client ended with $rc: $out"; fi ;;
      gnutls)
        out=$(gnutls-cli -p "$port" "$host" --verify-hostname="$host" </dev/null 2>&1); rc=$?
        if [ $rc -eq 0 ] && grep -q 'Handshake was completed' <<<"$out"; then OBSV=accepted; WHY=''
        elif grep -q 'certificate is NOT trusted' <<<"$out"; then OBSV=refused; WHY=$(sed -n 's/^- Status: The certificate is NOT trusted\. //p' <<<"$out" | head -n 1)
        else die "gnutls-cli ended with $rc: $out"; fi ;;
      nss)
        out=$(printf 'x' | timeout 4 tstclnt -h "$host" -p "$port" -d "sql:$NSSDB" -v 2>&1); rc=$?
        if grep -q 'authentication of server cert failed' <<<"$out"; then
          OBSV=refused; WHY=$(sed -n 's/.*cert failed: \([A-Z_]*\):.*/\1/p' <<<"$out" | head -n 1)
        elif [ $rc -eq 124 ] || [ $rc -eq 0 ]; then
          grep -q 'handshake\|Read from server\|stdin read' <<<"$out" || die "tstclnt: no sign of a connection: $out"
          OBSV=accepted; WHY=''
        else die "tstclnt ended with $rc: $out"; fi ;;
    esac
  }
  # expect <step> <expected> <server> <what> [host] [clients...]: every client must give the verdict
  CLIENTS='curl s_client gnutls'
  expect() {
    local step=$1 exp=$2 server=$3 what=$4 host=${5:-$HOST_GOOD} c
    for c in ${CLIENTS}; do
      attempt "$c" "$server" "$host"
      t "$step" "$c: $what -> $OBSV, expected $exp${WHY:+  ($WHY)}" [ "$OBSV" = "$exp" ]
    done
  }

  #### the system store
  bundle() { for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do [ -f "$f" ] && { echo "$f"; return; }; done; }
  in_bundle() { # cert.pem
    local needle; needle=$(sed -n 2p "/pki/$1.pem")
    grep -qF -- "$needle" "$(bundle)"
  }
  not_in_bundle() { ! in_bundle "$1"; }
  anchor_files() { ls /usr/local/share/ca-certificates/sick-root-* /etc/pki/ca-trust/source/anchors/sick-root-* 2>/dev/null; }
  p11_ours() { trust list 2>/dev/null | grep -c 'Trust OS Root R'; }
  p11_inter() { trust list 2>/dev/null | grep -c 'Trust OS Intermediate'; }
  ours_in_store() { # root: number of our anchors
    if [ $fam = p11 ]; then p11_ours; else anchor_files | wc -l; fi
  }
  state() {
    local d dirs=()
    for d in /usr/local/share/ca-certificates /etc/pki/ca-trust /etc/ca-certificates /etc/ssl/certs /etc/pki/tls; do [ -e "$d" ] && dirs+=("$d"); done
    { find -L "${dirs[@]}" 2>/dev/null | sort; find -L "${dirs[@]}" -type f -exec sha256sum {} + 2>/dev/null | sort; } | sha256sum | cut -d' ' -f1
  }
  run_trust() { # script args...
    local s=$1; shift
    OUT=$(env -u SICK_TRUST_ROOT sh "/scripts/$s" "$@" 2>&1); RC=$?
  }
  linux() { run_trust trust-linux.sh "$@"; }
  out_has() { grep -q -- "$1" <<<"$OUT"; }

  #### S: syntax
  note 'S: syntax of the scripts in this distribution'
  local s
  for s in trust-linux.sh trust-macos.sh trust-nss.sh; do
    t S "sh -n $s" sh -n "/scripts/$s"
  done
  command -v bash >/dev/null && t S 'bash -n of all three' bash -n /scripts/trust-linux.sh /scripts/trust-macos.sh /scripts/trust-nss.sh

  #### 0: controls
  note '0: controls'
  t 0 'the store holds none of our certificates before the start' [ "$(ours_in_store)" = 0 ]
  t 0 'the bundle has no root, no intermediate' bash -c "$(declare -f in_bundle bundle); ! in_bundle root && ! in_bundle inter"
  local ctl
  ctl() { # port host expected
    local out
    out=$(openssl s_client -connect "127.0.0.1:$1" -servername "$2" -verify_hostname "$2" -verify_return_error -no-CApath -no-CAstore -CAfile /pki/root.pem </dev/null 2>&1)
    if grep -q '^Verification: OK' <<<"$out"; then [ "$3" = accepted ]; elif grep -q '^Verification error' <<<"$out"; then [ "$3" = refused ]; else return 1; fi
  }
  t 0 'good server accepted with R'             ctl 4431 "$HOST_GOOD" accepted
  t 0 'wrong name refused with R'               ctl 4432 "$HOST_GOOD" refused
  t 0 'outside the constraint refused with R'   ctl 4433 "$HOST_OUT" refused
  t 0 'unrelated CA refused with R'             ctl 4434 "$HOST_GOOD" refused
  t 0 'unconstrained control accepted with R'   ctl 4435 "$HOST_OUT" accepted
  t 0 'the leaf-alone server is refused by R alone' ctl 4436 "$HOST_GOOD" refused
  [ "${SF[0]:-0}" -eq 0 ] || die 'a control failed'

  #### 1: before
  note '1: refused before the install'
  expect 1 refused good 'before the install' "$HOST_GOOD" x

  #### 2: refusals
  note '2: install without the right fingerprint'
  local before after
  before=$(state)
  linux install --fingerprint "$FP_WRONG"
  t 2 "wrong fingerprint: exit 1 (got $RC)" [ "$RC" -eq 1 ]
  t 2 'wrong fingerprint: the message says refused' out_has refused
  linux install
  t 2 "no fingerprint: exit 1 (got $RC)" [ "$RC" -eq 1 ]
  t 2 'no fingerprint: the message says refused' out_has refused
  linux install --fingerprint "$FP" --fingerprint "$FP_WRONG"
  t 2 "right fingerprint plus a wrong one: exit 1 (got $RC)" [ "$RC" -eq 1 ]
  linux install --fingerprint "not-a-fingerprint"
  t 2 "malformed fingerprint: exit 1 (got $RC)" [ "$RC" -eq 1 ]
  after=$(state)
  t 2 'nothing written: the files of the store are the same as before' [ "$before" = "$after" ]
  t 2 'no anchor of ours' [ "$(ours_in_store)" = 0 ]
  expect 2 refused good 'after the refused installs' "$HOST_GOOD" x

  #### 3: install
  note '3: install with the right fingerprint'
  local colons
  colons=$(printf '%s' "$FP" | sed -e 's/../&:/g' -e 's/:$//' | tr 'a-f' 'A-F')
  linux install --fingerprint "$colons"
  t 3 "install (fingerprint with colons, upper case): exit 0 (got $RC)" [ "$RC" -eq 0 ]
  printf '%s\n' "$OUT" | sed 's/^/      | /'
  t 3 'exactly one anchor of ours' [ "$(ours_in_store)" = 1 ]
  t 3 'the root is in the generated bundle' in_bundle root
  expect 3 accepted good 'root installed, service sends its chain' "$HOST_GOOD" x

  #### 4: negatives
  note '4: wrong name, out of the constraint, unrelated CA'
  expect 4 refused wrong 'wrong name' "$HOST_GOOD" x
  expect 4 refused out   'leaf outside the name constraint' "$HOST_OUT" x
  expect 4 refused other 'unrelated CA' "$HOST_GOOD" x
  expect 4k accepted free 'control: same name through the unconstrained intermediate' "$HOST_OUT" x

  #### 5: the intermediate is no anchor
  note '5: the intermediate is not an anchor'
  t 5 'the intermediate is not in the generated bundle' not_in_bundle inter
  if [ $fam = p11 ]; then
    t 5 'p11-kit does not list the intermediate' [ "$(p11_inter)" = 0 ]
  else
    t 5 'only the root file is in the anchor directory' [ "$(anchor_files | wc -l)" = 1 ]
    t 5 'no file in the anchor directory holds the intermediate' bash -c "! grep -lF -- \"\$(sed -n 2p /pki/inter.pem)\" /usr/local/share/ca-certificates/* /etc/pki/ca-trust/source/anchors/* 2>/dev/null | grep -q ."
  fi
  expect 5 refused bare 'service that sends its leaf alone (the intermediate is nowhere)' "$HOST_GOOD" x
  record "5: the script said: $(grep -i 'intermediate' <<<"$OUT" | head -n 1)"

  #### 6, 7: remove
  note '6: remove'
  linux remove
  t 6 "remove: exit 0 (got $RC)" [ "$RC" -eq 0 ]
  printf '%s\n' "$OUT" | sed 's/^/      | /'
  t 6 'no anchor of ours is left' [ "$(ours_in_store)" = 0 ]
  t 6 'the root is gone from the generated bundle' not_in_bundle root
  expect 6 refused good 'after the removal' "$HOST_GOOD" x
  note '7: remove again'
  before=$(state)
  linux remove
  t 7 "second remove: exit 0 (got $RC)" [ "$RC" -eq 0 ]
  t 7 'second remove says "not installed"' out_has 'not installed'
  printf '%s\n' "$OUT" | sed 's/^/      | /'
  after=$(state)
  t 7 'second remove changes nothing' [ "$before" = "$after" ]
  expect 7 refused good 'after the second removal' "$HOST_GOOD" x

  #### N: NSS
  if [ $nss = yes ]; then
    note 'N: trust-nss.sh into a fresh NSS database'
    rm -rf "$NSSDB"; mkdir -p "$NSSDB"
    certutil -N -d "sql:$NSSDB" --empty-password >/dev/null 2>&1 || die 'certutil -N'
    local nick_count; nick_count() { certutil -L -d "sql:$NSSDB" 2>/dev/null | grep -c '^sick '; }
    flags_of() { certutil -L -d "sql:$NSSDB" 2>/dev/null | grep "^sick $1" | awk '{print $NF}'; }
    CLIENTS=nss
    nsx() { [ $nsscli = yes ] && expect N "$@"; }
    [ $nsscli = yes ] || record 'N: no NSS client (tstclnt, vfychain) in this distribution: only the database is checked, not what a client says'
    nsx refused good 'NSS, empty database' "$HOST_GOOD" x
    run_trust trust-nss.sh install --fingerprint "$FP_WRONG" "$NSSDB"
    t N "NSS wrong fingerprint: exit 1 (got $RC)" [ "$RC" -eq 1 ]
    run_trust trust-nss.sh install "$NSSDB"
    t N "NSS no fingerprint: exit 1 (got $RC)" [ "$RC" -eq 1 ]
    t N 'NSS nothing written by the refusals' [ "$(nick_count)" = 0 ]
    run_trust trust-nss.sh install --fingerprint "$FP" "$NSSDB"
    t N "NSS install: exit 0 (got $RC)" [ "$RC" -eq 0 ]
    printf '%s\n' "$OUT" | sed 's/^/      | /'
    t N "NSS root has the flags C,, (got '$(flags_of root)')" [ "$(flags_of root)" = 'C,,' ]
    t N "NSS intermediate has the flags ,, (got '$(flags_of intermediate)')" [ "$(flags_of intermediate)" = ',,' ]
    nsx accepted good  'NSS, root C,, + intermediate ,,' "$HOST_GOOD" x
    nsx accepted bare  'NSS, service that sends its leaf alone: the intermediate helps build the chain' "$HOST_GOOD" x
    nsx refused wrong  'NSS, wrong name' "$HOST_GOOD" x
    nsx refused out    'NSS, outside the name constraint' "$HOST_OUT" x
    nsx refused other  'NSS, unrelated CA' "$HOST_GOOD" x
    nsx accepted free  'NSS, control: unconstrained intermediate' "$HOST_OUT" x
    run_trust trust-nss.sh remove "$NSSDB"
    t N "NSS remove: exit 0 (got $RC)" [ "$RC" -eq 0 ]
    printf '%s\n' "$OUT" | sed 's/^/      | /'
    t N 'NSS nothing of ours is left' [ "$(nick_count)" = 0 ]
    nsx refused good 'NSS, after the removal' "$HOST_GOOD" x
    run_trust trust-nss.sh remove "$NSSDB"
    t N "NSS second remove: exit 0 (got $RC)" [ "$RC" -eq 0 ]
    t N 'NSS second remove says "not installed"' out_has 'not installed'
    CLIENTS='curl s_client gnutls'
  else
    record 'N: certutil is not available in this distribution: the NSS script is not tried here'
  fi

  #### result
  say ''
  say "=== VERSIONS $distro"
  say "$(. /etc/os-release; echo "$PRETTY_NAME")"
  say "$(curl -V | head -n 1 | cut -c1-90)"
  say "$(openssl version)"
  say "$(gnutls-cli --version | head -n 1)"
  say "nss: $(modutil -dbdir "sql:/tmp/nssdb" -list 2>/dev/null | sed -n 's/.*library-version=\([0-9.]*\).*/\1/p' | head -n 1)"
  case $distro in
    debian|ubuntu) say "ca-certificates $(dpkg-query -W -f='${Version}' ca-certificates)" ;;
    fedora|rocky)  say "$(rpm -q ca-certificates)" ;;
    arch)          say "$(pacman -Q ca-certificates p11-kit | tr '\n' ' ')" ;;
    alpine)        say "$(apk info -v ca-certificates | head -n 1)" ;;
  esac
  say "sh is: $(readlink -f /bin/sh)"
  say '=== END VERSIONS'
  local st
  for st in S 0 1 2 3 4 4k 5 6 7 N; do
    if [ -n "${SN[$st]:-}" ]; then
      if step_ok "$st"; then say "CELL $distro $st ok (${SN[$st]})"; else say "CELL $distro $st FAIL (${SF[$st]:-0}/${SN[$st]})"; fi
    else say "CELL $distro $st -"; fi
  done
  say "SUMMARY $distro: $npass PASS, $nfail FAIL, $nrecord RECORD"
  exit 0
}

#### on the host ##############################################################

if [ "${1:-}" = --inside ]; then
  inside "$2"
  exit $?
fi

here=$(cd "$(dirname "$0")" && pwd)
self=$here/$(basename "$0")
repo=$(cd "$here/../.." && pwd)
dlabels=(--label sick=1 --label "$LABEL")
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || fail 'docker is not installed'
docker info >/dev/null 2>&1 || fail 'the Docker daemon does not answer'
command -v openssl >/dev/null || fail 'openssl is not installed'

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/sick-e2e-trust-os.XXXXXX")
chmod 700 "$work"
mkdir -p "$work/pki" "$work/scripts"

left_behind() {
  docker ps -a --format '{{.Names}}' | grep -E '^sick-e2e-trust-os-' | sed 's/^/container /'
  docker ps -aq --filter "label=$LABEL" | sed 's/^/labelled container /'
  docker volume ls -q | sort >"$work/vol.after"
  comm -13 "$work/vol.before" "$work/vol.after" | sed 's/^/volume not there at the start: /'
  docker network ls -q --filter "label=$LABEL" | sed 's/^/labelled network /'
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  docker ps -aq --filter label=sick=1 --filter "label=$LABEL" | xargs -r docker rm -f -v >/dev/null 2>&1
  local left; left=$(left_behind)
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass 'no container named sick-e2e-trust-os-* or labelled sick-e2e=trust-os is left, no new volume, no labelled network'
  fi
  printf -- '--- the pulled images stay as a cache; nothing was pruned\n'
  rm -rf "${work:?}"
  if [ "$rc" -eq 0 ]; then printf '\nDONE\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
docker volume ls -q | sort >"$work/vol.before"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[ -z "$(docker ps -a --format '{{.Names}}' | grep -E '^sick-e2e-trust-os-')" ] || fail 'a container sick-e2e-trust-os-* exists already; remove it by hand'

#### the PKI and the scripts ###################################################

make_pki() {
  cd "$work/pki" || fail cd
  local r
  ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null || fail "key $1"; }
  for r in "root:Trust OS Root R" "other:Trust OS Unrelated Root"; do
    ec "${r%%:*}.key"
    openssl req -x509 -new -key "${r%%:*}.key" -sha256 -days 2 -subj "/CN=${r#*:}" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -addext subjectKeyIdentifier=hash -out "${r%%:*}.pem" 2>/dev/null || fail "root ${r%%:*}"
  done
  inter() {
    ec "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null || fail "csr $1"
    { printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
      [ -n "$3" ] && printf '%s\n' "$3"; } >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA root.pem -CAkey root.key -CAcreateserial -days 2 -sha256 -extfile "$1.ext" -out "$1.pem" 2>/dev/null || fail "signing $1"
  }
  inter inter  'Trust OS Intermediate' 'nameConstraints=critical,permitted;DNS:example.internal'
  inter inter2 'Trust OS Intermediate (unconstrained)' ''
  leaf() {
    ec "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null || fail "csr $1"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\nauthorityKeyIdentifier=keyid\n' "$2" >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 2 -sha256 -extfile "$1.ext" -out "$1.pem" 2>/dev/null || fail "signing $1"
  }
  leaf good "$HOST_GOOD" inter
  leaf wrong wrong.example.internal inter
  leaf outside "$HOST_OUT" inter
  leaf other-leaf "$HOST_GOOD" other
  leaf free "$HOST_OUT" inter2
  cd "$here" || true
}

make_scripts() {
  command -v perl >/dev/null || fail 'perl is not installed'
  cat >"$work/sick.yml" <<EOF
ca:
  name: Trust OS Lab CA
  url: https://ca.example.internal:9000
  root: $work/pki/root.pem
  intermediates: $work/pki/inter.pem
  provisioner: sick
  password_file: $work/pw
devices:
  lab:
    type: files
    names: [lab.example.internal]
    dir: $work/lab
EOF
  ( cd "$repo" && perl -Ilib bin/sick -c "$work/sick.yml" trust "$work/scripts" >"$work/trust.log" 2>&1 ) \
    || { cat "$work/trust.log" >&2; fail 'sick trust did not write the scripts (is the Perl environment loaded?)'; }
  local f
  for f in trust-linux.sh trust-macos.sh trust-windows.ps1 trust-nss.sh; do
    [ -s "$work/scripts/$f" ] || fail "sick trust did not write $f"
  done
  FP=$(openssl x509 -in "$work/pki/root.pem" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')
  FP_WRONG=$(printf 'not the root' | openssl dgst -sha256 -r | cut -d' ' -f1)
  [ ${#FP} -eq 64 ] || fail 'no fingerprint'
  grep -q "$FP" "$work/scripts/index.html" && pass 'the fingerprint of the page is the one of the root made here'
  # the real script must not hold the intermediate if it is the Linux one
  printf 'CONTROL  trust-linux.sh carries %s certificate(s); trust-nss.sh carries %s\n' \
    "$(grep -c 'BEGIN CERTIFICATE' "$work/scripts/trust-linux.sh")" "$(grep -c 'BEGIN CERTIFICATE' "$work/scripts/trust-nss.sh")"
}

make_pki
make_scripts

#### the containers ############################################################

status=0
for d in $DISTROS; do
  want "$d" || continue
  image=${IMG[$d]}
  printf '\n######## %s (%s)\n' "$d" "$image"
  docker pull -q "$image" >/dev/null 2>&1 || printf 'RECORD  could not pull %s (using the local copy, if any)\n' "$image"
  if [ "$d" = alpine ]; then
    cmd=(sh -c 'apk add --no-cache bash >/dev/null && exec bash /trust-os.sh --inside alpine')
  else
    cmd=(bash /trust-os.sh --inside "$d")
  fi
  docker run --rm --name "sick-e2e-trust-os-$d" "${dlabels[@]}" \
    -e "FP=$FP" -e "FP_WRONG=$FP_WRONG" \
    -v "$self:/trust-os.sh:ro" -v "$work/pki:/pki:ro" -v "$work/scripts:/scripts:ro" \
    "$image" "${cmd[@]}" 2>&1 | tee "$work/$d.log"
  code=${PIPESTATUS[0]}
  if [ "$code" -ne 0 ]; then printf 'FAIL  the %s run ended with %s\n' "$d" "$code" >&2; status=1; fi
done

if want pwsh; then
  printf '\n######## powershell: syntax of trust-windows.ps1 only\n'
  if docker pull -q "${IMG[pwsh]}" >/dev/null 2>&1; then
    out=$(docker run --rm --name sick-e2e-trust-os-pwsh "${dlabels[@]}" -v "$work/scripts:/scripts:ro" "${IMG[pwsh]}" \
      pwsh -NoProfile -Command '$e=$null; $t=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("/scripts/trust-windows.ps1",[ref]$t,[ref]$e); "errors: " + $e.Count; $e | ForEach-Object { $_.Message }; $PSVersionTable.PSVersion.ToString()' 2>&1)
    echo "$out" | sed 's/^/      | /'
    if grep -qx 'errors: 0' <<<"$out"; then
      printf 'PASS     [pwsh] trust-windows.ps1 parses without errors (PowerShell %s); its behaviour is NOT tried\n' "$(tail -n 1 <<<"$out")"
      PWSH_CELL="parses (not run)"
    else
      printf 'FAIL     [pwsh] trust-windows.ps1 does not parse\n'; PWSH_CELL=FAIL
    fi
  else
    printf 'RECORD   [pwsh] image %s could not be pulled: trust-windows.ps1 not checked\n' "${IMG[pwsh]}"
    PWSH_CELL='not tried'
  fi
fi

printf '\n######## RESULT\n'
for d in $DISTROS; do
  [ -f "$work/$d.log" ] || continue
  sed -n "/^=== VERSIONS $d/,/^=== END VERSIONS/p" "$work/$d.log"
done
printf '\n%-8s' step; for d in $DISTROS; do [ -f "$work/$d.log" ] && printf ' %-9s' "$d"; done; printf '\n'
for st in S 0 1 2 3 4 4k 5 6 7 N; do
  printf '%-8s' "$st"
  for d in $DISTROS; do
    [ -f "$work/$d.log" ] || continue
    c=$(sed -n "s/^CELL $d $st \([^ ]*\).*/\1/p" "$work/$d.log")
    printf ' %-9s' "${c:--}"
  done
  printf '\n'
done
echo 'S syntax  0 controls  1 before  2 wrong/no fingerprint  3 install  4 negatives (4k control)  5 intermediate no anchor  6 remove  7 remove again  N NSS'
[ -z "${PWSH_CELL:-}" ] || echo "trust-windows.ps1: $PWSH_CELL;  trust-macos.sh: sh -n only (in S);  behaviour of both: not tried"
grep -hE '^SUMMARY' "$work"/*.log
grep -hE '^FAIL ' "$work"/*.log | sed 's/^/finding: /'
exit "$status"
