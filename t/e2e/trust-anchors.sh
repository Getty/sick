#!/bin/bash
#
# Where may the intermediate of the CA go? Evidence for the trust page (k28).
#
# The page used to tell people to put root AND intermediate where the system
# trusts: /usr/local/share/ca-certificates (Debian), ca-trust/source/anchors
# (Fedora), "trust anchor --store" (p11-kit). The claim of k28: an intermediate
# put there is a trust anchor in its own right, stays trusted after the root is
# removed, and cannot be cut off by removing the root. This script asks real
# TLS clients, in a Debian and in a Fedora container, whether that is true and
# which placements are safe.
#
# In each container (nothing leaves it: everything talks to 127.0.0.1 there):
#
#   * a throwaway PKI made at run time: root -> intermediate (CA, pathlen 0)
#     -> leaf for device.example.internal, plus an unrelated second root with a
#     leaf for the same name
#   * three openssl s_server on ports the system picks: "leaf" (the leaf only,
#     what a switch does), "chain" (leaf and intermediate) and "other" (the
#     leaf of the unrelated root)
#   * the clients: curl (OpenSSL), openssl s_client (OpenSSL, no PARTIAL_CHAIN),
#     gnutls-cli (GnuTLS) and tstclnt (NSS, with a database of its own and, on
#     Fedora, the system store through p11-kit as well)
#
# Cases (the ids are the rows of the table):
#
#   1    root in the system store, server sends the chain         accepted
#   2    same store, leaf-only server                             refused
#   3    root and intermediate installed as the page said, leaf-only server
#   4    root removed, intermediate left where the page put it; leaf-only (4)
#        and chain-sending (4c) server. The bug claimed in k28.
#   3p/4p  the same with "trust anchor --store" (Fedora, p11-kit)
#   5a   the intermediate in no store, root removed, server sends the chain
#   5b   Fedora/p11-kit: intermediate as a certificate that is no anchor
#        (trust: unspecified) next to the root (5b) and root removed (5b2, 5b2c)
#   5c   a per-application CAfile holding root and intermediate (5c); the
#        intermediate alone, root absent (5c2, 5c2c)
#   5d   NSS database: root trusted (C,,) and intermediate with no trust flags
#        (,,) (5d); the root removed (5d2, 5d2c)
#   4x   NSS database: the intermediate trusted as a CA (C,,), root absent
#        (a control: shows what turns an intermediate into an anchor in NSS)
#   6    the leaf of the unrelated CA, in every state above
#
# A line is one of
#   CONTROL  must hold or the harness proves nothing (case 1, 2, the servers):
#            a failed control ends the run with exit 1
#   PASS/FAIL  a claim of safety: "refused", or "accepted" for a placement
#            that is meant to work. FAIL is a finding, not an error: the run
#            goes on and the summary counts them
#   RECORD   what happened, for the placements the page used
#
# Exit code: 0 when the harness worked (also with FAIL lines), 1 when it did
# not (a control failed, a program is missing, a container is left behind).
#
# Needs Docker and internet for images and packages. Containers are named
# sick-e2e-trust-<distro> and labelled sick-e2e=trust-anchors, removed at the
# end, also after a failure or Ctrl-C. Nothing else is touched, nothing is
# pruned; the pulled images stay as a cache. No key or certificate leaves a
# container; the log files in the private temporary directory hold output only.
#
# Parameters, all from the environment:
#
#   SICK_E2E_TRUST_DEBIAN  image  (debian:trixie)
#   SICK_E2E_TRUST_FEDORA  image  (fedora:latest)
#   SICK_E2E_TRUST_ONLY    "debian" or "fedora": run one container only

set -uo pipefail

NAME=device.example.internal
LABEL=sick-e2e=trust-anchors

#### inside the container ####################################################

inside() {
  local distro=$1
  local -A OBS=()        # "case|client" -> accepted | refused
  local -A SIX=()        # "client" -> "accepted-count/total"
  local -A SIXN=() SIXA=()
  local CAFILE='' NSSDB='' WHY='' OBSV=''
  local npass=0 nfail=0 nrecord=0
  local clients_sys

  say()  { printf '%s\n' "$*"; }
  note() { printf -- '--- %s\n' "$*"; }
  die()  { printf 'ERROR %s\n' "$*" >&2; exit 1; }

  case $distro in
    debian) clients_sys='curl s_client gnutls' ;;
    fedora) clients_sys='curl s_client gnutls nss-sys'
            export PATH=$PATH:/usr/lib64/nss/unsupported-tools ;;
    *) die "unknown distribution '$distro'" ;;
  esac

  #### packages
  note "installing the clients ($distro)"
  if [ "$distro" = debian ]; then
    export DEBIAN_FRONTEND=noninteractive
    { apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        openssl curl gnutls-bin libnss3-tools ca-certificates p11-kit; } >/tmp/install.log 2>&1 \
      || { tail -20 /tmp/install.log >&2; die 'apt-get'; }
  else
    dnf -y -q install openssl curl gnutls-utils nss-tools ca-certificates p11-kit p11-kit-trust \
      >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log >&2; die 'dnf'; }
  fi
  for c in openssl curl gnutls-cli certutil tstclnt trust; do
    command -v "$c" >/dev/null || die "$c is not installed"
  done
  [ "$distro" = fedora ] && { command -v update-ca-trust >/dev/null || die 'update-ca-trust'; }
  [ "$distro" = debian ] && { command -v update-ca-certificates >/dev/null || die 'update-ca-certificates'; }

  echo "127.0.0.1 $NAME" >>/etc/hosts

  #### the PKI
  local w=/tmp/pki
  mkdir -p "$w"; chmod 700 "$w"; cd "$w" || die cd
  ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
  for r in root other-root; do
    ec $r.key
    openssl req -x509 -new -key $r.key -sha256 -days 2 -subj "/CN=Trust Lab $r" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -addext subjectKeyIdentifier=hash -out $r.pem 2>/dev/null || die "making $r"
  done
  ec inter.key
  openssl req -new -key inter.key -subj '/CN=Trust Lab Intermediate' -out inter.csr 2>/dev/null
  printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >inter.ext
  openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -days 2 -sha256 \
    -extfile inter.ext -out inter.pem 2>/dev/null || die 'signing the intermediate'
  local pair leaf signer
  for pair in leaf:inter other-leaf:other-root; do
    leaf=${pair%:*}; signer=${pair#*:}
    ec $leaf.key
    openssl req -new -key $leaf.key -subj "/CN=$NAME" -out $leaf.csr 2>/dev/null
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\nauthorityKeyIdentifier=keyid\n' "$NAME" >$leaf.ext
    openssl x509 -req -in $leaf.csr -CA $signer.pem -CAkey $signer.key -CAcreateserial -days 2 -sha256 \
      -extfile $leaf.ext -out $leaf.pem 2>/dev/null || die "signing $leaf"
  done
  cat root.pem inter.pem >bundle-both.pem
  cp inter.pem bundle-inter.pem

  #### the servers
  local -A PORT=()
  cleanup() { kill $(jobs -p) 2>/dev/null; }
  trap cleanup EXIT
  serve() { # name, then s_server arguments
    local n=$1; shift
    openssl s_server -accept 127.0.0.1:0 -www -no-CAfile -no-CApath -no-CAstore "$@" >"srv-$n.log" 2>&1 &
    local i
    for i in $(seq 50); do
      PORT[$n]=$(sed -n 's/^ACCEPT .*:\([0-9][0-9]*\)$/\1/p' "srv-$n.log")
      [ -n "${PORT[$n]}" ] && return 0
      sleep 0.2
    done
    die "server $n did not start: $(cat "srv-$n.log")"
  }
  serve leaf  -cert leaf.pem -key leaf.key
  serve chain -cert leaf.pem -key leaf.key -cert_chain inter.pem
  serve other -cert other-leaf.pem -key other-leaf.key
  local sent
  sent() { openssl s_client -connect 127.0.0.1:"${PORT[$1]}" -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'; }
  [ "$(sent leaf)" = 1 ]  || die 'the leaf-only server sends more than the leaf'
  [ "$(sent chain)" = 2 ] || die 'the chain server does not send leaf and intermediate'
  [ "$(sent other)" = 1 ] || die 'the unrelated server sends more than its leaf'
  say 'CONTROL  servers: "leaf" sends 1 certificate, "chain" sends 2, "other" sends 1 (127.0.0.1, ports picked by the system)'

  #### clients
  # attempt <client> <server>: sets OBSV (accepted|refused) and WHY, dies on anything else
  attempt() {
    local client=$1 port=${PORT[$2]} out rc args=()
    case $client in
      curl)
        [ -n "$CAFILE" ] && args=(--cacert "$CAFILE")
        out=$(curl -sS -o /dev/null --max-time 10 "${args[@]}" "https://$NAME:$port/" 2>&1); rc=$?
        case $rc in
          0)  OBSV=accepted; WHY='' ;;
          60) OBSV=refused;  WHY=$(sed -n 's/^curl: (60) //p' <<<"$out" | head -n 1) ;;
          *)  die "curl ended with $rc: $out" ;;
        esac ;;
      s_client)
        if [ -n "$CAFILE" ]; then args=(-no-CApath -no-CAstore -CAfile "$CAFILE"); fi
        out=$(openssl s_client -connect "$NAME:$port" -servername "$NAME" -verify_return_error \
          -verify_hostname "$NAME" "${args[@]}" </dev/null 2>&1); rc=$?
        if grep -q '^Verification: OK' <<<"$out"; then OBSV=accepted; WHY=''
        elif grep -q '^Verification error' <<<"$out"; then
          OBSV=refused; WHY=$(sed -n 's/^Verification error: //p' <<<"$out" | head -n 1)
        else die "openssl s_client ended with $rc: $out"; fi ;;
      gnutls)
        [ -n "$CAFILE" ] && args=(--x509cafile "$CAFILE")
        out=$(gnutls-cli -p "$port" "$NAME" --verify-hostname="$NAME" "${args[@]}" </dev/null 2>&1); rc=$?
        if [ $rc -eq 0 ] && grep -q 'Handshake was completed' <<<"$out"; then OBSV=accepted; WHY=''
        elif grep -q 'certificate is NOT trusted' <<<"$out"; then
          OBSV=refused; WHY=$(sed -n 's/^- Status: The certificate is NOT trusted\. //p' <<<"$out" | head -n 1)
        else die "gnutls-cli ended with $rc: $out"; fi ;;
      nss-sys|nss-db)
        # nss-sys: an empty database and the system store through p11-kit-trust, the way
        # NSS programs on Fedora get it (libnssckbi.so is an alternative for this module);
        # nss-db: the database alone, no module with roots
        local db=$NSSDB roots=()
        if [ "$client" = nss-sys ]; then db=/tmp/nss-empty; roots=(-R /usr/lib64/pkcs11/p11-kit-trust.so); fi
        # tstclnt stays connected after a good handshake: the timeout is the end of an accepted one
        out=$(printf 'x' | timeout 4 tstclnt -h "$NAME" -p "$port" -d "sql:$db" "${roots[@]}" -v 2>&1); rc=$?
        if grep -q 'authentication of server cert failed' <<<"$out"; then
          OBSV=refused; WHY=$(sed -n 's/.*cert failed: \([A-Z_]*\):.*/\1/p' <<<"$out" | head -n 1)
        elif [ $rc -eq 124 ] || [ $rc -eq 0 ]; then
          grep -q 'handshake\|Read from server\|stdin read' <<<"$out" || die "tstclnt: no sign of a connection: $out"
          OBSV=accepted; WHY=''
        else die "tstclnt ended with $rc: $out"; fi ;;
      *) die "unknown client $client" ;;
    esac
  }

  # report <class> <case> <client> <server> <expected> <what>
  report() {
    local class=$1 cid=$2 client=$3 server=$4 expected=$5 what=$6
    attempt "$client" "$server"
    OBS[$cid|$client]=$OBSV
    local line mark=''
    [ "$OBSV" = "$expected" ] || mark='  <== NOT AS EXPECTED'
    line=$(printf '[%s] %-4s %-9s %-5s expected %-8s observed %-8s %s%s%s' \
      "$distro" "$cid" "$client" "$server" "$expected" "$OBSV" "$what" "${WHY:+  ($WHY)}" "$mark")
    case $class in
      CONTROL) if [ "$OBSV" = "$expected" ]; then say "CONTROL  $line"; else say "CONTROL-FAIL  $line" >&2; die "a control failed: $cid $client"; fi ;;
      EXPECT)  if [ "$OBSV" = "$expected" ]; then say "PASS     $line"; npass=$((npass+1)); else say "FAIL     $line"; nfail=$((nfail+1)); fi ;;
      RECORD)  say "RECORD   $line"; nrecord=$((nrecord+1)) ;;
    esac
  }

  # unrelated <clients...>: case 6 in the current state
  unrelated() {
    local client
    for client in "$@"; do
      attempt "$client" other
      SIXN[$client]=$(( ${SIXN[$client]:-0} + 1 ))
      if [ "$OBSV" = refused ]; then
        printf 'PASS     [%s] 6    %-9s other expected refused  observed refused  (state: %s)%s\n' \
          "$distro" "$client" "$STATE" "${WHY:+  ($WHY)}"
        npass=$((npass+1))
      else
        SIXA[$client]=$(( ${SIXA[$client]:-0} + 1 ))
        printf 'FAIL     [%s] 6    %-9s other expected refused  observed accepted  (state: %s)  <== NOT AS EXPECTED\n' \
          "$distro" "$client" "$STATE"
        nfail=$((nfail+1))
      fi
    done
  }

  #### the stores
  local ROOTF INTF
  if [ "$distro" = debian ]; then
    ROOTF=/usr/local/share/ca-certificates/internal-root-ca.crt
    INTF=/usr/local/share/ca-certificates/internal-intermediate-ca.crt
    sys_update() { update-ca-certificates --fresh >/tmp/update.log 2>&1 || { cat /tmp/update.log >&2; die 'update-ca-certificates'; }; }
  else
    ROOTF=/etc/pki/ca-trust/source/anchors/internal-root-ca.pem
    INTF=/etc/pki/ca-trust/source/anchors/internal-intermediate-ca.pem
    sys_update() { update-ca-trust >/tmp/update.log 2>&1 || { cat /tmp/update.log >&2; die 'update-ca-trust'; }; }
  fi
  sys_clear() {
    rm -f "$ROOTF" "$INTF"
    [ "$distro" = fedora ] && rm -f /etc/pki/ca-trust/source/*.p11-kit
    sys_update
  }
  sys_put()    { cp "$1.pem" "$2"; sys_update; }
  sys_remove() { rm -f "$1"; sys_update; }
  store_has_ours() {
    if [ "$distro" = debian ]; then
      openssl storeutl -certs -text -noout /etc/ssl/certs/ca-certificates.crt 2>/dev/null | grep -q 'Subject: CN *= *Trust Lab'
    else
      trust list --filter=certificates | grep -q 'Trust Lab'
    fi
  }

  nss_new() {
    NSSDB=/tmp/nssdb; rm -rf "$NSSDB"; mkdir -p "$NSSDB"
    certutil -N -d "sql:$NSSDB" --empty-password >/dev/null 2>&1 || die 'certutil -N'
  }
  nss_add() { certutil -A -d "sql:$NSSDB" -n "$1" -t "$3" -i "$2.pem" >/dev/null 2>&1 || die "certutil -A $1"; }
  mkdir -p /tmp/nss-empty
  certutil -N -d sql:/tmp/nss-empty --empty-password >/dev/null 2>&1 || die 'certutil -N'

  sys_clear
  if store_has_ours; then die 'the store holds our CA before the start'; fi
  local c

  ####################################################################
  note 'case 1, 2: root in the system store'
  STATE='root only'
  sys_put root "$ROOTF"
  for c in $clients_sys; do report CONTROL 1 "$c" chain accepted 'root anchored, server sends the chain'; done
  for c in $clients_sys; do report CONTROL 2 "$c" leaf  refused  'root anchored, leaf-only server: the intermediate is missing'; done
  unrelated $clients_sys

  note 'case 5a: root removed, intermediate nowhere'
  STATE='nothing installed'
  sys_clear
  for c in $clients_sys; do report EXPECT 5a "$c" chain refused 'intermediate in no store, root removed, server sends the chain'; done
  unrelated $clients_sys

  note 'case 3: root and intermediate installed the way the page said'
  STATE='root + intermediate in the system anchors'
  sys_put root "$ROOTF"; sys_put inter "$INTF"
  for c in $clients_sys; do report RECORD 3 "$c" leaf accepted 'root and intermediate as anchors, leaf-only server'; done
  unrelated $clients_sys

  note 'case 4: the root removed, the intermediate left where the page put it'
  STATE='intermediate alone in the system anchors'
  sys_remove "$ROOTF"
  for c in $clients_sys; do report RECORD 4  "$c" leaf  refused 'root removed, intermediate left as anchor, leaf-only server'; done
  for c in $clients_sys; do report RECORD 4c "$c" chain refused 'root removed, intermediate left as anchor, server sends the chain'; done
  unrelated $clients_sys

  if [ "$distro" = fedora ]; then
    note 'case 3p, 4p: the same with trust anchor --store (p11-kit)'
    STATE='trust anchor --store root + intermediate'
    sys_clear
    trust anchor --store root.pem || die 'trust anchor --store root'
    trust anchor --store inter.pem || die 'trust anchor --store intermediate'
    sys_update
    for c in $clients_sys; do report RECORD 3p "$c" leaf accepted 'trust anchor --store root and intermediate, leaf-only server'; done
    unrelated $clients_sys
    STATE='trust anchor --store intermediate alone'
    trust anchor --remove root.pem || die 'trust anchor --remove root'
    sys_update
    if trust list | grep -q 'Trust Lab root'; then die 'trust anchor --remove did not remove the root'; fi
    for c in $clients_sys; do report RECORD 4p  "$c" leaf  refused 'root removed with trust anchor --remove, intermediate left, leaf-only server'; done
    for c in $clients_sys; do report RECORD 4pc "$c" chain refused 'same, server sends the chain'; done
    unrelated $clients_sys

    note 'case 5b: the intermediate as a certificate that is no anchor (p11-kit)'
    STATE='root anchor + intermediate non-anchor'
    sys_clear
    sys_put root "$ROOTF"
    { echo '[p11-kit-object-v1]'; echo 'label: "Trust Lab Intermediate"'; echo 'trusted: false'; cat inter.pem; } \
      >/etc/pki/ca-trust/source/internal-intermediate-ca.p11-kit
    sys_update
    local listing
    listing=$(trust list --filter=certificates | grep -A3 'label: Trust Lab Intermediate')
    say "      | $(tr '\n' ' ' <<<"$listing" | tr -s ' ')"
    grep -q 'trust: unspecified' <<<"$listing" || die 'the intermediate is not a non-anchor certificate in p11-kit'
    say "      | in the extracted tls-ca-bundle.pem: $(grep -c 'BEGIN CERTIFICATE' /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem) certificates, ours among them: $(openssl storeutl -certs -noout -text /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem 2>/dev/null | grep -c 'Subject: CN=Trust Lab')"
    for c in $clients_sys; do report RECORD 5b "$c" leaf accepted 'root anchor + non-anchor intermediate, leaf-only server'; done
    unrelated $clients_sys
    STATE='non-anchor intermediate alone'
    sys_remove "$ROOTF"
    for c in $clients_sys; do report EXPECT 5b2  "$c" leaf  refused 'root removed, non-anchor intermediate left, leaf-only server'; done
    for c in $clients_sys; do report EXPECT 5b2c "$c" chain refused 'root removed, non-anchor intermediate left, server sends the chain'; done
    unrelated $clients_sys
  fi

  note 'case 5c: a per-application CAfile'
  sys_clear
  STATE='CAfile root + intermediate'
  CAFILE=$w/bundle-both.pem
  for c in curl s_client gnutls; do report EXPECT 5c "$c" leaf accepted 'CAfile root + intermediate (ca_bundle.pem), leaf-only server'; done
  unrelated curl s_client gnutls
  STATE='CAfile intermediate only'
  CAFILE=$w/bundle-inter.pem
  for c in curl s_client gnutls; do report EXPECT 5c2  "$c" leaf  refused 'CAfile with the intermediate only, root absent, leaf-only server'; done
  for c in curl s_client gnutls; do report EXPECT 5c2c "$c" chain refused 'CAfile with the intermediate only, root absent, server sends the chain'; done
  unrelated curl s_client gnutls
  CAFILE=''

  note 'case 1, 2, 5d, 4x: an NSS database'
  STATE='NSS db: root C,,'
  nss_new; nss_add root root 'C,,'
  report CONTROL 1 nss-db chain accepted 'NSS db: root trusted (C,,), server sends the chain'
  report CONTROL 2 nss-db leaf  refused  'NSS db: root trusted (C,,), leaf-only server'
  unrelated nss-db
  STATE='NSS db: root C,, + intermediate ,,'
  nss_add inter inter ',,'
  report EXPECT 5d nss-db leaf accepted 'NSS db: root C,, + intermediate with no trust flags, leaf-only server'
  unrelated nss-db
  STATE='NSS db: intermediate ,, alone'
  nss_new; nss_add inter inter ',,'
  report EXPECT 5d2  nss-db leaf  refused 'NSS db: root absent, intermediate ,, left, leaf-only server'
  report EXPECT 5d2c nss-db chain refused 'NSS db: root absent, intermediate ,, left, server sends the chain'
  unrelated nss-db
  STATE='NSS db: intermediate C,, alone'
  nss_new; nss_add inter inter 'C,,'
  report RECORD 4x  nss-db leaf  refused 'NSS db: intermediate trusted as CA (C,,), root absent, leaf-only server'
  report RECORD 4xc nss-db chain refused 'NSS db: intermediate trusted as CA (C,,), root absent, server sends the chain'
  unrelated nss-db

  #### the result
  note 'final state of the store'
  sys_clear
  if store_has_ours; then die 'the store holds our CA at the end'; fi

  say ''
  say "=== VERSIONS $distro"
  if [ "$distro" = debian ]; then
    say "$(. /etc/os-release; echo "$PRETTY_NAME")"
    dpkg-query -W -f='${Package} ${Version}\n' curl libcurl4t64 openssl libssl3t64 gnutls-bin libgnutls30t64 \
      libnss3 libnss3-tools ca-certificates p11-kit 2>/dev/null | sed 's/^/package /'
  else
    say "$(. /etc/os-release; echo "$PRETTY_NAME")"
    rpm -q curl libcurl openssl-libs gnutls nss nss-tools ca-certificates p11-kit p11-kit-trust | sed 's/^/package /'
  fi
  say "curl:      $(curl -V | head -n 1)"
  say "openssl:   $(openssl version)"
  say "gnutls-cli: $(gnutls-cli --version | head -n 1)"
  say "nss:       $(modutil -dbdir sql:/tmp/nss-empty -list 2>/dev/null | sed -n 's/.*library-version=\([0-9.]*\).*/\1/p' | head -n 1)"
  say '=== END VERSIONS'

  say ''
  say "=== TABLE $distro"
  local cols rows
  if [ "$distro" = debian ]; then cols='curl s_client gnutls nss-db'; else cols='curl s_client gnutls nss-sys nss-db'; fi
  rows='1 2 3 4 4c 5a 5b 5b2 5b2c 3p 4p 4pc 5c 5c2 5c2c 5d 5d2 5d2c 4x 4xc 6'
  printf '%-5s' case; for c in $cols; do printf ' %-14s' "$c"; done; printf '\n'
  local r cell
  for r in $rows; do
    local any=''
    for c in $cols; do [ -n "${OBS[$r|$c]:-}" ] && any=yes; done
    [ "$r" = 6 ] && any=yes
    [ -z "$any" ] && continue
    printf '%-5s' "$r"
    for c in $cols; do
      if [ "$r" = 6 ]; then
        if [ -n "${SIXN[$c]:-}" ]; then
          if [ "${SIXA[$c]:-0}" -eq 0 ]; then cell="refused(${SIXN[$c]}x)"; else cell="ACCEPTED ${SIXA[$c]}/${SIXN[$c]}"; fi
        else cell='-'; fi
      else cell=${OBS[$r|$c]:--}; fi
      printf ' %-14s' "$cell"
    done
    printf '\n'
  done
  say '=== END TABLE'
  say ''
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
img_debian=${SICK_E2E_TRUST_DEBIAN:-debian:trixie}
img_fedora=${SICK_E2E_TRUST_FEDORA:-fedora:latest}
only=${SICK_E2E_TRUST_ONLY:-}

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || fail 'docker is not installed'
docker info >/dev/null 2>&1 || fail 'the Docker daemon does not answer'
case $only in ''|debian|fedora) ;; *) fail "SICK_E2E_TRUST_ONLY is 'debian' or 'fedora'" ;; esac

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/sick-e2e-trust.XXXXXX")

left_behind() {
  docker ps -a --format '{{.Names}}' | grep -E '^sick-e2e-trust-' | sed 's/^/container /'
  docker ps -aq --filter "label=$LABEL" | sed 's/^/container id /'
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  docker rm -f sick-e2e-trust-debian sick-e2e-trust-fedora >/dev/null 2>&1
  local left
  left=$(left_behind)
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass 'no container named sick-e2e-trust-* or labelled sick-e2e=trust-anchors is left'
  fi
  printf -- '--- the pulled images stay as a cache; nothing was pruned\n'
  rm -rf "${work:?}"
  if [ "$rc" -eq 0 ]; then printf '\nDONE\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ -z "$(left_behind)" ] || fail 'a container sick-e2e-trust-* exists already; remove it by hand'

status=0
for distro in debian fedora; do
  [ -z "$only" ] || [ "$only" = "$distro" ] || continue
  image=img_$distro
  printf '\n######## %s (%s)\n' "$distro" "${!image}"
  docker run --name "sick-e2e-trust-$distro" --label "$LABEL" \
    -v "$self:/trust-anchors.sh:ro" "${!image}" bash /trust-anchors.sh --inside "$distro" \
    2>&1 | tee "$work/$distro.log"
  code=${PIPESTATUS[0]}
  docker rm -f "sick-e2e-trust-$distro" >/dev/null 2>&1
  if [ "$code" -ne 0 ]; then printf 'FAIL  the %s run ended with %s\n' "$distro" "$code" >&2; status=1; fi
done

printf '\n######## RESULT\n'
for distro in debian fedora; do
  [ -f "$work/$distro.log" ] || continue
  sed -n "/^=== VERSIONS $distro/,/^=== END VERSIONS/p" "$work/$distro.log"
  sed -n "/^=== TABLE $distro/,/^=== END TABLE/p" "$work/$distro.log"
  grep -E "^SUMMARY $distro" "$work/$distro.log"
  echo
done
grep -hE '^FAIL ' "$work"/*.log | sed 's/^/finding: /'
exit "$status"
