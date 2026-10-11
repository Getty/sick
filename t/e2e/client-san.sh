#!/bin/bash
#
# Client certificates under a name-constrained intermediate (k58): does
# step-ca issue a clientAuth certificate with an email or URI SAN under an
# intermediate that constrains DNS names and IP addresses only, and do the
# validators of four independent stacks accept the chain? The facts for the
# choice between a clientAuth provisioner under the server intermediate and
# a client intermediate of its own; docs/findings/client-san.md holds the
# record.
#
#   t/e2e/client-san.sh                 both parts
#   t/e2e/client-san.sh narrow wide     the parts named, in this order
#
# Parts, each self-contained (ceremony, CA up, cases, CA down):
#
#   narrow  a ceremony intermediate with DNS constraint example.internal and
#           IP constraint 192.0.2.0/24 (as in ca-ceremony.sh), the CA in
#           import mode with docker/provisioners.example.json (provisioner
#           "clients": JWK, clientAuth only); then once more with the CA
#           policy SICK_CA_ALLOW_DNS=*.example.internal,
#           SICK_CA_ALLOW_IP=192.0.2.0/24 (email and URI SANs refused), and
#           a third time with SICK_CA_ALLOW_EMAIL=@example.internal and
#           SICK_CA_ALLOW_URI=example.internal added: person@example.internal
#           and spiffe://example.internal/machine/backup1 issued,
#           person@example.org and spiffe://example.org/x refused
#   wide    the same intermediate with email constraint example.internal and
#           URI constraint example.internal as well (ceremony.sh --email
#           --uri), read back with openssl
#
# The cases, per part:
#
#   c1-dns-in       backup1.example.internal             (control: accepted)
#   c2-email-in     email person@example.internal
#   c3-email-out    email person@example.org
#   c4-spiffe-in    URI spiffe://example.internal/machine/backup1
#   c5-spiffe-out   URI spiffe://example.org/machine/backup1
#   c6-urn          URI urn:example:machine:backup1 (no host)
#   c7-dns-out      outside.example.org     (control: refused at issuance)
#   c8-server-leaf  web.example.internal from "sick", serverAuth only,
#                   presented as a client          (control: refused)
#   c9-spiffe-cn    as c4, with the subject CN backup1.example.internal
#   d0-urn-cn       as c6, with the subject CN backup1.example.internal
#
# c1-c6 have the subject step gives them: the email address, or "backup1"
# for the URI cases - a single label, which a validator may take for a DNS
# name when the certificate has no DNS SAN; c9 and d0 tell the two apart.
#
# Each case is asked of step-ca through "clients" (c8 through "sick"). What
# step-ca refuses is signed with the intermediate key directly (openssl,
# bypassing step-ca) with the same names and the client profile, so that the
# validators judge every name form. Validators, each with the root alone as
# trust anchor and the intermediate as untrusted chain, for the purpose TLS
# client: OpenSSL (openssl verify -purpose sslclient), GnuTLS (certtool
# --verify --verify-purpose clientAuth), Go (crypto/x509 Verify with
# ExtKeyUsageClientAuth, t/e2e/client-san-verify.go), Java (the PKIX trust
# manager's checkClientTrusted, t/e2e/ClientSanVerify.java). Python is not
# asked: it is OpenSSL again.
#
# PASS/FAIL for the controls and for what the setup has to deliver; RECORD
# for each observation either answer of which is acceptable; per part a
# table. The first FAIL ends the script with 1.
#
# Everything it starts carries the labels sick=1 and sick-e2e=client-san (the
# Compose project sick-e2e-clientsan through t/e2e/compose.local.yml, the
# helper containers by --label). It removes them by label and project, also
# after a failure or Ctrl-C, and checks that nothing is left; a rerun first
# removes what an interrupted run left behind. No prune; the images stay as
# a cache. Ports on 127.0.0.1 only.
#
# Prerequisites: Docker Engine with Compose and BuildKit, openssl on this
# machine, the two source trees side by side; the internet for the Debian
# packages (openssl, gnutls-bin) and for images not yet here.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR        private working directory, mode 0700, removed at the
#                       end  ($HOME/.local/share/sick-lab/client-san)
#   SICK_E2E_PROJECT    Compose project name, sick-e2e-*   (sick-e2e-clientsan)
#   SICK_E2E_CA_PORT    port of the CA on 127.0.0.1                    (19110)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/client-san}
project=${SICK_E2E_PROJECT:-sick-e2e-clientsan}
ca_port=${SICK_E2E_CA_PORT:-19110}
label=sick-e2e=client-san
marker=.sick-e2e-client-san

# pinned by digest (as pulled on 2026-10-11)
img_debian=debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
img_go=golang:1@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602
img_java=eclipse-temurin:25-jdk@sha256:8c0a84ea11c8f6ed52600fc19f1040121f2a162998e9f50a5faebbbad9172dcc

parts=("$@")
[ "${#parts[@]}" -gt 0 ] || parts=(narrow wide)

step_no=0
step() { step_no=$((step_no + 1)); printf '\n=== %s. %s\n' "$step_no" "$*"; }
note() { printf -- '--- %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
record() { printf 'RECORD  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
expect() {
  if grep -Eq -- "$2" <<<"$3"; then pass "$1"; else
    printf '%s\n' "$3" | sed 's/^/      | /' >&2
    fail "$1 (expected /$2/)"
  fi
}
refuse() {
  if grep -Eq -- "$2" <<<"$3"; then
    printf '%s\n' "$3" | sed 's/^/      | /' >&2
    fail "$1 (found /$2/)"
  else pass "$1"; fi
}
plain() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r'; }
show() { plain | sed 's/^/    /'; }

#### prerequisites

for p in "${parts[@]}"; do
  case $p in narrow | wide) ;; *) fail "unknown part '$p' (narrow, wide)" ;; esac
done
for program in docker openssl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[[ $project =~ ^sick-e2e-[a-z0-9_-]+$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick-e2e-*"
[[ $ca_port =~ ^[0-9]+$ ]] || fail 'SICK_E2E_CA_PORT is a port number'
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"

umask 077
work_parent=$(dirname "$work")
mkdir -p "$work_parent"
work=$(cd "$work_parent" && pwd -P)/$(basename "$work")
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
if [ -e "$work" ]; then
  [ -e "$work/$marker" ] || fail "$work exists and is not the working directory of this script: remove it by hand"
fi

write_env() { # <variant dir> [<allow dns> <allow ip> <allow email> <allow uri>]
  cat >"$work/compose.env" <<EOF
# Generated by t/e2e/client-san.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=SICK E2E Client SAN CA
SICK_CA_DNS=ca.example.internal
SICK_CA_IMPORT=$1/ceremony
SICK_CA_PROVISIONERS=$work/provisioners.json
SICK_CA_ALLOW_DNS=${2:-}
SICK_CA_ALLOW_IP=${3:-}
SICK_CA_ALLOW_EMAIL=${4:-}
SICK_CA_ALLOW_URI=${5:-}
SICK_CA_PORT=127.0.0.1:$ca_port
SICK_TRUST_PORT=127.0.0.1:0
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
EOF
}
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ACME_LIFETIME SICK_CA_ACME_MAX_LIFETIME SICK_CA_ACME_MIN_LIFETIME \
  SICK_CA_ACME_CHALLENGES SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ALLOW_EMAIL SICK_CA_ALLOW_URI SICK_CA_IMPORT SICK_CA_IMPORT_DIR \
  SICK_CA_PROVISIONERS SICK_CA_PROVISIONERS_FILE SICK_TRUST_PORT SICK_INTERVAL SICK_RUN_OPTIONS \
  SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$repo/docker/compose.import.yml" -f "$repo/docker/compose.provisioners.yml" \
    -f "$here/compose.local.yml" -f "$here/compose.ceremony.yml" "$@"
}
in_ca() { compose exec -T "$@"; }
ca_log() { compose logs --no-log-prefix ca 2>&1 | plain; }

#### teardown, armed before anything exists

remove_ours() {
  docker ps -aq --filter label=sick=1 --filter "label=$label" | xargs -r docker rm -f -v >/dev/null 2>&1
  if [ -f "$work/compose.env" ]; then
    compose down --volumes --remove-orphans 2>&1 | show
  fi
}
leftovers() {
  docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container /'
  docker ps -aq --filter "label=$label" | sed 's/^/container /'
  docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
  docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network /'
  docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]" | sed 's/^/container /'
  docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
  docker network ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/network /'
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  remove_ours
  local left
  left=$(leftovers)
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass "no container, volume or network of $project or labelled $label is left"
  fi
  rm -rf "${work:?}"
  if [ -e "$work" ]; then
    printf 'FAIL  %s could not be removed\n' "$work" >&2; rc=1
  else
    pass 'the working directory (stand-in root keys included) is removed'
  fi
  note 'the images stay as a cache; nothing was pruned'
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}

# what an interrupted run left: its compose.env names the project
if [ -e "$work" ]; then
  note "an interrupted run left $work: removing its containers, volumes and network first"
  remove_ours
  rm -rf "$work"
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 "$work"
: >"$work/$marker"
mkdir -m 755 "$work/secrets"
printf '# Generated by t/e2e/client-san.sh: no devices.\nca: { url: https://ca.example.internal:9000 }\ndevices: {}\n' >"$work/sick.yml"
chmod 644 "$work/sick.yml"
install -m 0644 "$repo/docker/provisioners.example.json" "$work/provisioners.json"
write_env "$work/none"

printf 'project %s, working directory %s, CA on 127.0.0.1:%s, parts: %s\n' "$project" "$work" "$ca_port" "${parts[*]}"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
note 'docker compose build sick (the image the ceremony runs in: step, openssl, bash)'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }

#### the parts

# ceremony <variant dir> <ceremony.sh options...>
ceremony() {
  local dir=$1
  shift
  mkdir -m 700 "$dir" "$dir/rootkey"
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 >"$dir/rootkey/root.pw" || true
  docker run --rm --name "$project-ceremony" --label sick=1 --label "$label" --network none \
    --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint bash \
    -v "$repo/docker/ceremony.sh:/ceremony.sh:ro" -v "$dir:/work" \
    sick:local /ceremony.sh --operator 'E2E Operator' --root-password-file /work/rootkey/root.pw \
    --out /work/ceremony --root-key /work/rootkey/root_ca_key \
    --root-name 'SICK E2E Client Root CA' --intermediate-name 'SICK E2E Client Intermediate CA' "$@" 2>&1 | plain
}

# issue <case> <provisioner> <subject> [<--san value>...]: inside the CA
# container as the user step, so that the provisioner password stays in the
# volume. Prints "exit: N", step's output, and the chain after a marker.
issue() {
  local case=$1 prov=$2 subject=$3 pw
  shift 3
  if [ "$prov" = sick ]; then pw=/home/step/secrets/provisioner_password; else pw=/home/step/secrets/provisioner_${prov}_password; fi
  in_ca -u step ca sh -c '
    d=$(mktemp -d); cd "$d"; prov=$1 pw=$2 subject=$3; shift 3
    sans=""; for s in "$@"; do sans="$sans --san $s"; done
    STEPPATH=$d step ca certificate "$subject" c.crt c.key --provisioner "$prov" --provisioner-password-file "$pw" \
      --ca-url https://ca.example.internal:9000 --root /home/step/certs/root_ca.crt --not-after 24h $sans >out 2>&1
    echo "exit: $?"; cat out; [ ! -s c.crt ] || { echo "--- chain"; cat c.crt; }
    rm -rf "$d"' sh "$prov" "$pw" "$subject" "$@" 2>&1 | plain
}

# direct <variant dir> <case> <subject> <subjectAltName>: signed with the
# intermediate key by openssl, the client profile of "clients"
direct() {
  local dir=$1 case=$2 tmp
  tmp=$(mktemp -d "$work/direct.XXXXXX")
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$tmp/k" -subj "/CN=$3" -out "$tmp/csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=%s\n' "$4" >"$tmp/ext"
  openssl x509 -req -in "$tmp/csr" -CA "$dir/ceremony/intermediate_ca.crt" -CAkey "$dir/ceremony/intermediate_ca_key" \
    -passin "file:$dir/ceremony/password" -set_serial "0x$(openssl rand -hex 16)" -days 1 -extfile "$tmp/ext" \
    -out "$tmp/crt" 2>"$tmp/err" || { cat "$tmp/err" >&2; rm -rf "$tmp"; fail "signing $case directly"; }
  cat "$tmp/crt" "$dir/ceremony/intermediate_ca.crt" >"$dir/judge/cases/$case.pem"
  rm -rf "$tmp"
}

# the cases: name, provisioner, subject, SANs for step (--san), subjectAltName for openssl
cases=(
  'c1-dns-in|clients|backup1.example.internal||DNS:backup1.example.internal'
  'c2-email-in|clients|person@example.internal||email:person@example.internal'
  'c3-email-out|clients|person@example.org||email:person@example.org'
  'c4-spiffe-in|clients|backup1|spiffe://example.internal/machine/backup1|URI:spiffe://example.internal/machine/backup1'
  'c5-spiffe-out|clients|backup1|spiffe://example.org/machine/backup1|URI:spiffe://example.org/machine/backup1'
  'c6-urn|clients|backup1|urn:example:machine:backup1|URI:urn:example:machine:backup1'
  'c7-dns-out|clients|outside.example.org||DNS:outside.example.org'
  'c8-server-leaf|sick|web.example.internal||'
  'c9-spiffe-cn|clients|backup1.example.internal|spiffe://example.internal/machine/backup1|URI:spiffe://example.internal/machine/backup1'
  'd0-urn-cn|clients|backup1.example.internal|urn:example:machine:backup1|URI:urn:example:machine:backup1'
)

declare -A issued_by verdict
judges=(openssl gnutls go java)

judge() { # <variant dir>
  local dir=$1 out
  chmod -R a+rX "$dir/judge"
  note "OpenSSL and GnuTLS ($img_debian, packages from Debian)"
  out=$(docker run --rm --name "$project-judge-debian" --label sick=1 --label "$label" \
    -v "$dir/judge:/judge:ro" "$img_debian" bash -c '
      export DEBIAN_FRONTEND=noninteractive
      { apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl gnutls-bin; } >/tmp/apt.log 2>&1 \
        || { tail -20 /tmp/apt.log; echo "ERROR apt-get"; exit 1; }
      echo "VERSION $(openssl version)"
      echo "VERSION $(certtool --version | head -n 1)"
      cd /tmp
      for f in /judge/cases/*.pem; do
        c=$(basename "$f" .pem)
        awk "/BEGIN/{n++} n==1" "$f" >leaf.pem
        awk "/BEGIN/{n++} n>=2" "$f" >chain.pem
        o=$(openssl verify -purpose sslclient -no-CApath -no-CAstore -CAfile /judge/root_ca.crt -untrusted chain.pem leaf.pem 2>&1)
        if [ $? -eq 0 ]; then r=accepted; else r=refused; fi
        echo "RESULT $c openssl $r $(echo "$o" | grep -m1 -iE "error|OK" | tr -s " ")"
        o=$(certtool --verify --verify-purpose 1.3.6.1.5.5.7.3.2 --load-ca-certificate /judge/root_ca.crt --infile "$f" 2>&1)
        if [ $? -eq 0 ]; then r=accepted; else r=refused; fi
        echo "RESULT $c gnutls $r $(echo "$o" | grep -m1 -E "Chain verification output" | sed "s/.*Chain verification output: //" | tr -s " ")"
      done' 2>&1 | plain)
  show <<<"$out"
  grep -q '^RESULT ' <<<"$out" || fail 'no result from OpenSSL/GnuTLS'
  printf '%s\n' "$out" >"$dir/results"
  note "Go ($img_go, no network)"
  out=$(docker run --rm --name "$project-judge-go" --label sick=1 --label "$label" --network none \
    -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/go -e GOTOOLCHAIN=local \
    -v "$here/client-san-verify.go:/code/verify.go:ro" -v "$dir/judge:/judge:ro" \
    "$img_go" go run /code/verify.go /judge 2>&1 | plain)
  show <<<"$out"
  grep -q '^RESULT ' <<<"$out" || fail 'no result from Go'
  printf '%s\n' "$out" >>"$dir/results"
  note "Java ($img_java, no network)"
  out=$(docker run --rm --name "$project-judge-java" --label sick=1 --label "$label" --network none \
    -v "$here/ClientSanVerify.java:/code/ClientSanVerify.java:ro" -v "$dir/judge:/judge:ro" \
    "$img_java" java /code/ClientSanVerify.java /judge 2>&1 | plain)
  show <<<"$out"
  grep -q '^RESULT ' <<<"$out" || fail 'no result from Java'
  printf '%s\n' "$out" >>"$dir/results"
  local line c j
  for line in "${cases[@]}"; do
    c=${line%%|*}
    for j in "${judges[@]}"; do
      verdict[$c/$j]=$(grep -E "^RESULT $c $j " "$dir/results" | head -n 1 | cut -d' ' -f4)
      [ -n "${verdict[$c/$j]}" ] || fail "no result for $c from $j"
      record "$c ($( [ "${issued_by[$c]}" = step-ca ] && echo 'issued by step-ca' || echo 'signed directly' )): ${verdict[$c/$j]} by $j: $(grep -E "^RESULT $c $j " "$dir/results" | head -n 1 | cut -d' ' -f5-)"
    done
  done
  grep '^VERSION' "$dir/results" | sed 's/^VERSION /version: /' >"$dir/versions"
}

# all_judges <case> <accepted|refused> <what>: PASS when every validator agrees
all_judges() {
  local j bad=
  for j in "${judges[@]}"; do [ "${verdict[$1/$j]}" = "$2" ] || bad+=" $j:${verdict[$1/$j]}"; done
  [ -z "$bad" ] || fail "$3: expected $2 by all four, got$bad"
  pass "$3: $2 by OpenSSL, GnuTLS, Go and Java"
}

table() { # <variant>
  printf '\n%s: | case | SAN | step-ca | OpenSSL | GnuTLS | Go | Java |\n' "$1"
  local line c san
  for line in "${cases[@]}"; do
    IFS='|' read -r c _ _ _ san <<<"$line"
    [ -n "$san" ] || san='DNS:web.example.internal (serverAuth)'
    printf '%s: | %s | %s | %s | %s | %s | %s | %s |\n' "$1" "$c" "$san" "${step_ca[$c]}" \
      "${verdict[$c/openssl]}" "${verdict[$c/gnutls]}" "${verdict[$c/go]}" "${verdict[$c/java]}"
  done
}

declare -A step_ca

run_variant() { # <narrow|wide>
  local v=$1 dir=$work/$1 out line c prov subject san osan
  step "$v: the ceremony"
  local -a extra=()
  [ "$v" = narrow ] || extra=(--email example.internal --uri example.internal)
  out=$(ceremony "$dir" --dns example.internal --ip 192.0.2.0/24 "${extra[@]}")
  show <<<"$out"
  [ -s "$dir/ceremony/intermediate_ca.crt" ] || fail 'the ceremony made no intermediate'
  local nc
  nc=$(openssl x509 -in "$dir/ceremony/intermediate_ca.crt" -noout -ext nameConstraints)
  show <<<"$nc"
  expect 'the intermediate: DNS constraint example.internal (openssl, here)' '^ *DNS:example\.internal$' "$nc"
  expect '... IP constraint 192.0.2.0/24' '^ *IP:192\.0\.2\.0/255\.255\.255\.0$' "$nc"
  if [ "$v" = narrow ]; then
    refuse '... no email constraint' 'email:' "$nc"
    refuse '... no URI constraint' 'URI:' "$nc"
    expect '... and the record says email addresses and URIs are unconstrained' 'permitted email +\(none: email addresses unconstrained\)' "$(cat "$dir/ceremony/ceremony.txt")"
  else
    expect '... email constraint example.internal' '^ *email:example\.internal$' "$nc"
    expect '... URI constraint example.internal' '^ *URI:example\.internal$' "$nc"
    expect '... and the record lists both' 'permitted URI +example\.internal' "$(cat "$dir/ceremony/ceremony.txt")"
  fi

  step "$v: the CA in import mode with docker/provisioners.example.json"
  write_env "$dir"
  compose up -d --wait ca >"$work/up.log" 2>&1 \
    || { plain <"$work/up.log" | tail -20 >&2; compose logs ca 2>&1 | tail -30 >&2; fail 'the CA did not come up healthy'; }
  out=$(ca_log | grep '^init-ca:' || true)
  show <<<"$out"
  expect 'init-ca.sh: import mode' '^init-ca: import mode: ' "$out"
  expect "... the provisioner 'clients' made, clientAuth only" "^init-ca: declared provisioner 'clients' \(JWK\) issues for 720h \(5m to 2160h\), clientAuth only$" "$out"

  step "$v: issuing the cases through step-ca"
  mkdir -p "$dir/judge/cases"
  cp "$dir/ceremony/root_ca.crt" "$dir/judge/root_ca.crt"
  for line in "${cases[@]}"; do
    IFS='|' read -r c prov subject san osan <<<"$line"
    local -a sans=()
    [ -z "$san" ] || sans=("$san")
    out=$(issue "$c" "$prov" "$subject" "${sans[@]}")
    if grep -q '^exit: 0$' <<<"$out"; then
      step_ca[$c]=issued issued_by[$c]=step-ca
      sed -n '/^--- chain$/,$p' <<<"$out" | sed 1d >"$dir/judge/cases/$c.pem"
      local facts
      facts=$(openssl x509 -in "$dir/judge/cases/$c.pem" -noout -subject -ext subjectAltName,keyUsage,extendedKeyUsage | sed 's/^ *//' | tr '\n' ' ')
      record "$c: step-ca issues it through '$prov': $facts"
      if [ "$prov" = clients ]; then
        [ "$(openssl x509 -in "$dir/judge/cases/$c.pem" -noout -ext extendedKeyUsage | sed 1d | tr -d ' ')" = TLSWebClientAuthentication ] \
          || fail "... $c: the extended key usage is not clientAuth alone"
        [ "$(openssl x509 -in "$dir/judge/cases/$c.pem" -noout -ext keyUsage | sed 1d | tr -d ' ')" = DigitalSignature ] \
          || fail "... $c: the key usage is not digitalSignature alone"
        pass "... $c: extended key usage clientAuth alone, key usage digitalSignature alone"
      fi
    else
      local why
      why=$(grep -m1 -iE 'not permitted|not allowed|forbidden|cannot|error' <<<"$out" || echo '(no message)')
      step_ca[$c]=refused issued_by[$c]=direct
      record "$c: step-ca refuses it through '$prov': $why"
      [ -n "$osan" ] || fail "$c: refused by step-ca, and there is nothing to sign directly"
      direct "$dir" "$c" "$subject" "$osan"
    fi
  done
  [ "${step_ca[c1-dns-in]}" = issued ] || fail 'control c1-dns-in: step-ca refused backup1.example.internal'
  pass 'control c1-dns-in: step-ca issues backup1.example.internal through clients'
  [ "${step_ca[c7-dns-out]}" = refused ] || fail 'control c7-dns-out: step-ca issued outside.example.org'
  pass 'control c7-dns-out: step-ca refuses outside.example.org (outside the DNS constraint)'
  [ "${step_ca[c8-server-leaf]}" = issued ] || fail 'control c8-server-leaf: sick did not issue web.example.internal'
  refuse "control c8-server-leaf: serverAuth alone" 'Client Authentication' "$(openssl x509 -in "$dir/judge/cases/c8-server-leaf.pem" -noout -ext extendedKeyUsage)"
  if [ "$v" = wide ]; then
    for c in c2-email-in c4-spiffe-in; do
      [ "${step_ca[$c]}" = issued ] || fail "$c: step-ca refused a name inside the email/URI constraints"
      pass "$c: inside the email/URI constraints: issued"
    done
    for c in c3-email-out c5-spiffe-out c6-urn; do
      [ "${step_ca[$c]}" = refused ] || fail "$c: step-ca issued a name outside the email/URI constraints"
      pass "$c: outside the email/URI constraints (a URN has no host): refused at issuance"
    done
  fi

  step "$v: the validators"
  judge "$dir"
  all_judges c1-dns-in accepted 'control c1-dns-in'
  all_judges c7-dns-out refused 'control c7-dns-out (signed directly)'
  all_judges c8-server-leaf refused 'control c8-server-leaf, serverAuth only, as a client'
  if [ "$v" = wide ]; then
    all_judges c2-email-in accepted 'c2-email-in, inside the email constraint'
    all_judges c9-spiffe-cn accepted 'c9-spiffe-cn, inside the URI constraint, CN inside the DNS constraint'
    # who refuses c3, c5, c6 and d0 signed directly: RECORD lines and the table
  fi

  if [ "$v" = narrow ]; then
    step 'narrow: the same CA with the policy SICK_CA_ALLOW_DNS=*.example.internal SICK_CA_ALLOW_IP=192.0.2.0/24'
    write_env "$dir" '*.example.internal' '192.0.2.0/24'
    compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
    expect 'init-ca.sh sets the policy' 'names allowed: \*\.example\.internal, 192\.0\.2\.0/24' "$(ca_log | grep '^init-ca:')"
    declare -gA policy=()
    for line in "${cases[@]:0:6}" "${cases[@]:8:2}"; do
      IFS='|' read -r c prov subject san osan <<<"$line"
      local -a sans=()
      [ -z "$san" ] || sans=("$san")
      out=$(issue "$c" "$prov" "$subject" "${sans[@]}")
      if grep -q '^exit: 0$' <<<"$out"; then
        policy[$c]=issued
        record "$c with the policy: issued"
      else
        policy[$c]=refused
        record "$c with the policy: refused: $(grep -m1 -iE 'not permitted|not allowed|forbidden|cannot|error' <<<"$out" || echo '(no message)')"
      fi
    done
    [ "${policy[c1-dns-in]}" = issued ] || fail 'control c1-dns-in with the policy: refused'
    pass 'control c1-dns-in with the policy: issued'

    step 'narrow: the policy with email and URI as well: SICK_CA_ALLOW_EMAIL=@example.internal SICK_CA_ALLOW_URI=example.internal'
    write_env "$dir" '*.example.internal' '192.0.2.0/24' '@example.internal' 'example.internal'
    compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
    expect 'init-ca.sh sets the policy with all four forms' \
      'configuration updated: .*names allowed: \*\.example\.internal, 192\.0\.2\.0/24, @example\.internal, example\.internal' "$(ca_log | grep '^init-ca:')"
    local allow
    allow=$(in_ca ca jq -c .authority.policy.x509.allow /home/step/config/ca.json 2>&1 | plain)
    expect '... in ca.json' '^\{"dns":\["\*\.example\.internal"\],"ip":\["192\.0\.2\.0/24"\],"email":\["@example\.internal"\],"uri":\["example\.internal"\]\}$' "$allow"
    # name|subject|SAN for step|issued or the message of the refusal
    local -a wide_policy=(
      'person@example.internal|person@example.internal||issued'
      'spiffe://example.internal/machine/backup1|backup1.example.internal|spiffe://example.internal/machine/backup1|issued'
      'backup1.example.internal|backup1.example.internal||issued'
      'person@example.org|person@example.org||email name "person@example\.org" not allowed'
      'spiffe://example.org/x|backup1.example.internal|spiffe://example.org/x|uri name "spiffe://example\.org/x" not allowed'
    )
    local name want facts
    for line in "${wide_policy[@]}"; do
      IFS='|' read -r name subject san want <<<"$line"
      local -a sans=()
      [ -z "$san" ] || sans=("$san")
      out=$(issue "$name" clients "$subject" "${sans[@]}")
      if [ "$want" = issued ]; then
        expect "$name: issued through clients with the policy" '^exit: 0$' "$out"
        facts=$(sed -n '/^--- chain$/,$p' <<<"$out" | sed 1d | openssl x509 -noout -ext subjectAltName | sed 1d | tr -d ' ')
        case $name in
          *@*) [ "$facts" = "email:$name" ] ;;
          *://*) [ "$facts" = "URI:$name" ] ;;
          *) [ "$facts" = "DNS:$name" ] ;;
        esac || fail "... $name: the SAN is '$facts'"
        pass "... $name: the certificate carries $facts alone"
      else
        refuse "$name: refused through clients with the policy" '^exit: 0$' "$out"
        expect "... in the words of the CA: $want" "$want" "$out"
      fi
    done
    out=$(issue c4-spiffe-in clients backup1 spiffe://example.internal/machine/backup1)
    refuse 'c4-spiffe-in (subject CN backup1) with the policy: refused, the CN is judged as a DNS name' '^exit: 0$' "$out"
    expect '... in the words of the CA' 'cn name "backup1" not allowed' "$out"
  fi

  table "$v"
  sed "s/^/$v: /" "$dir/versions" | sort -u
  printf '%s: step-ca: %s\n' "$v" "$(in_ca ca step-ca version 2>&1 | plain | head -n 1)"
  printf '%s: step:    %s\n' "$v" "$(in_ca ca step version 2>&1 | plain | head -n 1)"
  [ "$v" != narrow ] || printf 'narrow: with the policy: %s\n' "$(for c in c1-dns-in c2-email-in c3-email-out c4-spiffe-in c5-spiffe-out c6-urn c9-spiffe-cn d0-urn-cn; do printf '%s=%s ' "$c" "${policy[$c]}"; done)"

  step "$v: the CA down"
  compose down --volumes --remove-orphans 2>&1 | show
  pass "$project is down with its volumes"
}

for p in "${parts[@]}"; do
  run_variant "$p"
done

# teardown runs in the EXIT trap
