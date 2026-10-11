#!/bin/bash
#
# The CA done properly, third part (k31): renewing the intermediate under
# the offline root while devices keep their certificates, and replacing the
# root in three phases - announce, switch, retire.
#
# What it proves, each with PASS/FAIL lines and an exit code of 1 on the
# first FAIL; RECORD lines are observations where the answer is known not
# to be a promise (see the end of this header):
#
#   1. a CA on a ceremony (docker/ceremony.sh, import mode) with
#      constraints example.internal and 192.0.2.0/24; sick issues for three
#      devices: web and web2 present their certificate alone (like a
#      switch), web3 sends its chain. A second ceremony makes the new
#      hierarchy for part II now, as it would be made ahead of time
#   2. intermediate renewal: ceremony.sh --renew-intermediate makes a new
#      intermediate with a new key under the same root, constraints copied
#      from the current one (openssl reads both alike); init-ca.sh
#      --switch-intermediate refuses an intermediate of another root, then
#      takes the new one without a restart of step-ca, and refuses a second
#      switch during the overlap
#   3. the overlap: the handover holds new and previous intermediate, new
#      first; web (under the previous one) stays "ok" and is not renewed;
#      a forced issuance for web2 comes from the new intermediate; the trust
#      page's ca_bundle.pem lets curl (OpenSSL) and gnutls-cli (GnuTLS)
#      accept both leaf-only devices, while the root alone does not
#      (control: the bundle's intermediates do the work)
#   4. retire: init-ca.sh --retire-intermediate drops the previous one; web
#      is foreign-ca and sick run renews it from the new intermediate, and
#      both clients accept it with the new page. web3, which sends its
#      chain, stays ok (its I1 still leads to R1; RECORD) and is forced
#   5. root replacement, phase A (announce): ca.additional_roots names the
#      new root; sick trust publishes both (root_ca_2.*, ca_bundle.pem with
#      the current root first, index.html with both fingerprints); sick run
#      changes nothing. A pilot device with a leaf of the new hierarchy
#      (signed with its intermediate key, sent with its chain) and the old
#      devices are accepted by both clients holding the page's bundle; a
#      client still holding the old page (old root and intermediate) refuses
#      the pilot
#   6. phase B (switch): the CA on a second volume in import mode with the
#      new hierarchy (docker/compose.ca-next.yml); the old volume is kept,
#      unused, for a planned rollback; ca.root is the new root (handover),
#      additional_roots the old one. With the page of phase B: web3 (old
#      root, chain) and the pilot (new root) are accepted; sick run --force
#      web issues under the new root, both clients accept it, the client
#      with the old page refuses it; sick run --force re-issues every
#      device, and a further sick run changes nothing (convergence)
#   7. phase C (retire): additional_roots emptied, the page holds the new
#      root alone; a client that took the new page (and so dropped the old
#      root) accepts the devices and refuses a leaf of the old hierarchy
#      (put on the pilot)
#   8. teardown, also after a failure or Ctrl-C: the project down with its
#      volumes (ca, ca-next and the rest), the client container removed by
#      its labels (sick=1, sick-e2e=ca-rollover), nothing of the project or
#      with that label left, the private working directory (stand-in root
#      keys, intermediate keys, passwords) removed
#
# RECORD, not PASS/FAIL: a device that presents its certificate alone and
# is still under the other root during phase A or B. ca.intermediates must
# lead to ca.root, so the page of either phase carries the intermediate of
# the current hierarchy only, and a client cannot build the path for such a
# device. Devices that send their chain are not affected.
#
# It DESTROYS the Compose project it works on (default sick-e2e-rollover).
# It touches nothing else: no other project, no prune. The images stay.
#
# Not covered here: a planned rollback actually performed (it is written
# down, not run); RSA hierarchies; NSS and Go as clients; the mobileconfig
# on a device.
#
# Prerequisites: Docker Engine with Compose and BuildKit, openssl on this
# machine, the two source trees side by side, the internet for images and
# packages.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR        private working directory, mode 0700, removed at the
#                       end  ($HOME/.local/share/sick-lab/rollover)
#   SICK_E2E_PROJECT    Compose project name, sick-e2e-*    (sick-e2e-rollover)
#   SICK_E2E_CA_PORT    port of the CA on 127.0.0.1                     (19300)
#   SICK_E2E_DEBIAN     image for the clients                  (debian:trixie)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/rollover}
project=${SICK_E2E_PROJECT:-sick-e2e-rollover}
ca_port=${SICK_E2E_CA_PORT:-19300}
debian=${SICK_E2E_DEBIAN:-debian:trixie}
label=sick-e2e=ca-rollover
client=${project}-client

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
sha256_pem() { openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
sha256_of() { sha256_pem <"$1"; }
# the SHA-256 of every certificate in a PEM file, in order, one per line
bundle_fps() {
  local pem='' line
  while IFS= read -r line; do
    pem+=$line$'\n'
    if [ "$line" = '-----END CERTIFICATE-----' ]; then sha256_pem <<<"$pem"; pem=''; fi
  done <"$1"
}
wait_for() { # <seconds> <what> <command ...>
  local seconds=$1 what=$2 start=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    [ $((SECONDS - start)) -lt "$seconds" ] || fail "waited ${seconds}s for $what"
    sleep 1
  done
}

#### prerequisites

for program in docker openssl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[[ $project =~ ^sick-e2e-[a-z0-9_-]+$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick-e2e-*"
[[ $ca_port =~ ^[0-9]+$ ]] || fail 'SICK_E2E_CA_PORT is a port number'
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
if (exec 3<>"/dev/tcp/127.0.0.1/$ca_port") 2>/dev/null; then
  fail "port $ca_port on 127.0.0.1 is in use: set SICK_E2E_CA_PORT"
fi
[ -z "$(docker ps -aq --filter "label=$label")" ] || fail "a container labelled $label exists already; remove it by hand"

umask 077
[ ! -e "$work" ] || fail "$work exists: remove it (it is the private directory of an earlier run)"
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd -P)
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
# gen1/ gen2/ gen3/  what goes to the CA: first hierarchy, renewed
# intermediate, new hierarchy   rootkey1/ rootkey3/  the stand-in root keys
# and their passwords, never mounted into the CA   secrets/  for SICK: the
# additional root   leaves/  hand-signed leaves   pages/  bundles as fetched
mkdir -m 700 "$work/gen1" "$work/gen2" "$work/gen3" "$work/rootkey1" "$work/rootkey3" "$work/leaves" "$work/pages"
mkdir -m 755 "$work/secrets"
for n in 1 3; do
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 >"$work/rootkey$n/root.pw" || true
  [ "$(wc -c <"$work/rootkey$n/root.pw")" -eq 40 ] || fail 'cannot generate a password'
done

ca_name='SICK E2E Rollover CA'
# write_list [additional root path]: the device list, with ca.additional_roots
# when a path is given
write_list() {
  {
    printf '# Generated by t/e2e/ca-rollover.sh. Neutral names only.\n'
    printf 'ca:\n'
    printf '  name: %s\n' "$ca_name"
    printf '  url: https://ca.example.internal:9000\n'
    printf '  root: /etc/sick/ca/root_ca.crt\n'
    printf '  intermediates: /etc/sick/ca/intermediate_ca.crt\n'
    [ -z "${1:-}" ] || printf '  additional_roots: [%s]\n' "$1"
    printf '  provisioner: sick\n'
    printf '  password_file: /etc/sick/ca/provisioner.pw\n'
    printf 'defaults:\n  lifetime: 397d\n  renew_before: 30d\n  key: rsa2048\n'
    printf 'devices:\n'
    printf '  web:\n    type: files\n    host: web\n    port: 443\n    names: [web.example.internal]\n    dir: /srv/device\n'
    printf '  web2:\n    type: files\n    host: web2\n    port: 443\n    names: [web2.example.internal]\n    dir: /srv/device2\n'
    printf '  web3:\n    type: files\n    host: web3\n    port: 443\n    names: [web3.example.internal]\n    dir: /srv/device3\n'
  } >"$work/sick.yml"
  chmod 644 "$work/sick.yml"
}
write_list ''

write_env() { # <import dir>
  cat >"$work/compose.env" <<EOF
# Generated by t/e2e/ca-rollover.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=$ca_name
SICK_CA_DNS=ca.example.internal
SICK_CA_IMPORT=$1
SICK_CA_PORT=127.0.0.1:$ca_port
SICK_TRUST_PORT=127.0.0.1:0
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
EOF
}
write_env "$work/gen1"
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ALLOW_EMAIL SICK_CA_ALLOW_URI SICK_CA_IMPORT SICK_CA_IMPORT_DIR \
  SICK_TRUST_PORT SICK_INTERVAL SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE \
  SICK_CA_ACME_CHALLENGES SICK_CA_PROVISIONERS SICK_CA_PROVISIONERS_FILE

# the pilot device of part II: not in the device list, files put by hand
cat >"$work/compose.pilot.yml" <<EOF
# Generated by t/e2e/ca-rollover.sh: the pilot device.
services:
  sick:
    volumes:
      - pilotfiles:/srv/pilot
  pilot:
    image: \${SICK_IMAGE:-sick:local}
    pull_policy: never
    init: true
    stop_grace_period: 3s
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    entrypoint: ["/bin/sh", "/usr/local/bin/web-serve.sh"]
    environment:
      SICK_E2E_WEB_CHAIN: "yes"
    tmpfs:
      - /tmp:mode=0700,size=4m
    volumes:
      - pilotfiles:/srv/device:ro
      - $here/web-serve.sh:/usr/local/bin/web-serve.sh:ro
volumes:
  pilotfiles:
EOF

files=(-f "$repo/docker/compose.yml" -f "$repo/docker/compose.import.yml" -f "$here/compose.local.yml"
  -f "$here/compose.rollover.yml" -f "$work/compose.pilot.yml")
# every command names the second CA volume too: down -v takes it along, and
# after phase B the ca service is defined with it
base_files=("${files[@]}")
all_files=("${files[@]}" -f "$repo/docker/compose.ca-next.yml")
compose() { docker compose --env-file "$work/compose.env" -p "$project" "${files[@]}" "$@"; }
in_ca() { compose exec -T ca "$@"; }
# a command in a fresh sick container; --no-deps everywhere: nothing here
# may make Compose recreate the CA behind the script's back
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
sick_do() { compose run --rm --no-deps -T sick sick "$@" 2>&1 | plain; }
ca_log() { compose logs --no-log-prefix ca 2>&1 | plain; }

#### 8. teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== 8. teardown\n'
  # by label only: the client carries sick=1 and this script's label
  docker ps -aq --filter label=sick=1 --filter "label=$label" | xargs -r docker rm -f -v >/dev/null 2>&1
  if [ -n "$armed" ]; then
    # twice: with compose.ca-next.yml the volume "ca" belongs to no service
    # and down -v leaves it; without it, "ca-next" is unknown
    note "docker compose -p $project down -v --remove-orphans, without and with compose.ca-next.yml"
    docker compose --env-file "$work/compose.env" -p "$project" "${base_files[@]}" \
      down --volumes --remove-orphans 2>&1 | show
    docker compose --env-file "$work/compose.env" -p "$project" "${all_files[@]}" \
      down --volumes --remove-orphans 2>&1 | show
  fi
  local left
  left=$(
    docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container id /'
    docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
    docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network id /'
    docker ps -aq --filter "label=$label" | sed 's/^/container id /'
    docker volume ls -q --filter "label=$label" | sed 's/^/volume /'
    docker network ls -q --filter "label=$label" | sed 's/^/network id /'
  )
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass "nothing of project $project and nothing labelled $label is left"
  fi
  rm -rf "${work:?}"
  if [ -e "$work" ]; then
    printf 'FAIL  %s could not be removed\n' "$work" >&2; rc=1
  else
    pass 'the working directory (stand-in root keys, intermediate keys, passwords) is removed'
  fi
  note 'the images stay as a cache; nothing was pruned'
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'project %s, working directory %s, CA on 127.0.0.1:%s\n' "$project" "$work" "$ca_port"
armed=yes
docker compose --env-file "$work/compose.env" -p "$project" "${base_files[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose --env-file "$work/compose.env" -p "$project" "${all_files[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true

note 'docker compose build (the sick image: step, openssl, bash - what the ceremony needs)'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }

# ceremony <args...>: docker/ceremony.sh in the sick image, no network, as
# the user running this script (so that it can remove what it wrote)
ceremony() {
  docker run --rm --label sick=1 --label "$label" --network none \
    --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint bash \
    -v "$repo/docker/ceremony.sh:/ceremony.sh:ro" -v "$work:/work" \
    sick:local /ceremony.sh --operator 'E2E Operator' "$@"
}

# the clients: curl (OpenSSL) and gnutls-cli (GnuTLS) in one Debian
# container in the project's network. No ca-certificates: nothing is
# trusted but the file a check names.
judge_in='
b=$1 h=$2 n=$3
o=$(curl -sS -o /dev/null --max-time 10 --cacert "$b" --capath /empty --connect-to "$n:443:$h:443" "https://$n/" 2>&1)
if [ $? -eq 0 ]; then echo "curl accepted"; else echo "curl refused: $(echo "$o" | head -n 1)"; fi
o=$(timeout 15 gnutls-cli --x509cafile "$b" --verify-hostname "$n" -p 443 "$h" </dev/null 2>&1)
if [ $? -eq 0 ]; then echo "gnutls accepted"; else echo "gnutls refused: $(echo "$o" | grep -m 1 -E "verification output|Status:|certificate is|Error" | tr -s " ")"; fi
'
# judge <what> <bundle in /pages> <host> <name> <accepted|refused> [record]
judge() {
  local out c line got
  out=$(docker exec "$client" sh -c "$judge_in" -- "/pages/$2" "$3" "$4" 2>&1 | plain)
  for c in curl gnutls; do
    line=$(grep -m 1 "^$c " <<<"$out" || true)
    [ -n "$line" ] || { show <<<"$out"; fail "$1: no answer from $c"; }
    got=$(cut -d' ' -f2 <<<"$line" | tr -d :)
    if [ "${6:-}" = record ]; then
      record "$1: $got by $c${line#"$c $got"}"
    elif [ "$got" = "$5" ]; then
      pass "$1: $5 by $c${line#"$c $got"}"
    else
      fail "$1: $got by $c, expected $5 (${line#"$c "})"
    fi
  done
}
# fetch_page <tag>: what a client takes from the trust page, into /pages
fetch_page() {
  docker exec "$client" sh -c 'cd /pages && curl -fsS -o "$1.pem" http://trust:8080/ca_bundle.pem \
    && curl -fsS -o "$1-root.pem" http://trust:8080/root_ca.pem && cat "$1.pem"' -- "$1" >"$work/pages/$1.pem" \
    || fail "cannot fetch the trust page ($1)"
}
# presented <host> <name>: issuer and SHA-256 of what the device presents
presented() {
  docker exec "$client" sh -c 'openssl s_client -connect "$1:443" -servername "$2" </dev/null 2>/dev/null \
    | openssl x509 -noout -issuer -nameopt RFC2253 -fingerprint -sha256' -- "$1" "$2" 2>&1 \
    | plain | sed 's/^sha256 Fingerprint=/sha256=/; /^sha256=/{s/://g; y/ABCDEF/abcdef/}'
}
fp_presented() { presented "$1" "$2" | sed -n 's/^sha256=//p'; }
issuer_presented() { presented "$1" "$2" | sed -n 's/^issuer=//p'; }
# sign_leaf <generation dir> <name> <out dir>: a leaf signed with the
# intermediate key of that generation directly (openssl), with its chain
sign_leaf() {
  local gen=$1 name=$2 out=$3
  mkdir -m 700 "$out"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$out/key.pem" -subj "/CN=$name" \
    -out "$out/csr.pem" 2>/dev/null || fail "cannot make a key for $name"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
    "$name" >"$out/ext"
  openssl x509 -req -in "$out/csr.pem" -CA "$gen/intermediate_ca.crt" -CAkey "$gen/intermediate_ca_key" \
    -passin "file:$gen/password" -set_serial "0x$(openssl rand -hex 16)" -days 30 -extfile "$out/ext" \
    -out "$out/cert.pem" 2>/dev/null || fail "cannot sign a leaf for $name"
  cp "$gen/intermediate_ca.crt" "$out/chain.pem"
  cat "$out/cert.pem" "$out/chain.pem" >"$out/fullchain.pem"
}
# to_pilot <leaf dir>: the files on the pilot, cert.pem last; then wait until
# it presents them
to_pilot() {
  local want
  want=$(sha256_of "$1/cert.pem")
  tar -C "$1" -cf - key.pem chain.pem fullchain.pem cert.pem \
    | compose run --rm --no-deps -T --entrypoint sh sick -c 'mkdir /tmp/p && tar --no-same-owner -C /tmp/p -xf - \
        && for f in key.pem chain.pem fullchain.pem cert.pem; do cp "/tmp/p/$f" "/srv/pilot/$f.new" && mv "/srv/pilot/$f.new" "/srv/pilot/$f"; done' \
    || fail 'cannot put the files on the pilot'
  pilot_is() { [ "$(fp_presented pilot pilot.example.internal)" = "$1" ]; }
  wait_for 30 'the pilot to present its new certificate' pilot_is "$want"
}

#### 1. a CA on a ceremony, three devices

step 'a CA on a ceremony, three devices with certificates; the new hierarchy made ahead of time'
set +e
out=$(ceremony --out /work/gen1 --root-key /work/rootkey1/root_ca_key --root-password-file /work/rootkey1/root.pw \
  --root-name 'SICK E2E Root CA' --intermediate-name 'SICK E2E Intermediate CA' \
  --dns example.internal --ip 192.0.2.0/24 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "the first ceremony ended with $code"
pass 'the first ceremony ran: root R1, intermediate I1'
set +e
out=$(ceremony --out /work/gen3 --root-key /work/rootkey3/root_ca_key --root-password-file /work/rootkey3/root.pw \
  --root-name 'SICK E2E Root CA 2' --intermediate-name 'SICK E2E Intermediate CA 2' \
  --dns example.internal --ip 192.0.2.0/24 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "the second ceremony ended with $code"
pass 'the ceremony of the new hierarchy ran: root R2, intermediate I3 (used in part II)'
r1=$(sha256_of "$work/gen1/root_ca.crt")
i1=$(sha256_of "$work/gen1/intermediate_ca.crt")
r2=$(sha256_of "$work/gen3/root_ca.crt")
i3=$(sha256_of "$work/gen3/intermediate_ca.crt")
note "R1 $r1"
note "I1 $i1"
note "R2 $r2"
note "I3 $i3"

note 'docker compose up -d --wait ca web web2 web3 pilot trust'
compose up -d --wait ca web web2 web3 pilot trust >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca 2>&1 | tail -30 >&2; fail 'the stack did not come up healthy'; }
pass 'ca, the devices and the trust page are up'
expect 'the CA runs on the first ceremony (import mode)' "root fingerprint \(SHA-256\): $r1" "$(ca_log | grep '^init-ca:')"
ca_id=$(compose ps -q ca)
started=$(docker inspect -f '{{.State.StartedAt}}' "$ca_id")

note "the client container ($debian: curl, gnutls-cli, openssl)"
docker run -d --name "$client" --label sick=1 --label "$label" --network "${project}_default" --init \
  "$debian" sleep infinity >/dev/null
docker exec "$client" sh -c 'export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq --no-install-recommends curl gnutls-bin openssl; } >/tmp/apt.log 2>&1 \
    || { tail -20 /tmp/apt.log; exit 1; }
  mkdir -p /pages /empty' 2>&1 | show || fail 'cannot set up the client container'
versions=$(docker exec "$client" sh -c 'curl --version | head -n 1; gnutls-cli --version | head -n 1; openssl version' | plain)
show <<<"$versions"
docker exec "$client" sh -c '[ -z "$(ls -A /etc/ssl/certs 2>/dev/null)" ]' || fail 'the client has a system trust store'
pass 'the client has no system trust store: nothing is trusted but the file a check names'

run=$(sick_do run)
show <<<"$run"
for d in web web2 web3; do expect "$d gets a certificate" "^$d +renewed +" "$run"; done
for d in web web2 web3; do
  expect "$d presents a leaf of I1" '^CN=SICK E2E Intermediate CA$' "$(issuer_presented "$d" "$d.example.internal")"
done
web_i1=$(fp_presented web web.example.internal)

#### 2. intermediate renewal: ceremony and switch

step 'a new intermediate under the same root, and the switch on the running CA'
set +e
out=$(ceremony --renew-intermediate --out /work/gen2 --root-cert /work/gen1/root_ca.crt \
  --root-key /work/rootkey1/root_ca_key --root-password-file /work/rootkey1/root.pw \
  --intermediate /work/gen1/intermediate_ca.crt 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "ceremony.sh --renew-intermediate ended with $code"
pass 'ceremony.sh --renew-intermediate ran'
listing=$(cd "$work/gen2" && ls -A | sort | tr '\n' ' ')
[ "$listing" = 'ceremony.txt intermediate_ca.crt intermediate_ca_key password root_ca.crt ' ] || fail "the output holds: $listing"
pass "the output for the CA is the import set: $listing"
[ "$(sha256_of "$work/gen2/root_ca.crt")" = "$r1" ] || fail 'root_ca.crt of the renewal is not R1'
pass '... root_ca.crt is R1'
i2=$(sha256_of "$work/gen2/intermediate_ca.crt")
note "I2 $i2"
refuse '... no root key in it' 'PRIVATE KEY' "$(cd "$work/gen2" && grep -l 'PRIVATE KEY' ceremony.txt password root_ca.crt intermediate_ca.crt 2>/dev/null)"
v=$(openssl verify -no-CApath -no-CAstore -CAfile "$work/gen1/root_ca.crt" "$work/gen2/intermediate_ca.crt" 2>&1)
expect 'openssl verifies I2 against R1' ': OK$' "$v"
[ "$(openssl x509 -in "$work/gen2/intermediate_ca.crt" -noout -pubkey)" != "$(openssl x509 -in "$work/gen1/intermediate_ca.crt" -noout -pubkey)" ] \
  || fail 'I2 has the key of I1'
pass 'I2 has a new key'
nc1=$(openssl x509 -in "$work/gen1/intermediate_ca.crt" -noout -ext nameConstraints,basicConstraints,keyUsage)
nc2=$(openssl x509 -in "$work/gen2/intermediate_ca.crt" -noout -ext nameConstraints,basicConstraints,keyUsage)
show <<<"$nc2"
[ "$nc1" = "$nc2" ] || fail 'constraints, basic constraints or key usage of I2 differ from I1'
pass 'name constraints, pathlen 0 and key usage of I2 are those of I1, as openssl reads them'
rec=$(cat "$work/gen2/ceremony.txt")
expect 'the record says renewal' '^mode: +renewal of the intermediate under the existing root$' "$rec"
expect '... the constraints were copied' 'constraints +copied from the current intermediate' "$rec"
expect '... which intermediate it follows' "SHA-256 fingerprint +$i1" "$rec"
expect '... and that the root key was only read' '^root key: +read at /work/rootkey1/root_ca_key \(not copied, not changed\)$' "$rec"
refuse '... and holds no password' "$(cat "$work/rootkey1/root.pw")|$(head -n 1 "$work/gen2/password")" "$rec"
int2_name=$(openssl x509 -in "$work/gen2/intermediate_ca.crt" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
note "I2 is $int2_name"

note 'a switch to an intermediate of another root (I3 under R2, without its root_ca.crt): refused'
mkdir -m 700 "$work/foreign"
cp "$work/gen3/intermediate_ca.crt" "$work/gen3/intermediate_ca_key" "$work/gen3/password" "$work/foreign/"
compose cp "$work/foreign/." ca:/home/step/switch >/dev/null 2>&1 || fail 'docker compose cp'
set +e
out=$(compose exec -T ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate 2>&1)
code=$?
set -e
out=$(plain <<<"$out")
show <<<"$out"
[ "$code" -ne 0 ] || fail 'the switch to a foreign intermediate went through'
expect 'refused: it does not lead to the root of this CA' 'does not lead to the root of this CA: refused, nothing changed' "$out"
[ "$(in_ca step certificate fingerprint /home/step/certs/intermediate_ca.crt | plain)" = "$i1" ] || fail '... but the intermediate changed'
refuse '... nothing changed, and the copied directory (with its key) is gone from the volume' 'previous|switch' \
  "$(in_ca find /home/step/certs /home/step/secrets /home/step -maxdepth 1 2>&1 | plain)"

note 'docker compose cp gen2/. ca:/home/step/switch; init-ca.sh --switch-intermediate'
compose cp "$work/gen2/." ca:/home/step/switch >/dev/null 2>&1 || fail 'docker compose cp'
set +e
out=$(compose exec -T ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate 2>&1)
code=$?
set -e
out=$(plain <<<"$out")
show <<<"$out"
[ "$code" -eq 0 ] || fail "init-ca.sh --switch-intermediate ended with $code"
expect 'switched: I2 signs from now on' "switched the intermediate: '$int2_name' \($i2\) signs from now on" "$out"
expect '... I1 stays in the handover' "the previous intermediate 'CN=SICK E2E Intermediate CA' \($i1\) stays in the handover" "$out"
expect '... the handover holds both' 'handed over intermediate_ca.crt: the new and the previous intermediate' "$out"
expect '... step-ca reloaded' 'step-ca reloads its configuration \(SIGHUP\)' "$out"
expect '... the copied directory is removed' 'removed /home/step/switch' "$out"
[ "$(docker inspect -f '{{.State.StartedAt}}' "$ca_id")" = "$started" ] || fail 'the CA was restarted'
pass 'the CA was not restarted'
in_ca sh -c 'step crypto key public /home/step/secrets/intermediate_ca_key --password-file /home/step/secrets/password' 2>/dev/null \
  | plain | cmp -s - <(openssl x509 -in "$work/gen2/intermediate_ca.crt" -noout -pubkey) \
  || fail 'the installed key is not the key of I2, or does not open with the password of the CA'
pass 'the installed key is the key of I2 and opens with the password the CA started with'
keys=$(in_ca sh -c 'grep -rl "PRIVATE KEY" /home/step /handover' 2>&1 | plain | sort)
show <<<"$keys"
[ "$keys" = $'/home/step/secrets/intermediate_ca_key\n/home/step/secrets/intermediate_ca_key.previous' ] \
  || fail 'private keys in the volumes other than the current and the previous intermediate key'
pass 'the only keys in the volumes: the intermediate key and the previous one (kept for the overlap)'

note 'a second switch during the overlap: refused'
compose cp "$work/gen2/." ca:/home/step/switch >/dev/null 2>&1 || fail 'docker compose cp'
set +e
out=$(compose exec -T ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate 2>&1)
code=$?
set -e
out=$(plain <<<"$out")
show <<<"$out"
[ "$code" -ne 0 ] || fail 'a second switch during the overlap went through'
expect 'refused: retire the previous one first' 'still in its overlap: retire it first' "$out"

#### 3. the overlap

step 'the overlap: devices under I1 stay, new issuance from I2, clients with the page accept both'
handover=$(in_ca cat /handover/intermediate_ca.crt | plain)
printf '%s\n' "$handover" >"$work/handover.pem"
[ "$(bundle_fps "$work/handover.pem" | tr '\n' ' ')" = "$i2 $i1 " ] || fail "the handover holds: $(bundle_fps "$work/handover.pem" | tr '\n' ' ')"
pass 'the handover intermediate_ca.crt holds I2, then I1'

run=$(sick_do run web)
show <<<"$run"
expect 'web, with a leaf under I1: unchanged, ok' '^web +unchanged +ok' "$run"
[ "$(fp_presented web web.example.internal)" = "$web_i1" ] || fail 'web presents another certificate'
pass '... and presents the same certificate'

run=$(sick_do run --force web2)
show <<<"$run"
expect 'web2, forced: renewed' '^web2 +renewed ' "$run"
expect '... from I2' "^$int2_name\$" "$(issuer_presented web2 web2.example.internal)"

out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
fetch_page overlap
[ "$(bundle_fps "$work/pages/overlap.pem" | tr '\n' ' ')" = "$r1 $i2 $i1 " ] \
  || fail "the page's ca_bundle.pem holds: $(bundle_fps "$work/pages/overlap.pem" | tr '\n' ' ')"
pass "the page's ca_bundle.pem holds R1, I2, I1"
judge 'web (leaf alone, under I1) with the page bundle' overlap.pem web web.example.internal accepted
judge 'web2 (leaf alone, under I2) with the page bundle' overlap.pem web2 web2.example.internal accepted
judge 'control: web2 (leaf alone) with root_ca.pem alone' overlap-root.pem web2 web2.example.internal refused

#### 4. retire

step 'retire the previous intermediate: web is foreign-ca, renewed from I2'
set +e
out=$(compose exec -T ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate 2>&1)
code=$?
set -e
out=$(plain <<<"$out")
show <<<"$out"
[ "$code" -eq 0 ] || fail "init-ca.sh --retire-intermediate ended with $code"
expect 'retired I1' "retired the previous intermediate 'CN=SICK E2E Intermediate CA' \($i1\)" "$out"
expect '... the handover holds I2 alone' 'handed over intermediate_ca.crt$' "$out"
in_ca cat /handover/intermediate_ca.crt | plain >"$work/handover.pem"
[ "$(bundle_fps "$work/handover.pem" | tr '\n' ' ')" = "$i2 " ] || fail 'the handover still holds more than I2'
refuse '... and the previous key is gone from the volume' 'previous' "$(in_ca find /home/step -name '*previous*' 2>&1 | plain)"

check=$(sick_do check)
show <<<"$check"
expect 'sick check: web is foreign-ca now' '^web +foreign-ca +yes' "$check"
expect '... web2 is ok' '^web2 +ok +no' "$check"
run=$(sick_do run)
show <<<"$run"
expect 'sick run renews web (foreign-ca)' '^web +renewed +foreign-ca' "$run"
expect '... web2 is unchanged' '^web2 +unchanged +ok' "$run"
# web3 sends its chain: the I1 it presents still leads to R1, and SICK
# judges a device by the root - it stays ok until it is due or forced
expect '... web3, which sends its chain (I1 included), stays ok' '^web3 +unchanged +ok' "$run"
record 'a device that sends the retired intermediate along stays ok while that intermediate is valid; after a compromise of it, sick run --force'
run=$(sick_do run --force web3)
show <<<"$run"
expect 'sick run --force web3: renewed' '^web3 +renewed ' "$run"
expect '... web is under I2 now' "^$int2_name\$" "$(issuer_presented web web.example.internal)"
out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
fetch_page retired
[ "$(bundle_fps "$work/pages/retired.pem" | tr '\n' ' ')" = "$r1 $i2 " ] \
  || fail "the page's ca_bundle.pem holds: $(bundle_fps "$work/pages/retired.pem" | tr '\n' ' ')"
pass "the page's ca_bundle.pem holds R1 and I2: I1 is gone"
judge 'web (leaf alone, renewed) with the new page bundle' retired.pem web web.example.internal accepted
# the client that will not follow the page during the root replacement
docker exec "$client" cp /pages/retired.pem /pages/old.pem

#### 5. root replacement, phase A: announce

step 'root replacement, phase A: the new root announced on the trust page'
cp "$work/gen3/root_ca.crt" "$work/secrets/root_ca_2.crt"
chmod 644 "$work/secrets/root_ca_2.crt"
write_list /etc/sick/secrets/root_ca_2.crt
note 'ca.additional_roots: [/etc/sick/secrets/root_ca_2.crt]; sick trust'
out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
page=$(in_sick 'cd /srv/trust && ls; for f in root_ca_2.pem; do [ -f $f ] && openssl x509 -in $f -noout -fingerprint -sha256; done' 2>&1 | plain)
show <<<"$page"
expect 'the page has root_ca_2.pem' '^root_ca_2\.pem$' "$page"
expect '... and root_ca_2.crt' '^root_ca_2\.crt$' "$page"
[ "$(sed -n 's/^sha256 Fingerprint=//p' <<<"$page" | tr -d : | tr 'A-F' 'a-f')" = "$r2" ] || fail 'root_ca_2.pem is not R2'
pass '... which is R2'
fetch_page a
[ "$(bundle_fps "$work/pages/a.pem" | tr '\n' ' ')" = "$r1 $r2 $i2 " ] \
  || fail "the page's ca_bundle.pem holds: $(bundle_fps "$work/pages/a.pem" | tr '\n' ' ')"
pass "the page's ca_bundle.pem holds R1 (current) first, then R2, then I2"
index=$(in_sick 'cat /srv/trust/index.html' 2>&1 | plain | sed 's/<br>//g' | tr -d ':' | tr 'A-F' 'a-f')
grep -q "$r1" <<<"$index" || fail 'index.html does not show the fingerprint of R1'
grep -q "$r2" <<<"$index" || fail 'index.html does not show the fingerprint of R2'
pass 'index.html shows the fingerprints of both roots'
run=$(sick_do run)
show <<<"$run"
for d in web web2 web3; do expect "sick run: $d unchanged, ok (the announcement changes nothing for the devices)" "^$d +unchanged +ok" "$run"; done

note 'the pilot: a leaf of the new hierarchy (signed with I3 directly), sent with its chain'
sign_leaf "$work/gen3" pilot.example.internal "$work/leaves/pilot-r2"
to_pilot "$work/leaves/pilot-r2"
judge 'phase A, page bundle: web (leaf alone, R1)' a.pem web web.example.internal accepted
judge 'phase A, page bundle: web3 (chain, R1)' a.pem web3 web3.example.internal accepted
judge 'phase A, page bundle: the pilot (chain, R2)' a.pem pilot pilot.example.internal accepted
judge 'phase A, the old page (R1 and I2 only): the pilot (R2)' old.pem pilot pilot.example.internal refused
judge 'phase A, the old page: web (R1), control' old.pem web web.example.internal accepted

#### 6. phase B: switch

step 'phase B: the CA on a new volume with the new hierarchy; re-issue every device'
cp "$work/gen1/root_ca.crt" "$work/secrets/root_ca_1.crt"
chmod 644 "$work/secrets/root_ca_1.crt"
note 'docker compose stop ca; SICK_CA_IMPORT=gen3, -f compose.ca-next.yml up -d --wait ca'
compose stop ca >/dev/null 2>&1
write_env "$work/gen3"
files=("${all_files[@]}")
compose up -d --wait ca >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca 2>&1 | tail -30 >&2; fail 'the new CA did not come up healthy'; }
pass 'the CA of the new hierarchy is up'
init=$(compose logs --no-log-prefix ca 2>&1 | plain | grep '^init-ca:' | tail -n 8)
show <<<"$init"
expect '... in import mode' '^init-ca: import mode: ' "$init"
expect '... on R2' "root fingerprint \(SHA-256\): $r2" "$init"
mounts=$(docker inspect -f '{{range .Mounts}}{{.Name}} {{.Destination}};{{end}}' "$(compose ps -q ca)")
expect '... on the volume ca-next' "${project}_ca-next /home/step;" "$mounts"
docker volume inspect "${project}_ca" >/dev/null 2>&1 || fail 'the old CA volume is gone'
[ -z "$(docker ps -aq --filter "volume=${project}_ca")" ] || fail 'a container still uses the old CA volume'
pass "the old CA volume ${project}_ca is kept, used by no container (planned rollback: start without compose.ca-next.yml)"
[ "$(in_ca cat /handover/root_ca.crt | plain | sha256_pem)" = "$r2" ] || fail 'the handover root is not R2'
pass 'the handover root (ca.root of the list) is R2 now'

write_list /etc/sick/secrets/root_ca_1.crt
note 'ca.additional_roots: [/etc/sick/secrets/root_ca_1.crt]; sick trust'
out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
fetch_page b
[ "$(bundle_fps "$work/pages/b.pem" | tr '\n' ' ')" = "$r2 $r1 $i3 " ] \
  || fail "the page's ca_bundle.pem holds: $(bundle_fps "$work/pages/b.pem" | tr '\n' ' ')"
pass "the page's ca_bundle.pem holds R2 (current) first, then R1, then I3"
judge 'phase B, page bundle: web3 (chain, still R1)' b.pem web3 web3.example.internal accepted
judge 'phase B, page bundle: the pilot (chain, R2)' b.pem pilot pilot.example.internal accepted
judge 'phase B before re-issue, page bundle: web (leaf alone, still R1/I2 - I2 is not on the page of B)' \
  b.pem web web.example.internal - record

run=$(sick_do run --force web)
show <<<"$run"
expect 'sick run --force web: renewed under the new CA' '^web +renewed ' "$run"
expect '... by I3' '^CN=SICK E2E Intermediate CA 2$' "$(issuer_presented web web.example.internal)"
judge 'phase B, page bundle: web (leaf alone, R2)' b.pem web web.example.internal accepted
judge 'phase B, page bundle: web3 (chain, R1), still' b.pem web3 web3.example.internal accepted
judge 'phase B, the old page (R1 and I2 only): web (R2)' old.pem web web.example.internal refused
judge 'phase B before its re-issue, phase A page bundle: web (leaf alone, R2 - I3 is not on the page of A)' \
  a.pem web web.example.internal - record

run=$(sick_do run --force)
show <<<"$run"
for d in web web2 web3; do expect "sick run --force: $d renewed" "^$d +renewed " "$run"; done
for d in web web2 web3; do
  expect "$d is under I3" '^CN=SICK E2E Intermediate CA 2$' "$(issuer_presented "$d" "$d.example.internal")"
done
run=$(sick_do run)
show <<<"$run"
for d in web web2 web3; do expect "convergence: a further run leaves $d unchanged, ok" "^$d +unchanged +ok" "$run"; done
out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
judge 'phase B, page bundle: web2 (leaf alone, R2)' b.pem web2 web2.example.internal accepted
judge 'phase B, page bundle: web3 (chain, R2)' b.pem web3 web3.example.internal accepted
judge 'phase B, the old page: web3 (R2)' old.pem web3 web3.example.internal refused

#### 7. phase C: retire the old root

step 'phase C: additional_roots emptied; a client takes the new page and drops the old root'
write_list ''
out=$(in_sick 'sick trust /srv/trust' 2>&1 | plain)
show <<<"$out"
refuse 'root_ca_2.* is gone from the page' '^root_ca_2\.' "$(in_sick 'ls /srv/trust' 2>&1 | plain)"
fetch_page c
[ "$(bundle_fps "$work/pages/c.pem" | tr '\n' ' ')" = "$r2 $i3 " ] \
  || fail "the page's ca_bundle.pem holds: $(bundle_fps "$work/pages/c.pem" | tr '\n' ' ')"
pass "the page's ca_bundle.pem holds R2 and I3: R1 is gone"
note 'the pilot: a leaf of the old hierarchy (signed with I2 directly), sent with its chain'
sign_leaf "$work/gen2" pilot.example.internal "$work/leaves/pilot-r1"
to_pilot "$work/leaves/pilot-r1"
judge 'phase C, new page: the pilot (chain, old root R1)' c.pem pilot pilot.example.internal refused
judge 'phase C, new page: web (leaf alone, R2)' c.pem web web.example.internal accepted
judge 'phase C, new page: web3 (chain, R2)' c.pem web3 web3.example.internal accepted
judge 'phase C, the old page: web2 (R2)' old.pem web2 web2.example.internal refused
judge 'phase C, the old page: the pilot (R1), control' old.pem pilot pilot.example.internal accepted
record "clients: $(tr '\n' ';' <<<"$versions")"

# 8. runs in the EXIT trap
