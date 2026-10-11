#!/bin/bash
#
# End-to-end proof of the Docker setup against a real switch.
#
# Builds the image, starts a brand-new step-ca, has SICK put a certificate of
# that CA onto a Cisco Small Business switch, and checks every link of the
# chain: the CA sets itself up once and only once, the switch is found due,
# renewed and then left alone, the trust page serves root and intermediate
# of the CA - and what it serves is enough for a client to accept the switch,
# which presents its certificate alone -, the schedule runs, and a stop in
# the middle of a run leaves no key behind.
#
# THIS CHANGES THE SWITCH: its HTTPS certificate is replaced and its running
# configuration is saved (which saves everything unsaved on it). And it
# DESTROYS the Compose project it works on, volumes and CA included, to
# start from nothing. Point it at a test switch and at a project of its own.
#
# Prerequisites, on the machine this script runs on:
#
# - Docker Engine 25 or newer with the Compose plugin and BuildKit (run
#   with 26.1 and Compose 2.26), openssl, curl; the network reaches the
#   switch on ports 22 and 443, and the internet for images and packages
# - the three source trees side by side:   <dir>/sick   <dir>/sick-target-ciscosb   <dir>/sick-target-proxmox
# - a credentials file for the switch - line 1 user, line 2 password -
#   readable by its owner only and outside <dir>
#
# Parameters, all from the environment:
#
#   SICK_E2E_SWITCH_HOST         address of the switch                (required)
#   SICK_E2E_SWITCH_NAMES        names for its certificate, comma
#                                separated, the address included      (required)
#   SICK_E2E_SWITCH_CREDENTIALS  path of the credentials file         (required)
#   SICK_E2E_SWITCH_DEVICE       name of the switch in the device list (switch)
#   SICK_E2E_DIR                 private working directory for the generated
#                                device lists; created with mode 0700
#                                                          ($HOME/sick-e2e)
#   SICK_E2E_PROJECT             Compose project name              (sick-e2e)
#   SICK_E2E_CA_NAME             name of the CA                 (SICK E2E CA)
#   SICK_E2E_CA_DNS              further names of the CA, comma separated  ()
#   SICK_E2E_CA_PORT             published port of the CA              (9000)
#   SICK_E2E_TRUST_PORT          published port of the trust page      (8080)
#   SICK_E2E_INTERVAL            SICK_INTERVAL of the stack that is left
#                                running at the end                      (1d)
#   SICK_E2E_DOWN                "yes": take the stack down at the end   (no)
#
# Nothing secret is printed: the credentials file is only ever named. The
# output does show the names and the address of the switch.
#
# Example:
#
#   SICK_E2E_SWITCH_HOST=192.0.2.10 \
#   SICK_E2E_SWITCH_NAMES=switch.example.internal,192.0.2.10 \
#   SICK_E2E_SWITCH_CREDENTIALS=/root/secrets/switch.cred \
#   t/e2e/run-lab.sh

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

host=${SICK_E2E_SWITCH_HOST:-}
names=${SICK_E2E_SWITCH_NAMES:-}
credentials=${SICK_E2E_SWITCH_CREDENTIALS:-}
device=${SICK_E2E_SWITCH_DEVICE:-switch}
work=${SICK_E2E_DIR:-$HOME/sick-e2e}
project=${SICK_E2E_PROJECT:-sick-e2e}
ca_name=${SICK_E2E_CA_NAME:-SICK E2E CA}
ca_port=${SICK_E2E_CA_PORT:-9000}
trust_port=${SICK_E2E_TRUST_PORT:-8080}
final_interval=${SICK_E2E_INTERVAL:-1d}

step_no=0
step() { step_no=$((step_no + 1)); printf '\n=== %s. %s\n' "$step_no" "$*"; }
note() { printf -- '--- %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

# expect <what> <extended regular expression> <text>
expect() {
  if grep -Eq -- "$2" <<<"$3"; then pass "$1"; else
    printf '%s\n' "$3" | sed 's/^/      | /' >&2
    fail "$1 (expected /$2/)"
  fi
}
# refuse <what> <extended regular expression> <text>
refuse() {
  if grep -Eq -- "$2" <<<"$3"; then
    printf '%s\n' "$3" | sed 's/^/      | /' >&2
    fail "$1 (found /$2/)"
  else pass "$1"; fi
}
# wait_for <seconds> <what> <command ...>: until the command succeeds
wait_for() {
  local seconds=$1 what=$2 start=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    [ $((SECONDS - start)) -lt "$seconds" ] || fail "waited ${seconds}s for $what"
    sleep 2
  done
}
# docker compose decorates what it prints with control sequences, piped or not
plain() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r'; }
show() { plain | sed 's/^/    /'; }

#### prerequisites

[ -n "$host" ] && [ -n "$names" ] && [ -n "$credentials" ] \
  || fail 'set SICK_E2E_SWITCH_HOST, SICK_E2E_SWITCH_NAMES and SICK_E2E_SWITCH_CREDENTIALS (see the top of this file)'
[[ $device =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || fail "SICK_E2E_SWITCH_DEVICE '$device' is not a device name"
[[ $host =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || fail "SICK_E2E_SWITCH_HOST '$host' is not a host name or address"
[[ $names =~ ^[A-Za-z0-9*][A-Za-z0-9.:*,-]*$ ]] || fail 'SICK_E2E_SWITCH_NAMES is not a comma separated list of names'
for program in docker openssl curl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
# the project is what this script destroys; on a shared Docker host it is sick-*
[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick or sick-*"
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
[ -d "$context/sick-target-proxmox/lib" ] || fail "no checkout of sick-target-proxmox next to $repo"
[ -f "$credentials" ] && [ -r "$credentials" ] || fail "cannot read the credentials file $credentials"
credentials=$(cd "$(dirname "$credentials")" && pwd)/$(basename "$credentials")
[ "$(stat -c '%a' "$credentials")" = 600 ] || [ "$(stat -c '%a' "$credentials")" = 400 ] \
  || fail "$credentials is readable by others: chmod 600"
case $credentials/ in "$context"/*) fail "$credentials lies inside the build context $context" ;; esac

mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
umask 077

# the first host name among the names: what a browser would ask for
sni=
IFS=, read -ra name_list <<<"$names"
for name in "${name_list[@]}"; do
  if [[ ! $name =~ ^[0-9.]+$ && $name != *:* ]]; then sni=$name; break; fi
done

cat >"$work/sick.yml" <<EOF
# Generated by t/e2e/run-lab.sh. Private: it names a real device.
ca:
  name: $ca_name
  url: https://ca:9000
  root: /etc/sick/ca/root_ca.crt
  intermediates: /etc/sick/ca/intermediate_ca.crt
  provisioner: sick
  password_file: /etc/sick/ca/provisioner.pw
devices:
  $device:
    type: cisco-sb
    host: $host
    names: [${names//,/, }]
    credentials: /etc/sick/secrets/$(basename "$credentials")
    legacy_algorithms: true
    host_key_check: accept-new
EOF

# For step 7: a "device" that is always due and whose deployment takes two
# minutes, so that a stop is certain to hit a run that holds a fresh key.
# SICK looks at the port of the CA itself, which presents a certificate of
# this CA under other names; the localcopy hook of acme.sh copies the
# certificate (not the key) into the state volume and then sleeps.
cat >"$work/held.yml" <<EOF
# Generated by t/e2e/run-lab.sh for the stop test. No real device in here.
ca:
  url: https://ca:9000
  root: /etc/sick/ca/root_ca.crt
  intermediates: /etc/sick/ca/intermediate_ca.crt
  provisioner: sick
  password_file: /etc/sick/ca/provisioner.pw
devices:
  held:
    type: acmesh
    hook: localcopy
    host: ca
    port: 9000
    names: [held.example.internal]
    lifetime: 1h
    renew_before: 10m
    env:
      DEPLOY_LOCALCOPY_FULLCHAIN: /var/lib/sick/e2e-held-fullchain.pem
      DEPLOY_LOCALCOPY_RELOADCMD: sleep 120
EOF

cat >"$work/compose.env" <<EOF
# Generated by t/e2e/run-lab.sh: the settings of the stack it leaves running.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$(dirname "$credentials")
SICK_CA_NAME=$ca_name
SICK_CA_DNS=${SICK_E2E_CA_DNS:-}
SICK_CA_PORT=$ca_port
SICK_TRUST_PORT=$trust_port
SICK_INTERVAL=$final_interval
EOF

# Only what this script sets may reach the compose file: the environment
# wins over the env file.
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ALLOW_EMAIL SICK_CA_ALLOW_URI SICK_TRUST_PORT SICK_INTERVAL \
  SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION

compose() { docker compose --env-file "$work/compose.env" -p "$project" -f "$repo/docker/compose.yml" "$@"; }
in_ca() { compose exec -T ca "$@"; }
sick_logs() { compose logs --no-log-prefix sick 2>&1 | plain; }
ca_init_log() { compose logs --no-log-prefix "$@" ca 2>&1 | plain | grep '^init-ca:' || true; }

printf 'project %s, working directory %s, switch %s as device "%s"\n' "$project" "$work" "$host" "$device"

#### 1. from nothing

step 'build, and start the CA from nothing'
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
note 'docker compose build'
compose build >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
pass 'the image is built from the three source trees'
note 'what is in it'
inside=$(compose run --rm --no-deps -T sick sh -c '
  sick --version
  perl -MSICK::Target::CiscoSB -e "print qq{SICK::Target::CiscoSB }, SICK::Target::CiscoSB->VERSION, qq{\n}"
  step version | head -n 1
  printf "acme.sh %s, %s deploy hooks next to it\n" "$(acme.sh --version | tail -n 1)" "$(ls "$(dirname "$(readlink -f "$(command -v acme.sh)")")"/deploy/*.sh | wc -l)"
  openssl version
  ssh -V 2>&1
  printf "cron: %s\n" "$(command -v cron crond crontab || echo none)"
' 2>&1 | plain)
show <<<"$inside"
expect 'sick, the Cisco target, step, acme.sh with its hooks, openssl and ssh are there' 'deploy hooks next to it' "$inside"
expect 'no cron in the image' '^cron: none$' "$inside"

note 'docker compose up -d --wait ca trust'
compose up -d --wait ca trust >/dev/null 2>&1 || { compose logs ca 2>&1 | tail -20 >&2; fail 'the CA did not come up healthy'; }
first=$(ca_init_log)
show <<<"$first"
expect 'init-ca.sh made the CA' "making '$ca_name'" "$first"
expect '... with the JWK provisioner and the ACME provisioner' "JWK provisioner 'sick', ACME provisioner 'acme'" "$first"
expect '... and raised the lifetime the provisioner grants' "configuration updated: 'sick' grants up to 19800h" "$first"
expect '... and handed root, intermediate and password to the sick service' 'handed over provisioner.pw' "$first"
provisioners=$(in_ca jq -c '[.authority.provisioners[] | {type, name, max: .claims.maxTLSCertDuration}]' /home/step/config/ca.json)
show <<<"$provisioners"
expect 'ca.json: JWK provisioner sick with 19800h (825 days)' '"type":"JWK","name":"sick","max":"19800h"' "$provisioners"
expect 'ca.json: an ACME provisioner' '"type":"ACME"' "$provisioners"
fingerprint=$(in_ca step certificate fingerprint /home/step/certs/root_ca.crt | tr -d '\r\n')
[[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || fail 'cannot read the fingerprint of the root'
note "root fingerprint $fingerprint"

#### 2. a second start

step 'a second start changes nothing'
state() { in_ca sh -c 'cat /home/step/config/ca.json /home/step/certs/*.crt /handover/* | sha256sum; ls /home/step/secrets | sort | tr "\n" " "'; }
before=$(state)
container=$(compose ps -q ca)
started=$(docker inspect -f '{{.State.StartedAt}}' "$container")
note 'docker compose up -d ca trust (again)'
compose up -d ca trust 2>&1 | show
[ "$(compose ps -q ca)" = "$container" ] && [ "$(docker inspect -f '{{.State.StartedAt}}' "$container")" = "$started" ] \
  || fail 'the second "up" restarted the CA'
pass 'the second "up" leaves the running CA alone'
note 'docker compose restart ca: init-ca.sh runs again'
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose restart ca >/dev/null 2>&1
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
second=$(ca_init_log --since "$since")
show <<<"$second"
expect 'init-ca.sh finds the CA' 'exists: nothing to make' "$second"
expect '... and its configuration as it should be' 'configuration unchanged' "$second"
refuse '... and hands nothing over again' 'handed over|making|updated' "$second"
[ "$(state)" = "$before" ] || fail 'configuration, certificates or handed over files changed'
pass 'ca.json, the certificates, the handed over files and the secrets directory are the same as before'
[ "$(in_ca step certificate fingerprint /home/step/certs/root_ca.crt | tr -d '\r\n')" = "$fingerprint" ] || fail 'the root changed'
pass 'the root fingerprint is the same'

#### 3. check

step "sick check: the switch is due"
note 'docker compose run --rm sick sick check'
set +e
check=$(compose run --rm -T sick sick check 2>&1 | plain)
code=$?
set -e
show <<<"$check"
[ "$code" -eq 0 ] || fail "sick check ended with $code"
expect "the certificate of the switch is not from this CA" "^$device +foreign-ca +yes +issued by " "$check"
refuse 'the detail is readable: no backslash' '\\' "$check"

#### 4. run

step "sick run $device: the switch gets a certificate of the CA"
note "docker compose run --rm sick sick run --verbose $device"
set +e
run=$(compose run --rm -T sick sick run --verbose "$device" 2>&1 | plain)
code=$?
set -e
show <<<"$run"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'renewed' "^$device +renewed +foreign-ca" "$run"
refuse 'ssh stored the host key of the switch' 'Failed to add the host' "$run"
known=$(compose run --rm -T sick sh -c 'wc -l </var/lib/sick/known_hosts' 2>/dev/null | plain | tr -d '\n ')
[ "${known:-0}" -ge 1 ] || fail 'no host key in /var/lib/sick/known_hosts'
pass "the host key of the switch is pinned in the state volume ($known line)"

note "what $host:443 presents now, seen from this machine with openssl s_client"
in_ca cat /home/step/certs/root_ca.crt >"$work/root_ca.crt"
in_ca cat /home/step/certs/intermediate_ca.crt >"$work/intermediate_ca.crt"
presented() {
  openssl s_client -connect "$host:443" ${sni:+-servername "$sni"} -showcerts </dev/null 2>/dev/null
}
handshake=$(presented)
sent=$(grep -c 'BEGIN CERTIFICATE' <<<"$handshake" || true)
openssl x509 <<<"$handshake" >"$work/presented.pem" || fail "no certificate from $host:443"
facts=$(openssl x509 -in "$work/presented.pem" -noout -subject -issuer -enddate -ext subjectAltName 2>&1)
show <<<"$facts"
expect 'issued by the intermediate of the new CA' "issuer=.*CN ?= ?$ca_name Intermediate CA" "$facts"
for name in "${name_list[@]}"; do
  if [[ $name =~ ^[0-9.]+$ || $name == *:* ]]; then
    expect "IP address $name" "IP Address:${name//./\\.}(,|\$)" "$facts"
  else
    expect "DNS name $name" "DNS:${name//./\\.}(,|\$)" "$facts"
  fi
done
wanted=$(tr ',' '\n' <<<"$names" | grep -c .)
have=$(grep -Eo '(DNS|IP Address):' <<<"$facts" | grep -c . || true)
[ "$have" -eq "$wanted" ] || fail "the certificate has $have names, the list has $wanted"
pass "exactly the $wanted names of the list"
note "the switch sends $sent certificate(s) in the handshake"
verify=$(openssl verify -no-CApath -no-CAstore -CAfile "$work/root_ca.crt" -untrusted "$work/intermediate_ca.crt" "$work/presented.pem" 2>&1 || true)
show <<<"$verify"
expect 'openssl verify: root as anchor, intermediate as help -> OK' ': OK$' "$verify"
alone=$(openssl verify -no-CApath -no-CAstore -CAfile "$work/root_ca.crt" "$work/presented.pem" 2>&1 || true)
if grep -q ': OK$' <<<"$alone"; then
  note 'with the root alone: OK as well (the device sends the intermediate along)'
else
  note 'with the root alone: fails, the switch sends no intermediate - which is what ca.intermediates is for:'
  show <<<"$alone"
fi

#### 5. again

step 'a second run changes nothing'
note 'docker compose run --rm sick sick run'
set +e
again=$(compose run --rm -T sick sick run 2>&1 | plain)
code=$?
set -e
show <<<"$again"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'unchanged' "^$device +unchanged +ok" "$again"
note 'docker compose run --rm sick sick check'
check=$(compose run --rm -T sick sick check 2>&1 | plain)
show <<<"$check"
expect 'ok, no renewal due' "^$device +ok +no +valid until " "$check"
after=$(presented | openssl x509 -noout -fingerprint -sha256)
[ "$after" = "$(openssl x509 -in "$work/presented.pem" -noout -fingerprint -sha256)" ] || fail 'the switch presents another certificate'
pass 'the switch still presents the same certificate'

#### 6. the schedule, and the trust page it keeps up

step 'the schedule: sick run every 20 seconds, sick trust after every run'
note 'SICK_INTERVAL=20s docker compose up -d sick'
SICK_INTERVAL=20s compose up -d sick >/dev/null 2>&1
two_runs() { [ "$(sick_logs | grep -c 'entrypoint: sick run: exit')" -ge 2 ]; }
wait_for 180 'two scheduled runs' two_runs
log=$(sick_logs)
show <<<"$log"
expect 'the entrypoint announces the schedule' 'entrypoint: sick run --verbose every 20s \(20s\)' "$log"
[ "$(grep -Ec "^$device +unchanged +ok" <<<"$log")" -ge 2 ] || fail 'fewer than two scheduled runs with the switch unchanged'
pass 'two scheduled runs, the switch unchanged in both'
[ "$(grep -c '^wrote root_ca.pem, root_ca.crt, intermediate_ca.pem, intermediate_ca.crt, ca_bundle.pem, root_ca.mobileconfig, index.html to /srv/trust' <<<"$log")" -ge 2 ] \
  || fail 'sick trust did not run after every run, or did not write the intermediate'
pass 'sick trust after each of them: root, intermediate, bundle, profile and page'
expect 'the pause is the interval' 'entrypoint: next run in 20s' "$log"

step 'the trust page serves what a client needs: root, intermediate, bundle, profile'
base=http://localhost:$trust_port
trust_files='index.html root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca.crt ca_bundle.pem root_ca.mobileconfig'
for file in $trust_files; do
  head=$(curl -fsS -o "$work/trust-$file" -D - "$base/$file" | tr -d '\r') || fail "GET $base/$file"
  printf '%s  %s  %s bytes\n' "$base/$file" "$(grep -i '^content-type:' <<<"$head" | tr -s ' ')" "$(stat -c %s "$work/trust-$file")" | show
done
curl -fsS -o /dev/null "$base/" || fail "GET $base/"
pass "index.html (also as /) and ${trust_files#index.html } are served"
sha256_of() { openssl x509 "$@" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
served=$(sha256_of -in "$work/trust-root_ca.pem")
note "SHA-256 of the served root_ca.pem: $served"
[ "$served" = "$fingerprint" ] || fail "the served root has another fingerprint than the CA ($fingerprint)"
pass 'root_ca.pem has the fingerprint of the root of the CA'
[ "$(sha256_of -inform DER -in "$work/trust-root_ca.crt")" = "$fingerprint" ] || fail 'root_ca.crt is not the same certificate in DER'
pass 'root_ca.crt is the same certificate in DER'
intermediate=$(in_ca step certificate fingerprint /home/step/certs/intermediate_ca.crt | tr -d '\r\n')
[[ $intermediate =~ ^[0-9a-f]{64}$ ]] || fail 'cannot read the fingerprint of the intermediate'
note "SHA-256 of the intermediate of the CA: $intermediate"
[ "$(sha256_of -in "$work/trust-intermediate_ca.pem")" = "$intermediate" ] || fail 'the served intermediate_ca.pem is not the intermediate of the CA'
[ "$(sha256_of -inform DER -in "$work/trust-intermediate_ca.crt")" = "$intermediate" ] || fail 'intermediate_ca.crt is not the same certificate in DER'
pass 'intermediate_ca.pem is the intermediate of the CA, intermediate_ca.crt the same in DER'
[ "$(grep -c 'BEGIN CERTIFICATE' "$work/trust-ca_bundle.pem")" -eq 2 ] || fail 'ca_bundle.pem does not hold two certificates'
cmp -s "$work/trust-ca_bundle.pem" <(cat "$work/trust-root_ca.pem" "$work/trust-intermediate_ca.pem") \
  || fail 'ca_bundle.pem is not the served root followed by the served intermediate'
pass 'ca_bundle.pem is the two of them in one file'
refuse 'no key is served' 'PRIVATE KEY' "$(cat "$work"/trust-*.pem "$work/trust-index.html" "$work/trust-root_ca.mobileconfig")"
grep -q 'com.apple.security.root' "$work/trust-root_ca.mobileconfig" || fail 'root_ca.mobileconfig is no root certificate profile'
grep -q 'com.apple.security.pkcs1' "$work/trust-root_ca.mobileconfig" || fail 'root_ca.mobileconfig does not carry the intermediate'
colons=$(sed 's/../&:/g; s/:$//' <<<"$fingerprint" | tr 'a-f' 'A-F')
# the page breaks the fingerprint into two lines
sed 's/<br>//g' "$work/trust-index.html" | grep -qi -e "$fingerprint" -e "$colons" || fail 'index.html does not show the fingerprint'
grep -q 'href="intermediate_ca.crt"' "$work/trust-index.html" || fail 'index.html does not offer the intermediate'
pass 'the profile carries the root and the intermediate, the page shows the fingerprint and offers both'
expect 'the profile is served as a configuration profile' 'application/x-apple-aspen-config' \
  "$(curl -fsS -o /dev/null -D - "$base/root_ca.mobileconfig")"

step 'a client that has what the page serves, and nothing else, accepts the switch'
# What a browser does: connect, take what the switch sends, and build the
# chain from what is installed - here one file from the trust page, with
# the certificate stores of this machine kept out.
if [[ $host =~ ^[0-9.]+$ || $host == *:* ]]; then name_check=(-verify_ip "$host"); else name_check=(-verify_hostname "$host"); fi
verdict() {
  { openssl s_client -connect "$host:443" ${sni:+-servername "$sni"} -CAfile "$1" -no-CApath -no-CAstore \
      "${name_check[@]}" </dev/null 2>/dev/null || true; } | grep -m 1 'Verify return code:' | sed 's/^ *//' || true
}
note "openssl s_client -connect $host:443 -CAfile ca_bundle.pem -no-CApath -no-CAstore ${name_check[*]}"
with_bundle=$(verdict "$work/trust-ca_bundle.pem")
show <<<"$with_bundle"
expect 'with ca_bundle.pem from the trust page: the chain is built and the name fits' '^Verify return code: 0 \(ok\)$' "$with_bundle"
note 'the same with -CAfile root_ca.pem'
with_root=$(verdict "$work/trust-root_ca.pem")
show <<<"$with_root"
if [ "$sent" -eq 1 ]; then
  refuse 'with root_ca.pem alone it is refused: the switch sends no intermediate, the client has to have it' '^Verify return code: 0 ' "$with_root"
  expect '... and for that reason, not for another' 'Verify return code: (20|21) ' "$with_root"
else
  note "the switch sends $sent certificates: the root alone may do here"
fi

#### 7. a stop in the middle of a run

step 'docker compose stop in the middle of a run'
note 'the sick service with a device list whose one "device" is always due and takes two minutes to deploy'
SICK_CONFIG_FILE=$work/held.yml SICK_INTERVAL=1h compose up -d sick >/dev/null 2>&1
hook_running() { sick_logs | grep -q 'held: running acme.sh'; }
key_on_disk() { compose exec -T sick sh -c 'ls /tmp/sick-*/held.example.internal/held.example.internal.key'; }
wait_for 120 'the run to reach the deployment' hook_running
wait_for 30 'the key file of the deployment' key_on_disk
note 'in /tmp of the container while the hook sleeps (names and modes only):'
compose exec -T sick sh -c 'cd /tmp && find . -mindepth 1 -printf "%M %p\n" | sort -k2' | show
note 'docker compose stop sick'
start=$SECONDS
compose stop sick >/dev/null 2>&1
note "stopped after $((SECONDS - start))s"
log=$(sick_logs | sed -n '/entrypoint: sick run --verbose every 1h/,$p')
show <<<"$log"
expect 'the entrypoint passes the signal on to the running sick' 'entrypoint: received TERM, sending TERM to sick \(pid [0-9]+\)' "$log"
expect 'sick ends through its own handler' 'entrypoint: sick run ended with exit code 143' "$log"
expect 'no temporary directory, no key is left' 'entrypoint: stopped by TERM; nothing is left in /tmp' "$log"
refuse '... says the entrypoint, which looks' 'LEFT BEHIND' "$log"
exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$(compose ps -aq sick)")
[ "$exit_code" = 0 ] || fail "the container ended with $exit_code"
pass 'the container ended with exit code 0'
# what the hook copied before it went to sleep: a certificate, no key
compose run --rm --no-deps -T sick rm -f /var/lib/sick/e2e-held-fullchain.pem >/dev/null 2>&1 || true

#### the end

if [ "${SICK_E2E_DOWN:-no}" = yes ]; then
  step 'take everything down'
  compose down --volumes --remove-orphans >/dev/null 2>&1
  pass 'containers and volumes are gone; the switch keeps its certificate'
else
  step "leave the stack running: the real device list, sick run every $final_interval"
  compose up -d sick >/dev/null 2>&1
  first_run_done() { sick_logs | sed -n "/every $final_interval /,\$p" | grep -q 'entrypoint: next run in'; }
  wait_for 120 'the first run' first_run_done
  log=$(sick_logs | sed -n "/every $final_interval /,\$p")
  show <<<"$log"
  expect 'the switch is unchanged' "^$device +unchanged +ok" "$log"
  compose ps 2>&1 | show
  printf '\nThe stack "%s" is running. To work with it:\n' "$project"
  printf '  docker compose --env-file %s -p %s -f %s <command>\n' "$work/compose.env" "$project" "$repo/docker/compose.yml"
  printf 'CA:          https://<this host>:%s   (root fingerprint %s)\n' "$ca_port" "$fingerprint"
  printf 'Trust page:  http://<this host>:%s/\n' "$trust_port"
fi

printf '\nALL STEPS PASSED\n'
