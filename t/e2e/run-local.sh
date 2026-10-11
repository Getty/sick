#!/bin/bash
#
# End-to-end proof of the Docker setup, with Docker and nothing else.
#
# The same proof as run-lab.sh, but the "device" is a container of the same
# Compose project instead of a switch: "web" serves over TLS whatever a
# SICK files device writes into a shared volume (t/e2e/web-serve.sh, the
# override t/e2e/compose.local.yml). docker/compose.yml is used as shipped.
#
# What it proves, each step with PASS/FAIL lines and an exit code of 1 on
# the first FAIL:
#
#   1. from nothing: build, up; the CA sets itself up and is healthy
#   2. sick check: the device is not presented with a certificate of this CA
#   3. sick run renews it; seen from a container of the network with
#      openssl s_client against the ca_bundle.pem of the trust page: verified,
#      the names are exactly the ones listed, it is the certificate written
#   4. a second sick run changes nothing
#   5. the schedule writes the trust page; it serves index.html, root_ca.pem,
#      intermediate_ca.pem, ca_bundle.pem; the root on it has the fingerprint
#      init-ca.sh logged; curl --cacert root_ca.pem reaches the CA
#   6. restarting the CA changes nothing
#   7. teardown, also after a failure or Ctrl-C: the project is taken down
#      with its volumes, what is left of it with the label sick=1 is
#      removed by that label, and no container, volume or network of the
#      project is left (every one of them carries sick=1, checked in step 1)
#
# It DESTROYS the Compose project it works on (default sick-e2e), volumes
# and CA included. It touches nothing else: no other project, no prune.
# The image sick:local (built from this checkout and ../sick-target-ciscosb)
# stays; it is a cache.
#
# Prerequisites: Docker Engine with the Compose plugin and BuildKit, openssl
# and curl on this machine; the two source trees side by side
# (<dir>/sick, <dir>/sick-target-ciscosb); the internet for images and
# packages at the first build. Run with Compose 2.26.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR         private working directory; created with mode 0700;
#                        keep it out of shared places, it holds the CA's
#                        public certificates  ($HOME/.local/share/sick-lab/e2e)
#   SICK_E2E_PROJECT     Compose project name                       (sick-e2e)
#   SICK_E2E_CA_PORT     port of the CA on 127.0.0.1                    (19000)
#   SICK_E2E_TRUST_PORT  port of the trust page on 127.0.0.1            (18080)
#   SICK_E2E_KEEP        "yes": keep the working directory at the end       (no)
#
# Ports are published on 127.0.0.1 only. Nothing secret is printed or
# written to the working directory; the CA's keys and the provisioner
# password stay in Docker volumes.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/e2e}
project=${SICK_E2E_PROJECT:-sick-e2e}
ca_port=${SICK_E2E_CA_PORT:-19000}
trust_port=${SICK_E2E_TRUST_PORT:-18080}
keep=${SICK_E2E_KEEP:-no}

ca_name='SICK E2E Local CA'
device=web
device_names='web.example.internal web'

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

for program in docker openssl curl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
# what this script creates and destroys is found by its project; on a shared
# Docker host that project is sick-*
[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick or sick-*"
[[ $ca_port =~ ^[0-9]+$ && $trust_port =~ ^[0-9]+$ ]] || fail 'SICK_E2E_CA_PORT and SICK_E2E_TRUST_PORT are port numbers'
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"

umask 077
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
mkdir -p "$work/secrets"    # SICK_SECRETS_DIR: empty, no device here has a credential
# sick runs as root without CAP_DAC_OVERRIDE (cap_drop: ALL): it reads what
# its owner or everybody may read. Here the owner is whoever runs this
# script, so the list (public: neutral names) and the empty directory are
# readable by all; the working directory itself stays 0700.
chmod 755 "$work/secrets"

# ports are free? (a connect that succeeds means somebody listens)
for port in "$ca_port" "$trust_port"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "port $port on 127.0.0.1 is in use: set SICK_E2E_CA_PORT / SICK_E2E_TRUST_PORT"
  fi
done

cat >"$work/sick.yml" <<EOF
# Generated by t/e2e/run-local.sh. Neutral names only.
ca:
  name: $ca_name
  url: https://ca:9000
  root: /etc/sick/ca/root_ca.crt
  intermediates: /etc/sick/ca/intermediate_ca.crt
  provisioner: sick
  password_file: /etc/sick/ca/provisioner.pw
defaults:
  lifetime: 397d
  renew_before: 30d
  key: rsa2048
devices:
  $device:
    type: files
    host: web
    port: 443
    names: [${device_names// /, }]
    dir: /srv/device
EOF
chmod 644 "$work/sick.yml"

cat >"$work/compose.env" <<EOF
# Generated by t/e2e/run-local.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=$ca_name
SICK_CA_PORT=127.0.0.1:$ca_port
SICK_TRUST_PORT=127.0.0.1:$trust_port
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
EOF

# Only what this script sets may reach the compose files: the environment
# wins over the env file.
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_TRUST_PORT SICK_INTERVAL \
  SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE \
  SICK_CA_ACME_CHALLENGES SICK_CA_PROVISIONERS SICK_CA_PROVISIONERS_FILE

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$here/compose.local.yml" "$@"
}
in_ca() { compose exec -T ca "$@"; }
# a command in a fresh sick container: no schedule, no CA as dependency
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
sick_logs() { compose logs --no-log-prefix sick 2>&1 | plain; }
ca_init_log() { compose logs --no-log-prefix "$@" ca 2>&1 | plain | grep '^init-ca:' || true; }

#### 7. teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== 7. teardown\n'
  if [ -n "$armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | plain | sed 's/^/    /'
    # what is left of the project and carries sick=1: by those labels
    docker ps -aq --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f -v >/dev/null 2>&1
    docker volume ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
    docker network ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
    left=$(
      docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]" | sed 's/^/container /'
      docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
      docker network ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/network /'
      docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container id /'
      docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
      docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network /'
    )
    if [ -n "$left" ]; then
      printf '%s\n' "$left" | sed 's/^/      | /' >&2
      printf 'FAIL  left behind by project %s (listed above)\n' "$project" >&2
      rc=1
    else
      pass "no container, volume or network named ${project}-* or ${project}_* is left"
    fi
    note 'the image sick:local (and the pulled step-ca and busybox images) stay as a cache'
  fi
  if [ "$keep" = yes ]; then
    note "working directory $work kept (SICK_E2E_KEEP=yes)"
  else
    # only what this script made; the directory itself goes when it is empty
    rm -f "${work:?}"/{sick.yml,compose.env,build.log,up.log,trust-index.html,trust-root_ca.pem,trust-intermediate_ca.pem,trust-ca_bundle.pem}
    rmdir "${work:?}/secrets" "${work:?}" 2>/dev/null
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'project %s, working directory %s, CA on 127.0.0.1:%s, trust page on 127.0.0.1:%s\n' \
  "$project" "$work" "$ca_port" "$trust_port"

#### 1. from nothing

step 'from nothing: build, up, the CA sets itself up'
armed=yes
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
note 'docker compose build'
compose build >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
pass 'the image is built from the two source trees'
note 'docker compose up -d --wait ca trust web'
compose up -d --wait ca trust web >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca web 2>&1 | tail -20 >&2; fail 'the stack did not come up healthy'; }
pass 'ca, trust and web are up and healthy'
first=$(ca_init_log)
show <<<"$first"
expect 'init-ca.sh made the CA' "making '$ca_name'" "$first"
expect '... with the JWK provisioner and the ACME provisioner' "JWK provisioner 'sick', ACME provisioner 'acme'" "$first"
expect '... and handed root, intermediate and password to the sick service' 'handed over provisioner.pw' "$first"
fingerprint=$(sed -n 's/^init-ca: root fingerprint (SHA-256): \([0-9a-f]\{64\}\).*/\1/p' <<<"$first" | head -n 1)
[[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || fail 'init-ca.sh logged no root fingerprint'
note "root fingerprint $fingerprint"
[ "$(in_ca step certificate fingerprint /home/step/certs/root_ca.crt | tr -d '\r\n')" = "$fingerprint" ] \
  || fail 'the root in the CA volume has another fingerprint than the one logged'
pass 'the root in the CA volume is the one logged'
hosts=$(docker inspect -f '{{range .NetworkSettings.Ports}}{{range .}}{{.HostIp}} {{end}}{{end}}' "$(compose ps -q ca)" "$(compose ps -q trust)" | tr -d '\n')
[ "$hosts" = '127.0.0.1 127.0.0.1 ' ] || fail "published on: $hosts (not 127.0.0.1 only)"
pass 'the CA and the trust page are published on 127.0.0.1 only'
unlabelled=$(
  for c in $(docker ps -aq --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker inspect -f '{{index .Config.Labels "sick"}}' "$c")" = 1 ] || docker inspect -f 'container {{.Name}}' "$c"
  done
  for v in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker volume inspect -f '{{index .Labels "sick"}}' "$v")" = 1 ] || echo "volume $v"
  done
  for n in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker network inspect -f '{{index .Labels "sick"}}' "$n")" = 1 ] || docker network inspect -f 'network {{.Name}}' "$n"
  done
  image=sick:local    # SICK_IMAGE is unset above: the default of the base file
  [ "$(docker image inspect -f '{{index .Config.Labels "sick"}}' "$image")" = 1 ] || echo "image $image"
)
[ -z "$unlabelled" ] || { printf '%s\n' "$unlabelled" | sed 's/^/      | /' >&2; fail 'without the label sick=1 (listed above)'; }
pass 'every container, volume and network of the project, and the image built, carry the label sick=1'

#### 2. check

step 'sick check: the device is not presented with a certificate of this CA'
note 'docker compose run --rm sick sick check'
set +e
check=$(compose run --rm -T sick sick check 2>&1 | plain)
code=$?
set -e
show <<<"$check"
[ "$code" -eq 0 ] || fail "sick check ended with $code"
expect "$device has the factory certificate (not from this CA) and is due" "^$device +(missing|foreign-ca) +yes" "$check"

#### 3. run

step "sick run: $device gets a certificate of the CA"
note "docker compose run --rm sick sick run --verbose $device"
set +e
run=$(compose run --rm -T sick sick run --verbose "$device" 2>&1 | plain)
code=$?
set -e
show <<<"$run"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'renewed' "^$device +renewed +" "$run"

note 'sick trust /srv/trust, as the schedule does after a run'
in_sick 'sick trust /srv/trust' 2>&1 | show
note "what $device presents, asked from a container in the network with openssl s_client and the ca_bundle.pem of the trust page"
seen=$(in_sick '
  openssl s_client -connect web:443 -servername web.example.internal -no-CApath -no-CAstore \
    -CAfile /srv/trust/ca_bundle.pem -verify_return_error -verify_hostname web.example.internal \
    </dev/null >/tmp/s_client.txt 2>&1; echo "s_client exit: $?"
  grep -E "^(Verification|Verify return code)" /tmp/s_client.txt
  echo "certificates sent: $(grep -c "BEGIN CERTIFICATE" /tmp/s_client.txt)"
  openssl x509 </tmp/s_client.txt -noout -issuer -ext subjectAltName
  echo "presented sha256: $(openssl x509 </tmp/s_client.txt -noout -fingerprint -sha256)"
  echo "written   sha256: $(openssl x509 </srv/device/cert.pem -noout -fingerprint -sha256)"
' 2>&1 | plain)
show <<<"$seen"
expect 'the handshake verified against the bundle of the trust page' '^s_client exit: 0$' "$seen"
expect '... Verification: OK' '^Verification: OK' "$seen"
expect '... issued by the intermediate of this CA' "issuer=.*CN ?= ?$ca_name Intermediate CA" "$seen"
got=$(grep -Eo '(DNS|IP Address):[^,]+' <<<"$seen" | sort | tr '\n' ' ')
want=$(for n in $device_names; do printf 'DNS:%s\n' "$n"; done | sort | tr '\n' ' ')
[ "$got" = "$want" ] || fail "the names are '$got', the list has '$want'"
pass "the names are exactly: $want"
presented=$(sed -n 's/^presented sha256: //p' <<<"$seen")
written=$(sed -n 's/^written   sha256: //p' <<<"$seen")
[ -n "$presented" ] && [ "$presented" = "$written" ] || fail 'the device presents another certificate than the one SICK wrote'
pass 'the device presents the certificate SICK wrote'

#### 4. again

step 'a second sick run changes nothing'
note 'docker compose run --rm sick sick run'
set +e
again=$(compose run --rm -T sick sick run 2>&1 | plain)
code=$?
set -e
show <<<"$again"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'unchanged' "^$device +unchanged +ok" "$again"
check=$(compose run --rm -T sick sick check 2>&1 | plain)
show <<<"$check"
expect 'ok, no renewal due' "^$device +ok +no +" "$check"
after=$(in_sick 'openssl s_client -connect web:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256')
[ "$(sed 's/.*=//' <<<"$after")" = "$(sed 's/.*=//' <<<"$presented")" ] || fail 'the device presents another certificate'
pass 'the device still presents the same certificate'

#### 5. the schedule, the trust page, the CA from the outside

step 'the schedule keeps the trust page up; the page and the CA from the outside'
note 'SICK_INTERVAL=20s docker compose up -d sick'
SICK_INTERVAL=20s compose up -d sick >/dev/null 2>&1
two_runs() { [ "$(sick_logs | grep -c 'entrypoint: sick run: exit')" -ge 2 ]; }
wait_for 180 'two scheduled runs' two_runs
log=$(sick_logs)
show <<<"$log"
expect 'the entrypoint announces the schedule' 'entrypoint: sick run --verbose every 20s \(20s\)' "$log"
[ "$(grep -Ec "^$device +unchanged +ok" <<<"$log")" -ge 2 ] || fail 'fewer than two scheduled runs with the device unchanged'
pass 'two scheduled runs, the device unchanged in both'
expect 'sick trust after the runs' '^wrote root_ca.pem, .*ca_bundle.pem.* to /srv/trust' "$log"

note 'the trust page on 127.0.0.1 serves what a client needs, and the CA answers to it'
base=http://127.0.0.1:$trust_port
for file in index.html root_ca.pem intermediate_ca.pem ca_bundle.pem; do
  head=$(curl -fsS -o "$work/trust-$file" -D - "$base/$file" | tr -d '\r') || fail "GET $base/$file"
  printf '%s  %s  %s bytes\n' "$base/$file" "$(grep -i '^content-type:' <<<"$head" | tr -s ' ')" "$(stat -c %s "$work/trust-$file")" | show
done
pass 'index.html, root_ca.pem, intermediate_ca.pem and ca_bundle.pem are served'
sha256_of() { openssl x509 "$@" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
served=$(sha256_of -in "$work/trust-root_ca.pem")
note "SHA-256 of the served root_ca.pem: $served"
[ "$served" = "$fingerprint" ] || fail "the served root has another fingerprint than the one init-ca.sh logged ($fingerprint)"
pass 'root_ca.pem has the fingerprint of the root of the CA'
[ "$(grep -c 'BEGIN CERTIFICATE' "$work/trust-ca_bundle.pem")" -eq 2 ] || fail 'ca_bundle.pem does not hold two certificates'
cmp -s "$work/trust-ca_bundle.pem" <(cat "$work/trust-root_ca.pem" "$work/trust-intermediate_ca.pem") \
  || fail 'ca_bundle.pem is not the served root followed by the served intermediate'
pass 'ca_bundle.pem is the served root followed by the served intermediate'
refuse 'no key is served' 'PRIVATE KEY' "$(cat "$work"/trust-*)"
expect 'index.html shows the fingerprint of the root' "$(sed 's/../&:/g; s/:$//' <<<"$fingerprint" | tr 'a-f' 'A-F')" "$(sed 's/<br>//g' "$work/trust-index.html" | grep -F 'SHA-256 fingerprint' | head -n 1)"
health=$(curl -fsS --cacert "$work/trust-root_ca.pem" --resolve "localhost:$ca_port:127.0.0.1" "https://localhost:$ca_port/health")
show <<<"$health"
expect 'curl --cacert root_ca.pem https://localhost:<port>/health: the CA answers and its certificate is accepted' '"status" *: *"ok"' "$health"

#### 6. a restart of the CA

step 'restarting the CA changes nothing'
state() { in_ca sh -c 'cat /home/step/config/ca.json /home/step/certs/*.crt /handover/* | sha256sum; ls /home/step/secrets | sort | tr "\n" " "'; }
before=$(state)
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
note 'docker compose restart ca'
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

# 7. runs in the EXIT trap
