#!/bin/bash
#
# Proxmox VE and Proxmox Backup Server through the acme.sh deploy hooks
# proxmoxve and proxmoxbs (acme.sh 3.1.6, in the sick image), against a
# recording stand-in of their certificate API (t/e2e/proxmox-standin.py).
# Not a real PVE or PBS: what the products do beyond the API call is not
# covered (docs/findings/device-proxmox.md).
#
# A Compose project (default sick-proxmox): the CA of docker/compose.yml,
# the sick image, and two stand-ins - pve1.example.internal (API and
# certificate on 8006, like pveproxy) and pbs1.example.internal (8007, like
# proxmox-backup-proxy). SICK runs devices of type acmesh with the hooks; the
# API token is a file in env_files, nowhere else.
#
# What it proves, each with PASS/FAIL lines; the first FAIL ends it with 1:
#
#   1. from nothing: build, up; every container, volume and network carries
#      sick=1, no port is published
#   2. before: sick check sees the stand-ins' self-signed certificates
#      (foreign-ca); curl in the sick image refuses that certificate, so a
#      hook that gets through has not verified it
#   3. sick run: both renewed; the stand-ins recorded exactly one upload each,
#      method, path, token form and fields as the hooks send them, the key a
#      PEM private key that matches the certificate; the fingerprint on 8006
#      and 8007 is the issued one; the API now verifies with the root
#   4. a second sick run changes nothing and uploads nothing
#   5. the token is on the command line of curl while the hook runs (a
#      finding, counted, never printed)
#   6. negatives: wrong token -> 401, device failed with the status in the
#      message; API answering 500 -> failed; API port closed while the
#      certificate port answers -> failed; nothing changed on the port
#   7. back: DELETE of the custom certificate -> the self-signed one is
#      presented again, sick check sees foreign-ca, sick run renews
#   8. the stand-in stopped: unreachable, nothing deployed, also with --force
#   9. no token in any output, record, log or container configuration
#  10. teardown, also after a failure or Ctrl-C: the project is taken down
#      with its volumes and checked to be gone
#
# It DESTROYS the Compose project it works on, and touches nothing else: no
# other project, no prune. The images (sick:local, step-ca, python) stay as
# a cache.
#
# Prerequisites: Docker with Compose 2.24 or newer, openssl; the two source
# trees side by side, as for run-local.sh.
#
# Parameters, all from the environment:
#
#   SICK_PROXMOX_DIR      private working directory, mode 0700
#                         ($HOME/.local/share/sick-lab/proxmox)
#   SICK_PROXMOX_PROJECT  Compose project name               (sick-proxmox)
#   SICK_PROXMOX_PYTHON   image of the stand-ins   (python:3.14.8-slim-trixie)
#   SICK_PROXMOX_KEEP     "yes": keep the working directory             (no)
#
# The API tokens (UUIDs, as PVE makes them) are generated at run time and
# live in the working directory and the containers only; they are never
# printed. The stand-ins' self-signed keys are made at run time as well.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_PROXMOX_DIR:-$HOME/.local/share/sick-lab/proxmox}
project=${SICK_PROXMOX_PROJECT:-sick-proxmox}
python_image=${SICK_PROXMOX_PYTHON:-python:3.14.8-slim-trixie}
keep=${SICK_PROXMOX_KEEP:-no}

pve=pve1.example.internal
pbs=pbs1.example.internal

step_no=0
step() { step_no=$((step_no + 1)); printf '\n=== %s. %s\n' "$step_no" "$*"; }
note() { printf -- '--- %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
plain() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r'; }
show() { plain | sed 's/^/    /'; }
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
# same <what> <expected> <observed>
same() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi; }

[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_PROXMOX_PROJECT '$project' is not sick or sick-*"

umask 077
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_PROXMOX_DIR $work lies inside the build context $context" ;; esac

#### teardown, armed before anything exists

compose_armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  if [ -n "$compose_armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | show
    docker rm -f "$project-argv" >/dev/null 2>&1
    # a container of "compose run --rm" may still be on its way out; what
    # is left of the project after that goes by the label sick=1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ] && break
      sleep 1
    done
    ids=$(docker ps -aq --filter label=sick=1 --filter "label=com.docker.compose.project=$project")
    [ -z "$ids" ] || { note "removing by label: $(echo $ids)"; docker rm -f $ids >/dev/null; }
    ids=$(docker volume ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project")
    [ -z "$ids" ] || docker volume rm $ids >/dev/null
    ids=$(docker network ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project")
    [ -z "$ids" ] || docker network rm $ids >/dev/null
    left=$(
      docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container /'
      docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
      docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network /'
      docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]" | sed 's/^/container /'
      docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
      docker network ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/network /'
    )
    if [ -n "$left" ]; then
      printf '%s\n' "$left" | sed 's/^/      | /' >&2
      printf 'FAIL  left behind by project %s (listed above)\n' "$project" >&2
      rc=1
    else
      pass "no container, volume or network of project $project is left"
    fi
  fi
  if [ "$keep" = yes ]; then
    note "working directory $work kept (SICK_PROXMOX_KEEP=yes)"
  else
    rm -rf "${work:?}"/{sick.yml,compose.env,compose.proxmox.yml,build.log,up.log,secrets,pve,pbs}
    rmdir "${work:?}" 2>/dev/null
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$work/compose.proxmox.yml" "$@"
}
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
# sick <arguments>: runs sick in a fresh container; output in $out, exit code in $code
all_out=
sick() {
  set +e
  out=$(compose run --rm --no-deps -T sick sick "$@" 2>&1)
  code=$?
  set -e
  out=$(plain <<<"$out")
  all_out+=$out$'\n'
  note "sick $* (exit $code)"
  show <<<"$out"
}
# fingerprint <host> <port>: SHA-256 of the certificate presented there, lower-case hex
fingerprint() {
  in_sick "openssl s_client -connect $1:$2 -servername $1 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" 2>/dev/null \
    | plain | sed -n 's/^sha256 Fingerprint=//Ip' | tr -d ':' | tr 'A-F' 'a-f'
}
# issued <device>: the fingerprint of the last certificate issued for it, from its record
issued() {
  in_sick "cat /var/lib/sick/devices/$1.json" 2>/dev/null \
    | perl -MJSON::PP -0777 -ne 'my $r = eval { decode_json($_) } or exit; print lc( ( $r->{last_issue} || {} )->{fingerprint_sha256} // q{} ) =~ s/://gr'
}
standin_log() { compose logs --no-log-prefix "$1" 2>&1 | plain | grep "^standin $1: " || true; }
uploads() { standin_log "$1" | grep -c "^standin $1: POST " || true; }
set_mode() { printf '%s\n' "$2" >"$work/$1/mode"; chmod 644 "$work/$1/mode"; }

#### 1. the project

step "a Compose project $project: CA, sick, stand-ins for PVE and PBS"
for program in docker openssl perl; do command -v "$program" >/dev/null || fail "$program is not installed"; done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"

compose_armed=yes
# an interrupted run of before: whatever is left of the project goes first
cat >"$work/compose.env" <<EOF
SICK_BUILD_CONTEXT=$context
EOF
printf 'services: {}\n' >"$work/compose.proxmox.yml"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
docker rm -f "$project-argv" >/dev/null 2>&1 || true
rm -rf "${work:?}"/{secrets,pve,pbs}

# Tokens: UUIDs like the secrets PVE and PBS hand out. Never printed.
uuid() { cat /proc/sys/kernel/random/uuid; }
mkdir -p "$work/secrets" "$work/pve" "$work/pbs"
# sick runs as root without CAP_DAC_OVERRIDE (cap_drop: ALL), the stand-ins
# as nobody: what they read is readable by all; the working directory stays 0700
chmod 755 "$work/secrets" "$work/pve" "$work/pbs"
uuid >"$work/secrets/pve.token"
uuid >"$work/secrets/pbs.token"
uuid >"$work/secrets/wrong.token"
cp "$work/secrets/pve.token" "$work/pve/token"
cp "$work/secrets/pbs.token" "$work/pbs/token"
for kind in pve pbs; do
  name=${kind}1.example.internal
  # the certificate of a fresh installation: self-signed, nobody trusts it
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=$name" \
    -addext "subjectAltName=DNS:$name,DNS:${kind}1" -keyout "$work/$kind/self.key" -out "$work/$kind/self.pem" 2>/dev/null \
    || fail "openssl could not make the self-signed certificate of $kind"
  set_mode "$kind" ok
done
chmod 644 "$work"/secrets/* "$work"/pve/* "$work"/pbs/*
tokens=("$(cat "$work/secrets/pve.token")" "$(cat "$work/secrets/pbs.token")" "$(cat "$work/secrets/wrong.token")")
self_pve=$(openssl x509 -in "$work/pve/self.pem" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
self_pbs=$(openssl x509 -in "$work/pbs/self.pem" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')

# device <name> <hook> <host> <port> <token file> [api port]
device() {
  local name=$1 hook=$2 host=$3 port=$4 token=$5 api=${6:-$4} var
  var=DEPLOY_$(tr 'a-z' 'A-Z' <<<"$hook")
  cat <<EOF
  $name:
    type: acmesh
    hook: $hook
    host: $host
    port: $port
    names: [$host]
    env:
      ${var}_SERVER: $host
      ${var}_SERVER_PORT: "$api"
EOF
  [ "$hook" = proxmoxve ] && printf '      %s_NODE_NAME: pve1\n' "$var"
  cat <<EOF
      ${var}_USER: sick
      ${var}_USER_REALM: $([ "$hook" = proxmoxve ] && echo pve || echo pbs)
      ${var}_API_TOKEN_NAME: sick
    env_files:
      ${var}_API_TOKEN_KEY: /etc/sick/secrets/$token
EOF
}
{
  cat <<'EOF'
# Generated by t/e2e/device-proxmox.sh. Neutral names only.
ca:
  name: SICK Proxmox Test CA
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
EOF
  device pve proxmoxve "$pve" 8006 pve.token
  device pbs proxmoxbs "$pbs" 8007 pbs.token
  echo '  # the same devices with what goes wrong'
  device pve-badtoken proxmoxve "$pve" 8006 wrong.token
  device pbs-badtoken proxmoxbs "$pbs" 8007 wrong.token
  device pve-500 proxmoxve "$pve" 8006 pve.token
  device pbs-500 proxmoxbs "$pbs" 8007 pbs.token
  device pve-noapi proxmoxve "$pve" 8006 pve.token 8443
} >"$work/sick.yml"
chmod 644 "$work/sick.yml"

cat >"$work/compose.env" <<EOF
# Generated by t/e2e/device-proxmox.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=SICK Proxmox Test CA
SICK_CA_ALLOW_DNS=*.example.internal
SICK_INTERVAL=1d
EOF
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_TRUST_PORT SICK_INTERVAL \
  SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION

standin() { # <kind> <port> <alias> <node>
  cat <<EOF
  $1:
    labels: { sick: "1" }
    image: $python_image
    user: "65534:65534"
    init: true
    stop_grace_period: 3s
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    command: ["python3", "-I", "-u", "/usr/local/lib/proxmox-standin.py", "$1"]
    environment:
      STANDIN_NODE: $4
    volumes:
      - $here/proxmox-standin.py:/usr/local/lib/proxmox-standin.py:ro
      - $work/$1:/etc/standin:ro
    tmpfs:
      - /run/standin:mode=0700,uid=65534,gid=65534,size=1m
    networks:
      default:
        aliases: [$3]
    healthcheck:
      test: ["CMD", "python3", "-I", "-c", "import socket, ssl; ssl._create_unverified_context().wrap_socket(socket.create_connection(('127.0.0.1', $2)), server_hostname='$3').close()"]
      interval: 2s
      timeout: 5s
      retries: 15
      start_period: 3s
EOF
}
{
  cat <<'EOF'
# Generated by t/e2e/device-proxmox.sh, added to docker/compose.yml: no
# published port, sick=1 on everything, the two stand-ins.
services:
  ca:
    labels: { sick: "1" }
    ports: !reset []
  trust:
    labels: { sick: "1" }
    ports: !reset []
  sick:
    labels: { sick: "1" }
EOF
  standin pve 8006 "$pve" pve1
  standin pbs 8007 "$pbs" localhost
  cat <<'EOF'
volumes:
  ca: { labels: { sick: "1" } }
  handover: { labels: { sick: "1" } }
  state: { labels: { sick: "1" } }
  trust: { labels: { sick: "1" } }
networks:
  default: { labels: { sick: "1" } }
EOF
} >"$work/compose.proxmox.yml"

note 'docker compose build sick'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
pass 'the image is built from the two source trees'
docker image inspect "$python_image" >/dev/null 2>&1 || docker pull -q "$python_image" >/dev/null || fail "cannot pull $python_image"
note 'docker compose up -d --wait ca pve pbs'
compose up -d --wait ca pve pbs >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs pve pbs 2>&1 | tail -20 >&2; fail 'the stack did not come up healthy'; }
pass 'ca, pve and pbs are up and healthy'
published=$(docker ps --filter "label=com.docker.compose.project=$project" --format '{{.Names}} {{.Ports}}' | grep -E '(->|0\.0\.0\.0|::)' || true)
[ -z "$published" ] || fail "published ports: $published"
pass 'no port is published'
unlabelled=$(
  for id in $(docker ps -aq --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker inspect -f '{{index .Config.Labels "sick"}}' "$id")" = 1 ] || echo "container $id"
  done
  for v in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker volume inspect -f '{{index .Labels "sick"}}' "$v")" = 1 ] || echo "volume $v"
  done
  for n in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    [ "$(docker network inspect -f '{{index .Labels "sick"}}' "$n")" = 1 ] || echo "network $n"
  done
)
[ -z "$unlabelled" ] || fail "without the label sick=1: $unlabelled"
pass 'every container, volume and network of the project carries sick=1'

note 'versions'
{
  for image in "$python_image" "smallstep/step-ca:0.30.2"; do
    printf '%s %s\n' "$image" "$(docker image inspect -f '{{join .RepoDigests " "}}' "$image")"
  done
  printf 'sick:local %s\n' "$(docker image inspect -f '{{.Id}}' sick:local)"
  in_sick 'sick --version; acme.sh --version | tail -n 1; curl --version | head -n 1; openssl version; cd /opt/acme.sh/deploy && sha256sum proxmoxve.sh proxmoxbs.sh'
  compose exec -T pve python3 -I -c 'import sys, ssl; print("stand-in: Python", sys.version.split()[0], ssl.OPENSSL_VERSION)'
} 2>&1 | show

#### 2. before

step 'before: the stand-ins present the certificate of a fresh installation'
sick check pve pbs
expect 'sick check: pve is not presented with a certificate of this CA' '^pve +.*foreign-ca' "$out"
expect '... nor pbs' '^pbs +.*foreign-ca' "$out"
same 'port 8006 presents the self-signed certificate of pve' "$self_pve" "$(fingerprint "$pve" 8006)"
same 'port 8007 presents the self-signed certificate of pbs' "$self_pbs" "$(fingerprint "$pbs" 8007)"
set +e
in_sick "curl -sS -o /dev/null https://$pve:8006/" >/dev/null 2>&1
verify_code=$?
set -e
same 'curl in the sick image refuses the self-signed API certificate (exit 60)' 60 "$verify_code"

#### 3. the first run

step 'sick run: both devices through their hooks'
sick run --verbose pve pbs
same 'sick run ends with 0' 0 "$code"
expect 'pve is renewed' '^pve +renewed +' "$out"
expect 'pbs is renewed' '^pbs +renewed +' "$out"
expect 'acme.sh ran the hook proxmoxve' 'deploy-hook proxmoxve' "$out"
expect 'acme.sh ran the hook proxmoxbs' 'deploy-hook proxmoxbs' "$out"
expect '... and reported success' 'acme.sh: Success' "$out"

log_pve=$(standin_log pve)
log_pbs=$(standin_log pbs)
note 'what the stand-ins recorded'
show <<<"$log_pve"
show <<<"$log_pbs"
same 'pve recorded one upload' 1 "$(uploads pve)"
same 'pbs recorded one upload' 1 "$(uploads pbs)"
post_pve=$(grep '^standin pve: POST ' <<<"$log_pve")
post_pbs=$(grep '^standin pbs: POST ' <<<"$log_pbs")
expect 'pve: POST /api2/json/nodes/pve1/certificates/custom, JSON' '^standin pve: POST /api2/json/nodes/pve1/certificates/custom ctype=application/json ' "$post_pve"
expect 'pve: Authorization: PVEAPIToken=sick@pve!sick=<secret>, the right secret' 'auth=PVEAPIToken\(sick@pve!sick, format ok, id ok, secret=ok\)' "$post_pve"
expect 'pve: the fields certificates, force, key, node, restart, all strings' 'fields=certificates:str,force:str,key:str,node:str,restart:str ' "$post_pve"
expect 'pve: node "pve1", restart "1", force "1"' 'node="pve1"\(str\) restart="1"\(str\) force="1"\(str\) ' "$post_pve"
expect 'pve: certificate and intermediate' 'certificates=2 PEM, first sha256 [0-9a-f]{64} ' "$post_pve"
expect 'pve: a PEM private key (RSA) that matches the certificate' 'key=PEM private key, RSA .*matches certificate: yes -> 200' "$post_pve"
expect 'pbs: POST /api2/json/nodes/localhost/certificates/custom, JSON' '^standin pbs: POST /api2/json/nodes/localhost/certificates/custom ctype=application/json ' "$post_pbs"
expect 'pbs: Authorization: PBSAPIToken=sick@pbs!sick:<secret>, the right secret' 'auth=PBSAPIToken\(sick@pbs!sick, format ok, id ok, secret=ok\)' "$post_pbs"
expect 'pbs: the fields certificates, force:bool, key, node, restart:bool' 'fields=certificates:str,force:bool,key:str,node:str,restart:bool ' "$post_pbs"
expect 'pbs: node "localhost", restart true, force true' 'node="localhost"\(str\) restart=true\(bool\) force=true\(bool\) ' "$post_pbs"
expect 'pbs: certificate and intermediate' 'certificates=2 PEM, first sha256 [0-9a-f]{64} ' "$post_pbs"
expect 'pbs: a PEM private key (RSA) that matches the certificate' 'key=PEM private key, RSA .*matches certificate: yes -> 200' "$post_pbs"

issued_pve=$(issued pve)
issued_pbs=$(issued pbs)
[[ $issued_pve =~ ^[0-9a-f]{64}$ && $issued_pbs =~ ^[0-9a-f]{64}$ ]] || fail 'no issued fingerprint in the records of pve and pbs'
same 'pve: the uploaded certificate is the issued one' "$issued_pve" "$(sed -n 's/.*first sha256 \([0-9a-f]\{64\}\).*/\1/p' <<<"$post_pve")"
same 'pbs: the uploaded certificate is the issued one' "$issued_pbs" "$(sed -n 's/.*first sha256 \([0-9a-f]\{64\}\).*/\1/p' <<<"$post_pbs")"
same 'port 8006 presents the issued certificate' "$issued_pve" "$(fingerprint "$pve" 8006)"
same 'port 8007 presents the issued certificate' "$issued_pbs" "$(fingerprint "$pbs" 8007)"
in_sick "curl -sS -o /dev/null --cacert /etc/sick/ca/root_ca.crt https://$pve:8006/ && curl -sS -o /dev/null --cacert /etc/sick/ca/root_ca.crt https://$pbs:8007/" 2>&1 | show \
  || fail 'the APIs do not verify with the root after the deployment'
pass 'both APIs now verify with the root of the CA (a hook could check them; these do not)'

#### 4. the second run

step 'a second sick run changes nothing'
sick run pve pbs
same 'sick run ends with 0' 0 "$code"
expect 'pve unchanged' '^pve +unchanged +ok' "$out"
expect 'pbs unchanged' '^pbs +unchanged +ok' "$out"
same 'pve recorded no further upload' 1 "$(uploads pve)"
same 'pbs recorded no further upload' 1 "$(uploads pbs)"

#### 5. the token on the command line of curl

step 'while the hook runs: is the token on the command line of curl?'
set_mode pve slow
# counts processes whose argument list holds the header with a 36-character
# secret; prints the count only
probe='n=0; for f in /proc/[0-9]*/cmdline; do
  if tr "\000" "\n" <"$f" 2>/dev/null | grep -Eq "^Authorization: PVEAPIToken=sick@pve!sick=.{36}$"; then n=$((n + 1)); fi
done; echo "$n"'
compose run -d --name "$project-argv" --no-deps -T sick sick run --force pve >/dev/null
seen=0
for _ in $(seq 1 60); do
  n=$(docker exec "$project-argv" sh -c "$probe" 2>/dev/null || true)
  if [ -n "$n" ] && [ "$n" -gt 0 ]; then seen=$n; break; fi
  docker inspect -f '{{.State.Running}}' "$project-argv" 2>/dev/null | grep -q true || break
  sleep 0.25
done
docker wait "$project-argv" >/dev/null 2>&1 || true
argv_out=$(docker logs "$project-argv" 2>&1 | plain)
all_out+=$argv_out$'\n'
show <<<"$argv_out"
docker rm -f "$project-argv" >/dev/null 2>&1 || true
set_mode pve ok
expect 'the forced run renewed pve' '^pve +renewed +' "$argv_out"
if [ "$seen" -gt 0 ]; then
  pass "FINDING: the token was in the argument list of $seen process(es) while the hook ran (curl -H, from _post of acme.sh)"
else
  fail 'the token was not seen on a command line; the finding of the reading does not hold'
fi
issued_pve=$(issued pve)

#### 6. negatives

step 'a wrong token: 401, the device fails, the port is unchanged'
sick run --force pve-badtoken pbs-badtoken
same 'sick run ends with 1' 1 "$code"
expect 'pve-badtoken failed with the status in the message' '^pve-badtoken +failed +.*HTTP status 401' "$out"
expect 'pbs-badtoken failed with the status in the message' '^pbs-badtoken +failed +.*HTTP status 401' "$out"
expect 'pve: the stand-in saw the wrong secret and answered 401' 'PVEAPIToken\(sick@pve!sick, format ok, id ok, secret=wrong\) -> 401' "$(standin_log pve)"
expect 'pbs: the stand-in saw the wrong secret and answered 401' 'PBSAPIToken\(sick@pbs!sick, format ok, id ok, secret=wrong\) -> 401' "$(standin_log pbs)"
same 'port 8006 still presents the certificate of before' "$issued_pve" "$(fingerprint "$pve" 8006)"
same 'port 8007 still presents the certificate of before' "$issued_pbs" "$(fingerprint "$pbs" 8007)"

step 'the API answers 500: the device fails'
set_mode pve 500
set_mode pbs 500
sick run --force pve-500 pbs-500
set_mode pve ok
set_mode pbs ok
same 'sick run ends with 1' 1 "$code"
expect 'pve-500 failed with the status in the message' '^pve-500 +failed +.*HTTP status 500' "$out"
expect 'pbs-500 failed with the status in the message' '^pbs-500 +failed +.*HTTP status 500' "$out"
same 'port 8006 still presents the certificate of before' "$issued_pve" "$(fingerprint "$pve" 8006)"
same 'port 8007 still presents the certificate of before' "$issued_pbs" "$(fingerprint "$pbs" 8007)"

step 'the API port closed while the certificate port answers: the device fails'
before_uploads=$(uploads pve)
sick run --force pve-noapi
same 'sick run ends with 1' 1 "$code"
expect 'pve-noapi failed (not unreachable: the device answered on 8006)' '^pve-noapi +failed +.*acme\.sh failed' "$out"
expect '... with curl'"'"'s error in the message' 'error code: 7' "$out"
same 'nothing reached the stand-in' "$before_uploads" "$(uploads pve)"

#### 7. back

step 'back: delete the custom certificate, the node presents its own again'
# the header goes to curl from a file (-H @file), not on its command line
back=$(in_sick "
  umask 077
  printf 'Authorization: PVEAPIToken=sick@pve!sick=%s\n' \"\$(head -n 1 /etc/sick/secrets/pve.token)\" >/tmp/h
  curl -sS -k -o /dev/null -w '%{http_code}' -X DELETE -H @/tmp/h https://$pve:8006/api2/json/nodes/pve1/certificates/custom
  rm -f /tmp/h" 2>&1 | plain)
same 'DELETE /api2/json/nodes/pve1/certificates/custom answers 200' 200 "$back"
same 'port 8006 presents the self-signed certificate again' "$self_pve" "$(fingerprint "$pve" 8006)"
sick check pve
expect 'sick check: pve is foreign-ca again' '^pve +.*foreign-ca' "$out"
sick run pve
same 'sick run ends with 0' 0 "$code"
expect 'a normal run renews pve' '^pve +renewed +' "$out"
same 'port 8006 presents the newly issued certificate' "$(issued pve)" "$(fingerprint "$pve" 8006)"

#### 8. unreachable

step 'the node does not answer: unreachable, nothing is deployed'
compose stop pve 2>&1 | show
sick run --verbose pve
same 'sick run ends with 1' 1 "$code"
expect 'pve fails as unreachable' '^pve +failed +unreachable +' "$out"
refuse '... and acme.sh was not started' 'acme\.sh --deploy' "$out"
sick run --force --verbose pve
expect 'with --force too: unreachable' '^pve +failed +unreachable +' "$out"
refuse '... and acme.sh was not started' 'acme\.sh --deploy' "$out"

#### 9. the secret

step 'the tokens appear nowhere'
records=$(in_sick 'cat /var/lib/sick/devices/*.json' 2>&1 | plain)
logs=$(compose logs --no-log-prefix 2>&1 | plain)
config=$(for id in $(docker ps -aq --filter "label=com.docker.compose.project=$project"); do docker inspect "$id"; done)
for where in 'the output of sick' 'the device records' 'the logs of the project' 'the container configuration'; do
  case $where in
    'the output of sick') text=$all_out ;;
    'the device records') text=$records ;;
    'the logs of the project') text=$logs ;;
    *) text=$config ;;
  esac
  [ -n "$text" ] || fail "$where: nothing to look at"
  for t in "${tokens[@]}"; do
    if grep -Fq -- "$t" <<<"$text"; then fail "$where: a token is in it"; fi
  done
  pass "$where: no token in it"
done
