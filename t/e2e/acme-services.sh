#!/bin/bash
#
# The ACME recipes of contrib/acme, proven in containers against the lab CA
# of docker/compose.yml: Traefik, Caddy, nginx with acme.sh.
#
#   t/e2e/acme-services.sh                      all three, one after another
#   t/e2e/acme-services.sh traefik              the parts named
#
# Each run starts from nothing: the CA in lab mode with a name policy
# (SICK_CA_ALLOW_DNS=*.example.internal) and a short ACME lifetime
# (SICK_CA_ACME_LIFETIME=3m, minimum 1m), so that renewal happens within
# minutes. The CA and every service have a name in example.internal on the
# Compose network; Compose's resolver is the lab's DNS, for the CA that
# validates the challenges as well as for the client. A real network needs
# its internal DNS to resolve these names for the CA (see the README of each
# recipe).
#
# Per part (traefik, caddy, nginx), with PASS/FAIL lines; the first FAIL
# ends the script with 1:
#
#   1. the service obtains a certificate from the lab CA and serves it: a
#      client in the network with nothing but the root verifies it with curl
#      (OpenSSL) and gnutls-cli (GnuTLS); issued by the lab intermediate,
#      extended key usage serverAuth alone, read back from the served
#      certificate
#   2. it renews without a manual step: the fingerprint presented on port
#      443 changes within a deadline, and the new certificate verifies
#   3. a name outside the CA's policy (outside.example.org) is refused by
#      the CA, in its words; what the service presents for that name is
#      recorded; the service keeps serving its own name
#   4. a challenge for a name it does not control fails:
#      decoy.example.internal lies inside the policy, but resolves to
#      "decoy", a plain web server, so the CA's http-01/tls-alpn-01 request
#      never reaches the service
#
# The recipes are used as shipped, with these changes for the test only
# (each checked to apply, the diff is printed):
#   traefik  certificatesDuration 720 -> 1 (Traefik's bracket below 24 hours:
#            renew 20 minutes before expiry, check every minute)
#   caddy    renew_interval 10m -> 10s
#   nginx    ACME_CHECK_INTERVAL 12h -> 20s (t/e2e/compose.acme.yml)
# and, for steps 3 and 4, a router (Traefik) or site (Caddy) per foreign name
# added to the running service, or one acme.sh --issue (nginx).
#
# Teardown, also after a failure or Ctrl-C: the Compose project is taken
# down with its volumes; whatever still carries sick=1 and the project's
# label is removed by those labels; nothing of the project may be left.
# While the stack runs, every container, volume and network of the project
# is checked to carry sick=1. Nothing is published on a port. The images
# stay as a cache.
#
# It DESTROYS the Compose project it works on and its private working
# directory, at the start (a rerun after an interrupted run starts clean)
# and at the end. It touches nothing else: no other project, no prune.
#
# Prerequisites: Docker with Compose 2.24.4 or newer (!reset, !override),
# openssl; the internet for the images and for apt in the client container.
#
# Parameters, all from the environment:
#
#   SICK_ACME_DIR      private working directory, mode 0700
#                      ($HOME/.local/share/sick-lab/acme-services)
#   SICK_ACME_PROJECT  Compose project name, sick-*      (sick-e2e-acme)
#   SICK_ACME_DEBIAN   image of the client     (debian:trixie-20261005-slim)
#   SICK_ACME_KEEP     "yes": keep the working directory            (no)
#
# Nothing secret is written to the working directory or printed: it holds
# the root certificate of the lab CA and copies of the recipes.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

work=${SICK_ACME_DIR:-$HOME/.local/share/sick-lab/acme-services}
project=${SICK_ACME_PROJECT:-sick-e2e-acme}
keep=${SICK_ACME_KEEP:-no}

parts=("$@")
[ "${#parts[@]}" -gt 0 ] || parts=(traefik caddy nginx)

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

for p in "${parts[@]}"; do
  case $p in traefik | caddy | nginx) ;; *) fail "unknown part '$p' (traefik, caddy, nginx)" ;; esac
done
[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_ACME_PROJECT '$project' is not sick or sick-*"
for program in docker openssl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'

#### the Compose project

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" \
    -f "$repo/contrib/acme/traefik/compose.yml" \
    -f "$repo/contrib/acme/caddy/compose.yml" \
    -f "$repo/contrib/acme/nginx/compose.yml" \
    -f "$here/compose.acme.yml" "$@"
}
in_client() { compose exec -T client sh -c "$1"; }
logs_of() { compose logs --no-log-prefix "$1" 2>&1 | plain; }

#### teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  if [ -n "$armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | show
    # what is left of the project and carries sick=1: by those labels
    docker ps -aq --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f -v >/dev/null 2>&1
    docker volume ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
    docker network ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
    left=$(
      docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container id /'
      docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
      docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network id /'
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
    note "working directory $work kept (SICK_ACME_KEEP=yes)"
  else
    rm -rf "${work:?}"
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED (%s)\n' "${parts[*]}"; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

#### from nothing

step "from nothing: project $project, the lab CA with a name policy and 3-minute ACME certificates"
umask 077
# an earlier run that was interrupted: its working directory and project go
rm -rf "${work:?}"
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
cat >"$work/compose.env" <<EOF
# Generated by t/e2e/acme-services.sh
SICK_CA_NAME=SICK ACME Lab CA
SICK_CA_DNS=ca.example.internal
SICK_CA_ALLOW_DNS=*.example.internal
SICK_CA_ACME_LIFETIME=3m
SICK_CA_ACME_MIN_LIFETIME=1m
SICK_ACME_WORK=$work
SICK_ACME_REPO=$repo
EOF
# only what this script sets reaches the compose files
unset SICK_CA_NAME SICK_CA_DNS SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ACME_LIFETIME \
  SICK_CA_ACME_MIN_LIFETIME SICK_CA_ACME_MAX_LIFETIME SICK_CA_MAX_LIFETIME SICK_CA_PORT \
  SICK_TRUST_PORT SICK_CONFIG_FILE SICK_SECRETS_DIR STEP_VERSION BUSYBOX_VERSION SICK_IMAGE \
  SICK_ACME_WORK SICK_ACME_REPO
armed=yes
compose down --volumes --remove-orphans >/dev/null 2>&1 || true

# the copies of the recipes, with the test's timing
mkdir -p "$work/traefik/dynamic" "$work/caddy" "$work/lab"
chmod 755 "$work/lab"
cp "$repo/contrib/acme/traefik/dynamic/app.yml" "$work/traefik/dynamic/"
# change <file> <sed expression> <what>: applied once, or FAIL
change() {
  local before
  before=$(cat "$1")
  sed -i "$2" "$1"
  [ "$(diff <(printf '%s\n' "$before") "$1" | grep -c '^>')" -eq 1 ] || fail "the test's change to $1 did not apply: $3"
}
cp "$repo/contrib/acme/traefik/traefik.yml" "$work/traefik/traefik.yml"
change "$work/traefik/traefik.yml" 's/^\(      certificatesDuration:\) 720$/\1 1/' 'certificatesDuration 720 -> 1'
cp "$repo/contrib/acme/caddy/Caddyfile" "$work/caddy/Caddyfile"
change "$work/caddy/Caddyfile" 's/^\(\trenew_interval\) 10m$/\1 10s/' 'renew_interval 10m -> 10s'
for f in traefik/traefik.yml caddy/Caddyfile; do
  note "contrib/acme/$f as the test uses it:"
  diff "$repo/contrib/acme/$f" "$work/$f" | show || true
done
chmod -R go+rX "$work/traefik" "$work/caddy"

note 'docker compose up -d --wait ca app decoy client'
compose up -d --wait ca app decoy client >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca client 2>&1 | tail -20 >&2; fail 'the CA, app, decoy and client did not come up'; }
pass 'the CA is healthy; app, decoy and the client are up'
init=$(logs_of ca | grep '^init-ca:' || true)
show <<<"$init"
expect "init-ca.sh: the policy *.example.internal" 'DNS names \*\.example\.internal|\*\.example\.internal' "$init"
expect "... and 'acme' issues for 3m, serverAuth only" "'acme' issues for 3m \\(1m to 2160h\\), serverAuth only" "$init"
fingerprint=$(sed -n 's/^init-ca: root fingerprint (SHA-256): \([0-9a-f]\{64\}\).*/\1/p' <<<"$init" | head -n 1)
[[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || fail 'init-ca.sh logged no root fingerprint'
compose exec -T ca cat /home/step/certs/root_ca.crt >"$work/lab/root_ca.crt"
chmod 644 "$work/lab/root_ca.crt"
got=$(openssl x509 -in "$work/lab/root_ca.crt" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
[ "$got" = "$fingerprint" ] || fail "the root taken from the CA has $got, init-ca.sh logged $fingerprint"
pass "the root for the services and the client is the one init-ca.sh logged ($fingerprint)"
directory=$(in_client 'curl -fsS --cacert /etc/lab/root_ca.crt https://ca.example.internal:9000/acme/acme/directory')
show <<<"$directory"
expect "the client reaches the ACME directory as ca.example.internal, verified with the root" '"newOrder"' "$directory"
if grep -q renewalInfo <<<"$directory"; then note 'the directory offers renewalInfo (ARI)'; else note 'the directory offers no renewalInfo: no ARI, the clients schedule by themselves'; fi
in_client 'printf "client: %s; %s; %s\n" "$(curl --version | head -n 1 | cut -d" " -f1-5)" "$(gnutls-cli --version | head -n 1)" "$(openssl version)"' | show

# what the client sees on <host>:443 for <name>: verification by curl and
# gnutls-cli with the root alone, then the presented certificate
probe() {
  in_client "
    h=$1 n=$2
    o=\$(curl -sS --cacert /etc/lab/root_ca.crt --connect-to \"\$n:443:\$h:443\" \"https://\$n/\" 2>&1)
    echo \"curl exit: \$? \$(echo \"\$o\" | head -n 1)\"
    o=\$(timeout 15 gnutls-cli --x509cafile /etc/lab/root_ca.crt --verify-hostname \"\$n\" --sni-hostname \"\$n\" -p 443 \"\$h\" </dev/null 2>&1)
    echo \"gnutls exit: \$? \$(echo \"\$o\" | grep -m 1 -E 'Status:|verification output|Error|Fatal' | tr -s ' ')\"
    openssl s_client -connect \"\$h:443\" -servername \"\$n\" </dev/null 2>/dev/null >/tmp/s.txt
    if openssl x509 -in /tmp/s.txt -noout >/dev/null 2>&1; then
      openssl x509 -in /tmp/s.txt -noout -subject -issuer -startdate -enddate -ext subjectAltName,extendedKeyUsage | grep -v '^X509v3'
      echo \"sha256: \$(openssl x509 -in /tmp/s.txt -noout -fingerprint -sha256 | sed 's/.*=//')\"
    else
      echo 'no certificate presented'
    fi
  " 2>&1 | plain
}
fingerprint_on() { probe "$1" "$2" | sed -n 's/^sha256: //p'; }

ca_log_since() { compose logs --no-log-prefix --since "$1" ca 2>&1 | plain; }

# run_part <service> <name> <foreign-name-hook>
run_part() {
  local svc=$1 name=$2 seen fp1 fp2 start since log ca_log
  step "$svc: obtain a certificate for $name and serve it"
  since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  if [ "$svc" = nginx ]; then
    compose up -d nginx acme >"$work/up-$svc.log" 2>&1 || { plain <"$work/up-$svc.log" | tail -20 >&2; fail "docker compose up $svc"; }
  else
    compose up -d "$svc" >"$work/up-$svc.log" 2>&1 || { plain <"$work/up-$svc.log" | tail -20 >&2; fail "docker compose up $svc"; }
  fi
  label_check
  start=$SECONDS
  until probe "$name" "$name" | grep -q '^curl exit: 0 '; do
    [ $((SECONDS - start)) -lt 120 ] || { logs_of "$([ "$svc" = nginx ] && echo acme || echo "$svc")" | tail -30 >&2; fail "$svc serves no certificate for $name that verifies, after 120s"; }
    sleep 3
  done
  seen=$(probe "$name" "$name")
  show <<<"$seen"
  pass "$svc obtained a certificate after $((SECONDS - start))s"
  expect "curl with the root alone verifies $name and gets the page of app" '^curl exit: 0 hello' "$seen"
  expect "gnutls-cli with the root alone verifies $name" '^gnutls exit: 0 ' "$seen"
  expect '... issued by the lab intermediate' 'issuer=.*SICK ACME Lab CA Intermediate CA' "$seen"
  expect "... for $name" "DNS:$name" "$seen"
  expect '... extended key usage serverAuth' '^ *TLS Web Server Authentication$' "$seen"
  refuse '... and nothing else (no clientAuth)' 'Client Authentication|,' "$(grep -E '^ *TLS Web' <<<"$seen")"
  fp1=$(sed -n 's/^sha256: //p' <<<"$seen")
  [ -n "$fp1" ] || fail 'no fingerprint read'

  step "$svc: renews within the test, without a manual step"
  start=$SECONDS
  note "presented now: $fp1; waiting for another fingerprint on $name:443 (deadline 360s)"
  until fp2=$(fingerprint_on "$name" "$name") && [ -n "$fp2" ] && [ "$fp2" != "$fp1" ]; do
    [ $((SECONDS - start)) -lt 360 ] || fail "$svc still presents $fp1 after 360s"
    sleep 5
  done
  seen=$(probe "$name" "$name")
  show <<<"$seen"
  pass "$svc presents a new certificate after $((SECONDS - start))s: $fp2"
  expect '... which curl verifies with the root alone' '^curl exit: 0 hello' "$seen"
  expect '... and gnutls-cli' '^gnutls exit: 0 ' "$seen"
  expect '... serverAuth only' '^ *TLS Web Server Authentication$' "$seen"

  step "$svc: a name outside the CA's policy (outside.example.org)"
  since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  "foreign_$svc" outside.example.org
  start=$SECONDS
  until ca_log_since "$since" | grep -q 'outside\.example\.org.*not allowed\|not allowed.*outside\.example\.org'; do
    [ $((SECONDS - start)) -lt 90 ] || { ca_log_since "$since" | tail -20 >&2; fail 'the CA logged no refusal of outside.example.org within 90s'; }
    sleep 3
  done
  ca_log=$(ca_log_since "$since" | grep -m 3 -o '.\{0,60\}outside\.example\.org.\{0,120\}' || true)
  show <<<"$ca_log"
  pass 'the CA refused outside.example.org by its policy'
  log=$(foreign_log "$svc" "$since" outside.example.org)
  show <<<"$log"
  expect "$svc reports the refusal" 'not allowed|forbidden|rejectedIdentifier|policy' "$log"
  seen=$(probe "$name" outside.example.org)
  show <<<"$seen"
  refuse "for outside.example.org the client gets nothing it accepts" '^curl exit: 0 |^gnutls exit: 0 ' "$seen"
  refuse '... and no certificate of the CA for that name' 'DNS:outside\.example\.org' "$seen"
  note "what $svc presents for outside.example.org: $(grep -E '^(subject=|no certificate)' <<<"$seen" | head -n 1)"
  seen=$(probe "$name" "$name")
  expect "$svc keeps serving $name" '^curl exit: 0 hello' "$seen"

  step "$svc: a challenge for a name it does not control (decoy.example.internal)"
  since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  "foreign_$svc" decoy.example.internal
  # the evidence is the CA's own record: the authorization for the name
  # with the error of its challenge (step-ca keeps a failed challenge
  # pending and tries again; the client gives up in its own time)
  start=$SECONDS
  until decoy_errors "$since" | grep -q 'urn:ietf:params:acme:error'; do
    [ $((SECONDS - start)) -lt 120 ] || {
      ca_log_since "$since" | grep -i decoy | tail -n 5 | cut -c 1-600 >&2
      fail "the CA recorded no failed challenge for decoy.example.internal within 120s"
    }
    sleep 3
  done
  decoy_errors "$since" | show
  pass "the CA's challenge for decoy.example.internal failed"
  # step-ca 0.30.2 reports an HTTP status >= 400 of the target with this
  # same type and generic detail (acme/challenge.go); what the CA reached
  # is seen by the client at the same name: decoy, without the token
  seen=$(in_client 'echo "page: $(curl -sS http://decoy.example.internal/)"; echo "challenge path: $(curl -sS -o /dev/null -w "%{http_code}" http://decoy.example.internal/.well-known/acme-challenge/probe)"' 2>&1 | plain)
  show <<<"$seen"
  expect "... decoy.example.internal leads to decoy, not to $svc" '^page: decoy$' "$seen"
  expect '... which has no token to show (404)' '^challenge path: 404$' "$seen"
  ca_log=$(ca_log_since "$since" | grep -F 'decoy.example.internal' | sed 's/\\"/"/g' | grep -c '"status":"valid"' || true)
  [ "$ca_log" -eq 0 ] || fail 'the CA answered with status valid about decoy.example.internal'
  pass '... no authorization or order for it became valid'
  log=$(foreign_log "$svc" "$since" decoy.example.internal)
  [ -z "$log" ] || show <<<"$log"
  note "$svc about decoy.example.internal so far: $([ -n "$log" ] && echo 'the lines above' || echo 'nothing yet (still polling the pending authorization)')"
  seen=$(probe "$name" decoy.example.internal)
  show <<<"$seen"
  refuse '... and the client gets no certificate it accepts for that name' '^curl exit: 0 |^gnutls exit: 0 ' "$seen"
  refuse '... no certificate of the CA names it' 'DNS:decoy\.example\.internal' "$seen"
  seen=$(probe "$name" "$name")
  expect "$svc keeps serving $name" '^curl exit: 0 hello' "$seen"
}

# decoy_errors <since>: the challenge errors in the CA's answers about
# decoy.example.internal, one line per distinct error
decoy_errors() {
  ca_log_since "$1" | grep -F 'decoy.example.internal' | sed 's/\\"/"/g' \
    | grep -o '"type":"urn:ietf:params:acme:error:[A-Za-z]*","detail":"[^"]*"' | sort -u | head -n 4 || true
}

# the images of the running containers of the project, with their digests
images_in_use() {
  local c
  for c in $(docker ps -q --filter "label=com.docker.compose.project=$project"); do
    docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{.Image}}' "$c"
  done | sort | while read -r svc image id; do
    printf '%s: %s %s\n' "$svc" "$image" "$(docker image inspect -f '{{index .RepoDigests 0}}' "$id" 2>/dev/null | sed 's/.*@//')"
  done
}

# every container, volume and network of the project carries sick=1
label_check() {
  local unlabelled
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
  )
  [ -z "$unlabelled" ] || { printf '%s\n' "$unlabelled" | sed 's/^/      | /' >&2; fail 'resources of the project without the label sick=1 (listed above)'; }
  pass "every container, volume and network of $project carries sick=1 ($(docker ps -aq --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | wc -l) containers)"
}

# foreign_<service> <name>: make the service ask for a certificate for <name>
foreign_traefik() {
  local router=${1%%.*}
  cat >"$work/traefik/dynamic/$router.yml" <<EOF
# added by acme-services.sh: a router for a name this Traefik should not get
http:
  routers:
    $router:
      rule: Host(\`$1\`)
      entryPoints: [websecure]
      service: app
      tls:
        certResolver: stepca
EOF
  chmod 644 "$work/traefik/dynamic/$router.yml"
}
foreign_caddy() {
  # appended in place: the file is bind-mounted, its inode has to stay
  printf '\n# added by acme-services.sh\n%s {\n\timport stepca\n\trespond "%s"\n}\n' "$1" "$1" >>"$work/caddy/Caddyfile"
  compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | show
}
foreign_nginx() {
  local rc=0 out
  out=$(compose exec -T acme acme.sh --issue --server https://ca.example.internal:9000/acme/acme/directory \
    --ca-bundle /etc/acme/root_ca.crt -d "$1" --webroot /var/www/acme --days -10 --keylength ec-256 2>&1) || rc=$?
  printf '%s\nacme.sh exit: %s\n' "$out" "$rc" >"$work/foreign-$1.log"
  [ "$rc" -ne 0 ] || fail "acme.sh got a certificate for $1"
}
# foreign_log <service> <since> <name>: what the service said about <name>
# (head ends the pipe early: under pipefail that is no failure here)
foreign_log() {
  case $1 in
    nginx) plain <"$work/foreign-$3.log" | grep -v '^ *$' | tail -n 5 | cut -c 1-600 || true ;;
    *) compose logs --no-log-prefix --since "$2" "$1" 2>&1 | plain | grep -F "$3" | grep -iE 'error|not allowed|invalid|unauthorized|forbidden|fail' | head -n 4 | cut -c 1-600 || true ;;
  esac
}

for p in "${parts[@]}"; do
  case $p in
    traefik) run_part traefik traefik.example.internal ;;
    caddy) run_part caddy caddy.example.internal ;;
    nginx) run_part nginx nginx.example.internal ;;
  esac
done
label_check
note 'images in use (tag, digest)'
images_in_use | show

# teardown runs in the EXIT trap
