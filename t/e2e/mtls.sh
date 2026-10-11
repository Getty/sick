#!/bin/bash
#
# The mTLS recipe of contrib/mtls proven in containers (k59, P8): client
# certificates for a person and a machine from the provisioner "clients" of
# the lab CA, nginx that lets the approved identities in and refuses the six
# cases of P8's done-when, a second client stack, PKCS#12 into NSS, renewal.
# docs/findings/mtls.md holds the record.
#
#   t/e2e/mtls.sh                    every part
#   t/e2e/mtls.sh direct nss         the parts named (the setup always runs)
#
# Setup, every run:
#   - a ceremony intermediate (docker/ceremony.sh, no network) with name
#     constraints DNS example.internal, IP 192.0.2.0/24, email
#     example.internal;
#   - step-ca in import mode on it with docker/provisioners.example.json
#     (provisioner "clients": JWK, clientAuth only, 720h, at most 2160h) and
#     the policy SICK_CA_ALLOW_DNS=*.example.internal,*.machines.example.internal
#     SICK_CA_ALLOW_IP=192.0.2.0/24 SICK_CA_ALLOW_EMAIL=@example.internal;
#   - the admin takes the "clients" password out of the volume (docker/README.md,
#     "Further provisioners") and enrols with contrib/mtls/enroll.sh in the
#     sick image (step 0.30.2): person@example.internal (approved, with
#     PKCS#12), backup1.machines.example.internal (approved),
#     other@example.internal (valid, not in principals.map),
#     proxy.machines.example.internal (the proxy's own identity),
#     person@example.internal once more with 5 minutes (for "expired");
#     server certificates through "sick" for the three nginx and
#     web.example.internal (a serverAuth-only leaf to present as a client);
#     a client certificate of another CA (openssl, here);
#   - a CSR that asks for another subject or SAN than its token is sent to
#     the CA (step ca sign): refused, or the mapping on the subject DN would
#     not hold;
#   - contrib/mtls/compose.yml: nginx "mtls" (mtls.conf), "proxy"
#     (proxy.conf) and "backend" (backend.conf), and a Debian client.
#
# Parts, PASS/FAIL per case with the layer that refused (RECORD for what is
# observed either way); the first FAIL ends the script with 1:
#   direct   curl (OpenSSL) against mtls.conf: person and machine get 200 with
#            their principal; refused: (1) no certificate, (2) another CA,
#            (3) serverAuth-only leaf, (5) valid but not allowed -> 403; the
#            verify result nginx logged says which layer
#   proxy    through proxy.conf: 200 with the principal from the proxy;
#            (6) a spoofed X-Client-Identity through the proxy is replaced;
#            sent directly to the backend: refused with and without a client
#            certificate of the CA; not allowed through the proxy: 403
#   go       Go crypto/tls (t/e2e/mtls-client.go) as the second stack: the
#            same answers for person, machine, not allowed; the refusals
#            recorded
#   nss      the person's PKCS#12 into an NSS database with pk12util
#            (password from a file), tstclnt presents it: 200; a wrong
#            PKCS#12 password: refused, nothing imported
#   renew    step ca renew of the person's certificate over mTLS with
#            --expires-in 240h (not due: untouched) and without (renewed,
#            new serial, same identity, accepted); the old serial revoked
#            through "clients": its renewal refused, nginx still accepts it
#            (passive revocation) until revoked-serials.map names it (403);
#            a certificate renewed before the revocation renews on
#   expired  (4) the 5-minute certificate after its end (the script waits for
#            it): refused by nginx, its renewal refused by the CA
#   policy   the CA again with SICK_CA_ALLOW_DNS=*.example.internal alone:
#            recorded whether it covers backup2.machines.example.internal
#            (two labels below) and whether backup1's renewal is refused
#            once the policy no longer allows its name (last: it changes
#            the CA)
#
# Everything it starts carries the label sick=1 (the Compose project
# through t/e2e/compose.local.yml and t/e2e/mtls-compose.yml, the helper
# containers by --label, with sick-e2e=mtls as well). It removes them by
# project and label, also after a failure or Ctrl-C, checks that nothing is
# left and removes its working directory; a rerun first removes what an
# interrupted run left behind. No prune; the images stay as a cache. No
# port is published but the CA's, on 127.0.0.1 at a random port.
#
# Prerequisites: Docker Engine with Compose 2.24.4 or newer (!reset,
# !override), openssl on this machine, the three source trees side by side;
# the internet for the Debian packages of the client and for images not yet
# here.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR        private working directory, mode 0700, removed at the
#                       end                ($HOME/.local/share/sick-lab/mtls)
#   SICK_E2E_PROJECT    Compose project name, sick-e2e-*        (sick-e2e-mtls)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/mtls}
project=${SICK_E2E_PROJECT:-sick-e2e-mtls}
label=sick-e2e=mtls
marker=.sick-e2e-mtls

# pinned by digest (as pulled on 2026-10-11); nginx and Debian also in
# t/e2e/mtls-compose.yml
img_go=golang:1@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602

all_parts=(direct proxy go nss renew expired policy)
parts=("$@")
[ "${#parts[@]}" -gt 0 ] || parts=("${all_parts[@]}")
wants() { local p; for p in "${parts[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

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

# the results table: case | client | expected | observed | layer
results=()
row() { results+=("| $1 | $2 | $3 | $4 | $5 |"); }

#### prerequisites

for p in "${parts[@]}"; do
  case " ${all_parts[*]} " in *" $p "*) ;; *) fail "unknown part '$p' (${all_parts[*]})" ;; esac
done
for program in docker openssl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[[ $project =~ ^sick-e2e-[a-z0-9_-]+$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick-e2e-*"
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
[ -d "$context/sick-target-proxmox/lib" ] || fail "no checkout of sick-target-proxmox next to $repo"

umask 077
work_parent=$(dirname "$work")
mkdir -p "$work_parent"
work=$(cd "$work_parent" && pwd -P)/$(basename "$work")
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
if [ -e "$work" ]; then
  [ -e "$work/$marker" ] || fail "$work exists and is not the working directory of this script: remove it by hand"
fi

unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ACME_LIFETIME SICK_CA_ACME_MAX_LIFETIME SICK_CA_ACME_MIN_LIFETIME \
  SICK_CA_ACME_CHALLENGES SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ALLOW_EMAIL SICK_CA_ALLOW_URI SICK_CA_IMPORT SICK_CA_IMPORT_DIR \
  SICK_CA_PROVISIONERS SICK_CA_PROVISIONERS_FILE SICK_TRUST_PORT SICK_INTERVAL SICK_RUN_OPTIONS \
  SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE MTLS_REPO MTLS_WORK MTLS_CERTS

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$repo/docker/compose.import.yml" -f "$repo/docker/compose.provisioners.yml" \
    -f "$here/compose.local.yml" -f "$here/compose.ceremony.yml" \
    -f "$repo/contrib/mtls/compose.yml" -f "$here/mtls-compose.yml" "$@"
}
in_ca() { compose exec -T "$@"; }
logs_of() { compose logs --no-log-prefix "$1" 2>&1 | plain; }

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
    pass 'the working directory (keys and passwords of the run included) is removed'
  fi
  note 'the images stay as a cache; nothing was pruned'
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}

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
mkdir -m 700 "$work/admin" "$work/holders" "$work/nginx" "$work/maps" "$work/ceremony-run"
printf '# Generated by t/e2e/mtls.sh: no devices.\nca: { url: https://ca.example.internal:9000 }\ndevices: {}\n' >"$work/sick.yml"
chmod 644 "$work/sick.yml"
install -m 0644 "$repo/docker/provisioners.example.json" "$work/provisioners.json"
install -m 0644 "$repo/contrib/mtls/nginx/revoked-serials.map" "$work/maps/revoked-serials.map"
chmod 755 "$work/maps"

cat >"$work/compose.env" <<EOF
# Generated by t/e2e/mtls.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=SICK E2E mTLS CA
SICK_CA_DNS=ca.example.internal
SICK_CA_IMPORT=$work/ceremony-run/ceremony
SICK_CA_PROVISIONERS=$work/provisioners.json
SICK_CA_ALLOW_DNS=*.example.internal,*.machines.example.internal
SICK_CA_ALLOW_IP=192.0.2.0/24
SICK_CA_ALLOW_EMAIL=@example.internal
SICK_CA_ALLOW_URI=
SICK_CA_PORT=127.0.0.1:0
SICK_TRUST_PORT=127.0.0.1:0
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
MTLS_REPO=$repo
MTLS_WORK=$work
MTLS_CERTS=$work/nginx
EOF

printf 'project %s, working directory %s, parts: %s\n' "$project" "$work" "${parts[*]}"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true

step 'the sick image (step 0.30.2, openssl, bash: the ceremony and the admin tools)'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
pass 'docker compose build sick'

#### setup: ceremony, CA

step 'the ceremony: DNS example.internal, IP 192.0.2.0/24, email example.internal'
dir=$work/ceremony-run
mkdir -m 700 "$dir/rootkey"
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 >"$dir/rootkey/root.pw" || true
docker run --rm --name "$project-ceremony" --label sick=1 --label "$label" --network none \
  --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint bash \
  -v "$repo/docker/ceremony.sh:/ceremony.sh:ro" -v "$dir:/work" \
  sick:local /ceremony.sh --operator 'E2E Operator' --root-password-file /work/rootkey/root.pw \
  --out /work/ceremony --root-key /work/rootkey/root_ca_key \
  --root-name 'SICK E2E mTLS Root CA' --intermediate-name 'SICK E2E mTLS Intermediate CA' \
  --dns example.internal --ip 192.0.2.0/24 --email example.internal 2>&1 | plain >"$work/ceremony.log" \
  || { tail -20 "$work/ceremony.log" >&2; fail 'ceremony.sh'; }
[ -s "$dir/ceremony/intermediate_ca.crt" ] || { tail -20 "$work/ceremony.log" >&2; fail 'the ceremony made no intermediate'; }
nc=$(openssl x509 -in "$dir/ceremony/intermediate_ca.crt" -noout -ext nameConstraints)
show <<<"$nc"
expect 'the intermediate: DNS constraint example.internal' '^ *DNS:example\.internal$' "$nc"
expect '... IP constraint 192.0.2.0/24' '^ *IP:192\.0\.2\.0/255\.255\.255\.0$' "$nc"
expect '... email constraint example.internal' '^ *email:example\.internal$' "$nc"
rm -rf "$dir/rootkey"
pass 'the stand-in root key and its password are removed (the CA never sees them)'

step 'the CA in import mode, provisioner "clients", policy with email'
compose up -d --wait ca >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; logs_of ca | tail -30 >&2; fail 'the CA did not come up healthy'; }
out=$(logs_of ca | grep '^init-ca:' || true)
show <<<"$out"
expect 'init-ca.sh: import mode' '^init-ca: import mode: ' "$out"
expect "... provisioner 'clients' made, clientAuth only" "^init-ca: declared provisioner 'clients' \(JWK\) issues for 720h \(5m to 2160h\), clientAuth only$" "$out"
expect '... the policy with email addresses' 'names allowed: \*\.example\.internal, \*\.machines\.example\.internal, 192\.0\.2\.0/24, @example\.internal' "$out"

step 'the admin: the passwords of "clients" and "sick" out of the volume, the root from the ceremony'
compose cp ca:/home/step/secrets/provisioner_clients_password "$work/admin/clients.pw" >/dev/null 2>&1 || fail 'docker compose cp of the clients password'
compose cp ca:/home/step/secrets/provisioner_password "$work/admin/sick.pw" >/dev/null 2>&1 || fail 'docker compose cp of the sick password'
chmod 600 "$work/admin/clients.pw" "$work/admin/sick.pw"
install -m 0644 "$dir/ceremony/root_ca.crt" "$work/admin/root_ca.crt"
install -m 0644 "$dir/ceremony/root_ca.crt" "$work/holders/root_ca.crt"
pass 'clients.pw and sick.pw in the admin directory, mode 0600'

# admin <script>: bash in the sick image, as this user, on the project's
# network; the admin directory and the holders' directories mounted, the
# recipe read-only
admin() {
  docker run --rm --label sick=1 --label "$label" --network "${project}_default" \
    --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -e CLIENTS_PASSWORD_FILE=/admin/clients.pw -e STEP_ROOT=/admin/root_ca.crt \
    -e STEP_CA_URL=https://ca.example.internal:9000 ${LIFETIME:+-e LIFETIME=$LIFETIME} \
    -v "$work/admin:/admin" -v "$work/holders:/holders" -v "$repo/contrib/mtls:/recipe:ro" \
    --entrypoint bash sick:local -c "$1" 2>&1 | plain
}

step 'enrolment with contrib/mtls/enroll.sh'
enrol() { # <kind> <identity> <holder dir> [lifetime]
  local out
  out=$(LIFETIME=${4:-} admin "/recipe/enroll.sh $1 $2 /holders/$3; echo \"exit: \$?\"")
  show <<<"$out"
  expect "enroll.sh $1 $2" '^exit: 0$' "$out"
}
enrol person person@example.internal person
enrol machine backup1.machines.example.internal backup1
enrol person other@example.internal other
enrol machine proxy.machines.example.internal proxy
if wants expired; then
  enrol person person@example.internal late 5m
fi
for h in person:person@example.internal:email backup1:backup1.machines.example.internal:DNS other:other@example.internal:email; do
  IFS=: read -r d id form <<<"$h"
  f=$work/holders/$d/$id.crt
  facts="$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253)"
  for e in subjectAltName keyUsage extendedKeyUsage; do facts+=" $(openssl x509 -in "$f" -noout -ext $e | sed 1d | tr -d ' ')"; done
  expect "... $id: CN = the identity, $form SAN alone, digitalSignature, clientAuth alone" "^subject=CN=$id $form:$id DigitalSignature TLSWebClientAuthentication$" "$facts"
  [ "$(stat -c %a "$work/holders/$d/$id.key")" = 600 ] || fail "... $id.key is not mode 0600"
done
pass 'every key file is mode 0600, every holder directory 0700, one key per holder'
keys=$(for d in person backup1 other proxy; do openssl pkey -in "$work/holders/$d/"*.key -pubout 2>/dev/null | sha256sum; done | sort -u | wc -l)
[ "$keys" = 4 ] || fail "four holders, $keys distinct keys"
pass 'four holders, four distinct public keys'
p12info=$(openssl pkcs12 -in "$work/holders/person/person@example.internal.p12" -passin "file:$work/holders/person/person@example.internal.p12.pw" -info -noout 2>&1 || true)
show <<<"$p12info"
expect 'the PKCS#12 opens with its password file (openssl pkcs12 -info)' 'MAC: sha256|MAC:' "$p12info"
record "PKCS#12 of step certificate p12: $(grep -E '^(MAC|PKCS7|Shrouded|PKCS7 Encrypted)' <<<"$p12info" | tr '\n' ';')"
nchain=$(openssl pkcs12 -in "$work/holders/person/person@example.internal.p12" -passin "file:$work/holders/person/person@example.internal.p12.pw" -nokeys 2>/dev/null | grep -c 'BEGIN CERTIFICATE')
[ "$nchain" = 2 ] || fail "the PKCS#12 holds $nchain certificates, not leaf and intermediate"
pass 'the PKCS#12 holds the leaf and the intermediate'

step 'server certificates through "sick", and a serverAuth-only leaf to present as a client'
out=$(admin '
  set -e
  export STEPPATH=$(mktemp -d)
  for n in mtls app backend web; do
    mkdir -p /holders/server-$n
    step ca certificate $n.example.internal /holders/server-$n/server.crt /holders/server-$n/server.key \
      --provisioner sick --provisioner-password-file /admin/sick.pw --not-after 24h \
      --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt >/dev/null
    echo "issued $n.example.internal: $(openssl x509 -in /holders/server-$n/server.crt -noout -ext extendedKeyUsage | sed 1d | tr -d " ")"
  done')
show <<<"$out"
expect 'mtls, app, backend and web.example.internal issued, serverAuth alone' '^issued web\.example\.internal: TLSWebServerAuthentication$' "$out"
[ "$(grep -c ': TLSWebServerAuthentication$' <<<"$out")" = 4 ] || fail '... not all four serverAuth alone'

note 'a client certificate of another CA (openssl, here): same subject and SAN as the approved person'
f=$work/holders/foreign
mkdir -m 700 "$f"
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$f/ca.key" -subj '/CN=Foreign Root CA' \
  -days 1 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$f/ca.crt" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$f/client.key" -subj '/CN=person@example.internal' -out "$f/client.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=email:person@example.internal\n' >"$f/ext"
openssl x509 -req -in "$f/client.csr" -CA "$f/ca.crt" -CAkey "$f/ca.key" -set_serial "0x$(openssl rand -hex 16)" -days 1 \
  -extfile "$f/ext" -out "$f/client.crt" 2>/dev/null
rm -f "$f/ca.key" "$f/client.csr" "$f/ext"
pass 'foreign: CN=person@example.internal, email SAN, clientAuth, signed by "Foreign Root CA"'

step 'a CSR that asks for another identity than its token'
out=$(admin '
  export STEPPATH=$(mktemp -d); cd "$STEPPATH"
  token() { step ca token person@example.internal --san person@example.internal --provisioner clients \
    --provisioner-password-file /admin/clients.pw --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt 2>/dev/null; }
  probe() { # <name> <subject> <SAN>
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout k -subj "/CN=$2" -addext "subjectAltName=$3" -out r.csr 2>/dev/null
    rm -f c.crt
    step ca sign --token "$(token)" --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt r.csr c.crt >o 2>&1
    rc=$?
    echo "$1 exit=$rc $(grep -m1 -iE "error|forbidden|not|invalid|fail" o)"
    [ ! -s c.crt ] || echo "$1 issued $(openssl x509 -in c.crt -noout -subject -nameopt RFC2253) $(openssl x509 -in c.crt -noout -ext subjectAltName | sed 1d | tr -d " ")"
  }
  probe cn-other admin@example.internal email:person@example.internal
  probe san-other person@example.internal email:admin@example.internal
  probe both-match person@example.internal email:person@example.internal
  rm -rf "$STEPPATH"')
show <<<"$out"
expect 'control: a CSR that matches its token is signed' '^both-match exit=0' "$out"
expect '... with the subject of the token' '^both-match issued subject=CN=person@example\.internal email:person@example\.internal$' "$out"
for c in cn-other san-other; do
  if grep -q "^$c exit=0" <<<"$out"; then
    expect "$c: signed, but with the token's identity, not the CSR's" "^$c issued subject=CN=person@example\.internal email:person@example\.internal$" "$out"
    record "$c: the CA signed it and took subject and SAN from the token"
  else
    pass "$c: the CA refuses a CSR whose $( [ $c = cn-other ] && echo subject || echo SAN ) differs from the token"
    record "$c: $(grep "^$c exit=" <<<"$out" | cut -d' ' -f3-)"
  fi
done

step 'the nginx services and the client'
for n in mtls proxy backend; do mkdir -m 700 "$work/nginx/$n"; done
cat "$dir/ceremony/root_ca.crt" "$dir/ceremony/intermediate_ca.crt" >"$work/nginx/client-ca-bundle.pem"
for n in mtls proxy backend; do
  src=$n; [ "$n" = proxy ] && src=app
  install -m 0644 "$work/holders/server-$src/server.crt" "$work/nginx/$n/server.crt"
  install -m 0600 "$work/holders/server-$src/server.key" "$work/nginx/$n/server.key"
  install -m 0644 "$work/nginx/client-ca-bundle.pem" "$work/nginx/$n/client-ca-bundle.pem"
done
install -m 0644 "$work/holders/proxy/proxy.machines.example.internal.crt" "$work/nginx/proxy/proxy-client.crt"
install -m 0600 "$work/holders/proxy/proxy.machines.example.internal.key" "$work/nginx/proxy/proxy-client.key"
install -m 0644 "$dir/ceremony/root_ca.crt" "$work/nginx/proxy/upstream-ca.pem"
rm -f "$work/nginx/client-ca-bundle.pem"
pass 'client-ca-bundle.pem = root + intermediate, for each nginx; the server chains apart'
published=$(compose config --format json 2>/dev/null | python3 -I -c '
import json, sys
c = json.load(sys.stdin)
for name, svc in c.get("services", {}).items():
    for p in svc.get("ports") or []:
        print(name, p.get("host_ip", "0.0.0.0"), p.get("published"))')
show <<<"$published"
refuse 'no port published beyond 127.0.0.1 (compose config)' '.' "$(grep -v ' 127\.0\.0\.1 ' <<<"$published" || true)"
refuse '... the nginx services publish nothing' '^(mtls|proxy|backend|client) ' "$published"
compose up -d --wait mtls proxy backend client >"$work/up-nginx.log" 2>&1 \
  || { plain <"$work/up-nginx.log" | tail -20 >&2; for n in mtls proxy backend; do logs_of $n | tail -10 >&2; done; fail 'the nginx services did not come up'; }
pass 'mtls, proxy, backend and client are up'
for kind in container volume network; do
  for id in $(docker $kind ls -q --filter "label=com.docker.compose.project=$project" 2>/dev/null || docker ps -q --filter "label=com.docker.compose.project=$project"); do
    if [ "$kind" = container ]; then fmt='{{index .Config.Labels "sick"}}'; else fmt='{{index .Labels "sick"}}'; fi
    [ "$(docker $kind inspect --format "$fmt" "$id" 2>/dev/null)" = 1 ] || fail "$kind $id of $project carries no label sick=1"
  done
done
pass "every container, volume and network of $project carries sick=1"

note 'the client: curl, openssl, the NSS tools from Debian'
out=$(compose exec -T client bash -c '
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates openssl libnss3-tools; } >/tmp/apt.log 2>&1 \
    || { tail -20 /tmp/apt.log; echo "ERROR apt-get"; exit 1; }
  echo "VERSION $(curl --version | head -n 1)"
  echo "VERSION $(openssl version)"
  echo "VERSION NSS $(dpkg-query -W -f "\${Version}" libnss3)"
  command -v tstclnt pk12util certutil' 2>&1 | plain)
show <<<"$out"
expect 'curl, pk12util, certutil and tstclnt in the client' 'tstclnt' "$out"
grep '^VERSION' <<<"$out" | sed 's/^VERSION /version: /' >"$work/versions"
printf 'version: nginx %s\n' "$(compose exec -T mtls nginx -v 2>&1 | plain | sed 's/^nginx version: //')" >>"$work/versions"

#### the probes

# curl_probe <url> <cert|-> <key|-> [curl args...]: from the client; prints
# code=, exit=, body=, err=
curl_probe() {
  compose exec -T client bash -c '
    url=$1 cert=$2 key=$3; shift 3
    args=(); [ "$cert" = - ] || args=(--cert "$cert" --key "$key")
    code=$(curl -sS --max-time 10 --cacert /holders/root_ca.crt "${args[@]}" "$@" -o /tmp/body -w "%{http_code}" "$url" 2>/tmp/err)
    rc=$?
    echo "code=$code exit=$rc"
    echo "body=$(head -n 1 /tmp/body 2>/dev/null)"
    echo "err=$(head -n 1 /tmp/err)"
    rm -f /tmp/body /tmp/err' bash "$@" 2>&1 | plain
}
last_log() { logs_of "$1" | grep 'verify=' | tail -n 1; }
layer_of() { # <probe output> <nginx log line>
  local code
  code=$(sed -n 's/^code=\([0-9]*\) .*/\1/p' <<<"$1" | head -n 1)
  if ! grep -q 'exit=0' <<<"$1"; then echo "TLS: $(sed -n 's/^err=//p' <<<"$1")"
  elif [ "$code" = 400 ]; then echo "HTTP 400 after the handshake, nginx $(grep -o 'verify=[^ ]*\( [a-z][^=]*\)*' <<<"$2" | sed 's/ dn$//')"
  elif [ "$code" = 403 ]; then echo "HTTP 403 (authorization), nginx $(grep -o 'verify=[A-Z]*' <<<"$2") $(grep -o 'principal="[^"]*"' <<<"$2")"
  else echo "HTTP $code"; fi
}

# direct_case <case> <want code> <want body regex|-> <want verify regex> <url> <cert> <key> [curl args]
H=/holders
P=$H/person/person@example.internal
M=$H/backup1/backup1.machines.example.internal
O=$H/other/other@example.internal
probe_case() {
  local name=$1 svc=$2 want=$3 body=$4 verify=$5 url=$6 cert=$7 key=$8 out log layer code
  shift 8
  out=$(curl_probe "$url" "$cert" "$key" "$@")
  log=$(last_log "$svc")
  layer=$(layer_of "$out" "$log")
  code=$(sed -n 's/^code=\([0-9]*\) .*/\1/p' <<<"$out" | head -n 1)
  [ "$code" = "$want" ] || { printf '%s\n%s\n' "$out" "$log" | sed 's/^/      | /' >&2; fail "$name: HTTP $code, expected $want"; }
  [ "$body" = - ] || grep -Eq -- "^body=$body\$" <<<"$out" || { printf '%s\n' "$out" | sed 's/^/      | /' >&2; fail "$name: body is not /$body/"; }
  [ "$verify" = - ] || grep -Eq -- "verify=$verify" <<<"$log" || { printf '%s\n' "$log" | sed 's/^/      | /' >&2; fail "$name: nginx logged no /verify=$verify/"; }
  pass "$name: $layer$( [ "$body" = - ] || printf ', %s' "$(sed -n 's/^body=//p' <<<"$out")")"
  row "$name" curl "$want" "$code $(sed -n 's/^body=//p' <<<"$out" | cut -c1-40)" "$layer"
}

if wants direct; then
  step 'direct: curl (OpenSSL) against mtls.conf'
  U=https://mtls.example.internal/
  probe_case 'approved person' mtls 200 'principal=person' SUCCESS "$U" "$P.crt" "$P.key"
  probe_case 'approved machine' mtls 200 'principal=backup1' SUCCESS "$U" "$M.crt" "$M.key"
  probe_case '(1) no certificate' mtls 400 - NONE "$U" - -
  probe_case '(2) a certificate of another CA (same subject and SAN)' mtls 400 - 'FAILED:' "$U" "$H/foreign/client.crt" "$H/foreign/client.key"
  probe_case '(3) serverAuth-only leaf of the CA as a client' mtls 400 - 'FAILED:.*purpose' "$U" "$H/server-web/server.crt" "$H/server-web/server.key"
  probe_case '(5) valid certificate, identity not allowed' mtls 403 'not allowed' SUCCESS "$U" "$O.crt" "$O.key"
  record "nginx logged for (2) and (3): $(logs_of mtls | grep -o 'verify=FAILED:.* dn=' | sed 's/ dn=$//' | sort -u | tr '\n' ';')"
fi

if wants proxy; then
  step 'proxy: proxy.conf in front of backend.conf'
  U=https://app.example.internal/
  B=https://backend.example.internal:8443/
  probe_case 'through the proxy: approved person' proxy 200 'principal=person' SUCCESS "$U" "$P.crt" "$P.key"
  probe_case 'through the proxy: approved machine' proxy 200 'principal=backup1' SUCCESS "$U" "$M.crt" "$M.key"
  probe_case '(6) spoofed X-Client-Identity through the proxy: replaced' proxy 200 'principal=person' SUCCESS "$U" "$P.crt" "$P.key" -H 'X-Client-Identity: admin'
  probe_case '(6) ... twice, in another case: replaced' proxy 200 'principal=person' SUCCESS "$U" "$P.crt" "$P.key" -H 'X-Client-Identity: admin' -H 'x-client-identity: root'
  probe_case '(6) ... by an identity not allowed: 403 at the proxy' proxy 403 'not allowed' SUCCESS "$U" "$O.crt" "$O.key" -H 'X-Client-Identity: person'
  # direct to the backend: the log of the backend is the default format
  out=$(curl_probe "$B" - - -H 'X-Client-Identity: person')
  code=$(sed -n 's/^code=\([0-9]*\) .*/\1/p' <<<"$out")
  refuse '(6) spoofed header directly to the backend, no certificate: no principal' '^body=principal=' "$out"
  [ "$code" = 400 ] || fail "... HTTP $code, expected 400 (no certificate)"
  pass "... $(layer_of "$out" 'verify=NONE')"
  row '(6) spoofed header direct to backend, no certificate' curl 400 "$code" "$(layer_of "$out" 'verify=NONE')"
  out=$(curl_probe "$B" "$P.crt" "$P.key" -H 'X-Client-Identity: person')
  code=$(sed -n 's/^code=\([0-9]*\) .*/\1/p' <<<"$out")
  expect '(6) spoofed header directly to the backend with the approved person'"'"'s certificate: 403' '^body=not the proxy$' "$out"
  [ "$code" = 403 ] || fail "... HTTP $code, expected 403"
  row '(6) spoofed header direct to backend, valid client certificate' curl 403 "$code not the proxy" 'HTTP 403 (backend: DN is not the proxy)'
  out=$(curl_probe "$B" "$H/server-web/server.crt" "$H/server-web/server.key" -H 'X-Client-Identity: person')
  code=$(sed -n 's/^code=\([0-9]*\) .*/\1/p' <<<"$out")
  [ "$code" = 400 ] || fail "(6) ... with a serverAuth leaf: HTTP $code, expected 400"
  pass '(6) spoofed header directly to the backend with a serverAuth leaf: 400'
  backend_log=$(logs_of backend | grep -c '"GET / ' || true)
  record "backend access log: $backend_log requests"
fi

if wants go; then
  step 'go: the second stack (Go crypto/tls)'
  declare -A gnginx=()
  cat >"$work/holders/cases" <<EOF
approved-person https://mtls.example.internal/ $P.crt $P.key
approved-machine https://mtls.example.internal/ $M.crt $M.key
not-allowed https://mtls.example.internal/ $O.crt $O.key
no-certificate https://mtls.example.internal/ - -
other-ca https://mtls.example.internal/ $H/foreign/client.crt $H/foreign/client.key
serverauth-leaf https://mtls.example.internal/ $H/server-web/server.crt $H/server-web/server.key
proxy-person https://app.example.internal/ $P.crt $P.key
backend-direct https://backend.example.internal:8443/ $P.crt $P.key
EOF
  chmod 644 "$work/holders/cases"
  out=$(docker run --rm --name "$project-go" --label sick=1 --label "$label" --network "${project}_default" \
    -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/go -e GOTOOLCHAIN=local \
    -v "$here/mtls-client.go:/code/main.go:ro" -v "$work/holders:/holders:ro" \
    "$img_go" go run /code/main.go /holders 2>&1 | plain)
  show <<<"$out"
  grep '^VERSION' <<<"$out" | sed 's/^VERSION /version: /' >>"$work/versions"
  gexp() { # <case> <regex> <what>
    local line
    line=$(grep "^RESULT $1 " <<<"$out" || true)
    grep -Eq -- "$2" <<<"$line" || fail "Go $1: $line (expected /$2/)"
    pass "Go $1: $3: ${line#RESULT $1 }"
    row "$1" Go "$3" "${line#RESULT $1 }" "$( case $line in *status=403*) echo 'HTTP 403 (authorization)';; *status=400*) echo 'HTTP 400 after the handshake';; *error=*) echo TLS;; *) echo 'HTTP 200';; esac)"
  }
  # what nginx saw of the six requests to mtls.example.internal, in order
  mapfile -t glog < <(logs_of mtls | grep 'verify=' | tail -n 6)
  gi=0
  for c in approved-person approved-machine not-allowed no-certificate other-ca serverauth-leaf; do
    record "Go $c, nginx logged: $(grep -o 'verify=.* dn=' <<<"${glog[$gi]}" | sed 's/ dn=$//')"
    gnginx[$c]=$(grep -o 'verify=.* dn=' <<<"${glog[$gi]}" | sed 's/ dn=$//')
    gi=$((gi + 1))
  done
  gexp approved-person 'status=200 body=principal=person$' '200'
  gexp approved-machine 'status=200 body=principal=backup1$' '200'
  gexp not-allowed 'status=403 body=not allowed$' '403'
  gexp proxy-person 'status=200 body=principal=person$' '200'
  for c in no-certificate other-ca serverauth-leaf backend-direct; do
    line=$(grep "^RESULT $c " <<<"$out" || true)
    refuse "Go $c: refused" 'status=200' "$line"
    record "Go $c: ${line#RESULT $c }"
    row "$c" Go refused "${line#RESULT $c }" "$( case $line in *status=403*) echo 'HTTP 403';; *status=400*) echo "HTTP 400 after the handshake, nginx ${gnginx[$c]:-}";; *) echo TLS;; esac)"
  done
fi

if wants nss; then
  step 'nss: the PKCS#12 into an NSS database, tstclnt presents it'
  out=$(compose exec -T client bash -c '
    d=$(mktemp -d)
    head -c 24 /dev/urandom | base64 | tr -d "\n" >"$d/db.pw"
    certutil -N -d "sql:$d" -f "$d/db.pw" || { echo "ERROR certutil -N"; exit 1; }
    certutil -A -d "sql:$d" -n "lab root" -t "C,," -i /holders/root_ca.crt -f "$d/db.pw" || { echo "ERROR certutil -A"; exit 1; }
    p12=/holders/person/person@example.internal.p12
    printf "not-the-password" >"$d/wrong.pw"
    pk12util -i "$p12" -d "sql:$d" -k "$d/db.pw" -w "$d/wrong.pw" >"$d/o" 2>&1; echo "wrong exit=$? $(head -n 2 "$d/o" | tr "\n" " ")"
    echo "after wrong: $(certutil -L -d "sql:$d" | grep -c "u,u,u") user certificates"
    pk12util -i "$p12" -d "sql:$d" -k "$d/db.pw" -w "${p12}.pw" >"$d/o" 2>&1; echo "right exit=$? $(head -n 2 "$d/o" | tr "\n" " ")"
    certutil -L -d "sql:$d" | sed "s/^/list: /"
    nick=$(certutil -L -d "sql:$d" | grep "u,u,u" | sed "s/ *u,u,u *$//" | head -n 1)
    echo "nickname: $nick"
    req() { printf "GET / HTTP/1.0\r\nHost: $1\r\n\r\n"; }
    req mtls.example.internal | timeout 10 tstclnt -h mtls.example.internal -p 443 -d "sql:$d" -W "$d/db.pw" -n "$nick" >"$d/t" 2>&1
    echo "tstclnt with the certificate exit=$?"; grep -E "^HTTP/|^principal=" "$d/t" | sed "s/^/tstclnt: /"
    req mtls.example.internal | timeout 10 tstclnt -h mtls.example.internal -p 443 -d "sql:$d" -W "$d/db.pw" >"$d/t" 2>&1
    echo "tstclnt without exit=$?"; grep -E "^HTTP/" "$d/t" | sed "s/^/tstclnt-none: /"
    rm -rf "$d"' 2>&1 | plain)
  show <<<"$out"
  refuse 'pk12util with a wrong password file: refused' '^wrong exit=0 ' "$out"
  expect '... and nothing imported' '^after wrong: 0 user certificates$' "$out"
  record "pk12util, wrong password: $(grep '^wrong exit=' <<<"$out")"
  row 'PKCS#12, wrong password' pk12util refused "$(grep '^wrong exit=' <<<"$out" | cut -c1-60)" 'PKCS#12 MAC'
  expect 'pk12util with the password file: imported' '^right exit=0 ' "$out"
  expect '... the person'"'"'s certificate with its key (u,u,u)' 'u,u,u' "$out"
  expect 'tstclnt presents it: 200 with the principal' '^tstclnt: principal=person$' "$out"
  row 'PKCS#12 in NSS, tstclnt' tstclnt 200 "$(grep -m1 '^tstclnt: HTTP' <<<"$out" | sed 's/^tstclnt: //') principal=person" 'HTTP 200'
  log=$(last_log mtls)
  record "tstclnt without -n: $(grep -m1 '^tstclnt-none: ' <<<"$out" | sed 's/^tstclnt-none: //'), nginx: $(grep -o 'verify=[A-Z]*' <<<"$log") $(grep -o 'principal="[^"]*"' <<<"$log") - NSS picks a certificate of its own database whose issuer the server names"
  row 'NSS, no nickname given (-n missing)' tstclnt '(observed)' "$(grep -m1 '^tstclnt-none: ' <<<"$out" | sed 's/^tstclnt-none: //')" "nginx $(grep -o 'verify=[A-Z]*' <<<"$log") $(grep -o 'principal="[^"]*"' <<<"$log")"
fi

if wants renew; then
  step 'renew: step ca renew of the person'"'"'s certificate over mTLS'
  cp -p "$work/holders/person/person@example.internal.crt" "$work/admin/person-old.crt"
  cp -p "$work/holders/person/person@example.internal.key" "$work/admin/person-old.key"
  cp -p "$work/admin/person-old.crt" "$work/holders/person/old.crt"
  cp -p "$work/admin/person-old.key" "$work/holders/person/old.key"
  old_serial=$(openssl x509 -in "$work/admin/person-old.crt" -noout -serial | sed 's/^serial=//')
  out=$(admin '
    export STEPPATH=$(mktemp -d)
    c=/holders/person/person@example.internal
    step ca renew --force --expires-in 240h --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt $c.crt $c.key 2>&1 | sed "s/^/not-due: /"
    echo "not-due serial $(openssl x509 -in $c.crt -noout -serial)"
    step ca renew --force --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt $c.crt $c.key 2>&1 | sed "s/^/renew: /"
    echo "renew exit=${PIPESTATUS[0]}"
    echo "renewed serial $(openssl x509 -in $c.crt -noout -serial)"
    echo "renewed $(openssl x509 -in $c.crt -noout -subject -nameopt RFC2253) $(openssl x509 -in $c.crt -noout -ext subjectAltName | sed 1d | tr -d " ") $(openssl x509 -in $c.crt -noout -ext extendedKeyUsage | sed 1d | tr -d " ")"')
  show <<<"$out"
  expect '--expires-in 240h on a fresh 720h certificate: not renewed' "^not-due serial serial=$old_serial\$" "$out"
  expect 'step ca renew: exit 0' '^renew exit=0$' "$out"
  new_serial=$(sed -n 's/^renewed serial serial=//p' <<<"$out")
  [ -n "$new_serial" ] && [ "$new_serial" != "$old_serial" ] || fail "the renewal did not change the serial ($old_serial -> $new_serial)"
  pass "renewed: serial $old_serial -> $new_serial"
  expect '... same identity, clientAuth alone' '^renewed subject=CN=person@example\.internal email:person@example\.internal TLSWebClientAuthentication$' "$out"
  same=$(for f in "$work/admin/person-old.crt" "$work/holders/person/person@example.internal.crt"; do openssl x509 -in "$f" -noout -pubkey | sha256sum; done | sort -u | wc -l)
  record "the renewed certificate has $( [ "$same" = 1 ] && echo 'the same key' || echo 'a new key') (step ca renew without --rekey)"
  probe_case 'the renewed certificate at nginx' mtls 200 'principal=person' SUCCESS https://mtls.example.internal/ "$P.crt" "$P.key"
  out=$(logs_of mtls | grep 'verify=SUCCESS' | tail -n 1)
  expect '... nginx saw the new serial' "serial=$new_serial " "$out"

  note 'the old certificate revoked through "clients" (a lost device)'
  out=$(admin '
    export STEPPATH=$(mktemp -d)
    serial=$(step certificate inspect --format json /admin/person-old.crt | sed -n "s/.*\"serial_number\": *\"\([0-9]*\)\".*/\1/p")
    tok=$(step ca token "$serial" --revoke --provisioner clients --provisioner-password-file /admin/clients.pw \
      --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt 2>/dev/null)
    step ca revoke --token "$tok" --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt "$serial" 2>&1 | sed "s/^/revoke: /"
    echo "revoke exit=${PIPESTATUS[0]}"
    cp /admin/person-old.crt "$STEPPATH/o.crt"; cp /admin/person-old.key "$STEPPATH/o.key"
    step ca renew --force --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt "$STEPPATH/o.crt" "$STEPPATH/o.key" 2>&1 | sed "s/^/renew-revoked: /"
    echo "renew-revoked exit=${PIPESTATUS[0]}"
    c=/holders/person/person@example.internal
    cp $c.crt "$STEPPATH/n.crt"; cp $c.key "$STEPPATH/n.key"
    step ca renew --force --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt "$STEPPATH/n.crt" "$STEPPATH/n.key" 2>&1 | sed "s/^/renew-descendant: /"
    echo "renew-descendant exit=${PIPESTATUS[0]}"
    rm -rf "$STEPPATH"')
  show <<<"$out"
  expect 'step ca revoke of the old serial with a "clients" token: exit 0' '^revoke exit=0$' "$out"
  refuse '... its renewal is refused by the CA' '^renew-revoked exit=0$' "$out"
  record "renewal of the revoked certificate: $(grep -m1 '^renew-revoked: ' <<<"$out" | sed 's/^renew-revoked: //')"
  row 'renewal of a revoked certificate' step refused "$(grep -m1 '^renew-revoked: ' <<<"$out" | sed 's/^renew-revoked: //' | cut -c1-60)" 'CA (renew)'
  if grep -q '^renew-descendant exit=0$' <<<"$out"; then
    record 'the certificate renewed from the old one BEFORE the revocation renews on: revoking a serial does not reach its renewals'
    row 'renewal of a certificate renewed before the revocation' step '(observed)' 'renewed' 'CA (renew)'
  else
    record "the certificate renewed before the revocation: renewal refused: $(grep -m1 '^renew-descendant: ' <<<"$out")"
    row 'renewal of a certificate renewed before the revocation' step '(observed)' 'refused' 'CA (renew)'
  fi
  # step renew keeps the key: the old certificate and the renewed one share it
  if [ "$same" = 1 ]; then
    probe_case 'the revoked certificate at nginx: still accepted (no CRL, no OCSP: passive revocation)' mtls 200 'principal=person' SUCCESS https://mtls.example.internal/ "$H/person/old.crt" "$H/person/old.key"
    printf '%s 1;\n' "$old_serial" >>"$work/maps/revoked-serials.map"
    compose exec -T mtls nginx -s reload >/dev/null 2>&1 || fail 'nginx -s reload'
    sleep 1
    probe_case 'the revoked serial in revoked-serials.map, nginx reloaded: 403' mtls 403 'revoked' SUCCESS https://mtls.example.internal/ "$H/person/old.crt" "$H/person/old.key"
    probe_case '... the renewed certificate of the same person: 200' mtls 200 'principal=person' SUCCESS https://mtls.example.internal/ "$P.crt" "$P.key"
  else
    record 'the renewal made a new key: the old certificate cannot be presented any more'
  fi
  dec=$(admin 'step certificate inspect --format json /holders/person/person@example.internal.crt | sed -n "s/.*\"serial_number\": *\"\([0-9]*\)\".*/\1/p"')
  renew_lines=$(logs_of ca | grep 'path=/renew' | tail -n 3 | grep -oE '(status|subject|serial|error)=("[^"]*"|[^ ]*)' | paste -sd' ' -)
  show <<<"$renew_lines"
  ca_log=$(logs_of ca)
  if [ -n "$dec" ] && grep -q "path=/renew.*serial=$dec " <<<"$ca_log"; then
    record "the CA log names subject and serial of every renewal (serial=$dec subject=person@example.internal): an admin finds the renewals of a lost certificate there"
  else
    record "the CA log does not name the serial of the renewal ($dec)"
  fi
fi

if wants expired; then
  step 'expired: (4) the 5-minute certificate after its end'
  L=$H/late/person@example.internal
  end=$(openssl x509 -in "$work/holders/late/person@example.internal.crt" -noout -enddate | sed 's/^notAfter=//')
  end_s=$(date -d "$end" +%s)
  wait_s=$((end_s - $(date +%s) + 3))
  record "issued by step-ca through clients with --not-after 5m, ends $end"
  if [ "$wait_s" -gt 0 ]; then
    note "waiting ${wait_s}s for it to expire"
    sleep "$wait_s"
  fi
  probe_case '(4) an expired client certificate of the CA' mtls 400 - 'FAILED:certificate has expired' https://mtls.example.internal/ "$L.crt" "$L.key"
  out=$(admin '
    export STEPPATH=$(mktemp -d); cp /holders/late/person@example.internal.crt "$STEPPATH/l.crt"; cp /holders/late/person@example.internal.key "$STEPPATH/l.key"
    step ca renew --force --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt "$STEPPATH/l.crt" "$STEPPATH/l.key" 2>&1 | sed "s/^/renew-expired: /"
    echo "renew-expired exit=${PIPESTATUS[0]}"; rm -rf "$STEPPATH"')
  show <<<"$out"
  refuse '... its renewal is refused by the CA (no renewal after expiry)' '^renew-expired exit=0$' "$out"
  row 'renewal of an expired certificate' step refused "$(grep -m1 '^renew-expired: ' <<<"$out" | sed 's/^renew-expired: //' | cut -c1-60)" 'CA (renew)'
  if wants go; then
    printf 'expired https://mtls.example.internal/ %s.crt %s.key\n' "$L" "$L" >"$work/holders/cases"
    chmod 644 "$work/holders/cases"
    out=$(docker run --rm --name "$project-go" --label sick=1 --label "$label" --network "${project}_default" \
      -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/go -e GOTOOLCHAIN=local \
      -v "$here/mtls-client.go:/code/main.go:ro" -v "$work/holders:/holders:ro" \
      "$img_go" go run /code/main.go /holders 2>&1 | plain)
    line=$(grep '^RESULT expired ' <<<"$out" || true)
    refuse 'Go expired: refused' 'status=200' "$line"
    record "Go expired: ${line#RESULT expired }"
    row expired Go refused "${line#RESULT expired }" "$(case $line in *status=400*) echo 'HTTP 400 after the handshake';; *) echo TLS;; esac)"
  fi
fi

if wants policy; then
  step 'policy: SICK_CA_ALLOW_DNS=*.example.internal alone - two labels below?'
  sed -i 's/^SICK_CA_ALLOW_DNS=.*/SICK_CA_ALLOW_DNS=*.example.internal/' "$work/compose.env"
  compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
  expect 'init-ca.sh: the policy without *.machines.example.internal' 'configuration updated: .*names allowed: \*\.example\.internal, 192\.0\.2\.0/24, @example\.internal' "$(logs_of ca | grep '^init-ca:')"
  out=$(admin '
    export STEPPATH=$(mktemp -d); cd "$STEPPATH"
    step ca certificate backup2.machines.example.internal c.crt c.key --provisioner clients --provisioner-password-file /admin/clients.pw \
      --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt >o 2>&1; echo "issue exit=$? $(grep -m1 -iE "not allowed|forbidden|error" o)"
    step ca certificate host2.example.internal c2.crt c2.key --provisioner clients --provisioner-password-file /admin/clients.pw \
      --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt >o 2>&1; echo "control exit=$?"
    cp /holders/backup1/backup1.machines.example.internal.crt b.crt; cp /holders/backup1/backup1.machines.example.internal.key b.key
    step ca renew --force --ca-url https://ca.example.internal:9000 --root /admin/root_ca.crt b.crt b.key >o 2>&1; echo "renew exit=$? $(head -n 1 o)"
    rm -rf "$STEPPATH"')
  show <<<"$out"
  expect 'control: host2.example.internal (one label below) issued' '^control exit=0$' "$out"
  if grep -q '^issue exit=0' <<<"$out"; then
    record '*.example.internal covers backup2.machines.example.internal (two labels below)'
  else
    record "*.example.internal does not cover backup2.machines.example.internal: $(grep '^issue exit=' <<<"$out" | cut -d' ' -f3-)"
  fi
  record "renewal of backup1.machines.example.internal once the policy no longer allows it: $(grep '^renew exit=' <<<"$out")"
  row 'policy *.example.internal: backup2.machines.example.internal' step '(observed)' "$(grep '^issue exit=' <<<"$out" | cut -c1-70)" 'CA policy (issue)'
  row 'policy *.example.internal: renewal of backup1.machines.example.internal' step '(observed)' "$(grep '^renew exit=' <<<"$out" | cut -c1-70)" 'CA policy (renew)'
fi

#### the record

step 'results'
printf '| case | client | expected | observed | layer |\n|---|---|---|---|---|\n'
printf '%s\n' "${results[@]}"
printf '\n'
sort -u "$work/versions"
printf 'version: step-ca %s\n' "$(in_ca ca step-ca version 2>&1 | plain | head -n 1)"
printf 'version: step (admin, sick image) %s\n' "$(admin 'step version' | head -n 1)"

# teardown runs in the EXIT trap
