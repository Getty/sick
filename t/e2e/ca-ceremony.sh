#!/bin/bash
#
# The CA done properly, first part (k29): a ceremony makes root and
# intermediate outside step-ca, the CA is built on them without the root
# key, and the name constraints hold - at enrollment and in the path.
#
# What it proves, each with PASS/FAIL lines and an exit code of 1 on the
# first FAIL (RECORD lines say what was observed where either answer is
# acceptable):
#
#   1. the ceremony (docker/ceremony.sh, in the sick image, without network)
#      with a stand-in root key in a private directory, DNS constraint
#      example.internal, IP constraint 192.0.2.0/24: the root key lands where
#      it was told and nowhere in the output; it refuses a root key inside
#      the output; it warns about DNS without IP; --exclude-all-ip reads
#      back as excluded 0.0.0.0/0 and ::/0
#   2. the ceremony record matches the certificates: fingerprints and
#      constraints recomputed with openssl here
#   3. step-ca in import mode (docker/compose.yml + compose.import.yml, the
#      shipped files): it comes up healthy on the imported hierarchy, and
#      the root key is not in the CA volume, nor in the handover volume
#   4. sick issues for a device in scope (web.example.internal, 192.0.2.10)
#      and the device presents it: openssl and GnuTLS accept it against the
#      root alone; it has serverAuth as its only extended key usage
#   5. enrollment negatives. Without a policy: step-ca refuses an
#      out-of-scope name on the constraints of its intermediate. With the
#      policy (SICK_CA_ALLOW_*, second line, narrower than the constraints:
#      *.example.internal, 192.0.2.0/25) after a restart: an in-scope
#      request is granted (control); an out-of-scope name and an
#      out-of-scope address are refused (RECORD: by which line); a name and
#      an address inside the constraints but outside the policy are refused
#      by the policy; a CSR asking for CA:true comes out
#      without it or is refused (RECORD says which); a lifetime above the
#      maximum is refused. A refused request leaves no certificate: no file,
#      and no "certificate issued" (POST /sign, status 201) in the CA's log.
#   6. path negatives: leaves for outside.example.org and 198.51.100.9,
#      signed with the intermediate key directly (openssl, bypassing
#      step-ca), are refused by openssl verify and by GnuTLS certtool
#      against the root; an in-scope leaf signed the same way is accepted
#      by both. The errors are printed.
#   7. the ACME provisioner (k46): after the first start ca.json gives "acme"
#      the leaf template without clientAuth and the lifetimes 5m / 720h /
#      2160h, and init-ca.sh says so. A real ACME order (step, http-01,
#      standalone solver in a helper container the CA reaches under
#      acme.example.internal) yields a certificate with serverAuth as its
#      only extended key usage and a lifetime of 720h (openssl, here). With
#      SICK_CA_ACME_LIFETIME=10m and SICK_CA_ACME_MIN_LIFETIME=1m after a
#      restart the next order lasts 10m; a second start with the same values
#      changes nothing; a lifetime above the maximum stops init-ca.sh before
#      it touches anything
#   8. declared provisioners (k58, k50): with docker/compose.provisioners.yml
#      and docker/provisioners.example.json, and SICK_CA_ACME_CHALLENGES=
#      tls-alpn-01, on the running CA after a restart: init-ca.sh makes
#      "clients", "cert-manager" and "acme-long" and says so; ca.json gives
#      each its template (clientAuth only / serverAuth only), its lifetimes
#      and "acme-long" the challenge http-01, "acme" tls-alpn-01 alone; the
#      passwords are generated in the volume (0600, user step, no newline at
#      the end) and appear in no log; step-ca lists all three; "clients"
#      issues clientAuth only for 720h, "cert-manager" serverAuth only for
#      720h; an ACME order through "acme" fails, its http-01 not being
#      offered, one through "acme-long" lasts 1440h, serverAuth only; a second
#      start changes nothing (ca.json and the passwords byte for byte); a
#      provisioner taken out of the file stays and is named in the log; a
#      broken file stops init-ca.sh before it touches anything
#   9. teardown, also after a failure or Ctrl-C: the project down with its
#      volumes, the helper containers (labelled sick=1 and
#      sick-e2e=ca-ceremony) removed by their labels, nothing named sick-e2e-
#      ceremony* left, the private working directory (stand-in root key
#      included) removed
#
# It DESTROYS the Compose project it works on (default sick-e2e-ceremony).
# It touches nothing else: no other project, no prune. The images
# (sick:local, step-ca, debian) stay as a cache.
#
# Not covered here (the rest of P3): backup and restore, rollover of
# intermediate and root, provisioner password rotation; NSS and Go as
# path validators (GnuTLS is the independent one here).
#
# Prerequisites: Docker Engine with Compose and BuildKit, openssl on this
# machine, the two source trees side by side, the internet for images and
# packages.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR        private working directory, mode 0700, removed at the
#                       end  ($HOME/.local/share/sick-lab/ceremony)
#   SICK_E2E_PROJECT    Compose project name, sick-e2e-*   (sick-e2e-ceremony)
#   SICK_E2E_CA_PORT    port of the CA on 127.0.0.1                    (19100)
#   SICK_E2E_DEBIAN     image for GnuTLS                       (debian:trixie)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/ceremony}
project=${SICK_E2E_PROJECT:-sick-e2e-ceremony}
ca_port=${SICK_E2E_CA_PORT:-19100}
debian=${SICK_E2E_DEBIAN:-debian:trixie}
label=sick-e2e=ca-ceremony
helpers=(sick-e2e-ceremony-make sick-e2e-ceremony-gnutls sick-e2e-ceremony-acme)

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
sha256_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }

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
for name in "${helpers[@]}"; do
  [ -z "$(docker ps -aq --filter "name=^${name}\$")" ] || fail "a container $name exists already; remove it by hand"
done

umask 077
[ ! -e "$work" ] || fail "$work exists: remove it (it is the private directory of an earlier run)"
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd -P)
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
# ceremony/  what goes to the CA   rootkey/  the stand-in root key and its
# password, never mounted into the CA   secrets/  empty, for SICK
mkdir -m 700 "$work/ceremony" "$work/rootkey" "$work/scratch"
mkdir -m 755 "$work/secrets"
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 >"$work/rootkey/root.pw" || true
[ "$(wc -c <"$work/rootkey/root.pw")" -eq 40 ] || fail 'cannot generate a password'

ca_name='SICK E2E Ceremony CA'
device=web
cat >"$work/sick.yml" <<EOF
# Generated by t/e2e/ca-ceremony.sh. Neutral names only.
ca:
  name: $ca_name
  url: https://ca.example.internal:9000
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
    names: [web.example.internal, 192.0.2.10]
    dir: /srv/device
EOF
chmod 644 "$work/sick.yml"

write_env() { # <allow dns> <allow ip>
  cat >"$work/compose.env" <<EOF
# Generated by t/e2e/ca-ceremony.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=$ca_name
SICK_CA_DNS=ca.example.internal
SICK_CA_IMPORT=$work/ceremony
SICK_CA_ALLOW_DNS=$1
SICK_CA_ALLOW_IP=$2
SICK_CA_ACME_LIFETIME=${acme_lifetime:-}
SICK_CA_ACME_MIN_LIFETIME=${acme_min:-}
SICK_CA_ACME_CHALLENGES=${acme_challenges:-}
SICK_CA_PROVISIONERS=$work/provisioners.json
SICK_CA_PORT=127.0.0.1:$ca_port
SICK_TRUST_PORT=127.0.0.1:0
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
EOF
}
write_env '' ''
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ACME_LIFETIME SICK_CA_ACME_MAX_LIFETIME SICK_CA_ACME_MIN_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_IMPORT SICK_CA_IMPORT_DIR \
  SICK_TRUST_PORT SICK_INTERVAL SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE \
  SICK_CA_ACME_CHALLENGES SICK_CA_PROVISIONERS SICK_CA_PROVISIONERS_FILE

# with_provisioners=yes adds docker/compose.provisioners.yml (part 8)
with_provisioners=no
compose() {
  local -a extra=()
  [ "$with_provisioners" = no ] || extra=(-f "$repo/docker/compose.provisioners.yml")
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$repo/docker/compose.import.yml" "${extra[@]}" \
    -f "$here/compose.local.yml" -f "$here/compose.ceremony.yml" "$@"
}
in_ca() { compose exec -T ca "$@"; }
in_sick() { compose run --rm --no-deps -T -e STEPPATH=/tmp/step -e HOME=/tmp --entrypoint sh sick -c "$1"; }
ca_log() { compose logs --no-log-prefix ca 2>&1 | plain; }
issued() { ca_log | grep -E 'method=POST' | grep -E 'path=/sign ' | grep -c 'status=201' || true; }

#### 9. teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== 9. teardown\n'
  # the helpers by their labels (sick=1 and this script's), never by name
  docker ps -aq --filter label=sick=1 --filter "label=$label" | xargs -r docker rm -f -v >/dev/null 2>&1
  if [ -n "$armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | show
  fi
  local left
  left=$(
    docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]|^sick-e2e-ceremony-" | sed 's/^/container /'
    docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
    docker network ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/network /'
    docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container id /'
    docker ps -aq --filter "label=$label" | sed 's/^/container id /'
    docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
  )
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass "no container, volume or network of $project, no container sick-e2e-ceremony-* is left"
  fi
  rm -rf "${work:?}"
  if [ -e "$work" ]; then
    printf 'FAIL  %s could not be removed\n' "$work" >&2; rc=1
  else
    pass "the working directory (stand-in root key included) is removed"
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
compose down --volumes --remove-orphans >/dev/null 2>&1 || true

note 'docker compose build (the sick image: step, openssl, bash - what the ceremony needs)'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }

#### 1. the ceremony

# ceremony <args...>: docker/ceremony.sh in the sick image, no network, as
# the user running this script (so that it can remove what it wrote)
ceremony() {
  docker run --rm --name sick-e2e-ceremony-make --label sick=1 --label "$label" --network none \
    --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint bash \
    -v "$repo/docker/ceremony.sh:/ceremony.sh:ro" -v "$work:/work" \
    sick:local /ceremony.sh --operator 'E2E Operator' --root-password-file /work/rootkey/root.pw "$@"
}

step 'the ceremony: root and constrained intermediate, the root key where the operator says'
set +e
out=$(ceremony --out /work/ceremony --root-key /work/rootkey/root_ca_key \
  --root-name 'SICK E2E Root CA' --intermediate-name 'SICK E2E Intermediate CA' \
  --dns example.internal --ip 192.0.2.0/24 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "the ceremony ended with $code"
pass 'the ceremony ran'
listing=$(cd "$work/ceremony" && ls -A | sort | tr '\n' ' ')
[ "$listing" = 'ceremony.txt intermediate_ca.crt intermediate_ca_key password root_ca.crt ' ] \
  || fail "the output holds: $listing"
pass "the output for the CA holds: $listing"
grep -q 'PRIVATE KEY' "$work/rootkey/root_ca_key" || fail 'no root key at the destination'
pass 'the root key is at the destination the operator named'
refuse '... and no other file of the output holds a private key' 'PRIVATE KEY' \
  "$(cd "$work/ceremony" && grep -l 'PRIVATE KEY' ceremony.txt password root_ca.crt intermediate_ca.crt 2>/dev/null)"
refuse '... and the root key is not in it, byte for byte' "^$(sha256sum <"$work/rootkey/root_ca_key" | cut -d' ' -f1)" \
  "$(cd "$work/ceremony" && sha256sum ./* | cut -d' ' -f1)"
openssl pkey -in "$work/rootkey/root_ca_key" -passin "file:$work/rootkey/root.pw" -pubout 2>/dev/null \
  | cmp -s - <(openssl x509 -in "$work/ceremony/root_ca.crt" -noout -pubkey) \
  || fail 'the root key at the destination is not the key of root_ca.crt'
pass 'the root key at the destination is the key of root_ca.crt (opened with its password)'
refuse '... and is encrypted' 'BEGIN (EC |RSA )?PRIVATE KEY-----$' "$(head -n 2 "$work/rootkey/root_ca_key" | tr '\n' '$')"

note 'refusals and warnings of the ceremony'
set +e
out=$(ceremony --out /work/scratch/a --root-key /work/scratch/a/root_ca_key --dns example.internal --ip 192.0.2.0/24 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'the ceremony accepted a root key inside the output for the CA'
expect 'it refuses a root key inside the output for the CA' 'lies inside .*goes to the CA' "$out"
[ ! -e "$work/scratch/a/root_ca_key" ] || fail '... but wrote it'
set +e
out=$(ceremony --out /work/scratch/b --root-key /work/scratch/b-root_ca_key --dns example.internal 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "the ceremony with DNS only ended with $code"
expect 'DNS constraints without IP constraints: it warns that addresses stay unconstrained' 'WARNING: DNS constraints without IP constraints' "$out"
expect '... and the record says so' 'permitted IP +\(none: IP addresses unconstrained\)' "$(cat "$work/scratch/b/ceremony.txt")"
set +e
out=$(ceremony --out /work/scratch/c --root-key /work/scratch/c-root_ca_key --dns example.internal --exclude-all-ip 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "the ceremony with --exclude-all-ip ended with $code"
refuse '--exclude-all-ip: no warning' 'WARNING' "$out"
nc=$(openssl x509 -in "$work/scratch/c/intermediate_ca.crt" -noout -ext nameConstraints)
show <<<"$nc"
expect '... the intermediate excludes all IPv4' 'Excluded:' "$nc"
expect '... 0.0.0.0/0' 'IP:0\.0\.0\.0/0\.0\.0\.0' "$nc"
expect '... and all IPv6 (::/0)' 'IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0' "$nc"
rm -rf "$work/scratch"

#### 2. the record

step 'the ceremony record matches the certificates'
rec=$(cat "$work/ceremony/ceremony.txt")
show <<<"$rec"
refuse 'the record holds no key and no password' "PRIVATE KEY|$(cat "$work/rootkey/root.pw")|$(head -n 1 "$work/ceremony/password")" "$rec"
expect 'the record names the operator' '^operator: +E2E Operator$' "$rec"
expect '... the versions' '^step: +Smallstep CLI/' "$rec"
expect '... and where the root key went, as a path' '^root key: +written to /work/rootkey/root_ca_key \(encrypted\)$' "$rec"
for which in root intermediate; do
  want=$(sha256_of "$work/ceremony/${which}_ca.crt")
  got=$(sed -n "/^$which: /,/^\$/s/^  SHA-256 fingerprint *//p" <<<"$rec")
  [ "$got" = "$want" ] || fail "$which: the record says $got, openssl computes $want"
  pass "$which fingerprint in the record = the one openssl computes ($want)"
done
root_fp=$(sha256_of "$work/ceremony/root_ca.crt")
nc=$(openssl x509 -in "$work/ceremony/intermediate_ca.crt" -noout -ext nameConstraints,basicConstraints,keyUsage | sed 's/^ *//')
show <<<"$nc"
recnc=$(sed -n '/^intermediate: /,$p' <<<"$rec" | sed -n '/read back with openssl/,/^$/p' | sed '1d; s/^ *//' | sed '/^$/d')
for line in 'X509v3 Name Constraints: critical' 'Permitted:' 'DNS:example.internal' 'IP:192.0.2.0/255.255.255.0' \
  'X509v3 Basic Constraints: critical' 'CA:TRUE, pathlen:0' 'X509v3 Key Usage: critical' 'Certificate Sign, CRL Sign'; do
  grep -qxF -- "$line" <<<"$nc" || fail "the intermediate has no '$line'"
  grep -qxF -- "$line" <<<"$recnc" || fail "the record has no '$line'"
done
pass 'constraints, pathlen 0 and key usage: in the certificate (openssl, here) and in the record alike'

#### 3. step-ca in import mode

step 'step-ca in import mode: built on the ceremony, without the root key'
note 'docker compose up -d --wait ca web (compose.yml + compose.import.yml)'
compose up -d --wait ca web >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca web 2>&1 | tail -30 >&2; fail 'ca and web did not come up healthy'; }
pass 'ca and web are up and healthy (the healthcheck asks https://ca.example.internal:9000 against the root)'
first=$(ca_log | grep '^init-ca:' || true)
show <<<"$first"
expect 'init-ca.sh says import mode' '^init-ca: import mode: ' "$first"
refuse '... not lab mode' 'lab mode' "$first"
expect '... and made the CA on the imported hierarchy' "made the CA on the imported hierarchy: JWK provisioner 'sick', ACME provisioner 'acme'" "$first"
expect '... with the provisioner set up' "configuration updated: 'sick' grants up to 19800h, serverAuth only, names not restricted" "$first"
expect '... and the ACME provisioner' "names not restricted; 'acme' issues for 720h \\(5m to 2160h\\), serverAuth only" "$first"
acme_conf=$(in_ca jq -r '.authority.provisioners[] | select(.type == "ACME" and .name == "acme")
  | "claims: \(.claims.minTLSCertDuration) \(.claims.defaultTLSCertDuration) \(.claims.maxTLSCertDuration)",
    (.options.x509.template | split("\n")[] | "template: " + .)' /home/step/config/ca.json 2>&1 | plain)
show <<<"$acme_conf"
expect 'ca.json: "acme" has min 5m, default 720h, max 2160h' '^claims: 5m 720h 2160h$' "$acme_conf"
expect '... a template with extended key usage serverAuth' '^template:[[:space:]]+"extKeyUsage": \["serverAuth"\]$' "$acme_conf"
refuse '... and without clientAuth' 'clientAuth' "$acme_conf"
expect '... and the root fingerprint of the ceremony' "root fingerprint \(SHA-256\): $root_fp" "$first"

note 'the volumes, searched for the root key'
key_sum=$(sha256sum <"$work/rootkey/root_ca_key" | cut -d' ' -f1)
vol=$(in_ca sh -c 'cd /home/step && find . /handover -type f | sort; echo ---; find . /handover -type f -exec sha256sum {} +; echo ---; grep -rl "PRIVATE KEY" . /handover' 2>&1 | plain)
show <<<"$vol"
refuse 'no file named root_ca_key in the CA volume' 'root_ca_key' "$vol"
refuse 'no staged import left in the volume' '^\./import' "$vol"
refuse 'no file in the CA or handover volume is the root key, byte for byte' "^$key_sum" "$vol"
[ "$(sed -n '/^---$/,$p' <<<"$vol" | sed '1,/^---$/d')" = './secrets/intermediate_ca_key' ] \
  || fail 'a file other than secrets/intermediate_ca_key holds a private key'
pass 'the only private key in the volumes is secrets/intermediate_ca_key'
int_pub=$(in_ca step crypto key public /home/step/secrets/intermediate_ca_key --password-file /home/step/secrets/password | plain)
[ "$int_pub" = "$(openssl x509 -in "$work/ceremony/intermediate_ca.crt" -noout -pubkey)" ] \
  || fail 'secrets/intermediate_ca_key is not the key of the intermediate'
pass '... and it is the intermediate key of the ceremony'
[ "$(in_ca step certificate fingerprint /home/step/certs/root_ca.crt | plain)" = "$root_fp" ] || fail 'the root in the volume is another'
pass 'the root in the CA volume is the root of the ceremony'
hosts=$(docker inspect -f '{{range .NetworkSettings.Ports}}{{range .}}{{.HostIp}} {{end}}{{end}}' "$(compose ps -q ca)")
[ "$hosts" = '127.0.0.1 ' ] || fail "the CA is published on: $hosts"
pass 'the CA is published on 127.0.0.1 only'

#### 4. sick issues, the device presents

step 'sick issues for a device in scope, and the device presents it'
set +e
run=$(compose run --rm -T sick sick run --verbose "$device" 2>&1 | plain)
code=$?
set -e
show <<<"$run"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'renewed' "^$device +renewed +" "$run"
seen=$(in_sick '
  openssl s_client -connect web:443 -servername web.example.internal -no-CApath -no-CAstore \
    -CAfile /etc/sick/ca/root_ca.crt -verify_return_error -verify_hostname web.example.internal \
    </dev/null >/tmp/s.txt 2>&1; echo "s_client exit: $?"
  grep -E "^(verify error|Verification|Verify return code)" /tmp/s.txt
  openssl s_client -connect web:443 -no-CApath -no-CAstore -CAfile /etc/sick/ca/root_ca.crt \
    -verify_return_error -verify_ip 192.0.2.10 </dev/null >/dev/null 2>&1; echo "s_client ip exit: $?"
  openssl x509 </tmp/s.txt -noout -issuer -ext subjectAltName,extendedKeyUsage,basicConstraints
  echo "presented sha256: $(openssl x509 </tmp/s.txt -noout -fingerprint -sha256)"
  echo "written   sha256: $(openssl x509 </srv/device/cert.pem -noout -fingerprint -sha256)"
' 2>&1 | plain)
show <<<"$seen"
expect 'openssl s_client verifies the device against the root alone, name web.example.internal' '^s_client exit: 0$' "$seen"
expect '... and address 192.0.2.10' '^s_client ip exit: 0$' "$seen"
expect '... issued by the intermediate of the ceremony' 'issuer=.*SICK E2E Intermediate CA' "$seen"
expect '... with both names' 'DNS:web\.example\.internal, IP Address:192\.0\.2\.10' "$seen"
expect '... extended key usage serverAuth' '^ *TLS Web Server Authentication$' "$seen"
refuse '... and nothing else (no clientAuth)' 'Client Authentication' "$seen"
presented=$(sed -n 's/^presented sha256: //p' <<<"$seen")
[ -n "$presented" ] && [ "$presented" = "$(sed -n 's/^written   sha256: //p' <<<"$seen")" ] \
  || fail 'the device presents another certificate than the one SICK wrote'
pass 'the device presents the certificate SICK wrote'

#### 5. enrollment negatives

# ask <label> <step command line, run in a sick container>: output and exit code
ask() {
  in_sick "
    o='--ca-url https://ca.example.internal:9000 --root /etc/sick/ca/root_ca.crt --provisioner sick --provisioner-password-file /etc/sick/ca/provisioner.pw'
    cd /tmp; $1; echo \"exit: \$?\"; ls /tmp/*.crt 2>/dev/null | sed 's/^/file: /'; true" 2>&1 | plain
}
# denied <what> <output> <issued before>: refused, no file, nothing issued
denied() {
  show <<<"$2"
  refuse "$1: refused" '^exit: 0$' "$2"
  refuse '... no certificate file' '^file: ' "$2"
  [ "$(issued)" -eq "$3" ] || fail '... but the CA logged a certificate issued'
  pass '... and the CA logged no certificate issued'
}

step 'enrollment negatives'
note 'without a policy: the constraints of the intermediate, at step-ca'
n=$(issued)
out=$(ask 'step ca certificate outside.example.org /tmp/x.crt /tmp/x.key $o --not-after 24h')
denied 'outside.example.org without a policy' "$out" "$n"
record "step-ca without a policy: $(grep -m1 -E 'not permitted|not allowed|forbidden' <<<"$out" || echo '(no message)')"

note 'with the policy as second line, narrower than the constraints: SICK_CA_ALLOW_DNS=*.example.internal SICK_CA_ALLOW_IP=192.0.2.0/25, docker compose up -d'
write_env '*.example.internal' '192.0.2.0/25'
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect 'init-ca.sh finds the CA' 'exists: nothing to make' "$again"
expect '... ignores the import directory now' '/import is ignored' "$again"
expect '... and sets the policy' "configuration updated: .*names allowed: \*\.example\.internal, 192\.0\.2\.0/25" "$again"
refuse '... and no root key appeared' 'root_ca_key' "$(in_ca find /home/step /handover -type f 2>&1)"

n=$(issued)
out=$(ask 'step ca certificate in.example.internal /tmp/in.crt /tmp/in.key $o --san in.example.internal --san 192.0.2.7 --not-after 24h')
show <<<"$out"
expect 'control: in.example.internal with 192.0.2.7 is granted' '^exit: 0$' "$out"
[ "$(issued)" -eq $((n + 1)) ] || fail '... but the CA logged no certificate issued'
pass '... and the CA logged one certificate issued'

n=$(issued)
out=$(ask 'step ca certificate outside.example.org /tmp/x.crt /tmp/x.key $o --not-after 24h')
denied 'out-of-scope name outside.example.org (outside constraints and policy)' "$out" "$n"
record "outside.example.org: $(grep -m1 -E 'not permitted|not allowed|forbidden' <<<"$out" || echo '(no message)')"

out=$(ask 'step ca certificate in.example.internal /tmp/x.crt /tmp/x.key $o --san in.example.internal --san 198.51.100.9 --not-after 24h')
denied 'out-of-scope address 198.51.100.9 (outside constraints and policy)' "$out" "$n"
record "198.51.100.9: $(grep -m1 -E 'not permitted|not allowed|forbidden' <<<"$out" || echo '(no message)')"

out=$(ask 'step ca certificate example.internal /tmp/x.crt /tmp/x.key $o --not-after 24h')
denied 'example.internal (inside the constraints, outside the policy *.example.internal)' "$out" "$n"
expect '... by the policy' 'dns name "example.internal" not allowed' "$out"

out=$(ask 'step ca certificate in.example.internal /tmp/x.crt /tmp/x.key $o --san in.example.internal --san 192.0.2.200 --not-after 24h')
denied '192.0.2.200 (inside the constraints 192.0.2.0/24, outside the policy 192.0.2.0/25)' "$out" "$n"
expect '... by the policy' 'ip name "192.0.2.200" not allowed' "$out"

out=$(ask 'step ca certificate long.example.internal /tmp/x.crt /tmp/x.key $o --not-after 20000h')
denied 'a lifetime of 20000h, above the maximum of 19800h' "$out" "$n"
expect '... as too long' 'more than the authorized maximum' "$out"

note 'a CSR asking for CA:true'
out=$(ask 'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /tmp/sub.key -subj /CN=sub.example.internal \
    -addext subjectAltName=DNS:sub.example.internal -addext basicConstraints=critical,CA:TRUE,pathlen:0 \
    -addext keyUsage=critical,keyCertSign,cRLSign -out /tmp/sub.csr 2>/dev/null
  openssl req -in /tmp/sub.csr -noout -text | grep -A1 "Basic Constraints" | sed "s/^ */csr: /"
  step ca sign /tmp/sub.csr /tmp/sub.crt $o --not-after 24h
  if [ -s /tmp/sub.crt ]; then openssl x509 -in /tmp/sub.crt -noout -text | grep -E -A1 "Basic Constraints|Key Usage" | sed "s/^ */crt: /"; fi')
show <<<"$out"
expect 'the CSR asks for CA:TRUE' '^csr: CA:TRUE' "$out"
if grep -q '^exit: 0$' <<<"$out"; then
  refuse '... step-ca issued it, without CA:TRUE' '^crt: CA:TRUE' "$out"
  refuse '... and without certSign' '^crt: .*Certificate Sign' "$out"
  record 'CA:true CSR: step-ca issues a leaf and drops basicConstraints and keyUsage of the CSR (its template decides)'
else
  denied '... step-ca refused it' "$out" "$n"
  record 'CA:true CSR: step-ca refuses it'
fi

#### 6. path negatives

step 'path negatives: leaves signed with the intermediate key directly, judged by OpenSSL and GnuTLS'
inside='
set -u
export DEBIAN_FRONTEND=noninteractive
{ apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl gnutls-bin ca-certificates; } >/tmp/apt.log 2>&1 \
  || { tail -20 /tmp/apt.log; echo "ERROR apt-get"; exit 1; }
echo "VERSION $(openssl version)"
echo "VERSION $(certtool --version | head -n 1)"
mkdir -m 700 /tmp/p && cd /tmp/p
leaf() { # <name> <subjectAltName>
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -subj "/CN=$1" -out "$1.csr" 2>/dev/null
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$2" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA /ceremony/intermediate_ca.crt -CAkey /ceremony/intermediate_ca_key \
    -passin file:/ceremony/password -set_serial "0x$(openssl rand -hex 16)" -days 1 -extfile "$1.ext" -out "$1.crt" 2>/dev/null \
    || { echo "ERROR signing $1"; exit 1; }
  cat "$1.crt" /ceremony/intermediate_ca.crt >"$1.chain"
}
leaf inside.example.internal "DNS:inside.example.internal,IP:192.0.2.9"
leaf outside.example.org "DNS:outside.example.org"
leaf 198.51.100.9 "IP:198.51.100.9"
for c in inside.example.internal outside.example.org 198.51.100.9; do
  o=$(openssl verify -no-CApath -no-CAstore -CAfile /ceremony/root_ca.crt -untrusted /ceremony/intermediate_ca.crt "$c.crt" 2>&1)
  if [ $? -eq 0 ]; then r=accepted; else r=refused; fi
  echo "RESULT $c openssl $r $(echo "$o" | grep -m1 -iE "error|OK" | tr -s " ")"
  o=$(certtool --verify --load-ca-certificate /ceremony/root_ca.crt --infile "$c.chain" 2>&1)
  if [ $? -eq 0 ]; then r=accepted; else r=refused; fi
  echo "RESULT $c gnutls $r $(echo "$o" | grep -m1 -E "Chain verification output" | tr -s " ")"
done
o=$(gnutls-cli --x509cafile /ceremony/root_ca.crt --verify-hostname web.example.internal -p 443 web </dev/null 2>&1)
if [ $? -eq 0 ]; then r=accepted; else r=refused; fi
echo "RESULT device gnutls-cli $r $(echo "$o" | grep -m1 -E "Status: |certificate is" | tr -s " ")"
'
set +e
judged=$(docker run --rm --name sick-e2e-ceremony-gnutls --label sick=1 --label "$label" --network "${project}_default" \
  -v "$work/ceremony:/ceremony:ro" "$debian" bash -c "$inside" 2>&1 | plain)
code=$?
set -e
show <<<"$judged"
[ "$code" -eq 0 ] || fail "the Debian container ended with $code"
result() { # <case> <client> <accepted|refused> <what>
  local line
  line=$(grep -E "^RESULT $1 $2 " <<<"$judged" | head -n 1)
  [ -n "$line" ] || fail "no result for $1 / $2"
  if [ "$(cut -d' ' -f4 <<<"$line")" = "$3" ]; then
    pass "$4: $3 by $2 ($(cut -d' ' -f5- <<<"$line"))"
  else
    fail "$4: $(cut -d' ' -f4 <<<"$line") by $2, expected $3 ($(cut -d' ' -f5- <<<"$line"))"
  fi
}
result inside.example.internal openssl accepted 'in-scope leaf signed directly'
result inside.example.internal gnutls accepted 'in-scope leaf signed directly'
result outside.example.org openssl refused 'outside.example.org signed directly'
result outside.example.org gnutls refused 'outside.example.org signed directly'
result 198.51.100.9 openssl refused '198.51.100.9 signed directly'
result 198.51.100.9 gnutls refused '198.51.100.9 signed directly'
result device gnutls-cli accepted 'the device, live, against the root alone'

#### 7. the ACME provisioner

# acme_order <name>: a real ACME order with step, http-01 answered by its
# standalone solver in a helper container the CA reaches under <name>.
# Prints step's output, then the certificate (leaf first) between markers.
acme_order() { # <name> [<provisioner>]
  docker run --rm --name sick-e2e-ceremony-acme --label sick=1 --label "$label" \
    --network "${project}_default" --network-alias "$1" \
    -v "${project}_handover:/etc/sick/ca:ro" -e STEPPATH=/tmp/step -e HOME=/tmp \
    --entrypoint sh sick:local -c '
      cd /tmp && step ca certificate "$0" /tmp/a.crt /tmp/a.key --provisioner "$1" \
        --ca-url https://ca.example.internal:9000 --root /etc/sick/ca/root_ca.crt --http-listen :80 2>&1
      echo "exit: $?"
      if [ -s /tmp/a.crt ]; then echo "--- certificate"; cat /tmp/a.crt; fi' "$1" "${2:-acme}" 2>&1 | plain
}
# lifetime_of <output of acme_order>: notAfter - notBefore of the leaf, in seconds
leaf_of() { sed -n '/^--- certificate$/,$p' <<<"$1" | sed 1d | openssl x509; }
lifetime_of() {
  local leaf before after
  leaf=$(leaf_of "$1")
  before=$(openssl x509 -noout -startdate <<<"$leaf" | sed 's/^notBefore=//')
  after=$(openssl x509 -noout -enddate <<<"$leaf" | sed 's/^notAfter=//')
  echo $(( $(date -u -d "$after" +%s) - $(date -u -d "$before" +%s) ))
}
# lifetime_is <seconds> <output of acme_order> <what>: step-ca backdates
# notBefore by one minute, so the lifetime from issuance is the span less 60s
lifetime_is() {
  local span
  span=$(lifetime_of "$2")
  if [ "$span" -eq "$1" ] || [ "$span" -eq $(( $1 + 60 )) ]; then
    pass "$3: notAfter - notBefore = ${span}s ($(( span - $1 ))s of it the backdating of notBefore)"
  else
    fail "$3: notAfter - notBefore = ${span}s, expected $1s (+60s backdating)"
  fi
}

step 'the ACME provisioner: a real order, serverAuth only, the lifetime of SICK_CA_ACME_*'
note 'step ca certificate acme.example.internal --provisioner acme (http-01, standalone)'
n=$(issued)
out=$(acme_order acme.example.internal)
show <<<"$(sed '/^--- certificate$/,$d' <<<"$out")"
expect 'the ACME order is granted' '^exit: 0$' "$out"
leaf=$(leaf_of "$out")
facts=$(openssl x509 -noout -subject -issuer -startdate -enddate -ext subjectAltName,extendedKeyUsage <<<"$leaf")
show <<<"$facts"
expect '... for acme.example.internal' 'DNS:acme\.example\.internal' "$facts"
expect '... issued by the intermediate of the ceremony' 'issuer=.*SICK E2E Intermediate CA' "$facts"
expect '... extended key usage serverAuth' '^ *TLS Web Server Authentication$' "$facts"
refuse '... and nothing else (no clientAuth)' 'Client Authentication' "$facts"
lifetime_is $((720 * 3600)) "$out" '... lifetime 720h'
[ "$(issued)" -eq "$n" ] || fail '... but the JWK path (POST /sign) logged a certificate: the order went elsewhere'
pass '... through ACME, not through POST /sign'

note 'SICK_CA_ACME_LIFETIME=10m SICK_CA_ACME_MIN_LIFETIME=1m, docker compose up -d'
acme_lifetime=10m acme_min=1m
write_env '*.example.internal' '192.0.2.0/25'
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect 'init-ca.sh sets the short lifetime' "configuration updated: .*'acme' issues for 10m \(1m to 2160h\), serverAuth only" "$again"
acme_conf=$(in_ca jq -r '.authority.provisioners[] | select(.type == "ACME" and .name == "acme") | "claims: \(.claims.minTLSCertDuration) \(.claims.defaultTLSCertDuration) \(.claims.maxTLSCertDuration)"' /home/step/config/ca.json 2>&1 | plain)
expect '... ca.json: min 1m, default 10m, max 2160h' '^claims: 1m 10m 2160h$' "$acme_conf"
out=$(acme_order acme.example.internal)
show <<<"$(sed '/^--- certificate$/,$d' <<<"$out")"
expect 'the ACME order is granted' '^exit: 0$' "$out"
lifetime_is 600 "$out" '... lifetime 10m'
refuse '... still without clientAuth' 'Client Authentication' "$(leaf_of "$out" | openssl x509 -noout -ext extendedKeyUsage)"

note 'the same values again: docker compose restart ca'
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose restart ca >/dev/null 2>&1 || fail 'docker compose restart ca'
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect 'a start that finds everything in place changes nothing and says so' "configuration unchanged: .*'acme' issues for 10m \(1m to 2160h\), serverAuth only" "$again"

note 'SICK_CA_ACME_LIFETIME=3000h, above the maximum: init-ca.sh --initialise in a one-off container'
before=$(in_ca sha256sum /home/step/config/ca.json 2>&1 | plain)
set +e
out=$(compose run --rm --no-deps -T -e SICK_CA_ACME_LIFETIME=3000h ca --initialise 2>&1 | plain)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'init-ca.sh accepted a lifetime above the maximum'
expect 'init-ca.sh refuses a lifetime above the maximum' "SICK_CA_ACME_LIFETIME '3000h' is longer than SICK_CA_ACME_MAX_LIFETIME '2160h'" "$out"
[ "$(in_ca sha256sum /home/step/config/ca.json 2>&1 | plain)" = "$before" ] || fail '... but ca.json changed'
pass '... and ca.json is untouched'
set +e
out=$(compose run --rm --no-deps -T -e SICK_CA_ACME_LIFETIME=30d ca --initialise 2>&1 | plain)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'init-ca.sh accepted 30d'
expect 'init-ca.sh refuses 30d (Go knows no days)' "SICK_CA_ACME_LIFETIME '30d' is not a positive Go duration" "$out"

#### 8. declared provisioners

step 'declared provisioners: clients, cert-manager, acme-long; the challenge types of "acme"'
install -m 0644 "$repo/docker/provisioners.example.json" "$work/provisioners.json"
note 'docker/provisioners.example.json as SICK_CA_PROVISIONERS (compose.provisioners.yml), SICK_CA_ACME_CHALLENGES=tls-alpn-01, docker compose up -d'
with_provisioners=yes acme_challenges=tls-alpn-01
write_env '*.example.internal' '192.0.2.0/25'
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose up -d --wait ca >/dev/null 2>&1 || { compose logs ca 2>&1 | tail -30 >&2; fail 'the CA did not come back healthy'; }
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect "init-ca.sh makes 'clients' with a password generated in the volume" "^init-ca: made the declared JWK provisioner 'clients' \(password generated in /home/step/secrets/provisioner_clients_password\)$" "$again"
expect "... 'cert-manager' likewise" "^init-ca: made the declared JWK provisioner 'cert-manager' \(password generated in /home/step/secrets/provisioner_cert-manager_password\)$" "$again"
expect "... and the ACME provisioner 'acme-long'" "^init-ca: made the declared ACME provisioner 'acme-long'$" "$again"
expect "... says what 'clients' issues" "^init-ca: declared provisioner 'clients' \(JWK\) issues for 720h \(5m to 2160h\), clientAuth only$" "$again"
expect "... 'cert-manager'" "^init-ca: declared provisioner 'cert-manager' \(JWK\) issues for 720h \(5m to 2160h\), serverAuth only$" "$again"
expect "... 'acme-long'" "^init-ca: declared provisioner 'acme-long' \(ACME\) issues for 1440h \(5m to 2160h\), serverAuth only, challenges http-01$" "$again"
expect "... and 'acme' offers tls-alpn-01 alone" "configuration updated: .*'acme' issues for 10m \(1m to 2160h\), serverAuth only, challenges tls-alpn-01$" "$again"
refuse '... names no provisioner as undeclared' 'neither built in nor declared' "$again"

conf=$(in_ca jq -r '.authority.provisioners[] | select(.name == "clients" or .name == "cert-manager" or .name == "acme-long" or .name == "acme")
  | "\(.name) \(.type) claims \(.claims.minTLSCertDuration) \(.claims.defaultTLSCertDuration) \(.claims.maxTLSCertDuration) ssh \(.claims.enableSSHCA)"
    + " eku \(.options.x509.template | [scan("\"extKeyUsage\": \\[([^\\]]*)\\]")[0] | gsub("[\" ]"; "")] | join("|"))"
    + " ku \(.options.x509.template | [scan("\"keyUsage\": \\[([^\\]]*)\\]")[0] | gsub("[\" ]"; "")] | join("|"))"
    + " challenges \(.challenges // ["default"] | join(","))"' /home/step/config/ca.json 2>&1 | plain)
show <<<"$conf"
expect 'ca.json: clients is JWK, 5m/720h/2160h, no SSH, clientAuth alone, key usage digitalSignature' '^clients JWK claims 5m 720h 2160h ssh false eku clientAuth ku digitalSignature challenges default$' "$conf"
expect '... cert-manager is JWK, 5m/720h/2160h, serverAuth alone' '^cert-manager JWK claims 5m 720h 2160h ssh false eku serverAuth ku .* challenges default$' "$conf"
expect '... acme-long is ACME, 5m/1440h/2160h, serverAuth alone, challenge http-01' '^acme-long ACME claims 5m 1440h 2160h ssh false eku serverAuth ku .* challenges http-01$' "$conf"
expect '... acme offers tls-alpn-01 alone' '^acme ACME claims 1m 10m 2160h .* eku serverAuth .* challenges tls-alpn-01$' "$conf"

pws=$(in_ca sh -c 'for f in /home/step/secrets/provisioner_clients_password /home/step/secrets/provisioner_cert-manager_password; do
    echo "$(stat -c "%a %U" "$f") $(wc -c <"$f") last=$(tail -c 1 "$f" | od -An -c | tr -d " ") ${f##*/}"; done' 2>&1 | plain)
show <<<"$pws"
expect 'the passwords: mode 0600, user step, 40 characters, no newline at the end' '^600 step 40 last=[A-Za-z0-9] provisioner_clients_password$' "$pws"
expect '... both' '^600 step 40 last=[A-Za-z0-9] provisioner_cert-manager_password$' "$pws"
# compared here, never printed
if ca_log | grep -qF -f <(in_ca sh -c 'cat /home/step/secrets/provisioner_clients_password; echo; cat /home/step/secrets/provisioner_cert-manager_password; echo' 2>/dev/null); then
  fail '... but a password appears in the log of the CA'
fi
pass '... and appear in no log of the CA'


listed=$(in_ca step ca provisioner list --ca-url https://ca.example.internal:9000 --root /home/step/certs/root_ca.crt 2>/dev/null \
  | jq -r '.[] | "\(.type) \(.name)"' | plain)
show <<<"$listed"
for p in 'JWK clients' 'JWK cert-manager' 'ACME acme-long'; do
  expect "step-ca lists $p" "^$p\$" "$listed"
done

note 'issuing through the JWK provisioners, inside the CA container (the passwords stay in the volume)'
issue_jwk() { # <provisioner> <subject> [<step options>]: the certificate, or the error
  compose exec -T -u step ca sh -c '
    d=$(mktemp -d); cd "$d"
    STEPPATH=$d step ca certificate "$1" c.crt c.key --provisioner "$0" \
      --provisioner-password-file "/home/step/secrets/provisioner_$0_password" \
      --ca-url https://ca.example.internal:9000 --root /home/step/certs/root_ca.crt $2 >out 2>&1
    echo "exit: $?"; cat out; [ ! -s c.crt ] || { echo "--- certificate"; cat c.crt; }
    rm -rf "$d"' "$1" "$2" "${3:-}" 2>&1 | plain
}
# a DNS name: the policy of this CA (*.example.internal) refuses email and
# URI SANs - t/e2e/client-san.sh is about those
out=$(issue_jwk clients backup1.example.internal)
expect "'clients' issues for backup1.example.internal" '^exit: 0$' "$out"
facts=$(leaf_of "$out" | openssl x509 -noout -ext subjectAltName,keyUsage,extendedKeyUsage)
show <<<"$facts"
expect '... with the name' 'DNS:backup1\.example\.internal' "$facts"
expect '... extended key usage clientAuth' '^ *TLS Web Client Authentication$' "$facts"
refuse '... and not serverAuth' 'Server Authentication' "$facts"
expect '... key usage digitalSignature alone' '^ *Digital Signature$' "$facts"
lifetime_is $((720 * 3600)) "$out" '... lifetime 720h'
out=$(issue_jwk cert-manager svc.example.internal)
expect "'cert-manager' issues for svc.example.internal" '^exit: 0$' "$out"
facts=$(leaf_of "$out" | openssl x509 -noout -ext extendedKeyUsage)
expect '... serverAuth' '^ *TLS Web Server Authentication$' "$facts"
refuse '... and not clientAuth' 'Client Authentication' "$facts"
lifetime_is $((720 * 3600)) "$out" '... lifetime 720h'

note 'ACME: "acme" without http-01, "acme-long" with it'
out=$(acme_order acme.example.internal acme)
show <<<"$(sed '/^--- certificate$/,$d' <<<"$out")"
refuse 'an order through "acme" (tls-alpn-01 alone) is not granted to the http-01 client' '^exit: 0$' "$out"
expect '... as no challenge it can answer is offered' 'unable to validate any challenges' "$out"
out=$(acme_order acme.example.internal acme-long)
show <<<"$(sed '/^--- certificate$/,$d' <<<"$out")"
expect 'an order through "acme-long" (http-01) is granted' '^exit: 0$' "$out"
lifetime_is $((1440 * 3600)) "$out" '... lifetime 1440h'
facts=$(leaf_of "$out" | openssl x509 -noout -ext extendedKeyUsage)
expect '... serverAuth' '^ *TLS Web Server Authentication$' "$facts"
refuse '... and not clientAuth' 'Client Authentication' "$facts"

note 'the same file again: docker compose restart ca'
before=$(in_ca sha256sum /home/step/config/ca.json /home/step/secrets/provisioner_clients_password /home/step/secrets/provisioner_cert-manager_password 2>&1 | plain)
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose restart ca >/dev/null 2>&1 || fail 'docker compose restart ca'
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect 'a second start changes nothing and says so' '^init-ca: configuration unchanged: ' "$again"
refuse '... makes nothing' 'made the declared' "$again"
refuse '... warns of nothing' 'WARNING' "$again"
expect '... and still names what the declared ones issue' "^init-ca: declared provisioner 'clients' \(JWK\) issues for 720h" "$again"
[ "$(in_ca sha256sum /home/step/config/ca.json /home/step/secrets/provisioner_clients_password /home/step/secrets/provisioner_cert-manager_password 2>&1 | plain)" = "$before" ] \
  || fail '... but ca.json or a password changed'
pass '... ca.json and both passwords are unchanged, byte for byte'

note 'acme-long taken out of the file: docker compose restart ca'
jq '.provisioners |= map(select(.name != "acme-long"))' "$repo/docker/provisioners.example.json" >"$work/provisioners.json.new"
cat "$work/provisioners.json.new" >"$work/provisioners.json"   # the same inode: the bind mount sees it
rm -f "$work/provisioners.json.new"
since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
compose restart ca >/dev/null 2>&1 || fail 'docker compose restart ca'
compose up -d --wait ca >/dev/null 2>&1 || fail 'the CA did not come back healthy'
again=$(compose logs --no-log-prefix --since "$since" ca 2>&1 | plain | grep '^init-ca:' || true)
show <<<"$again"
expect 'a provisioner no longer declared is named in the log' "^init-ca: provisioner 'acme-long' \(ACME\) is neither built in nor declared in /etc/step-ca/provisioners.json: left as it is, not removed$" "$again"
expect '... and stays in ca.json' '^acme-long$' "$(in_ca jq -r '.authority.provisioners[].name' /home/step/config/ca.json 2>&1 | plain)"

note 'a broken provisioners file: init-ca.sh --initialise in a one-off container'
printf '{ "provisioners": [ { "name": "clients", "type": "JWK", "profile": "both", "colour": "red" } ] }\n' >"$work/broken.json"
chmod 644 "$work/broken.json"
before=$(in_ca sha256sum /home/step/config/ca.json 2>&1 | plain)
set +e
out=$(compose run --rm --no-deps -T -v "$work/broken.json:/etc/step-ca/broken.json:ro" \
  -e SICK_CA_PROVISIONERS_FILE=/etc/step-ca/broken.json ca --initialise 2>&1 | plain)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'init-ca.sh accepted a broken provisioners file'
expect 'init-ca.sh refuses an unknown key' "provisioners\[0\] \(clients\): unknown key colour" "$out"
expect '... and an unknown profile' 'profile is "server" or "client"' "$out"
expect '... and changes nothing' 'no provisioner changed' "$out"
[ "$(in_ca sha256sum /home/step/config/ca.json 2>&1 | plain)" = "$before" ] || fail '... but ca.json changed'
pass '... ca.json is untouched'

# 9. runs in the EXIT trap
