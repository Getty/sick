#!/bin/bash
#
# The CA done properly, second part (k30): backup, a restore drill in
# isolation, and rotation of the provisioner password.
#
# What it proves, each with PASS/FAIL lines and an exit code of 1 on the
# first FAIL; RECORD lines are measurements and observations:
#
#   1. a CA (docker/compose.yml as shipped, lab mode) issues: sick renews
#      the device "web" (t/e2e/compose.local.yml)
#   2. backup (docker/ca-backup.sh): archive mode 0600, a manifest without
#      a secret whose fingerprints are those of the CA; the CA was stopped
#      for the copy and is healthy again (RECORD: how long it was down)
#   3. restore into a fresh volume and a CA started on it in ISOLATION: a
#      network of its own (--internal), no published port. The original CA
#      keeps running, is the only CA in the project's network ("ca" resolves
#      to it alone) and the one SICK is served by (its log has the request,
#      the restored one's has not)
#   4. the restored CA issues a leaf that openssl verifies against the root
#      of the original; its intermediate is the original one and still
#      valid; its database holds the certificate issued before the backup
#      (the DER bytes are found in the Badger files of the restored volume -
#      step-ca has no API to look a certificate up). RECORD: the observed
#      RTO of this lab (restore command to first certificate of the
#      restored CA), and what the RPO is
#   5. refusals of the restore: a tampered archive (one byte changed) does
#      not match its manifest and no volume is made; a volume that holds a
#      CA is refused
#   6. provisioner rotation on the live CA (init-ca.sh --rotate-provisioner):
#      new key and password, handed over; sick issues with the new one; the
#      old password no longer opens the provisioner key; a token signed with
#      the old key - what somebody who knew the old password could still
#      have - is refused by the CA, while one signed the same way with the
#      new key is accepted (the control for the hand-made token)
#   7. teardown, also after a failure or Ctrl-C: the project down with its
#      volumes, the isolated CA, its volumes and network removed by their
#      labels (sick=1, sick-e2e=ca-recovery), nothing
#      named sick-e2e-recovery* left, the private working directory (backup
#      archive and old provisioner key included) removed
#
# It DESTROYS the Compose project it works on (default sick-e2e-recovery).
# It touches nothing else: no other project, no prune. The images stay.
#
# Not covered here: ACME accounts (P6), revocation, a restore onto another
# host, rollover of intermediate and root.
#
# Parameters, all from the environment:
#
#   SICK_E2E_DIR       private working directory, mode 0700, removed at the
#                      end  ($HOME/.local/share/sick-lab/recovery)
#   SICK_E2E_PROJECT   Compose project name, sick-e2e-*    (sick-e2e-recovery)
#   SICK_E2E_CA_PORT   port of the CA on 127.0.0.1                     (19200)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_E2E_DIR:-$HOME/.local/share/sick-lab/recovery}
project=${SICK_E2E_PROJECT:-sick-e2e-recovery}
ca_port=${SICK_E2E_CA_PORT:-19200}
step_image=smallstep/step-ca:0.30.2
label=sick-e2e=ca-recovery
restored=${project}-restored          # container of the restored CA
restored_volume=${project}-restored-ca
tampered_volume=${project}-tampered-ca
isolated=${project}-isolated          # its network
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
sha256_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
wait_for() { # <seconds> <what> <command ...>
  local seconds=$1 what=$2 start=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    [ $((SECONDS - start)) -lt "$seconds" ] || fail "waited ${seconds}s for $what"
    sleep 1
  done
}

#### prerequisites

for program in docker openssl perl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[[ $project =~ ^sick-e2e-[a-z0-9_-]+$ ]] || fail "SICK_E2E_PROJECT '$project' is not sick-e2e-*"
[[ $ca_port =~ ^[0-9]+$ ]] || fail 'SICK_E2E_CA_PORT is a port number'
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
if (exec 3<>"/dev/tcp/127.0.0.1/$ca_port") 2>/dev/null; then
  fail "port $ca_port on 127.0.0.1 is in use: set SICK_E2E_CA_PORT"
fi
for name in "$restored" "$client"; do
  [ -z "$(docker ps -aq --filter "name=^${name}\$")" ] || fail "a container $name exists already; remove it by hand"
done
for name in "$restored_volume" "$tampered_volume"; do
  ! docker volume inspect "$name" >/dev/null 2>&1 || fail "a volume $name exists already; remove it by hand"
done
! docker network inspect "$isolated" >/dev/null 2>&1 || fail "a network $isolated exists already; remove it by hand"

umask 077
[ ! -e "$work" ] || fail "$work exists: remove it (it is the private directory of an earlier run)"
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd -P)
case $work/ in "$context"/*) fail "SICK_E2E_DIR $work lies inside the build context $context" ;; esac
mkdir -m 700 "$work/backup"
mkdir -m 755 "$work/secrets"

ca_name='SICK E2E Recovery CA'
device=web
cat >"$work/sick.yml" <<EOF
# Generated by t/e2e/ca-recovery.sh. Neutral names only.
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
    names: [web.example.internal, web]
    dir: /srv/device
EOF
chmod 644 "$work/sick.yml"
cat >"$work/compose.env" <<EOF
# Generated by t/e2e/ca-recovery.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=$ca_name
SICK_CA_PORT=127.0.0.1:$ca_port
SICK_TRUST_PORT=127.0.0.1:0
SICK_INTERVAL=1d
SICK_E2E_HERE=$here
EOF
unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_IMPORT SICK_CA_IMPORT_DIR \
  SICK_TRUST_PORT SICK_INTERVAL SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_E2E_HERE

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$here/compose.local.yml" "$@"
}
in_ca() { compose exec -T ca "$@"; }
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
ca_log() { compose logs --no-log-prefix ca 2>&1 | plain; }
signed() { grep -E 'method=POST' | grep -E 'path=/sign ' | grep -c 'status=201' || true; }
# a step client in the project's network, as the user running this script,
# with the working directory at /work (read-only)
step_client() {
  docker run --rm --name "$client" --label sick=1 --label "$label" --network "${project}_default" \
    --user "$(id -u):$(id -g)" -e HOME=/tmp -e STEPPATH=/tmp/step -v "$work:/work:ro" \
    --entrypoint sh "$step_image" -c "$1"
}

#### 7. teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== 7. teardown\n'
  # by label only: containers and the network carry sick=1 and this
  # script's label; the volumes ca-backup.sh creates carry sick=1, and of
  # those only the two this script names go
  docker ps -aq --filter label=sick=1 --filter "label=$label" | xargs -r docker rm -f -v >/dev/null 2>&1
  docker volume ls -q --filter label=sick=1 | grep -xF -e "$restored_volume" -e "$tampered_volume" \
    | xargs -r docker volume rm >/dev/null 2>&1
  docker network ls -q --filter label=sick=1 --filter "label=$label" | xargs -r docker network rm >/dev/null 2>&1
  if [ -n "$armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | show
  fi
  local left
  left=$(
    docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]" | sed 's/^/container /'
    docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
    docker network ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/network /'
    docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container id /'
    docker ps -aq --filter "label=$label" | sed 's/^/container id /'
    docker network ls -q --filter "label=$label" | sed 's/^/network id /'
    docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
    docker volume ls -q --filter label=sick=1 | grep -xF -e "$restored_volume" -e "$tampered_volume" | sed 's/^/volume /'
  )
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    pass "no container, volume or network named ${project}-* or ${project}_* is left"
  fi
  rm -rf "${work:?}"
  if [ -e "$work" ]; then
    printf 'FAIL  %s could not be removed\n' "$work" >&2; rc=1
  else
    pass 'the working directory (backup, old provisioner key and passwords included) is removed'
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

#### 1. a CA that has issued

step 'a CA that has issued'
note 'docker compose build, up -d --wait ca web'
compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
compose up -d --wait ca web >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca web 2>&1 | tail -30 >&2; fail 'ca and web did not come up healthy'; }
pass 'ca and web are up and healthy'
in_ca cat /home/step/certs/root_ca.crt >"$work/root_ca.crt"
in_ca cat /home/step/certs/intermediate_ca.crt >"$work/intermediate_ca.crt"
chmod 644 "$work/root_ca.crt" "$work/intermediate_ca.crt"
root_fp=$(sha256_of "$work/root_ca.crt")
int_fp=$(sha256_of "$work/intermediate_ca.crt")
note "root $root_fp, intermediate $int_fp"
run=$(compose run --rm -T sick sick run "$device" 2>&1 | plain) || { show <<<"$run"; fail 'sick run'; }
show <<<"$run"
expect 'sick renewed the device' "^$device +renewed " "$run"
in_sick 'cat /srv/device/cert.pem' >"$work/before.pem"
openssl x509 -in "$work/before.pem" -outform DER -out "$work/before.der"
note "the certificate issued before the backup: serial $(openssl x509 -in "$work/before.pem" -noout -serial | sed 's/.*=//')"

#### 2. backup

step 'backup: the CA stopped for the copy, an archive and its manifest'
ca_id=$(compose ps -q ca)
started_before=$(docker inspect -f '{{.State.StartedAt}}' "$ca_id")
set +e
out=$("$repo/docker/ca-backup.sh" backup --volume "${project}_ca" --to "$work/backup/ca.tar" 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "ca-backup.sh backup ended with $code"
pass 'ca-backup.sh backup ran'
expect '... it stopped the CA for the copy' "stopping 1 container\(s\) that use ${project}_ca: ${project}-ca-1" "$out"
expect '... and started it again' "started again: ${project}-ca-1" "$out"
record "backup: $(grep -o 'the CA was stopped for [0-9]*s' <<<"$out")"
[ "$(docker inspect -f '{{.State.StartedAt}}' "$ca_id")" != "$started_before" ] || fail 'the CA was not restarted'
wait_for 60 'the CA to be healthy again' sh -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $ca_id)\" = healthy ]"
pass 'the CA is healthy again'
[ "$(stat -c %a "$work/backup/ca.tar")" = 600 ] || fail "the archive has mode $(stat -c %a "$work/backup/ca.tar")"
pass 'the archive has mode 0600'
manifest=$(cat "$work/backup/ca.tar.manifest")
show <<<"$(grep -v '^file ' <<<"$manifest"; printf '(%s file lines)\n' "$(grep -c '^file ' <<<"$manifest")")"
expect 'the manifest has the root fingerprint of the CA' "^root-fingerprint: $root_fp$" "$manifest"
expect '... and the intermediate fingerprint' "^intermediate-fingerprint: $int_fp$" "$manifest"
expect '... and the SHA-256 of the archive' "^archive-sha256: $(sha256sum "$work/backup/ca.tar" | cut -d' ' -f1)$" "$manifest"
listing=$(tar -tf "$work/backup/ca.tar" | sort)
for f in ./config/ca.json ./config/defaults.json ./certs/root_ca.crt ./certs/intermediate_ca.crt \
  ./secrets/intermediate_ca_key ./secrets/root_ca_key ./secrets/password ./secrets/provisioner_password; do
  grep -qxF "$f" <<<"$listing" || fail "the archive has no $f"
done
grep -q '^\./db/' <<<"$listing" || fail 'the archive has no database'
pass 'the archive holds ca.json, defaults.json, both certificates, the encrypted keys, the passwords and the database'
refuse 'the manifest holds no key and no password' \
  "PRIVATE KEY|$(in_ca cat /home/step/secrets/provisioner_password)|$(in_ca cat /home/step/secrets/password)" "$manifest"
key_enc=$(tar -xOf "$work/backup/ca.tar" ./secrets/intermediate_ca_key | head -n 2 | tr '\n' ' ')
expect 'the keys in the archive are encrypted' 'Proc-Type: 4,ENCRYPTED|ENCRYPTED PRIVATE KEY' "$key_enc"

#### 3. restore in isolation

step 'restore into a fresh volume; a CA on it in isolation, the original keeps serving'
t0=$SECONDS
set +e
out=$("$repo/docker/ca-backup.sh" restore --from "$work/backup/ca.tar" --volume "$restored_volume" 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "ca-backup.sh restore ended with $code"
expect 'the archive matched its manifest' 'the archive matches its manifest' "$out"
expect '... every file restored as in the manifest' 'files, each as in the manifest' "$out"
expect '... the intermediate is still valid' 'the intermediate is valid until ' "$out"
t_restored=$SECONDS
docker network create --internal --label sick=1 --label "$label" "$isolated" >/dev/null
docker run -d --name "$restored" --label sick=1 --label "$label" --network "$isolated" --user 0:0 \
  -v "$restored_volume:/home/step" -v "$repo/docker/init-ca.sh:/usr/local/bin/init-ca.sh:ro" \
  --entrypoint /bin/bash "$step_image" /usr/local/bin/init-ca.sh >/dev/null
restored_up() { docker exec "$restored" curl -fsS -o /dev/null --cacert /home/step/certs/root_ca.crt https://localhost:9000/health; }
wait_for 60 'the restored CA' restored_up
pass 'the restored CA answers (inside its own network)'
init=$(docker logs "$restored" 2>&1 | plain | grep '^init-ca:')
show <<<"$init"
expect 'init-ca.sh finds the restored CA as it was' 'exists: nothing to make' "$init"
expect '... unchanged' 'configuration unchanged' "$init"
expect '... with the root of the original' "root fingerprint \(SHA-256\): $root_fp" "$init"
leaf=$(docker exec -u step "$restored" sh -c '
  cd /tmp && step ca certificate drill.example.internal drill.crt drill.key --ca-url https://localhost:9000 \
    --root /home/step/certs/root_ca.crt --provisioner sick \
    --provisioner-password-file /home/step/secrets/provisioner_password --not-after 24h >/dev/null 2>&1 \
  && cat drill.crt' | plain)
rto=$((SECONDS - t0))
printf '%s\n' "$leaf" >"$work/drill.pem"
grep -q 'BEGIN CERTIFICATE' "$work/drill.pem" || fail 'the restored CA issued nothing'
pass 'the restored CA issued a certificate'

note 'isolation'
networks=$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$restored")
[ "$networks" = "$isolated " ] || fail "the restored CA is on: $networks"
[ "$(docker network inspect -f '{{.Internal}}' "$isolated")" = true ] || fail "$isolated is not internal"
pass "the restored CA is on $isolated alone, an internal network"
[ -z "$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{end}}' "$restored")" ] \
  && [ -z "$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostPort}} {{end}}{{end}}' "$restored")" ] \
  || fail 'the restored CA publishes a port'
pass '... and publishes no port'
[ "$(docker inspect -f '{{.State.Running}} {{.State.Health.Status}}' "$ca_id")" = 'true healthy' ] || fail 'the original CA is not running and healthy'
pass 'the original CA keeps running, healthy'
members=$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "${project}_default")
refuse "the project's network does not have the restored CA" "$restored" "$members"
ca_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${project}_default\").IPAddress}}" "$ca_id")
seen=$(in_sick "getent ahostsv4 ca | awk '{print \$1}' | sort -u | tr '\n' ' '; echo; getent hosts $restored >/dev/null && echo 'restored resolves' || echo 'restored unknown'" 2>&1 | plain)
show <<<"$seen"
[ "$(head -n 1 <<<"$seen")" = "$ca_ip " ] || fail "\"ca\" resolves to $(head -n 1 <<<"$seen")in the project, the original CA is $ca_ip"
pass "\"ca\" resolves to the original CA ($ca_ip) and nothing else in the project's network"
expect '... and the restored CA is unknown there' '^restored unknown$' "$seen"
orig_before=$(ca_log | signed)
rest_before=$(docker logs "$restored" 2>&1 | plain | signed)
run=$(compose run --rm -T sick sick run --force "$device" 2>&1 | plain) || { show <<<"$run"; fail 'sick run --force'; }
show <<<"$run"
expect 'sick renews the device once more' "^$device +renewed " "$run"
in_sick 'cat /srv/device/cert.pem' | openssl x509 -outform DER -out "$work/after.der"
[ "$(ca_log | signed)" -eq $((orig_before + 1)) ] || fail 'the original CA did not log the certificate'
[ "$(docker logs "$restored" 2>&1 | plain | signed)" -eq "$rest_before" ] || fail 'the restored CA signed for the project'
pass '... served by the original CA (one more certificate in its log, none in the restored one)'

#### 4. what the restored CA is

step 'the restored CA: same root, same intermediate, still valid, the database restored'
v=$(openssl verify -no-CApath -no-CAstore -CAfile "$work/root_ca.crt" -untrusted "$work/intermediate_ca.crt" "$work/drill.pem" 2>&1)
show <<<"$v"
expect 'the leaf of the restored CA verifies against the root of the original' ': OK$' "$v"
docker exec "$restored" cat /home/step/certs/intermediate_ca.crt >"$work/restored-intermediate.crt"
[ "$(sha256_of "$work/restored-intermediate.crt")" = "$int_fp" ] || fail 'the restored intermediate is another'
pass 'the restored intermediate is the original one'
[ "$(openssl x509 -in "$work/drill.pem" -noout -issuer)" = "$(openssl x509 -in "$work/intermediate_ca.crt" -noout -subject | sed 's/^subject/issuer/')" ] \
  || fail 'the leaf has another issuer'
openssl x509 -in "$work/restored-intermediate.crt" -noout -checkend 0 >/dev/null || fail 'the restored intermediate has expired'
pass "the restored intermediate is valid ($(openssl x509 -in "$work/restored-intermediate.crt" -noout -enddate))"
docker cp -q "$restored:/home/step/db" "$work/restored-db"
# files_with <DER file> <dir>: how many files in dir hold those bytes
files_with() {
  perl -e '
    local $/; open my $c, "<:raw", shift or die; my $der = <$c>;
    my $n = 0;
    for my $f (@ARGV) { open my $h, "<:raw", $f or next; my $d = <$h>; $n++ if index($d, $der) >= 0 }
    print $n' "$1" "$2"/*
}
found=$(files_with "$work/before.der" "$work/restored-db")
[ "$found" -gt 0 ] || fail 'the restored database does not hold the certificate issued before the backup'
pass "the restored database holds the certificate issued before the backup (its DER found in $found Badger file(s))"
found=$(files_with "$work/after.der" "$work/restored-db")
[ "$found" -eq 0 ] || fail 'the restored database holds a certificate issued after the backup'
pass '... and not the one the original issued after the backup (the search can tell them apart)'
record "observed RTO in this lab: ${rto}s from 'ca-backup.sh restore' to the first certificate of the restored CA (restore $((t_restored - t0))s, start $((rto - (t_restored - t0)))s; images cached, one host, $(du -h "$work/backup/ca.tar" | cut -f1) archive)"
record 'RPO: everything since the last backup - the certificate SICK got after it is missing from the restored database (above)'

#### 5. refusals of the restore

step 'restore refuses a tampered archive and a volume that holds a CA'
cp "$work/backup/ca.tar" "$work/backup/tampered.tar"
cp "$work/backup/ca.tar.manifest" "$work/backup/tampered.tar.manifest"
size=$(stat -c %s "$work/backup/tampered.tar")
byte=$(od -An -tu1 -j $((size / 2)) -N 1 "$work/backup/tampered.tar" | tr -d ' ')
printf "\\$(printf '%03o' $(( (byte + 1) % 256 )))" | dd of="$work/backup/tampered.tar" bs=1 seek=$((size / 2)) conv=notrunc status=none
set +e
out=$("$repo/docker/ca-backup.sh" restore --from "$work/backup/tampered.tar" --volume "$tampered_volume" 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'a tampered archive was restored'
expect 'one byte changed: refused by the manifest check' 'does not match its manifest' "$out"
! docker volume inspect "$tampered_volume" >/dev/null 2>&1 || fail '... but a volume was made'
pass '... and no volume was made'
docker stop "$restored" >/dev/null
gone() { [ -z "$(docker ps -q --filter "volume=$restored_volume")" ]; }
wait_for 30 'the restored CA to be stopped' gone
set +e
out=$("$repo/docker/ca-backup.sh" restore --from "$work/backup/ca.tar" --volume "$restored_volume" 2>&1)
code=$?
set -e
show <<<"$out"
[ "$code" -ne 0 ] || fail 'a restore over a CA went through'
expect 'a volume that holds a CA: refused' 'already holds a CA: refused' "$out"

#### 6. provisioner rotation

step 'provisioner rotation on the live CA: new key, new password'
in_ca cat /home/step/secrets/provisioner_password >"$work/old.pw"
old_kid=$(in_ca jq -r '.authority.provisioners[] | select(.name == "sick") | .key.kid' /home/step/config/ca.json | plain)
in_ca sh -c 'jq -r ".authority.provisioners[] | select(.name == \"sick\") | .encryptedKey" /home/step/config/ca.json | step crypto jwe decrypt --password-file /home/step/secrets/provisioner_password' >"$work/old.jwk" 2>/dev/null
grep -q '"d"' "$work/old.jwk" || fail 'cannot keep the old provisioner key for the test'
note "old key $old_kid, kept (with the old password) in the working directory for the negative test"
set +e
out=$(compose exec -T ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner 2>&1 | plain)
code=$?
set -e
show <<<"$out"
[ "$code" -eq 0 ] || fail "init-ca.sh --rotate-provisioner ended with $code"
expect 'rotated: a new key with a new password' "rotated provisioner 'sick': key .* replaces key $old_kid" "$out"
expect '... the new password handed over' 'handed over provisioner.pw' "$out"
expect '... step-ca reloaded' 'step-ca reloads its configuration' "$out"
new_kid=$(in_ca jq -r '.authority.provisioners[] | select(.name == "sick") | .key.kid' /home/step/config/ca.json | plain)
[ -n "$new_kid" ] && [ "$new_kid" != "$old_kid" ] || fail 'the provisioner key did not change'
in_ca sh -c 'cmp -s /home/step/secrets/provisioner_password /handover/provisioner.pw' || fail 'the handover has another password'
in_ca cat /home/step/secrets/provisioner_password | cmp -s - "$work/old.pw" && fail 'the password did not change'
pass "key $new_kid, a new password, the same in the handover volume"
claims=$(in_ca jq -c '.authority.provisioners[] | select(.name == "sick") | [.claims.maxTLSCertDuration, (.options.x509.template | test("serverAuth"))]' /home/step/config/ca.json | plain)
[ "$claims" = '["19800h",true]' ] || fail "the new provisioner lost its settings: $claims"
pass '... with the lifetime and the serverAuth template of the old one'
in_ca cat /home/step/secrets/provisioner_password >"$work/new.pw"
in_ca sh -c 'jq -r ".authority.provisioners[] | select(.name == \"sick\") | .encryptedKey" /home/step/config/ca.json | step crypto jwe decrypt --password-file /home/step/secrets/provisioner_password' >"$work/new.jwk" 2>/dev/null

run=$(compose run --rm -T sick sick run --force "$device" 2>&1 | plain) || { show <<<"$run"; fail 'sick run --force after the rotation'; }
show <<<"$run"
expect 'sick issues with the new password (handed over), no restart of the CA' "^$device +renewed " "$run"

n=$(ca_log | signed)
out=$(step_client 'cd /tmp && step ca certificate old.example.internal x.crt x.key --ca-url https://ca:9000 --root /work/root_ca.crt \
  --provisioner sick --provisioner-password-file /work/old.pw --not-after 24h; echo "exit: $?"; ls x.crt 2>/dev/null; true' 2>&1 | plain)
show <<<"$out"
refuse 'the old password: refused' '^exit: 0$' "$out"
expect '... it does not open the new provisioner key' 'decrypt|password' "$out"

# token <key file> <kid>: a token as step ca token makes it, signed by hand
token() {
  step_client "now=\$(date +%s); step crypto jwt sign --key /work/$1 --kid $2 --iss sick \
    --aud https://ca:9000/1.0/sign --sub keyed.example.internal --nbf \$now --iat \$now --exp \$((now + 300)) \
    --jti \$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" 2>/dev/null | plain
}
use_token() {
  step_client "cd /tmp && step ca certificate keyed.example.internal x.crt x.key --ca-url https://ca:9000 \
    --root /work/root_ca.crt --token '$1'; echo \"exit: \$?\"" 2>&1 | plain
}
out=$(use_token "$(token old.jwk "$old_kid")")
show <<<"$out"
refuse 'a token signed with the old key (what the old password could still give): refused by the CA' '^exit: 0$' "$out"
expect '... as unauthorized' 'lacked necessary authorization' "$out"
[ "$(ca_log | signed)" -eq "$n" ] || fail '... but the CA logged a certificate issued'
pass '... and the CA issued nothing'
record "the CA's reason: $(ca_log | grep 'path=/sign ' | grep 'status=401' | tail -n 1 | grep -o 'error="[^"]*"')"
out=$(use_token "$(token new.jwk "$new_kid")")
show <<<"$out"
expect 'control: the same hand-made token signed with the new key is accepted' '^exit: 0$' "$out"

# 7. runs in the EXIT trap
