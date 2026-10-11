#!/bin/bash
#
# MikroTik RouterOS through the acme.sh deploy hook "routeros", proven twice:
#
#   t/e2e/device-routeros.sh               both parts
#   t/e2e/device-routeros.sh standin chr   the parts named
#
# Parts, each with PASS/FAIL lines; the first FAIL ends the script with 1:
#
#   standin  a recording stand-in for the router: an sshd container (Alpine)
#            whose deploy key has a forced command, t/e2e/routeros-standin.sh.
#            SICK runs on this host with a device of type acmesh, hook
#            routeros, a deploy key of its own (a file) and strict host key
#            checking against a known_hosts made now. Asserted: the two files
#            uploaded (the key with mode 0600), the three commands byte for
#            byte (the script with certificate remove, import, file remove,
#            /ip service set www-ssl and api-ssl; run; remove), the second run
#            "unchanged"; refused: an unknown host key, a script run that
#            exits 1, and one that changes nothing but exits 0 - RouterOS
#            answers a failure at run time with 0 - where only SICK's
#            verification notices. The stand-in presents on its TLS port what the commands
#            "imported" - this proves what our side sends, not what RouterOS
#            does with it.
#   chr      RouterOS CHR (the raw image of download.mikrotik.com, version and
#            SHA-256 pinned, checked against the published .sha256 too) in
#            qemu-system-x86_64 without KVM (TCG) in a container. A group with
#            the policies ssh,ftp,read,write and a user with the deploy key are
#            made through the REST API of the fresh image (admin, no password -
#            the CHR default; the VM lives on 127.0.0.1 for minutes), the host
#            key is taken out of the router the same way. Then the real hook
#            through SICK: renewed, fingerprint on www-ssl's port equals the
#            issued one and RouterOS's own; second run unchanged; forced run
#            replaces cer_0 (the old one is gone); refused: an unknown host
#            key; a group without "read": the device fails - RouterOS
#            interrupts the script's creation (acme.sh fails) or, seen once,
#            accepts it, runs nothing and answers 0 (acme.sh says Success,
#            SICK's verification fails) - and the key file stays on the
#            router until the next good run.
#
# Every container and image this script makes carries the labels sick=1 and
# sick.e2e=device-routeros, and it removes containers by those two labels
# alone - also those of an interrupted earlier run, at the start. No volume,
# no network (the default bridge), ports on 127.0.0.1 only. The images
# (sick-e2e-routeros-standin:local, sick-e2e-routeros-qemu:local) and the
# downloaded CHR image (in SICK_ROUTEROS_CACHE) stay as a cache.
#
# Prerequisites: Docker, openssl, ssh, scp, ssh-keygen, curl, jq, unzip,
# acme.sh in the PATH (3.1.6 was used), the Perl dependencies of SICK
# (local::lib), and for "chr" network access to download.mikrotik.com once.
#
# Parameters, all from the environment:
#
#   SICK_ROUTEROS_DIR          private working directory, mode 0700
#                              ($HOME/.local/share/sick-lab/routeros)
#   SICK_ROUTEROS_CACHE        where the CHR image is kept
#                              ($HOME/.local/share/sick-lab/cache/routeros)
#   SICK_ROUTEROS_CHR_VERSION  RouterOS version                  (7.24.5)
#   SICK_ROUTEROS_CHR_SHA256   SHA-256 of chr-<version>.img.zip  (pinned below)
#   SICK_ROUTEROS_BOOT_WAIT    seconds the CHR may take to answer   (300)
#   SICK_ROUTEROS_KEEP         "yes": keep the working directory      (no)
#
# Keys are made now: the deploy key in the working directory, the
# certificates' keys by SICK. No key and no password is printed; the user's
# password on the CHR is random and goes to curl on its standard input.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_ROUTEROS_DIR:-$HOME/.local/share/sick-lab/routeros}
cache=${SICK_ROUTEROS_CACHE:-$HOME/.local/share/sick-lab/cache/routeros}
chr_version=${SICK_ROUTEROS_CHR_VERSION:-7.24.5}
chr_sha256=${SICK_ROUTEROS_CHR_SHA256:-16f07222a3213352c9c4fbea4f4dec6a8ffb78fdc0fa5e398c23103ed357c6eb}
boot_wait=${SICK_ROUTEROS_BOOT_WAIT:-300}
keep=${SICK_ROUTEROS_KEEP:-no}

alpine='alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8' # alpine:3.22
labels=(--label sick=1 --label sick.e2e=device-routeros)
filters=(--filter label=sick=1 --filter label=sick.e2e=device-routeros)
name=router.example.internal

parts=("$@")
[ "${#parts[@]}" -gt 0 ] || parts=(standin chr)
want() { local p; for p in "${parts[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

step_no=0
step() { step_no=$((step_no + 1)); printf '\n=== %s. %s\n' "$step_no" "$*"; }
note() { printf -- '--- %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
show() { sed 's/^/    /'; }
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
wait_for() {
  local seconds=$1 what=$2 start=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    [ $((SECONDS - start)) -lt "$seconds" ] || fail "waited ${seconds}s for $what"
    sleep 2
  done
}

for p in "${parts[@]}"; do
  case $p in standin | chr) ;; *) fail "unknown part '$p' (standin, chr)" ;; esac
done

umask 077
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_ROUTEROS_DIR $work lies inside the build context $context" ;; esac

#### teardown, armed before anything exists

ours() { docker ps -aq "${filters[@]}"; }
remove_ours() {
  local ids
  ids=$(ours)
  [ -z "$ids" ] || docker rm -f $ids >/dev/null
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  note 'removing the containers labelled sick=1 and sick.e2e=device-routeros'
  remove_ours
  left=$(ours)
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | container /' >&2
    printf 'FAIL  containers left behind (listed above)\n' >&2
    rc=1
  else
    pass 'no container of this script is left'
  fi
  if [ "$keep" = yes ]; then
    note "working directory $work kept (SICK_ROUTEROS_KEEP=yes)"
  else
    rm -rf "${work:?}"/standin "${work:?}"/chr
    rmdir "$work" 2>/dev/null
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED (%s)\n' "${parts[*]}"; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

#### common

step 'prerequisites'
for program in docker openssl ssh scp ssh-keygen curl jq unzip acme.sh perl; do
  command -v "$program" >/dev/null || fail "$program is not in the PATH"
done
perl -I"$repo/lib" -MSICK::CLI -e1 2>/dev/null || fail 'SICK does not load: the Perl dependencies are missing (local::lib?)'
note "acme.sh $(acme.sh --version 2>/dev/null | tail -n 1), $(ssh -V 2>&1), $(openssl version)"
note "docker $(docker version --format '{{.Server.Version}}')"
note 'containers of an earlier run of this script (by label):'
ours | sed 's/^/    /'
remove_ours
rm -rf "${work:?}"/standin "${work:?}"/chr
pass 'nothing of an earlier run is left'

# sick <part dir> <log name> <args ...>: runs bin/sick, keeps its output
sick() {
  local dir=$1 log=$2
  shift 2
  set +e
  perl -I"$repo/lib" "$repo/bin/sick" -c "$dir/sick.yml" "$@" >"$dir/out/$log" 2>&1
  code=$?
  set -e
  out=$(cat "$dir/out/$log")
  show <<<"$out"
}

# fingerprint <port>: SHA-256 of what 127.0.0.1:<port> presents, lower case hex
fingerprint() {
  openssl s_client -connect "127.0.0.1:$1" -servername "$name" </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
    | sed -n 's/^sha256 Fingerprint=//Ip' | tr -d : | tr 'A-F' 'a-f'
}
issued() { jq -r '.last_issue.fingerprint_sha256 // empty' "$1/state/devices/router.json"; }

# write_config <part dir> <ssh port> <tls port>
write_config() {
  local dir=$1 sshport=$2 tlsport=$3
  local opts="-F /dev/null -i $dir/deploy -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$dir/known_hosts"
  cat >"$dir/sick.yml" <<EOF
ca:
  type: selfsigned
  dir: $dir/ca
state: $dir/state
devices:
  router:
    type: acmesh
    hook: routeros
    host: 127.0.0.1
    port: $tlsport
    names: [$name]
    env:
      ROUTER_OS_HOST: 127.0.0.1
      ROUTER_OS_USERNAME: sick
      ROUTER_OS_SSH_CMD: ssh -p $sshport $opts
      ROUTER_OS_SCP_CMD: scp -P $sshport $opts
      ROUTER_OS_ADDITIONAL_SERVICES: "/ip service set api-ssl certificate=$name.cer_0"
EOF
}

# new_part <dir>: directories and the deploy key
new_part() {
  mkdir -p "$1/out" "$1/state" "$1/ca"
  ssh-keygen -q -t ed25519 -N '' -C sick-e2e-routeros -f "$1/deploy"
  # a host key nobody has, for the negative
  ssh-keygen -q -t ed25519 -N '' -C stranger -f "$1/stranger"
}

# no_secret <part dir> [<more text>]: no private key in what SICK printed, in
# its records or in the given text
no_secret() {
  local dir=$1 extra=${2-} body
  body=$(sed -n 2p "$dir/deploy")
  refuse 'no private key in the output of sick, in its records or in the recording' \
    'PRIVATE KEY' "$(cat "$dir"/out/* "$dir"/state/devices/*.json 2>/dev/null; printf '%s' "$extra")"
  if grep -rqF -- "$body" "$dir/out" "$dir/state" || grep -qF -- "$body" <<<"$extra"; then
    fail 'a line of the deploy key appears in an output'
  fi
  pass 'no line of the deploy key appears in an output'
}

#### the recording stand-in

if want standin; then
  step 'the stand-in image and container'
  dir=$work/standin
  new_part "$dir"
  build=$dir/build
  mkdir -p "$build"
  cp "$here/routeros-standin.sh" "$build/"
  cat >"$build/sshd_config" <<'EOF'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers sick
Subsystem sftp /usr/lib/ssh/sftp-server
LogLevel VERBOSE
EOF
  cat >"$build/Dockerfile" <<EOF
FROM $alpine
RUN apk add --no-cache openssh-server openssh-sftp-server openssl \\
 && adduser -D -s /bin/sh sick && echo 'sick:*' | chpasswd -e \\
 && mkdir -p /standin /home/sick/.ssh && chown sick:sick /home/sick/.ssh && chmod 700 /home/sick/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY routeros-standin.sh /standin/routeros-standin.sh
RUN chmod 0755 /standin/routeros-standin.sh
EXPOSE 22 8443
ENTRYPOINT ["/standin/routeros-standin.sh", "serve"]
EOF
  chmod -R go+rX "$build"
  docker build -q "${labels[@]}" -t sick-e2e-routeros-standin:local "$build" | show
  note "packages: $(docker run --rm "${labels[@]}" --network none --entrypoint apk sick-e2e-routeros-standin:local \
    info -v 2>/dev/null | grep -E '^(openssh-server|openssh-sftp-server|openssl)-[0-9]' | tr '\n' ' ')"
  docker run -d --name sick-e2e-routeros-standin "${labels[@]}" \
    -p 127.0.0.1::22 -p 127.0.0.1::8443 sick-e2e-routeros-standin:local | show
  sshport=$(docker port sick-e2e-routeros-standin 22/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
  tlsport=$(docker port sick-e2e-routeros-standin 8443/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
  [ -n "$sshport" ] && [ -n "$tlsport" ] || fail 'the stand-in published no port on 127.0.0.1'
  [ -z "$(docker port sick-e2e-routeros-standin | grep -v ' -> 127\.0\.0\.1:')" ] || fail 'a port is published beyond 127.0.0.1'
  wait_for 60 'sshd of the stand-in' docker exec sick-e2e-routeros-standin test -f /run/sshd.pid
  wait_for 60 'the TLS port of the stand-in' test -n "$(fingerprint "$tlsport")"
  pass "stand-in up: ssh on 127.0.0.1:$sshport, TLS on 127.0.0.1:$tlsport, labelled"

  # the deploy key, by forced command; the host key, out of band
  { printf 'restrict,command="/standin/routeros-standin.sh login" '; cat "$dir/deploy.pub"; } \
    | docker exec -i sick-e2e-routeros-standin sh -c \
      'cat >/home/sick/.ssh/authorized_keys && chown sick:sick /home/sick/.ssh/authorized_keys && chmod 600 /home/sick/.ssh/authorized_keys'
  printf '[127.0.0.1]:%s %s\n' "$sshport" \
    "$(docker exec sick-e2e-routeros-standin cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" >"$dir/known_hosts"
  cp "$dir/known_hosts" "$dir/known_hosts.good"
  printf '[127.0.0.1]:%s %s\n' "$sshport" "$(cut -d' ' -f1,2 "$dir/stranger.pub")" >"$dir/known_hosts.stranger"
  write_config "$dir" "$sshport" "$tlsport"
  pass 'deploy key installed with a forced command; known_hosts made from the container'

  recording() { docker exec sick-e2e-routeros-standin cat /standin/record/events; }
  in_home() { docker exec sick-e2e-routeros-standin ls -A /home/sick | grep -v '^\.' || true; }

  step 'sick check and sick run against the stand-in'
  bootstrap=$(fingerprint "$tlsport")
  sick "$dir" check.log check
  expect 'sick check: the bootstrap certificate is foreign' '^router +foreign-ca +yes' "$out"
  sick "$dir" run.log run -v
  [ "$code" -eq 0 ] || fail "sick run ended with $code"
  expect 'sick run: renewed' '^router +renewed +foreign-ca' "$out"
  presented=$(fingerprint "$tlsport")
  [ "$presented" = "$(issued "$dir")" ] && [ "$presented" != "$bootstrap" ] \
    || fail "the stand-in presents $presented, issued was $(issued "$dir")"
  pass "the stand-in presents the issued certificate ($presented)"

  step 'what the hook sent'
  events=$(recording)
  show <<<"$events"
  normalised=$(sed -E 's/^(upload [a-z]+ [^ ]+) [0-9]+ /\1 N /' <<<"$events")
  expected_events="upload sftp $name.key N 600
upload sftp $name.cer N 644
exec 1
exec 2
import $name.cer -> $name.cer_0
import $name.key -> $name.cer_0 (private key)
service www-ssl $name.cer_0
service api-ssl $name.cer_0
exec 3"
  if [ "$normalised" != "$expected_events" ]; then
    diff <(printf '%s\n' "$expected_events") <(printf '%s\n' "$normalised") | sed 's/^/      | /' >&2
    fail 'the recorded sequence differs from the expected one (diff above: < expected, > recorded)'
  fi
  pass 'uploads: the key (mode 0600) first, then the full chain as <name>.cer, both over SFTP'
  if grep -E '^upload ' <<<"$events" | awk '$4 == 0 { bad = 1 } END { exit bad }'; then
    pass 'no uploaded file is empty'
  else
    fail 'an uploaded file is empty'
  fi
  # the three commands, byte for byte, as acme.sh 3.1.6 sends them
  user=sick
  extra="/ip service set api-ssl certificate=$name.cer_0"
  printf '%s\n' ":do {/system script remove \"LECertDeploy-$name\" } on-error={ }; /system script add name=\"LECertDeploy-$name\" owner=$user comment=\"generated by routeros deploy script in acme.sh\" source=\"/certificate remove [ find name=$name.cer_0 ];\\n/certificate remove [ find name=$name.cer_1 ];\\n/certificate remove [ find name=$name.cer_2 ];\\n/certificate remove [ find name=$name.cer_3 ];\\ndelay 1;\\n/certificate import file-name=\\\"$name.cer\\\" passphrase=\\\"\\\";\\n/certificate import file-name=\\\"$name.key\\\" passphrase=\\\"\\\";\\ndelay 1;\\n:do {/file remove $name.cer; } on-error={ }\\n:do {/file remove $name.key; } on-error={ }\\ndelay 2;\\n/ip service set www-ssl certificate=$name.cer_0;\\n$extra;\\n\"" >"$dir/expected-cmd-1"
  printf '%s' "/system script run \"LECertDeploy-$name\"" >"$dir/expected-cmd-2"
  printf '%s' "/system script remove \"LECertDeploy-$name\"" >"$dir/expected-cmd-3"
  for n in 1 2 3; do
    docker exec sick-e2e-routeros-standin cat "/standin/record/cmd-$n" >"$dir/cmd-$n"
    note "command $n:"
    show <"$dir/cmd-$n"
    echo
    cmp -s "$dir/expected-cmd-$n" "$dir/cmd-$n" || {
      diff "$dir/expected-cmd-$n" "$dir/cmd-$n" | sed 's/^/      | /' >&2
      fail "command $n differs from the expected one"
    }
  done
  pass 'the three commands are exactly: add the script (remove cer_0..cer_3, import cer and key, remove the files, set www-ssl, the additional service), run it, remove it'
  [ -z "$(in_home)" ] || fail "files left in the stand-in's home: $(in_home)"
  pass 'the uploaded files were removed by the script'

  step 'a second run changes nothing'
  sick "$dir" run2.log run
  expect 'sick run: unchanged' '^router +unchanged +ok' "$out"
  [ "$(recording)" = "$events" ] || fail 'the stand-in was contacted although nothing was due'
  pass 'nothing was sent to the stand-in'

  step 'refused: an unknown host key'
  cp "$dir/known_hosts.stranger" "$dir/known_hosts"
  sick "$dir" hostkey.log run --force
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'the device failed: host key verification' '^router +failed +forced +deploy failed: .*Host key verification failed' "$out"
  [ "$(recording)" = "$events" ] || fail 'something reached the stand-in despite the wrong host key'
  pass 'nothing was uploaded or executed'
  cp "$dir/known_hosts.good" "$dir/known_hosts"

  step 'refused: the script run fails (exit 1)'
  docker exec -u sick sick-e2e-routeros-standin touch /standin/state/fail-run
  sick "$dir" fail-run.log run --force
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'the device failed: acme.sh failed with the error of the router' \
    '^router +failed +forced +deploy failed: acme.sh failed \(exit 1\): .*stand-in told to fail' "$out"
  [ "$(fingerprint "$tlsport")" = "$presented" ] || fail 'the stand-in presents something new after a failed run'
  pass 'the stand-in still presents the previous certificate'
  docker exec -u sick sick-e2e-routeros-standin rm -f /standin/state/fail-run

  step 'refused: the script run fails at run time and says 0, as RouterOS does'
  docker exec -u sick sick-e2e-routeros-standin touch /standin/state/noop-run
  sick "$dir" noop-run.log run --force -v
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'acme.sh reported success' 'acme.sh: Success' "$out"
  expect 'SICK caught it: verification failed' '^router +failed +forced +verification failed: the device does not present the new certificate' "$out"
  left=$(in_home)
  expect 'the uploaded key stays on the "router" (the script that removes it never ran)' "^$name\\.key$" "$left"
  docker exec -u sick sick-e2e-routeros-standin rm -f /standin/state/noop-run
  sick "$dir" recover.log run --force
  [ "$code" -eq 0 ] || fail "the next run ended with $code"
  expect 'the next run renews' '^router +renewed' "$out"
  [ "$(fingerprint "$tlsport")" = "$(issued "$dir")" ] || fail 'the stand-in does not present the newest certificate'
  [ -z "$(in_home)" ] || fail "files left in the stand-in's home: $(in_home)"
  pass 'and the files on the "router" are gone again'

  step 'no secret in the outputs'
  no_secret "$dir" "$(recording; docker logs sick-e2e-routeros-standin 2>&1)"
fi

#### RouterOS CHR in qemu

if want chr; then
  step "RouterOS CHR $chr_version: image"
  dir=$work/chr
  new_part "$dir"
  mkdir -p "$cache" "$dir/vm"
  zip=$cache/chr-$chr_version.img.zip
  url=https://download.mikrotik.com/routeros/$chr_version/chr-$chr_version.img.zip
  if [ ! -f "$zip" ]; then
    note "downloading $url"
    curl -fsS -o "$zip.part" "$url" && mv "$zip.part" "$zip"
  fi
  published=$(curl -fsS "$url.sha256" | cut -d' ' -f1)
  actual=$(sha256sum "$zip" | cut -d' ' -f1)
  note "SHA-256 pinned $chr_sha256, published $published, of the file $actual"
  [ "$actual" = "$chr_sha256" ] || fail 'the image does not have the pinned SHA-256'
  [ "$published" = "$chr_sha256" ] || fail 'download.mikrotik.com publishes another SHA-256'
  pass 'the image matches the pinned and the published SHA-256'
  unzip -p "$zip" "chr-$chr_version.img" >"$dir/vm/disk.img"
  chmod -R go+rwX "$dir/vm"

  build=$dir/build
  mkdir -p "$build"
  printf 'FROM %s\nRUN apk add --no-cache qemu-system-x86_64\n' "$alpine" >"$build/Dockerfile"
  chmod -R go+rX "$build"
  docker build -q "${labels[@]}" -t sick-e2e-routeros-qemu:local "$build" | show
  note "$(docker run --rm "${labels[@]}" --network none sick-e2e-routeros-qemu:local qemu-system-x86_64 --version | head -n 1)"

  step 'boot the CHR (TCG, no KVM)'
  started=$SECONDS
  docker run -d --name sick-e2e-routeros-chr "${labels[@]}" --user "$(id -u):$(id -g)" \
    -v "$dir/vm:/work" -p 127.0.0.1::22 -p 127.0.0.1::80 -p 127.0.0.1::443 \
    sick-e2e-routeros-qemu:local qemu-system-x86_64 -accel tcg -m 512 -smp 2 -display none \
    -serial file:/work/console.log -drive file=/work/disk.img,format=raw,if=virtio \
    -netdev user,id=n0,hostfwd=tcp::22-:22,hostfwd=tcp::80-:80,hostfwd=tcp::443-:443 \
    -device virtio-net-pci,netdev=n0 | show
  sshport=$(docker port sick-e2e-routeros-chr 22/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
  webport=$(docker port sick-e2e-routeros-chr 80/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
  tlsport=$(docker port sick-e2e-routeros-chr 443/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
  [ -n "$sshport" ] && [ -n "$webport" ] && [ -n "$tlsport" ] || fail 'the CHR container published no port on 127.0.0.1'
  [ -z "$(docker port sick-e2e-routeros-chr | grep -v ' -> 127\.0\.0\.1:')" ] || fail 'a port is published beyond 127.0.0.1'
  rest_url=http://127.0.0.1:$webport/rest
  # rest <method> <path> [json on stdin]
  rest() {
    if [ "$1" = GET ]; then
      curl -fsS -m 60 -u admin: "$rest_url$2"
    else
      curl -fsS -m 60 -u admin: -H 'content-type: application/json' -X "$1" --data-binary @- "$rest_url$2"
    fi
  }
  wait_for "$boot_wait" 'the REST API of the CHR' rest GET /system/resource
  pass "the CHR answers after $((SECONDS - started))s: $(rest GET /system/resource | jq -r '.version + ", " + ."board-name"')"
  tr -d '\r' <"$dir/vm/console.log" | grep -a 'MikroTik' | tail -n 1 | show

  step 'a group and a user for SICK, the host key'
  all=$(rest GET '/user/group?name=full' | jq -r '.[0].policy' | tr ',' '\n' | sed 's/^!//' | sort -u)
  policy=$(for p in $all; do case ,ssh,ftp,read,write, in *,"$p",*) printf ',%s' "$p" ;; *) printf ',!%s' "$p" ;; esac; done)
  set_policy() {
    local want=",$1," p s=
    for p in $all; do case $want in *,"$p",*) s="$s,$p" ;; *) s="$s,!$p" ;; esac; done
    jq -n --arg p "${s#,}" '{numbers: "sick", policy: $p}' | rest POST /user/group/set >/dev/null
  }
  jq -n --arg p "${policy#,}" '{name: "sick", policy: $p, comment: "SICK deploys certificates"}' | rest PUT /user/group | jq -c '{name, policy}' | show
  # a password nobody uses (keys only): random, on curl's standard input
  jq -n --arg pw "$(openssl rand -hex 24)" '{name: "sick", group: "sick", password: $pw}' | rest PUT /user | jq -c '{name, group}' | show
  jq -n --arg k "$(cat "$dir/deploy.pub")" '{user: "sick", key: $k}' | rest PUT /user/ssh-keys | jq -c '{user, "key-type", fingerprint}' | show
  printf '{"numbers": "www-ssl", "disabled": "false"}' | rest POST /ip/service/set >/dev/null
  printf '{"numbers": "api-ssl", "disabled": "false"}' | rest POST /ip/service/set >/dev/null
  # the host key, out of band: exported to a file, the public half read, both files removed
  printf '{"key-file-prefix": "sick-e2e-hostkey"}' | rest POST /ip/ssh/export-host-key >/dev/null
  rest GET '/file?name=sick-e2e-hostkey_rsa_pub.pem' | jq -r '.[0].contents' >"$dir/hostkey.pem"
  for f in $(rest GET /file | jq -r '.[].name | select(startswith("sick-e2e-hostkey"))'); do
    jq -n --arg f "$f" '{numbers: $f}' | rest POST /file/remove >/dev/null
  done
  [ -z "$(rest GET /file | jq -r '.[].name | select(startswith("sick-e2e-hostkey"))')" ] || fail 'the exported host key files are still on the router'
  printf '[127.0.0.1]:%s %s\n' "$sshport" "$(ssh-keygen -i -m PKCS8 -f "$dir/hostkey.pem")" >"$dir/known_hosts"
  cp "$dir/known_hosts" "$dir/known_hosts.good"
  printf '[127.0.0.1]:%s %s\n' "$sshport" "$(cut -d' ' -f1,2 "$dir/stranger.pub")" >"$dir/known_hosts.stranger"
  write_config "$dir" "$sshport" "$tlsport"
  pass 'group sick (ssh,ftp,read,write), user sick with the deploy key, www-ssl and api-ssl enabled, known_hosts from the router'

  ros_certs() { rest GET /certificate | jq -r '.[] | .name + " " + .fingerprint + " key=" + ."private-key"'; }
  ros_files() { rest GET /file | jq -r '.[] | select(.type != "directory") | .name'; }
  ros_service() { rest GET "/ip/service?name=$1" | jq -r '.[0].certificate'; }

  step 'sick run with the real hook'
  sick "$dir" check.log check
  expect 'sick check: www-ssl presents nothing yet' '^router +missing +yes' "$out"
  sick "$dir" run.log run -v
  [ "$code" -eq 0 ] || fail "sick run ended with $code"
  expect 'sick run: renewed, verified by SICK on the port' 'router: renewed, the device presents the new certificate' "$out"
  presented=$(fingerprint "$tlsport")
  certs=$(ros_certs)
  show <<<"$certs"
  [ "$presented" = "$(issued "$dir")" ] || fail "www-ssl presents $presented, issued was $(issued "$dir")"
  expect 'RouterOS has the issued certificate as cer_0, with its key' "^$name\\.cer_0 $presented key=true$" "$certs"
  [ "$(ros_service www-ssl)" = "$name.cer_0" ] && [ "$(ros_service api-ssl)" = "$name.cer_0" ] \
    || fail "www-ssl uses $(ros_service www-ssl), api-ssl $(ros_service api-ssl)"
  pass "www-ssl presents the issued certificate ($presented); www-ssl and api-ssl use $name.cer_0"
  [ -z "$(ros_files)" ] || fail "files left on the router: $(ros_files | tr '\n' ' ')"
  [ "$(rest GET /system/script | jq length)" = 0 ] || fail 'the deploy script is still on the router'
  pass 'no file and no script left on the router'
  # what the stand-in's noop-run imitates: a failure at run time is exit 0
  set +e
  answer=$(ssh -p "$sshport" -F /dev/null -i "$dir/deploy" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$dir/known_hosts" sick@127.0.0.1 \
    '/certificate import file-name="sick-e2e-missing.cer" passphrase=""' 2>&1 | tr -d '\r')
  status=${PIPESTATUS[0]}
  set -e
  show <<<"$answer"
  [ "$status" -eq 0 ] || fail "RouterOS ended a failed import with $status"
  expect 'RouterOS prints the error of a failed import and the ssh session still exits 0' 'input does not match any value of file-name' "$answer"

  step 'a second run changes nothing, a forced one replaces cer_0'
  sick "$dir" run2.log run
  expect 'sick run: unchanged' '^router +unchanged +ok' "$out"
  sick "$dir" force.log run --force
  expect 'sick run --force: renewed' '^router +renewed +forced' "$out"
  certs=$(ros_certs)
  show <<<"$certs"
  [ "$(wc -l <<<"$certs")" -eq 1 ] && [ "$presented" != "$(issued "$dir")" ] \
    || fail 'expected exactly one certificate, a new one'
  expect 'the new certificate is cer_0; the old one is removed, not kept' "^$name\\.cer_0 $(issued "$dir") key=true$" "$certs"
  presented=$(fingerprint "$tlsport")
  [ "$presented" = "$(issued "$dir")" ] || fail 'www-ssl does not present the new certificate'
  pass 'www-ssl presents the new certificate without a restart'

  step 'refused: an unknown host key'
  cp "$dir/known_hosts.stranger" "$dir/known_hosts"
  sick "$dir" hostkey.log run --force
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'the device failed: host key verification' '^router +failed +forced +deploy failed: .*Host key verification failed' "$out"
  [ "$(fingerprint "$tlsport")" = "$presented" ] && [ -z "$(ros_files)" ] || fail 'the router changed'
  pass 'the router is unchanged'
  cp "$dir/known_hosts.good" "$dir/known_hosts"

  step 'refused: a group without "read"'
  set_policy ssh,ftp,write
  sick "$dir" noread.log run --force -v
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'the device failed' '^router +failed +forced +(deploy failed: acme.sh failed|verification failed: the device does not present the new certificate)' "$out"
  if grep -q 'acme.sh: Success' <<<"$out"; then
    note 'this time: acme.sh said Success, SICK verification failed'
  else
    note "this time: RouterOS answered '$(sed -n 's/^router: acme.sh: //p' <<<"$out" | grep -v -E '^(Push key|Submitting)' | head -n 1)', acme.sh failed"
  fi
  [ "$(fingerprint "$tlsport")" = "$presented" ] || fail 'www-ssl presents something else'
  pass 'www-ssl still presents the previous certificate'
  files=$(ros_files)
  expect 'the uploaded key stays on the router' "^$name\\.key$" "$files"
  set_policy ssh,ftp,read,write
  sick "$dir" recover.log run --force
  [ "$code" -eq 0 ] || fail "the next run ended with $code"
  expect 'with the policies back, the next run renews' '^router +renewed' "$out"
  [ -z "$(ros_files)" ] || fail "files left on the router: $(ros_files | tr '\n' ' ')"
  [ "$(fingerprint "$tlsport")" = "$(issued "$dir")" ] || fail 'www-ssl does not present the newest certificate'
  pass 'and the files on the router are gone'

  step 'no secret in the outputs, nor in the log of the router'
  rest GET /log | jq -r '.[] | .time + " " + .topics + " " + .message' >"$dir/routeros.log"
  grep -E 'script|certificate|service' "$dir/routeros.log" | tail -n 8 | cut -c1-160 | show
  no_secret "$dir" "$(cat "$dir/routeros.log")"
  note "boot to REST: see above; whole CHR part: $((SECONDS - started))s"
fi
