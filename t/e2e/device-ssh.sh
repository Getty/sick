#!/bin/bash
#
# A Linux host over SSH, proven with Docker: SICK deploys through the
# acme.sh hook "ssh" onto a container that runs sshd and nginx, as an
# account that may write one directory and reload nginx, and nothing more.
#
# The host ("www", alias www.example.internal) is Debian with openssh-server,
# nginx and sudo; it is set up the way contrib/devices/linux-ssh/README.md
# describes, with the sudoers file of that directory. The device list is the
# one of contrib/devices/linux-ssh/sick.yml plus the CA of docker/compose.yml
# (used as shipped, with an override written into the working directory).
#
# What it proves, each step with PASS/FAIL lines and an exit code of 1 on
# the first FAIL:
#
#   1. from nothing: images, the CA, the host; every container, volume and
#      network of the project carries sick=1
#   2. the access: a deploy key made at test time inside a secrets volume
#      (root, 0600, never on this machine's disk, never in the environment);
#      authorized_keys with restrict,from=<network of the project>; a
#      known_hosts made from the host's key as read on the host itself
#   3. sick check: www is not presented with a certificate of this CA
#   4. sick run renews it; the fingerprint nginx presents on 443 equals the
#      one SICK issued; the chain verifies against the root
#   5. a second sick run changes nothing
#   6. the access is as small as claimed: the account owns nothing but the
#      certificate directory, sudo allows "nginx -s reload" and nothing else,
#      writing elsewhere and forwarding are refused
#   7. (a) host key unknown: refused, nothing written
#   8. (a) host key changed: refused, nothing written
#   9. (c) a deploy key the host does not know: refused, nothing written
#  10. (b) the reload fails: the device fails, nginx still presents the old
#      certificate; the new files and the hook's backup are on disk; back to
#      a consistent state from the backup
#  11. (b) the reload is accepted, but nginx does not take the new
#      configuration: the hook reports success, SICK's look at the port
#      fails the device
#  12. (d) the host does not answer: unreachable, nothing issued
#  13. the smaller access: the forced command sick-deploy-gate, no shell,
#      the hook's backup off; sick run renews, a shell command is refused
#  14. teardown, also after a failure or Ctrl-C: the project goes with its
#      volumes; nothing of it may be left
#
# It DESTROYS the Compose project it works on (default sick-dev-ssh). It
# touches nothing else: no other project, no prune. The images sick:local
# and sick-dev-ssh-www:local stay as a cache. Nothing is published on a
# port.
#
# Prerequisites: Docker with Compose 2.24 or newer, perl (core) on this
# machine; the two source trees side by side, as for run-local.sh. sick:local
# is built as run-local.sh builds it when it is not there (or always, with
# SICK_DEVSSH_BUILD=yes).
#
# Parameters, all from the environment:
#
#   SICK_DEVSSH_DIR      private working directory, mode 0700
#                        ($HOME/.local/share/sick-lab/device-ssh)
#   SICK_DEVSSH_PROJECT  Compose project name, sick-*        (sick-dev-ssh)
#   SICK_DEVSSH_BUILD    "yes": rebuild sick:local                      (no)
#   SICK_DEVSSH_KEEP     "yes": keep the working directory              (no)
#
# Nothing secret is printed or written to the working directory: the deploy
# keys exist in the secrets volume only, the CA's keys in the CA's volume.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)
recipe=$repo/contrib/devices/linux-ssh

work=${SICK_DEVSSH_DIR:-$HOME/.local/share/sick-lab/device-ssh}
project=${SICK_DEVSSH_PROJECT:-sick-dev-ssh}
build=${SICK_DEVSSH_BUILD:-no}
keep=${SICK_DEVSSH_KEEP:-no}

# Debian 13 (trixie) slim of 2026-10-05, by digest
base_image='debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f'
www_image=sick-dev-ssh-www:local
ca_name='SICK Device SSH CA'
device=www
name=www.example.internal
tls=/etc/nginx/tls

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

#### prerequisites

for program in docker perl; do
  command -v "$program" >/dev/null || fail "$program is not installed"
done
docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_DEVSSH_PROJECT '$project' is not sick or sick-*"
[ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
for file in sick.yml sudoers authorized_keys sick-deploy-gate; do
  [ -r "$recipe/$file" ] || fail "$recipe/$file is missing"
done

umask 077
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_DEVSSH_DIR $work lies inside the build context $context" ;; esac

#### the files of the stack, all in the working directory

mkdir -p "$work/www"
cp "$recipe/sudoers" "$recipe/sick-deploy-gate" "$work/www/"

cat >"$work/www/Dockerfile" <<EOF
# Generated by t/e2e/device-ssh.sh: the Linux host.
FROM $base_image
RUN apt-get update \\
 && apt-get install -y --no-install-recommends nginx openssh-server openssl sudo \\
 && rm -rf /var/lib/apt/lists/*
COPY sudoers /etc/sudoers.d/sick-deploy
COPY sshd.conf /etc/ssh/sshd_config.d/sick.conf
COPY site.conf /etc/nginx/conf.d/tls.conf
COPY --chmod=0755 entrypoint.sh /usr/local/sbin/www-entrypoint
COPY --chmod=0755 sick-deploy-gate /usr/local/sbin/sick-deploy-gate
# the account: no password, a home that belongs to root (it cannot change
# its authorized_keys), and one directory of its own
RUN chown root:root /etc/sudoers.d/sick-deploy && chmod 0440 /etc/sudoers.d/sick-deploy \\
 && visudo -cf /etc/sudoers.d/sick-deploy \\
 && rm -f /etc/nginx/sites-enabled/default /etc/ssh/ssh_host_* \\
 && useradd --no-create-home --home-dir /home/sick-deploy --shell /bin/sh sick-deploy \\
 && usermod -p '*' sick-deploy \\
 && install -d -o root -g root -m 0755 /home/sick-deploy /home/sick-deploy/.ssh \\
 && install -o root -g root -m 0644 /dev/null /home/sick-deploy/.ssh/authorized_keys \\
 && install -d -o sick-deploy -g sick-deploy -m 0700 $tls
ENTRYPOINT ["/usr/local/sbin/www-entrypoint"]
EOF

cat >"$work/www/sshd.conf" <<'EOF'
# Generated by t/e2e/device-ssh.sh
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers sick-deploy
EOF

cat >"$work/www/site.conf" <<EOF
# Generated by t/e2e/device-ssh.sh
server {
    listen 443 ssl;
    server_name $name;
    ssl_certificate     $tls/fullchain.pem;
    ssl_certificate_key $tls/key.pem;
    return 200 "www\n";
}
EOF

cat >"$work/www/entrypoint.sh" <<EOF
#!/bin/sh
# Generated by t/e2e/device-ssh.sh: host key, the certificate an installer
# leaves (self-signed), nginx, sshd in the foreground.
set -eu
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
if [ ! -f $tls/fullchain.pem ]; then
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \\
      -subj /CN=$name -keyout $tls/key.pem -out $tls/fullchain.pem 2>/dev/null )
  chown sick-deploy:sick-deploy $tls/key.pem $tls/fullchain.pem
fi
mkdir -p /run/sshd
nginx
exec /usr/sbin/sshd -D -e
EOF

cat >"$work/compose.device-ssh.yml" <<EOF
# Generated by t/e2e/device-ssh.sh. Added to docker/compose.yml: no port
# published, every container, volume and network labelled sick=1, the host
# "www", a secrets volume for the sick service and a one-off service that
# fills it.
services:
  ca:
    labels: { sick: "1" }
    ports: !reset []
  trust:
    labels: { sick: "1" }
    ports: !reset []
  sick:
    labels: { sick: "1" }
    build:
      labels: { sick: "1" }
  www:
    labels: { sick: "1" }
    image: $www_image
    build:
      context: $work/www
      labels: { sick: "1" }
    init: true
    stop_grace_period: 3s
    networks:
      default:
        aliases: [$name]
    healthcheck:
      test: ["CMD-SHELL", "test -s /run/sshd.pid && openssl s_client -connect 127.0.0.1:443 </dev/null >/dev/null 2>&1"]
      interval: 2s
      timeout: 5s
      retries: 15
      start_period: 3s
  secrets:
    labels: { sick: "1" }
    image: \${SICK_IMAGE:-sick:local}
    pull_policy: never
    profiles: [setup]
    network_mode: none
    entrypoint: ["/bin/sh", "-c"]
    volumes:
      - sshsecrets:/secrets
volumes:
  ca: { labels: { sick: "1" } }
  handover: { labels: { sick: "1" } }
  state: { labels: { sick: "1" } }
  trust: { labels: { sick: "1" } }
  sshsecrets: { labels: { sick: "1" } }
networks:
  default: { labels: { sick: "1" } }
EOF

cat >"$work/compose.env" <<EOF
# Generated by t/e2e/device-ssh.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=sshsecrets
SICK_CA_NAME=$ca_name
SICK_INTERVAL=1d
EOF

unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
  SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_TRUST_PORT SICK_INTERVAL \
  SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION

# write_config [<deploy key file> <known_hosts file> [gate]]: the device
# list, the device as in contrib/devices/linux-ssh/sick.yml with the two
# files swapped; "gate": with the hook's backup off, for sick-deploy-gate
write_config() {
  local key=${1:-www-deploy.key} known=${2:-www.known_hosts} backup='DEPLOY_SSH_BACKUP_PATH: \1'
  [ "${3:-}" != gate ] || backup='DEPLOY_SSH_BACKUP: "no"'

  {
    cat <<EOF
# Generated by t/e2e/device-ssh.sh. Neutral names only.
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
  key: ec256
EOF
    sed -n '/^devices:/,$p' "$recipe/sick.yml" \
      | sed "s#/etc/sick/secrets/www-deploy.key#/etc/sick/secrets/$key#g; s#/etc/sick/secrets/www.known_hosts#/etc/sick/secrets/$known#g; s#DEPLOY_SSH_BACKUP_PATH: \(.*\)#$backup#"
  } >"$work/sick.yml.new"
  chmod 644 "$work/sick.yml.new"
  mv "$work/sick.yml.new" "$work/sick.yml"
}
write_config

compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$work/compose.device-ssh.yml" "$@"
}
# a command in a fresh sick container: no schedule
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
# a command on the host, as root (the administrator, not SICK)
on_www() { compose exec -T www sh -c "$1"; }
# sick <args>: output and exit code of a sick command in a fresh container
sick_cmd() {
  set +e
  out=$(compose run --rm -T sick sick "$@" 2>&1 | plain)
  code=$?
  set -e
}

# the SHA-256 fingerprint nginx presents on 443, 64 lower-case hex digits
presented() {
  in_sick "openssl s_client -connect $name:443 -servername $name </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" \
    | plain | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
}
# the fingerprint of the first certificate of a file on the host
on_disk() {
  on_www "openssl x509 -in $1 -noout -fingerprint -sha256" | plain | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
}
# what SICK recorded as issued last: "<fingerprint> <serial>"
last_issue() {
  in_sick "cat /var/lib/sick/devices/$device.json" | plain \
    | perl -MJSON::PP -0777 -ne '$r = decode_json($_)->{last_issue} || {}; print "$r->{fingerprint_sha256} $r->{serial}\n"'
}
# the certificate directory of the host: names, sizes, times, modes, owners,
# and one checksum over all contents (not printed)
www_state() {
  on_www "cd $tls && find . -exec stat -c '%n %s %Y %a %U' {} + | sort && find . -type f | sort | xargs cat | sha256sum" | plain
}
listing() { sed '$d' <<<"$1"; }

# down with the volumes, then what is left of the project and carries sick=1
sweep() {
  compose --profile setup down --volumes --remove-orphans "$@"
  docker ps -aq --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f -v >/dev/null 2>&1
  docker volume ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
  docker network ls -q --filter label=sick=1 --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
}

#### teardown, armed before anything exists

armed=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== %s. teardown\n' "$((step_no + 1))"
  if [ -n "$armed" ]; then
    compose unpause www >/dev/null 2>&1
    note "docker compose -p $project down -v --remove-orphans"
    sweep 2>&1 | show
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
      pass "no container, volume or network of project $project is left"
    fi
    note "the images sick:local and $www_image (and the pulled step-ca and Debian images) stay as a cache"
  fi
  if [ "$keep" = yes ]; then
    note "working directory $work kept (SICK_DEVSSH_KEEP=yes)"
  else
    rm -rf "${work:?}"/{sick.yml,sick.yml.new,compose.env,compose.device-ssh.yml,build.log,up.log,www}
    rmdir "${work:?}" 2>/dev/null
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'project %s, working directory %s\n' "$project" "$work"

#### 1. from nothing

step 'from nothing: images, the CA, the host'
armed=yes
# what an interrupted earlier run left: by project, then by label
sweep >/dev/null 2>&1 || true
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ] || fail "containers of project $project are left from an earlier run"
if [ "$build" = yes ] || ! docker image inspect sick:local >/dev/null 2>&1; then
  note 'docker compose build sick'
  compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build sick'; }
fi
note 'docker compose build www'
compose build www >>"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build www'; }
pass "the host image is built from $base_image"
note "sick:local $(docker image inspect -f '{{.Id}} built {{.Created}}' sick:local)"
note "$www_image $(docker image inspect -f '{{.Id}}' "$www_image")"
note "step-ca $(docker image inspect -f '{{index .RepoDigests 0}}' smallstep/step-ca:0.30.2 2>/dev/null || echo 'not pulled yet')"
note 'docker compose up -d --wait ca www'
compose up -d --wait ca www >"$work/up.log" 2>&1 \
  || { plain <"$work/up.log" | tail -20 >&2; compose logs ca www 2>&1 | tail -20 >&2; fail 'ca and www did not come up healthy'; }
pass 'ca and www are up and healthy'
versions=$(on_www 'nginx -v 2>&1; sshd -V 2>&1 | head -n 1; sudo -V | head -n 1; openssl version' | plain)
show <<<"$versions"
note "in sick: $(in_sick 'acme.sh --version | tail -n 1; ssh -V 2>&1; sick --version' | plain | tr '\n' ' ')"
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
  [ "$(docker image inspect -f '{{index .Config.Labels "sick"}}' "$www_image")" = 1 ] || echo "image $www_image"
)
[ -z "$unlabelled" ] || { printf '%s\n' "$unlabelled" | sed 's/^/      | /' >&2; fail 'without the label sick=1 (listed above)'; }
pass 'every container, volume and network of the project, and the host image, carry the label sick=1'
published=$(docker ps --filter "label=com.docker.compose.project=$project" --format '{{.Ports}}' | grep -c -- '->' || true)
[ "$published" -eq 0 ] || fail 'a port is published'
pass 'nothing is published on a port'

#### 2. the access

step 'the access: a deploy key of its own, authorized_keys with restrict and from, a known_hosts from the host'
note 'deploy key and a stranger key, made in the secrets volume (root, 0600)'
pub=$(compose --profile setup run --rm -T secrets '
  set -e; umask 077; cd /secrets; rm -f ./*
  ssh-keygen -q -t ed25519 -N "" -C sick-deploy -f www-deploy.key
  ssh-keygen -q -t ed25519 -N "" -C stranger -f stranger.key
  ssh-keygen -q -t ed25519 -N "" -C not-the-host -f not-the-host.key
  rm -f stranger.key.pub
  cat www-deploy.key.pub' 2>/dev/null | plain | grep '^ssh-ed25519 ')
[ -n "$pub" ] || fail 'no deploy key was made'
pass "deploy key $(awk '{print $1, substr($2, 1, 24) "..."}' <<<"$pub")"

subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "${project}_default" | awk '{print $1}')
[[ $subnet =~ ^[0-9.]+/[0-9]+$ ]] || fail "no IPv4 subnet for ${project}_default ($subnet)"
# the two lines of contrib/devices/linux-ssh/authorized_keys: with a shell, and with the gate
options=$(grep -E '^restrict' "$recipe/authorized_keys" | awk '{print $1}' | sed "s#from=\"[^\"]*\"#from=\"$subnet\"#")
gate_options=$(grep -E '^#restrict' "$recipe/authorized_keys" | awk '{print $1}' | sed "s/^#//; s#from=\"[^\"]*\"#from=\"$subnet\"#")
expect 'the options of contrib/devices/linux-ssh/authorized_keys' '^restrict,from="[0-9./]+"$' "$options"
expect '... and those of its line for sick-deploy-gate' '^restrict,from="[0-9./]+",command="/usr/local/sbin/sick-deploy-gate"$' "$gate_options"
note "authorized_keys: $options <deploy key>"
printf '%s %s\n' "$options" "$pub" | on_www "cat >/home/sick-deploy/.ssh/authorized_keys"
perms=$(on_www 'stat -c "%n %U:%G %a" /home/sick-deploy /home/sick-deploy/.ssh /home/sick-deploy/.ssh/authorized_keys /etc/sudoers.d/sick-deploy '$tls | plain)
show <<<"$perms"
[ "$(grep -c ' root:root ' <<<"$perms")" -eq 4 ] && grep -q "^$tls sick-deploy:sick-deploy 700$" <<<"$perms" \
  || fail 'ownership or modes are not as set up'
pass 'home, .ssh, authorized_keys and the sudoers file belong to root; the certificate directory to sick-deploy (0700)'

note 'known_hosts: the host key read on the host, not over the network; a wrong one; an empty one'
hostkey=$(on_www 'cat /etc/ssh/ssh_host_ed25519_key.pub' | plain | awk '{print $1, $2}')
[[ $hostkey =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || fail 'no ed25519 host key on www'
printf '%s %s\n' "$name" "$hostkey" | compose --profile setup run --rm -T secrets '
  set -e; cd /secrets
  cat >www.known_hosts
  printf "%s %s\n" '"$name"' "$(cut -d" " -f1,2 not-the-host.key.pub)" >changed.known_hosts
  : >unknown.known_hosts
  rm -f not-the-host.key not-the-host.key.pub
  chmod 644 ./*.known_hosts www-deploy.key.pub
  ls -ln' 2>/dev/null | plain | show
pass "known_hosts holds $name $(awk '{print $1, substr($2, 1, 24) "..."}' <<<"$hostkey")"
modes=$(in_sick 'stat -c "%n %u %a" /etc/sick/secrets/www-deploy.key /etc/sick/secrets/stranger.key; env' | plain)
expect 'the deploy key is a file of root with mode 0600 in the sick service' '^/etc/sick/secrets/www-deploy.key 0 600$' "$modes"
refuse '... and not in its environment' 'PRIVATE KEY|AAAAC3NzaC1lZDI1NTE5' "$(grep -v '^/etc/sick/secrets' <<<"$modes")"
refuse 'the device list holds no key' 'PRIVATE KEY|AAAA' "$(cat "$work/sick.yml")"

#### 3. check

step "sick check: $device is not presented with a certificate of this CA"
sick_cmd check
show <<<"$out"
[ "$code" -eq 0 ] || fail "sick check ended with $code"
expect "$device has the installer's self-signed certificate and is due" "^$device +foreign-ca +yes" "$out"
first_fp=$(presented)
before=$(www_state)

#### 4. run

step "sick run: $device gets a certificate of the CA over ssh"
sick_cmd run --verbose "$device"
show <<<"$out"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'renewed' "^$device +renewed +foreign-ca" "$out"
expect '... through acme.sh with the hook ssh, by scp' 'acme.sh: Using scp as alternate method' "$out"
expect '... the hook reports success' 'acme.sh: Success' "$out"
refuse '... and no key reached the output' 'PRIVATE KEY' "$out"
read -r issued serial < <(last_issue)
[[ $issued =~ ^[0-9a-f]{64}$ ]] || fail 'no fingerprint in the record of the issue'
fp=$(presented)
note "issued    $issued (serial $serial)"
note "presented $fp"
[ "$fp" = "$issued" ] || fail 'nginx presents another certificate than the one SICK issued'
pass 'the fingerprint nginx presents on 443 is the one SICK issued'
[ "$(on_disk $tls/fullchain.pem)" = "$issued" ] || fail "$tls/fullchain.pem is not the issued certificate"
pass "$tls/fullchain.pem on the host is the issued certificate"
seen=$(in_sick "openssl s_client -connect $name:443 -servername $name -no-CApath -no-CAstore \
  -CAfile /etc/sick/ca/root_ca.crt -verify_return_error -verify_hostname $name </dev/null 2>&1 \
  | grep -E '^(Verification|Verify return code)'; echo \"exit \${?}\"" | plain)
show <<<"$seen"
expect 'the chain nginx sends verifies against the root of the CA, for the name' '^Verification: OK' "$seen"
files=$(on_www "ls -ln $tls; ls -lnR $tls/backup" | plain)
show <<<"$files"
expect "the hook kept the installer's files in $tls/backup/$name-backup-<UTC time>" "^$tls/backup/$name-backup-[0-9-]+:[0-9:]+:" "$files"
after_first=$(www_state)

#### 5. again

step 'a second sick run changes nothing'
sick_cmd run
show <<<"$out"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'unchanged' "^$device +unchanged +ok" "$out"
[ "$(www_state)" = "$after_first" ] || fail 'the certificate directory changed'
pass 'nothing on the host changed'

#### 6. how small the access is

step 'the access is as small as claimed'
owned=$(on_www "find / -xdev -user sick-deploy 2>/dev/null | sort" | plain)
show <<<"$owned"
outside=$(grep -v "^$tls\(/\|$\)" <<<"$owned" || true)
[ -z "$outside" ] || { printf '%s\n' "$outside" | sed 's/^/      | /' >&2; fail 'sick-deploy owns files outside the certificate directory'; }
pass "sick-deploy owns nothing outside $tls"
sudo_l=$(on_www 'sudo -l -U sick-deploy' | plain)
show <<<"$sudo_l"
expect 'sudo allows the deploy account one command: nginx -s reload' '\(root\) NOPASSWD: /usr/sbin/nginx -s reload$' "$sudo_l"
[ "$(grep -c NOPASSWD <<<"$sudo_l")" -eq 1 ] || fail 'sudo allows more than one command'
# over the deploy key itself, as SICK would connect
opts="-T -i /etc/sick/secrets/www-deploy.key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/sick/secrets/www.known_hosts -o ConnectTimeout=10"
probe=$(in_sick "
  ssh $opts sick-deploy@$name 'id -un; touch /etc/nginx/nginx.conf; echo \"touch nginx.conf: \$?\"'
  ssh $opts sick-deploy@$name 'touch /etc/nginx/conf.d/x.conf; echo \"touch conf.d: \$?\"'
  ssh $opts sick-deploy@$name 'sudo -n /usr/sbin/nginx -t; echo \"sudo nginx -t: \$?\"'
  ssh $opts sick-deploy@$name 'sudo -n /bin/sh -c id; echo \"sudo sh: \$?\"'
  ssh $opts -tt sick-deploy@$name 'tty; echo \"tty: \$?\"'
  timeout 15 ssh $opts -W 127.0.0.1:22 sick-deploy@$name </dev/null; echo \"forwarding: \$?\"
" 2>&1 | plain)
show <<<"$probe"
expect 'the deploy key logs in as sick-deploy' '^sick-deploy$' "$probe"
expect '... cannot write nginx.conf' '^touch nginx.conf: 1$' "$probe"
expect '... cannot add a file to conf.d' '^touch conf.d: 1$' "$probe"
expect '... cannot sudo nginx -t' '^sudo nginx -t: 1$' "$probe"
expect '... cannot sudo a shell' '^sudo sh: 1$' "$probe"
expect '... gets no terminal (restrict)' 'PTY allocation request failed' "$probe"
expect '... cannot forward (restrict)' 'administratively prohibited' "$probe"

#### 7. (a) host key

for variant in unknown changed; do
  step "(a) the host key is $variant: refused, nothing written"
  write_config www-deploy.key "$variant.known_hosts"
  before=$(www_state)
  sick_cmd run --force --verbose "$device"
  show <<<"$out"
  [ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
  expect 'failed in the deployment, through acme.sh' "^$device +failed +forced +deploy failed: acme.sh failed \(exit 1\)" "$out"
  if [ "$variant" = unknown ]; then
    expect '... ssh: no host key is known, strict checking' 'No ED25519 host key is known for www.example.internal and you have requested strict checking' "$out"
  else
    expect '... ssh: the host identification has changed' 'REMOTE HOST IDENTIFICATION HAS CHANGED' "$out"
  fi
  expect '... Host key verification failed' 'Host key verification failed' "$out"
  [ "$(www_state)" = "$before" ] || { listing "$(www_state)" | show; fail 'something changed on the host'; }
  pass 'nothing changed in the certificate directory of the host (backup included)'
  [ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate'
  pass 'nginx presents the certificate of step 4'
done

#### 8. (c) a key the host does not know

step '(c) the deploy key is not authorized: refused, nothing written'
write_config stranger.key www.known_hosts
before=$(www_state)
sick_cmd run --force --verbose "$device"
show <<<"$out"
[ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
expect 'failed in the deployment, through acme.sh' "^$device +failed +forced +deploy failed: acme.sh failed \(exit 1\)" "$out"
expect '... ssh: Permission denied (publickey)' 'Permission denied \(publickey\)' "$out"
[ "$(www_state)" = "$before" ] || { listing "$(www_state)" | show; fail 'something changed on the host'; }
pass 'nothing changed in the certificate directory of the host'
[ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate'
pass 'nginx presents the certificate of step 4'
write_config

#### 9. (b) the reload fails

step '(b) the reload fails: the device fails, nginx keeps the old certificate'
note 'the administrator broke the nginx configuration: conf.d/broken.conf'
on_www 'echo "this is not nginx" >/etc/nginx/conf.d/broken.conf'
backups_before=$(on_www "ls $tls/backup" | plain)
sick_cmd run --force --verbose "$device"
show <<<"$out"
[ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
expect 'failed in the deployment, through acme.sh' "^$device +failed +forced +deploy failed: acme.sh failed \(exit 1\)" "$out"
expect '... with the words of nginx' 'emerg.*broken.conf' "$out"
[ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate'
pass 'nginx presents the certificate of step 4 (the one before this run)'
read -r new_fp new_serial < <(last_issue)
[ "$new_fp" != "$issued" ] || fail 'no new certificate was issued'
[ "$(on_disk $tls/fullchain.pem)" = "$new_fp" ] || fail "$tls/fullchain.pem is not the certificate of this run"
pass "left on the host: the new key and certificate in $tls (serial $new_serial), not served"
backup=$(on_www "ls $tls/backup" | plain | grep -vxF -f <(printf '%s\n' "$backups_before") | tail -n 1)
[ -n "$backup" ] || fail 'the hook made no backup'
[ "$(on_disk "$tls/backup/$backup/fullchain.pem")" = "$issued" ] || fail 'the backup does not hold the certificate of step 4'
pass "... and the files of step 4 in $tls/backup/$backup"
note 'back: the administrator copies the backup over, removes broken.conf, reloads'
on_www "cp '$tls/backup/$backup/key.pem' '$tls/backup/$backup/fullchain.pem' $tls/ && rm /etc/nginx/conf.d/broken.conf && nginx -s reload" 2>&1 | show
sleep 1
[ "$(presented)" = "$issued" ] && [ "$(on_disk $tls/fullchain.pem)" = "$issued" ] || fail 'not back at the certificate of step 4'
pass 'nginx presents, and the directory holds, the certificate of step 4 again'
sick_cmd run "$device"
show <<<"$out"
expect 'the next sick run finds the device ok' "^$device +unchanged +ok" "$out"

#### 10. (b) the reload is accepted, nginx does not take it

step '(b) the reload is accepted but nginx keeps the old configuration: the look at the port fails the device'
note 'the administrator added a server on port 22, where sshd listens: conf.d/port22.conf'
on_www 'echo "server { listen 22; }" >/etc/nginx/conf.d/port22.conf'
sick_cmd run --force --verbose "$device"
show <<<"$out"
[ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
expect 'the hook reports success' 'acme.sh: Success' "$out"
expect 'failed in the verification' "^$device +failed +forced +verification failed: the device does not present the new certificate" "$out"
errlog=$(on_www 'tail -n 5 /var/log/nginx/error.log' | plain)
show <<<"$errlog"
expect 'nginx could not bind port 22 and stayed with what it had' 'bind\(\) to 0.0.0.0:22 failed' "$errlog"
[ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate'
pass 'nginx presents the certificate of step 4'
read -r new_fp new_serial < <(last_issue)
[ "$(on_disk $tls/fullchain.pem)" = "$new_fp" ] || fail "$tls/fullchain.pem is not the certificate of this run"
note 'back: the administrator removes port22.conf and reloads; the new files on disk are valid'
on_www 'rm /etc/nginx/conf.d/port22.conf && nginx -s reload' 2>&1 | show
sleep 1
[ "$(presented)" = "$new_fp" ] || fail 'nginx does not present the certificate of this run'
pass "nginx presents the certificate of this run (serial $new_serial)"
sick_cmd run "$device"
show <<<"$out"
expect 'the next sick run finds the device ok' "^$device +unchanged +ok" "$out"
issued=$new_fp
serial=$new_serial

#### 11. (d) unreachable

step '(d) the host does not answer: unreachable, nothing issued'
note 'docker compose pause www: the address stays, nothing answers'
compose pause www >/dev/null 2>&1
sick_cmd run --force --verbose "$device"
compose unpause www >/dev/null 2>&1
show <<<"$out"
[ "$code" -eq 1 ] || fail "sick run ended with $code, not 1"
expect 'failed as unreachable' "^$device +failed +unreachable +unreachable: $name:443 did not answer within 10s" "$out"
refuse '... nothing issued, nothing deployed' 'issuing a certificate|deploying|acme.sh' "$out"
[ "$(last_issue)" = "$issued $serial" ] || fail 'the record of the last issue changed'
pass 'the record of the last issue is the one before'
[ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate'
pass 'nginx, answering again, presents the certificate it had'

#### 13. the smaller access

step 'the smaller access: forced command sick-deploy-gate, no shell, no backup'
note "authorized_keys: $gate_options <deploy key>"
printf '%s %s\n' "$gate_options" "$pub" | on_www "cat >/home/sick-deploy/.ssh/authorized_keys"
write_config www-deploy.key www.known_hosts gate
grep -q '^      DEPLOY_SSH_BACKUP: "no"' "$work/sick.yml" || fail 'the device list has the backup on'
backups_before=$(on_www "ls $tls/backup" | plain)
sick_cmd run --force --verbose "$device"
show <<<"$out"
[ "$code" -eq 0 ] || fail "sick run ended with $code"
expect 'renewed: scp went through the SFTP subsystem, the reload as the gate allows it' "^$device +renewed +forced" "$out"
refuse '... without the backup' 'Backup of old certificate files' "$out"
read -r issued serial < <(last_issue)
[ "$(presented)" = "$issued" ] || fail 'nginx presents another certificate than the one SICK issued'
pass 'the fingerprint nginx presents on 443 is the one SICK issued'
[ "$(on_www "ls $tls/backup" | plain)" = "$backups_before" ] || fail 'a backup was made'
pass 'no backup was made'
sftp_opts="-i /etc/sick/secrets/www-deploy.key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/sick/secrets/www.known_hosts -o ConnectTimeout=10"
probe=$(in_sick "
  ssh -T $sftp_opts sick-deploy@$name id; echo \"shell command: \$?\"
  ssh -T $sftp_opts sick-deploy@$name sudo -n /usr/sbin/nginx -s reload; echo \"reload, not as the hook spells it: \$?\"
  echo 'put /etc/hostname /etc/nginx/conf.d/x.conf' | sftp -b - $sftp_opts sick-deploy@$name; echo \"sftp put into conf.d: \$?\"
" 2>&1 | plain)
show <<<"$probe"
expect 'a shell command is refused by the gate' '^shell command: 1$' "$probe"
expect '... so is the reload in any other spelling' '^reload, not as the hook spells it: 1$' "$probe"
expect 'SFTP cannot write outside the certificate directory' '^sftp put into conf.d: 1$' "$probe"

# 14. runs in the EXIT trap
