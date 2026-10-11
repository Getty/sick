#!/bin/bash
#
# Scheduling and alerting, proven in containers: the units of contrib/systemd,
# the cron line of contrib/cron/sick, contrib/notify/sick-notify, the alert
# rules of contrib/prometheus and k8s/cronjob.
#
#   t/e2e/ops.sh                     all parts
#   t/e2e/ops.sh units notify alerts the parts named
#
# Parts, each with PASS/FAIL lines; the first FAIL ends the script with 1:
#
#   units   systemd-analyze verify of contrib/systemd/*, in a temporary root
#           that holds the units, the host's system units and stand-ins for
#           /usr/local/bin/sick and sick-notify (no Docker)
#   notify  a Compose project (default sick-ops): the CA of docker/compose.yml,
#           a TLS "device" (web, as in run-local.sh), a webhook receiver.
#           A device whose reload fails makes sick run exit 1; the cron line
#           of contrib/cron/sick, run verbatim, delivers a message naming the
#           device to the webhook and by mail (a sendmail stand-in); so does
#           sick-notify -u as sick-notify@.service starts it (a journalctl
#           stand-in, since there is no systemd in a container). Exit code 3
#           (lock held) delivers nothing; a wrong webhook URL is exit 1. The
#           secret part of the webhook URL appears in no output.
#   alerts  same project: promtool runs the rule tests of contrib/prometheus
#           and k8s/cronjob; then a real sick.prom from sick check, first of a
#           healthy setup, then with the device serving the certificate it had
#           before the last one and the CA stopped, is evaluated against
#           contrib/prometheus/sick-alerts.yml: SickDeviceStale and
#           SickCAUnreachable fire for the second and not for the first. A
#           sick run against the stopped CA notifies, naming the device.
#   k8s     a k3d cluster sick-p5-ops with its own kubeconfig in a temporary
#           directory: images imported, k8s/daten, k8s/test, k8s/cronjob
#           applied, a Job made from the CronJob completes and fills the
#           metrics and the trust page; a second Job while the lock is held
#           ends with sick's exit code 3 and is no failure; the CronJob holds
#           back a scheduled run while one is active (Forbid). The cluster is
#           deleted by its exact name.
#
# Teardown, also after a failure or Ctrl-C: the Compose project is taken down
# with its volumes and checked to be gone; the k3d cluster is deleted. Every
# container, volume and network this script makes carries the label sick=1;
# nothing is published on a port (the k3d API listens on 127.0.0.1 only).
# The images (sick:local, step-ca, busybox, python, prom/prometheus,
# rancher/k3s) stay as a cache.
#
# It DESTROYS the Compose project and the k3d cluster it works on. It touches
# nothing else: no other project, no other cluster, no prune, never the
# default kubeconfig (KUBECONFIG points into the temporary directory for
# every k3d and kubectl call).
#
# Prerequisites: Docker with Compose 2.24 or newer, openssl; for "units"
# systemd-analyze; for "k8s" k3d and kubectl. The three source trees side by
# side, as for run-local.sh.
#
# Parameters, all from the environment:
#
#   SICK_OPS_DIR           private working directory, mode 0700
#                          ($HOME/.local/share/sick-lab/ops)
#   SICK_OPS_PROJECT       Compose project name                  (sick-ops)
#   SICK_OPS_CLUSTER       k3d cluster name, sick-p5-*         (sick-p5-ops)
#   SICK_OPS_PROMETHEUS    image with promtool       (prom/prometheus:v3.15.0)
#   SICK_OPS_PYTHON_IMAGE  image of the webhook receiver           (python:3)
#   SICK_OPS_KEEP          "yes": keep the working directory            (no)
#
# The webhook's secret is made at run time (openssl rand) and lives in the
# working directory and the containers only; nothing else secret is
# written there or printed.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
context=$(cd "$repo/.." && pwd)

work=${SICK_OPS_DIR:-$HOME/.local/share/sick-lab/ops}
project=${SICK_OPS_PROJECT:-sick-ops}
cluster=${SICK_OPS_CLUSTER:-sick-p5-ops}
prometheus=${SICK_OPS_PROMETHEUS:-prom/prometheus:v3.15.0}
keep=${SICK_OPS_KEEP:-no}

parts=("$@")
[ "${#parts[@]}" -gt 0 ] || parts=(units notify alerts k8s)
want() { local p; for p in "${parts[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

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
# wait_for <seconds> <what> <command ...>
wait_for() {
  local seconds=$1 what=$2 start=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    [ $((SECONDS - start)) -lt "$seconds" ] || fail "waited ${seconds}s for $what"
    sleep 2
  done
}

for p in "${parts[@]}"; do
  case $p in units | notify | alerts | k8s) ;; *) fail "unknown part '$p' (units, notify, alerts, k8s)" ;; esac
done
[[ $project =~ ^sick(-[a-z0-9_-]+)?$ ]] || fail "SICK_OPS_PROJECT '$project' is not sick or sick-*"
[[ $cluster =~ ^sick-p5-[a-z0-9-]+$ ]] || fail "SICK_OPS_CLUSTER '$cluster' is not sick-p5-*"

umask 077
mkdir -p "$work"
chmod 700 "$work"
work=$(cd "$work" && pwd)
case $work/ in "$context"/*) fail "SICK_OPS_DIR $work lies inside the build context $context" ;; esac

#### teardown, armed before anything exists

compose_armed=
kube_dir=
sa_root=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  if [ -n "$compose_armed" ]; then
    note "docker compose -p $project down -v --remove-orphans"
    compose down --volumes --remove-orphans 2>&1 | show
    left=$(
      docker ps -aq --filter "label=com.docker.compose.project=$project" | sed 's/^/container /'
      docker volume ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/volume /'
      docker network ls -q --filter "label=com.docker.compose.project=$project" | sed 's/^/network /'
      docker ps -a --format '{{.Names}}' | grep -E "^${project}[-_]" | sed 's/^/container /'
      docker volume ls --format '{{.Name}}' | grep -E "^${project}[-_]" | sed 's/^/volume /'
    )
    if [ -n "$left" ]; then
      printf '%s\n' "$left" | sed 's/^/      | /' >&2
      printf 'FAIL  left behind by project %s (listed above)\n' "$project" >&2
      rc=1
    else
      pass "no container, volume or network of project $project is left"
    fi
  fi
  if [ -n "$kube_dir" ]; then
    note "k3d cluster delete $cluster"
    KUBECONFIG=$kube_dir/kubeconfig k3d cluster delete "$cluster" 2>&1 | show
    left=$(
      docker ps -a --format '{{.Names}}' | grep -E "^k3d-${cluster}(-|$)" | sed 's/^/container /'
      docker volume ls --format '{{.Name}}' | grep -E "^k3d-${cluster}(-|$)" | sed 's/^/volume /'
      docker network ls --format '{{.Name}}' | grep -E "^k3d-${cluster}$" | sed 's/^/network /'
    )
    if [ -n "$left" ]; then
      printf '%s\n' "$left" | sed 's/^/      | /' >&2
      printf 'FAIL  left behind by cluster %s (listed above)\n' "$cluster" >&2
      rc=1
    else
      pass "no container, volume or network of k3d cluster $cluster is left"
    fi
    rm -rf "$kube_dir"
  fi
  [ -z "$sa_root" ] || rm -rf "$sa_root"
  if [ "$keep" = yes ]; then
    note "working directory $work kept (SICK_OPS_KEEP=yes)"
  else
    rm -rf "${work:?}"/{sick.yml,compose.env,notify.conf,notify,hook,build.log,up.log,healthy.prom,stale.prom,healthy.test.yml,stale.test.yml}
    rmdir "${work:?}/secrets" "${work:?}" 2>/dev/null
  fi
  if [ "$rc" -eq 0 ]; then printf '\nALL PASSED (%s)\n' "${parts[*]}"; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

#### units

if want units; then
  step 'systemd-analyze verify of contrib/systemd'
  command -v systemd-analyze >/dev/null || fail 'systemd-analyze is not installed'
  sa_root=$(mktemp -d "${TMPDIR:-/tmp}/sick-ops-units.XXXXXXXX")
  mkdir -p "$sa_root/etc/systemd/system" "$sa_root/usr/local/bin" "$sa_root/usr/lib/systemd"
  cp "$repo"/contrib/systemd/sick.service "$repo"/contrib/systemd/sick.timer \
    "$repo/contrib/systemd/sick-notify@.service" "$sa_root/etc/systemd/system/"
  # the targets and slices the units refer to
  cp -a /usr/lib/systemd/system "$sa_root/usr/lib/systemd/"
  printf '#!/bin/sh\nexit 0\n' >"$sa_root/usr/local/bin/sick"
  cp "$repo/contrib/notify/sick-notify" "$sa_root/usr/local/bin/"
  chmod 755 "$sa_root/usr/local/bin/"*
  note "systemd $(systemd-analyze --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p'), root $sa_root"
  set +e
  verify=$(cd "$sa_root" && systemd-analyze verify --root="$sa_root" \
    etc/systemd/system/sick.service etc/systemd/system/sick.timer \
    etc/systemd/system/sick-notify@sick.service 2>&1)
  code=$?
  set -e
  show <<<"${verify:-(no output)}"
  [ "$code" -eq 0 ] || fail "systemd-analyze verify ended with $code"
  [ -z "$verify" ] || fail 'systemd-analyze verify complained (above)'
  pass 'sick.service, sick.timer and sick-notify@sick.service verify without a word'
  exposure=$(cd "$sa_root" && systemd-analyze security --offline=true --root="$sa_root" etc/systemd/system/sick.service 2>&1 | tail -n 1)
  show <<<"$exposure"
  # a unit with an error in it is caught: the stand-in for sick removed
  rm "$sa_root/usr/local/bin/sick"
  set +e
  broken=$(cd "$sa_root" && systemd-analyze verify --root="$sa_root" etc/systemd/system/sick.service 2>&1)
  code=$?
  set -e
  show <<<"$broken"
  [ "$code" -ne 0 ] || fail 'systemd-analyze verify passed a unit whose ExecStart does not exist'
  pass '... and refuses sick.service when /usr/local/bin/sick is missing'
  next=$(systemd-analyze calendar --iterations=2 "$(sed -n 's/^OnCalendar=//p' "$repo/contrib/systemd/sick.timer")" 2>&1)
  show <<<"$next"
  expect 'the timer fires daily at 04:17' 'Next elapse: .* 04:17:00' "$next"
  line=$(sed -n 's/^[0-9][0-9]* [0-9][0-9]* \* \* \*  root  //p' "$repo/contrib/cron/sick")
  [ -n "$line" ] || fail 'no command line found in contrib/cron/sick'
  sh -n -c "$line" || fail 'the command of contrib/cron/sick is no valid sh'
  sh -n "$repo/contrib/notify/sick-notify" || fail 'contrib/notify/sick-notify is no valid sh'
  pass 'the cron line and sick-notify parse as POSIX sh'
fi

#### the Compose project for notify and alerts

device_names='web.example.internal web'
compose() {
  docker compose --env-file "$work/compose.env" -p "$project" \
    -f "$repo/docker/compose.yml" -f "$here/compose.ops.yml" "$@"
}
in_sick() { compose run --rm --no-deps -T --entrypoint sh sick -c "$1"; }
fingerprint_of_web() {
  in_sick 'openssl s_client -connect web:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256' 2>/dev/null \
    | plain | sed -n 's/^sha256 Fingerprint=//Ip'
}
hook_log() { compose logs --no-log-prefix hook 2>&1 | plain; }
posts() { hook_log | grep -c '^hook: POST json' || true; }
more_posts() { [ "$(posts)" -gt "$before" ]; }

if want notify || want alerts; then
  step "a Compose project $project: CA, a device, a webhook"
  for program in docker openssl; do command -v "$program" >/dev/null || fail "$program is not installed"; done
  docker compose version >/dev/null 2>&1 || fail 'the Compose plugin of Docker is not installed'
  [ -d "$context/sick-target-ciscosb/lib" ] || fail "no checkout of sick-target-ciscosb next to $repo"
  [ -d "$context/sick-target-proxmox/lib" ] || fail "no checkout of sick-target-proxmox next to $repo"

  # The webhook's secret: the path of its URL. Generated now, never printed.
  token=$(openssl rand -hex 16)
  wrong=$(openssl rand -hex 16)
  mkdir -p "$work/notify/bin" "$work/hook"
  # sick runs as root without CAP_DAC_OVERRIDE (cap_drop: ALL) and the hook as
  # nobody: what they read is readable by all; the working directory stays 0700
  chmod 755 "$work/notify" "$work/notify/bin" "$work/hook"
  printf '/hooks/%s\n' "$token" >"$work/hook/path"
  printf 'http://hook:8080/hooks/%s\n' "$token" >"$work/notify/webhook.url"
  printf 'http://hook:8080/hooks/%s\n' "$wrong" >"$work/notify/wrong.url"
  cat >"$work/notify.conf" <<'EOF'
# Generated by t/e2e/ops.sh: webhook and mail, through a sendmail stand-in.
webhook_url_file = /etc/sick/notify/webhook.url
mail_to = ops@example.internal
mail_from = sick@example.internal
sendmail = /etc/sick/notify/bin/sendmail
timeout = 10
EOF
  cat >"$work/notify/wrong.conf" <<'EOF'
# Generated by t/e2e/ops.sh: a webhook URL the receiver refuses, no mail.
webhook_url_file = /etc/sick/notify/wrong.url
EOF
  # sendmail: keeps what it is given in /tmp of the container
  cat >"$work/notify/bin/sendmail" <<'EOF'
#!/bin/sh
{ printf 'sendmail %s\n' "$*"; cat; } >/tmp/mail.txt
EOF
  # journalctl: what sick-notify asks for, then the log of the last run
  cat >"$work/notify/bin/journalctl" <<'EOF'
#!/bin/sh
printf 'journalctl %s\n' "$*"
cat /var/lib/sick/last-run.log
EOF
  chmod 644 "$work/hook/path" "$work/notify/webhook.url" "$work/notify/wrong.url" "$work/notify.conf" "$work/notify/wrong.conf"
  chmod 755 "$work/notify/bin/sendmail" "$work/notify/bin/journalctl"

  cat >"$work/sick.yml" <<EOF
# Generated by t/e2e/ops.sh. Neutral names only.
ca:
  name: SICK Ops CA
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
  web:
    type: files
    host: web
    port: 443
    names: [${device_names// /, }]
    dir: /srv/device
  # a device whose reload always fails: every attempt ends "failed"
  broken:
    type: files
    names: [broken.example.internal]
    dir: /var/lib/sick/broken
    reload: [/bin/false]
EOF
  mkdir -p "$work/secrets"
  chmod 755 "$work/secrets"
  chmod 644 "$work/sick.yml"
  cat >"$work/compose.env" <<EOF
# Generated by t/e2e/ops.sh: the settings of the stack.
SICK_BUILD_CONTEXT=$context
SICK_CONFIG_FILE=$work/sick.yml
SICK_SECRETS_DIR=$work/secrets
SICK_CA_NAME=SICK Ops CA
SICK_INTERVAL=1d
SICK_OPS_HERE=$here
SICK_OPS_WORK=$work
EOF
  unset SICK_BUILD_CONTEXT SICK_CONFIG_FILE SICK_SECRETS_DIR SICK_CA_NAME SICK_CA_DNS SICK_CA_PORT \
    SICK_CA_MAX_LIFETIME SICK_CA_ALLOW_DNS SICK_CA_ALLOW_IP SICK_CA_ALLOW_EMAIL SICK_CA_ALLOW_URI SICK_TRUST_PORT SICK_INTERVAL \
    SICK_RUN_OPTIONS SICK_IMAGE SICK_FROM STEP_VERSION BUSYBOX_VERSION SICK_OPS_HERE SICK_OPS_WORK

  compose_armed=yes
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  note 'docker compose build'
  compose build sick >"$work/build.log" 2>&1 || { tail -30 "$work/build.log" >&2; fail 'docker compose build'; }
  pass 'the image is built from the three source trees'
  note 'docker compose up -d --wait ca web hook'
  compose up -d --wait ca web hook >"$work/up.log" 2>&1 \
    || { plain <"$work/up.log" | tail -20 >&2; fail 'the stack did not come up healthy'; }
  pass 'ca, web and hook are up and healthy'
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

  note 'sick run web: the device gets its first certificate of this CA'
  set +e
  run=$(compose run --rm -T sick sick run web 2>&1 | plain)
  code=$?
  set -e
  show <<<"$run"
  [ "$code" -eq 0 ] || fail "sick run web ended with $code"
  expect 'web is renewed' '^web +renewed +' "$run"
fi

#### notify

secret_free() { # <what> <text>
  if grep -Fq -e "$token" -e "$wrong" <<<"$2"; then fail "$1: the secret of the webhook URL is in it"; fi
  pass "$1: the secret of the webhook URL is not in it"
}

if want notify; then
  step 'a failing device: the cron line of contrib/cron/sick notifies'
  line=$(sed -n 's/^[0-9][0-9]* [0-9][0-9]* \* \* \*  root  //p' "$repo/contrib/cron/sick")
  path=$(sed -n 's/^PATH=//p' "$repo/contrib/cron/sick")
  [ -n "$line" ] && [ -n "$path" ] || fail 'no command line or PATH in contrib/cron/sick'
  case $line$path in *\'*) fail "the cron line has a single quote, which this test cannot pass on" ;; esac
  note "the command of contrib/cron/sick, as cron runs it (sh -c, PATH=$path):"
  show <<<"$line"
  before=$(posts)
  set +e
  cron=$(in_sick "
    rm -f /tmp/mail.txt
    env -i PATH='$path' SHELL=/bin/sh HOME=/var/lib/sick TMPDIR=/tmp sh -c '$line' 2>/tmp/stderr
    echo \"cron line exit: \$?\"
    echo '--- stderr (cron would mail this)'; cat /tmp/stderr
    echo '--- /var/lib/sick/last-run.log'; cat /var/lib/sick/last-run.log
    echo '--- mail'; cat /tmp/mail.txt 2>/dev/null || echo '(no mail)'
    echo '--- textfile'; grep -E '^sick_device_info' /var/lib/prometheus/node-exporter/sick.prom
    echo '--- trust'; ls /srv/trust | tr '\n' ' '; echo
  " 2>&1 | plain)
  code=$?
  set -e
  show <<<"$cron"
  [ "$code" -eq 0 ] || fail "the container ended with $code"
  expect 'sick run: broken failed, web unchanged' '^broken +failed +' "$cron"
  expect '... web unchanged' '^web +unchanged +ok' "$cron"
  expect 'sick-notify: delivered to the webhook' 'sick-notify: webhook: delivered \(HTTP 204\)' "$cron"
  expect 'sick-notify: handed to sendmail' 'sick-notify: mail: handed to /etc/sick/notify/bin/sendmail' "$cron"
  expect 'the mail names the device and the failure' '^broken +failed +' "$(sed -n '/^--- mail$/,/^--- textfile$/p' <<<"$cron")"
  expect '... with the subject of the cron line' '^Subject: sick run failed on ' "$cron"
  expect 'sick check wrote the textfile despite the failed run' '^sick_device_info\{device="broken"' "$cron"
  expect 'sick trust wrote the trust page' 'root_ca.pem' "$(sed -n '/^--- trust$/,$p' <<<"$cron")"
  secret_free 'the output of the cron line' "$cron"
  wait_for 10 'the webhook to log the POST' more_posts
  posted=$(hook_log | grep '^hook: POST json' | tail -n 1)
  show <<<"$posted"
  expect 'the webhook got JSON' '^hook: POST json application/json ' "$posted"
  expect '... naming the failed device' 'broken +failed' "$posted"
  expect '... with the subject' '"subject":"sick run failed on ' "$posted"
  secret_free 'the log of the webhook' "$(hook_log)"

  step 'sick-notify@sick.service: sick-notify -u, as systemd starts it after a failure'
  note 'MONITOR_* as systemd sets them for an OnFailure= unit; journalctl is a stand-in'
  before=$(posts)
  set +e
  unit=$(in_sick "
    rm -f /tmp/mail.txt
    PATH=/etc/sick/notify/bin:\$PATH MONITOR_UNIT=sick.service MONITOR_INVOCATION_ID=0123456789abcdef0123456789abcdef \
      MONITOR_SERVICE_RESULT=exit-code MONITOR_EXIT_CODE=exited MONITOR_EXIT_STATUS=1 \
      sick-notify -u sick.service 'sick.service failed on ops-host'
    echo \"sick-notify exit: \$?\"
    echo '--- mail'; cat /tmp/mail.txt
  " 2>&1 | plain)
  set -e
  show <<<"$unit"
  expect 'sick-notify exits 0' '^sick-notify exit: 0$' "$unit"
  expect 'it asked the journal for the failed run only' '^journalctl _SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef -n 50 ' "$unit"
  expect 'the message says how the unit ended' '^sick.service: result exit-code, exited 1$' "$unit"
  expect 'the mail names the failed device' '^broken +failed +' "$unit"
  secret_free 'the output of sick-notify -u' "$unit"
  wait_for 10 'the webhook to log the POST' more_posts
  posted=$(hook_log | grep '^hook: POST json' | tail -n 1)
  show <<<"$posted"
  expect 'the webhook got the subject of the unit' '"subject":"sick.service failed on ops-host"' "$posted"
  expect '... how it ended and the failed device' 'result exit-code, exited 1.*broken +failed' "$posted"

  step 'exit code 3 notifies nobody; a webhook that refuses is exit 1'
  before=$(hook_log | grep -c '^hook: POST' || true)
  set +e
  busy=$(in_sick "
    rm -f /tmp/mail.txt
    flock /var/lib/sick/sick.lock sleep 20 &
    holder=\$!
    sleep 1
    env -i PATH='$path' SHELL=/bin/sh HOME=/var/lib/sick TMPDIR=/tmp sh -c '$line' 2>/tmp/stderr
    echo \"cron line exit: \$?\"
    echo '--- stderr'; cat /tmp/stderr
    echo '--- /var/lib/sick/last-run.log'; cat /var/lib/sick/last-run.log
    echo '--- mail'; cat /tmp/mail.txt 2>/dev/null || echo '(no mail)'
    kill \$holder 2>/dev/null
  " 2>&1 | plain)
  set -e
  show <<<"$busy"
  expect 'sick run found the lock held' "another sick run holds the lock '/var/lib/sick/sick.lock'" "$busy"
  expect '... no mail' '^\(no mail\)$' "$busy"
  refuse '... sick-notify was not started' 'sick-notify:' "$busy"
  sleep 2
  [ "$(hook_log | grep -c '^hook: POST' || true)" -eq "$before" ] || fail 'the webhook got a POST for exit code 3'
  pass '... and the webhook got nothing'
  set +e
  refused=$(in_sick "
    printf 'sick run failed\n' | sick-notify -c /etc/sick/notify/wrong.conf 'test of a refusing webhook'
    echo \"sick-notify exit: \$?\"
  " 2>&1 | plain)
  set -e
  show <<<"$refused"
  expect 'a refusing webhook is reported with its HTTP status' 'sick-notify: webhook: the receiver answered HTTP 404' "$refused"
  expect '... and nothing delivered is exit 1' '^sick-notify exit: 1$' "$refused"
  secret_free 'the output of the refused sick-notify' "$refused"
fi

#### alerts

# A test file for promtool from a file of sick check: every sample becomes a
# series that keeps its value for three hours.
prom_to_test() { # <prom file> <expected alerts at 2h: yes|no>
  printf 'rule_files:\n  - /rules/sick-alerts.yml\nevaluation_interval: 1m\ntests:\n  - interval: 1m\n    input_series:\n'
  grep -v '^#' "$1" | grep -v '^$' | while IFS= read -r sample; do
    series=${sample% *}
    value=${sample##* }
    printf "      - series: '%s'\n        values: '%sx180'\n" "${series//\'/\'\'}" "$value"
  done
  printf '    alert_rule_test:\n'
  # before the "for:" of both rules is over: nothing in either case
  printf '      - { eval_time: 20m, alertname: SickDeviceStale, exp_alerts: [] }\n'
  printf '      - { eval_time: 20m, alertname: SickCAUnreachable, exp_alerts: [] }\n'
  if [ "$2" = yes ]; then
    cat <<'EOF'
      - eval_time: 2h
        alertname: SickDeviceStale
        exp_alerts:
          - exp_labels: { severity: warning, device: web }
            exp_annotations:
              summary: "web: does not present the certificate issued for it last"
      - eval_time: 2h
        alertname: SickCAUnreachable
        exp_alerts:
          - exp_labels: { severity: warning }
            exp_annotations:
              summary: "the CA does not answer its health check"
EOF
  else
    printf '      - { eval_time: 2h, alertname: SickDeviceStale, exp_alerts: [] }\n'
    printf '      - { eval_time: 2h, alertname: SickCAUnreachable, exp_alerts: [] }\n'
  fi
}
promtool() { # <args> - in a container, the rules and the working directory read-only
  docker run --rm --label sick=1 --network none --user "$(id -u):$(id -g)" \
    -v "$repo/contrib/prometheus:/rules:ro" -v "$repo/k8s/cronjob:/k8s-rules:ro" -v "$work:/work:ro" \
    --entrypoint promtool "$prometheus" "$@"
}

if want alerts; then
  step "the rule tests of contrib/prometheus and k8s/cronjob ($prometheus)"
  docker image inspect "$prometheus" >/dev/null 2>&1 || docker pull -q "$prometheus" >/dev/null || fail "cannot pull $prometheus"
  note "$(promtool --version 2>&1 | head -n 1)"
  out=$(promtool check rules /rules/sick-alerts.yml /k8s-rules/sick-job-alerts.yml 2>&1) || { show <<<"$out"; fail 'promtool check rules'; }
  show <<<"$out"
  pass 'promtool check rules: both files'
  out=$(promtool test rules /rules/sick-alerts.test.yml 2>&1) || { show <<<"$out"; fail 'promtool test rules contrib/prometheus/sick-alerts.test.yml'; }
  show <<<"$out"
  pass 'promtool test rules contrib/prometheus/sick-alerts.test.yml (k40)'
  out=$(promtool test rules /k8s-rules/sick-job-alerts.test.yml 2>&1) || { show <<<"$out"; fail 'promtool test rules k8s/cronjob/sick-job-alerts.test.yml'; }
  show <<<"$out"
  pass 'promtool test rules k8s/cronjob/sick-job-alerts.test.yml'

  step 'a healthy setup: no SickDeviceStale, no SickCAUnreachable'
  set +e
  in_sick 'sick check --format prometheus web' 2>/dev/null | plain >"$work/healthy.prom"
  code=${PIPESTATUS[0]}
  set -e
  [ "$code" -eq 0 ] || fail "sick check --format prometheus web ended with $code"
  grep -E '^sick_(ca_up|device_info|device_matches_last_issue)' "$work/healthy.prom" | show
  expect 'the CA answers' '^sick_ca_up 1$' "$(cat "$work/healthy.prom")"
  expect 'web presents its last issue' '^sick_device_matches_last_issue\{device="web"\} 1$' "$(cat "$work/healthy.prom")"
  out=$(promtool check metrics <"$work/healthy.prom" 2>&1) || { show <<<"$out"; fail 'promtool check metrics'; }
  pass 'promtool check metrics accepts the file'
  prom_to_test "$work/healthy.prom" no >"$work/healthy.test.yml"
  chmod 644 "$work/healthy.prom" "$work/healthy.test.yml"
  out=$(promtool test rules /work/healthy.test.yml 2>&1) || { show <<<"$out"; fail 'the rules alert on a healthy file'; }
  show <<<"$out"
  pass 'the rules evaluated over the healthy file: neither alert fires'

  step 'web serves the certificate before its last one, and the CA is stopped'
  note 'sick run --force web: a second certificate; the first stays as the previous generation'
  first=$(fingerprint_of_web)
  set +e
  run=$(compose run --rm -T sick sick run --force web 2>&1 | plain)
  code=$?
  set -e
  show <<<"$run"
  [ "$code" -eq 0 ] || fail "sick run --force web ended with $code"
  new_cert() { local f; f=$(fingerprint_of_web); [ -n "$f" ] && [ "$f" != "$first" ]; }
  wait_for 30 'web to present the new certificate' new_cert
  second=$(fingerprint_of_web)
  [ "$second" != "$first" ] || fail 'web presents the same certificate as before'
  note 'the device is set back to the previous generation, as a restored backup would'
  in_sick 'cd /srv/device/.sick && ln -sfn "$(readlink previous)" current.new && mv -T current.new current && readlink current' 2>&1 | show
  back() { [ "$(fingerprint_of_web)" = "$first" ]; }
  wait_for 30 'web to present the first certificate again' back
  pass "web presents its first certificate again (${first:0:23}...), not the last one (${second:0:23}...)"
  check=$(compose run --rm -T sick sick check web 2>&1 | plain)
  show <<<"$check"
  expect 'for sick check it is fine: valid, from the CA, the right names' '^web +ok +no +' "$check"
  note 'docker compose stop ca'
  compose stop ca 2>&1 | show
  set +e
  in_sick 'sick check --format prometheus web' 2>/dev/null | plain >"$work/stale.prom"
  code=${PIPESTATUS[0]}
  set -e
  [ "$code" -eq 0 ] || fail "sick check --format prometheus web ended with $code"
  grep -E '^sick_(ca_up|device_info|device_matches_last_issue)' "$work/stale.prom" | show
  expect 'the CA does not answer' '^sick_ca_up 0$' "$(cat "$work/stale.prom")"
  expect 'web does not present its last issue' '^sick_device_matches_last_issue\{device="web"\} 0$' "$(cat "$work/stale.prom")"
  out=$(promtool check metrics <"$work/stale.prom" 2>&1) || { show <<<"$out"; fail 'promtool check metrics'; }
  pass 'promtool check metrics accepts the file'
  prom_to_test "$work/stale.prom" yes >"$work/stale.test.yml"
  chmod 644 "$work/stale.prom" "$work/stale.test.yml"
  out=$(promtool test rules /work/stale.test.yml 2>&1) || { show <<<"$out"; sed 's/^/      | /' "$work/stale.test.yml" >&2; fail 'SickDeviceStale and SickCAUnreachable over the stale file'; }
  show <<<"$out"
  pass 'the rules evaluated over that file: SickDeviceStale{device="web"} and SickCAUnreachable fire after their "for:", not before'

  step 'a run against the stopped CA notifies, naming the device'
  before=$(posts)
  set +e
  down=$(in_sick "
    rm -f /tmp/mail.txt
    sick run --force web >/tmp/run.log 2>&1 || [ \$? -eq 3 ] || sick-notify 'sick run failed on ops-host' </tmp/run.log
    echo \"exit: \$?\"
    cat /tmp/run.log
  " 2>&1 | plain)
  set -e
  show <<<"$down"
  expect 'web failed: the CA cannot be reached' '^web +failed +' "$down"
  expect 'sick-notify delivered' 'sick-notify: webhook: delivered \(HTTP 204\)' "$down"
  wait_for 10 'the webhook to log the POST' more_posts
  posted=$(hook_log | grep '^hook: POST json' | tail -n 1)
  show <<<"$posted"
  expect 'the webhook got the failed device' 'web +failed' "$posted"
  secret_free 'everything the webhook logged' "$(hook_log)"
fi

#### k8s

if want k8s; then
  step "k3d cluster $cluster with its own kubeconfig"
  for program in k3d kubectl docker; do command -v "$program" >/dev/null || fail "$program is not installed"; done
  default_kubeconfig_mtime=$(stat -c %Y "$HOME/.kube/config" 2>/dev/null || echo none)
  kube_dir=$(mktemp -d "${TMPDIR:-/tmp}/sick-ops-kube.XXXXXXXX")
  export KUBECONFIG=$kube_dir/kubeconfig
  : >"$KUBECONFIG"
  chmod 600 "$KUBECONFIG"
  note "KUBECONFIG=$KUBECONFIG"
  k() { kubectl -n dev-sick "$@"; }
  if k3d cluster list "$cluster" >/dev/null 2>&1; then
    note "a cluster $cluster is left from an earlier run: deleting it by name"
    k3d cluster delete "$cluster" 2>&1 | show
  fi
  api_port=$(
    for p in $(seq 16443 16543); do
      (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || { echo "$p"; break; }
    done
  )
  [ -n "$api_port" ] || fail 'no free port for the API between 16443 and 16543'
  # In an LXC container /dev/kmsg is no device (here a link to /dev/console)
  # and a privileged container does not get it: the kubelet then refuses to
  # start. An empty one is enough for it.
  kmsg=()
  if [ -L /dev/kmsg ] || [ ! -c /dev/kmsg ]; then
    kmsg=(--volume '/dev/null:/dev/kmsg@server:*')
    note '/dev/kmsg is no device on this host: the node gets /dev/null in its place'
  fi
  note "k3d cluster create $cluster --api-port 127.0.0.1:$api_port --no-lb ${kmsg[*]}"
  k3d cluster create "$cluster" --api-port "127.0.0.1:$api_port" --no-lb "${kmsg[@]}" \
    --kubeconfig-update-default=false --kubeconfig-switch-context=false \
    --runtime-label 'sick=1@server:*' \
    --k3s-arg '--disable=traefik@server:*' --k3s-arg '--disable=metrics-server@server:*' \
    --wait --timeout 180s 2>&1 | show
  k3d kubeconfig get "$cluster" >"$KUBECONFIG"
  server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  note "API server $server"
  [[ $server == https://127.0.0.1:* ]] || fail "the API server is $server, not on 127.0.0.1"
  [ "$(docker inspect -f '{{index .Config.Labels "sick"}}' "k3d-$cluster-server-0")" = 1 ] || fail 'the node container has no label sick=1'
  pass 'the cluster is up, its API on 127.0.0.1, its node labelled sick=1'
  wait_for 120 'the node to be Ready' kubectl wait --for=condition=Ready node --all --timeout=5s
  note 'k3d image import sick:local smallstep/step-ca:0.30.2 busybox:1.37'
  k3d image import -c "$cluster" sick:local smallstep/step-ca:0.30.2 busybox:1.37 2>&1 | tail -n 2 | show

  step 'k8s/daten, k8s/test, then k8s/cronjob'
  kubectl create namespace dev-sick 2>&1 | show
  kubectl apply -k "$repo/k8s/daten" 2>&1 | show
  kubectl apply -k "$repo/k8s/test" 2>&1 | show
  k rollout status deploy/sick --timeout=240s 2>&1 | show || fail 'k8s/test did not come up'
  pass 'k8s/test is up'
  kubectl apply -k "$repo/k8s/cronjob" 2>&1 | show
  k rollout status deploy/sick --timeout=240s 2>&1 | show || fail 'k8s/cronjob did not come up'
  containers=$(k get deploy sick -o jsonpath='{.spec.template.spec.containers[*].name}')
  note "containers of the Deployment: $containers"
  [ "$containers" = 'metrics ca trust' ] || [ "$(tr ' ' '\n' <<<"$containers" | sort | tr '\n' ' ')" = 'ca metrics trust ' ] \
    || fail "the Deployment has the containers '$containers', not ca, trust and metrics"
  pass 'the Deployment keeps ca and trust, gains metrics, and has no sick loop any more'
  k get cronjob sick-run -o jsonpath='{.spec.schedule} {.spec.concurrencyPolicy} {.spec.startingDeadlineSeconds} {.spec.jobTemplate.spec.backoffLimit}{"\n"}' | show
  [ "$(k get cronjob sick-run -o jsonpath='{.spec.concurrencyPolicy}')" = Forbid ] || fail 'concurrencyPolicy is not Forbid'
  pass 'CronJob sick-run: concurrencyPolicy Forbid'

  job_done() { # <job>: 0 complete, 1 failed, 2 neither yet
    local s
    s=$(k get job "$1" -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type} {end}' 2>/dev/null)
    case $s in *Complete*) return 0 ;; *Failed*) return 1 ;; *) return 2 ;; esac
  }
  wait_job() { # <job> <seconds>
    local start=$SECONDS rc
    while :; do
      set +e; job_done "$1"; rc=$?; set -e
      [ "$rc" -ne 2 ] && return "$rc"
      [ $((SECONDS - start)) -lt "$2" ] || { k describe job "$1" | tail -20 >&2; fail "job $1 did not finish in $2 s"; }
      sleep 2
    done
  }

  step 'a Job from the CronJob completes'
  k create job --from=cronjob/sick-run sick-run-ops-1 2>&1 | show
  set +e; wait_job sick-run-ops-1 240; rc=$?; set -e
  log=$(k logs job/sick-run-ops-1 2>&1)
  show <<<"$log"
  [ "$rc" -eq 0 ] || fail 'the Job failed'
  pass 'Job sick-run-ops-1 is Complete'
  expect '... sick run ended with 0' '^sick run: exit 0$' "$log"
  expect '... the device probe renewed or unchanged' '^probe +(renewed|unchanged) +' "$log"
  note 'the metrics as Prometheus would scrape them: Service sick-metrics, from inside the Pod'
  metrics=$(k exec deploy/sick -c metrics -- wget -S -q -O - http://sick-metrics:9101/sick.prom 2>&1)
  grep -Ei '^ *(HTTP/|content-type)|^sick_(check_timestamp|ca_up|device_info)' <<<"$metrics" | show
  expect 'sick.prom is served as the text format' '[Cc]ontent-[Tt]ype: text/plain; ?version=0\.0\.4' "$metrics"
  expect '... with the device probe' '^sick_device_info\{device="probe",type="files",status="ok"\} 1$' "$metrics"
  expect '... and the CA answering' '^sick_ca_up 1$' "$metrics"
  trust=$(k exec deploy/sick -c trust -- wget -q -O - http://127.0.0.1:8080/root_ca.pem 2>&1 | head -n 1)
  expect 'the trust page serves what the Job wrote' '^-----BEGIN CERTIFICATE-----$' "$trust"

  step 'a second run while the lock is held: exit code 3, and the Job is no failure'
  k apply -f - 2>&1 <<'EOF' | show
apiVersion: batch/v1
kind: Job
metadata:
  name: sick-ops-lock-holder
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 300
  template:
    metadata:
      labels: { app.kubernetes.io/name: sick-ops-lock-holder }
    spec:
      restartPolicy: Never
      affinity:
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector: { matchLabels: { app: sick } }
              topologyKey: kubernetes.io/hostname
      containers:
        - name: hold
          image: sick:local
          command: [flock, /var/lib/sick/sick.lock, sh, -c, "echo holding the lock; sleep 120"]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ALL] }
          volumeMounts:
            - { name: state, mountPath: /var/lib/sick }
      volumes:
        - name: state
          persistentVolumeClaim: { claimName: sick-state }
EOF
  holding() { k logs job/sick-ops-lock-holder 2>/dev/null | grep -q 'holding the lock'; }
  wait_for 120 'the holder to take the lock' holding
  pass 'a Job holds the lock of sick-state'
  k create job --from=cronjob/sick-run sick-run-ops-2 2>&1 | show
  set +e; wait_job sick-run-ops-2 180; rc=$?; set -e
  log=$(k logs job/sick-run-ops-2 2>&1)
  show <<<"$log"
  expect 'sick run found the lock held' "another sick run holds the lock '/var/lib/sick/sick.lock'" "$log"
  expect '... ended with 3, nothing done' '^sick run: exit 3, another sick run holds the lock' "$log"
  [ "$rc" -eq 0 ] || fail 'the Job counts as failed'
  pass '... and the Job is Complete, not Failed: kube_job_status_failed stays 0'
  k delete job sick-ops-lock-holder --wait=false 2>&1 | show

  step 'Forbid: no scheduled run starts while one is active'
  note 'the CronJob made to start every minute, with a run that takes three minutes'
  k patch cronjob sick-run --type=json -p '[
    {"op":"replace","path":"/spec/schedule","value":"* * * * *"},
    {"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/command","value":["sleep","180"]}
  ]' 2>&1 | show
  forbidden() { k get events --field-selector involvedObject.name=sick-run,reason=JobAlreadyActive -o name | grep -q .; }
  wait_for 200 'the CronJob to hold back a run (event JobAlreadyActive)' forbidden
  k get events --field-selector involvedObject.name=sick-run -o custom-columns=REASON:.reason,MESSAGE:.message --no-headers | sort -u | show
  active=$(k get cronjob sick-run -o jsonpath='{range .status.active[*]}{.name}{"\n"}{end}' | grep -c . || true)
  [ "$active" -eq 1 ] || fail "$active Jobs of the CronJob are active, not 1"
  pass 'one Job active, the next schedule held back: Not starting job because prior execution is running'
  k patch cronjob sick-run -p '{"spec":{"suspend":true}}' 2>&1 | show

  now_mtime=$(stat -c %Y "$HOME/.kube/config" 2>/dev/null || echo none)
  [ "$now_mtime" = "$default_kubeconfig_mtime" ] || fail "$HOME/.kube/config changed"
  pass "$HOME/.kube/config is untouched (mtime $now_mtime)"
fi
