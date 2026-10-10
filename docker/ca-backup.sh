#!/bin/bash
#
# Backup and restore of the CA volume (the volume "ca" of compose.yml).
#
#   ca-backup.sh backup  --volume sick_ca --to /safe/place/ca-2026-10-10.tar
#   ca-backup.sh restore --from /safe/place/ca-2026-10-10.tar --volume NAME
#
# backup   stops the containers that use the volume (step-ca keeps its
#          database, Badger, open while it runs; a copy of open files is not
#          a consistent copy), archives the whole volume - encrypted keys,
#          the passwords in secrets/, ca.json, defaults.json, the database,
#          the certificates - and starts them again. Writes
#            FILE           the archive, mode 0600. It holds the keys AND the
#                           passwords that open them: keep it like the keys.
#            FILE.manifest  what is in it: SHA-256 of the archive and of
#                           every file, root and intermediate fingerprint,
#                           end of the intermediate's validity. No secret.
# restore  checks the archive against its manifest first and refuses on any
#          difference; refuses a volume that holds a CA or anything else, or
#          that a running container uses; unpacks into the volume (created
#          when missing), checks every file and both fingerprints against
#          the manifest, and says how long the intermediate stays valid.
#          A restore that does not match is emptied again. A volume it
#          creates carries the label sick=1, as do its helper containers.
#
# The manifest guards against a damaged or altered archive as long as it is
# kept apart from the archive (or its archive-sha256 line is written down
# elsewhere): whoever can change both can change both.
#
# Restoring does not start a CA. For a drill, start it on a network of its
# own without published ports (t/e2e/ca-recovery.sh shows how), never next
# to the running one: two CAs with the same keys and two databases diverge.
# To replace a lost volume of the Compose project, create the volume
# through Compose first (docker compose create ca), restore into it, then
# docker compose up -d.
#
# Options:
#   --volume NAME     the Docker volume of the CA
#   --to FILE         backup: the archive to write; must not exist
#   --from FILE       restore: the archive
#   --manifest FILE   restore: the manifest (default FILE.manifest)
#   --image IMAGE     helper image with tar, sha256sum, step and jq
#                     (default smallstep/step-ca:${STEP_VERSION:-0.30.2})
#   --stop-timeout N  seconds docker stop waits for step-ca (default 30)

set -euo pipefail
umask 077

log() { printf 'ca-backup: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

command=${1:-}
[ $# -eq 0 ] || shift
volume='' to='' from='' manifest=''
running=()
image=smallstep/step-ca:${STEP_VERSION:-0.30.2}
stop_timeout=30
while [ $# -gt 0 ]; do
  case $1 in
    --volume|--to|--from|--manifest|--image|--stop-timeout) [ $# -ge 2 ] || die "$1 needs a value" ;;
    -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) die "unknown argument '$1' (--help)" ;;
  esac
  case $1 in
    --volume) volume=$2 ;;
    --to) to=$2 ;;
    --from) from=$2 ;;
    --manifest) manifest=$2 ;;
    --image) image=$2 ;;
    --stop-timeout) stop_timeout=$2 ;;
  esac
  shift 2
done

command -v docker >/dev/null || die 'docker is not installed'
[ -n "$volume" ] || die '--volume is required'
[[ $volume =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "--volume '$volume' is not a volume name"
[[ $stop_timeout =~ ^[0-9]+$ ]] || die '--stop-timeout is a number of seconds'

# helper <volume mount options> -- <command ...>: a throwaway container
# without network, as root (the files of the volume belong to "step").
# Labelled sick=1 like everything SICK creates; --rm also removes the
# anonymous volume the step-ca image declares for /home/step.
helper() {
  local -a mounts=()
  while [ "$1" != -- ]; do mounts+=(-v "$1"); shift; done
  shift
  docker run --rm -i --label sick=1 --network none --user 0:0 --entrypoint "$1" "${mounts[@]}" "$image" "${@:2}"
}

# the file list with checksums and the facts of the certificates, read in
# the volume mounted at /ca
describe='
  set -e
  cd /ca
  echo "root-fingerprint: $(step certificate fingerprint certs/root_ca.crt)"
  echo "intermediate-fingerprint: $(step certificate fingerprint certs/intermediate_ca.crt)"
  echo "intermediate-not-after: $(step certificate inspect --format json certs/intermediate_ca.crt | jq -r .validity.end)"
  echo "files: $(find . -type f | wc -l)"
  find . -type f | LC_ALL=C sort | while IFS= read -r f; do printf "file %s\n" "$(sha256sum "$f")"; done
'

sha256_file() { sha256sum "$1" | cut -d' ' -f1; }

backup() {
  [ -n "$to" ] || die '--to is required'
  [ ! -e "$to" ] || die "$to exists: a backup never overwrites"
  [ ! -e "$to.manifest" ] || die "$to.manifest exists: a backup never overwrites"
  local dir
  dir=$(dirname "$to")
  [ -d "$dir" ] || die "$dir does not exist"
  docker volume inspect "$volume" >/dev/null 2>&1 || die "there is no volume $volume"
  helper "$volume:/ca:ro" -- test -f /ca/config/ca.json || die "the volume $volume holds no CA (no config/ca.json)"

  running=()
  mapfile -t running < <(docker ps -q --filter "volume=$volume")
  local stopped_at=$SECONDS
  if [ ${#running[@]} -gt 0 ]; then
    log "stopping ${#running[@]} container(s) that use $volume: $(docker inspect -f '{{.Name}}' "${running[@]}" | tr -d / | tr '\n' ' ')"
    # started again on every way out, also when the backup fails
    trap 'restart_them' EXIT
    docker stop -t "$stop_timeout" "${running[@]}" >/dev/null
  fi

  helper "$volume:/ca:ro" -- tar -C /ca -cf - . >"$to.part" || { rm -f "$to.part"; die 'archiving the volume failed'; }
  local facts
  facts=$(helper "$volume:/ca:ro" -- sh -c "$describe") || { rm -f "$to.part"; die 'reading the volume failed'; }

  if [ ${#running[@]} -gt 0 ]; then
    restart_them
    trap - EXIT
    log "the CA was stopped for $((SECONDS - stopped_at))s"
  fi

  {
    printf '# SICK CA backup manifest. Holds no secret.\n'
    printf 'created: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'volume: %s\n' "$volume"
    printf 'archive: %s\n' "$(basename "$to")"
    printf 'archive-sha256: %s\n' "$(sha256_file "$to.part")"
    printf '%s\n' "$facts"
  } >"$to.manifest"
  mv "$to.part" "$to"
  chmod 600 "$to" "$to.manifest"
  log "wrote $to ($(stat -c %s "$to") bytes, mode 0600) and $to.manifest"
  log "$(grep '^root-fingerprint' "$to.manifest")"
  log "keep the archive like the CA keys: it holds them and their passwords"
}

restart_them() {
  [ ${#running[@]} -gt 0 ] || return 0
  docker start "${running[@]}" >/dev/null && log "started again: $(docker inspect -f '{{.Name}}' "${running[@]}" | tr -d / | tr '\n' ' ')"
  running=()
}

restore() {
  [ -n "$from" ] || die '--from is required'
  [ -f "$from" ] || die "$from does not exist"
  manifest=${manifest:-$from.manifest}
  [ -f "$manifest" ] || die "$manifest does not exist: without the manifest nothing is restored"

  # 1. the archive against the manifest, before anything else happens
  local want got
  want=$(sed -n 's/^archive-sha256: //p' "$manifest")
  [[ $want =~ ^[0-9a-f]{64}$ ]] || die "$manifest has no archive-sha256 line"
  got=$(sha256_file "$from")
  [ "$got" = "$want" ] || die "$from does not match its manifest (SHA-256 $got, the manifest says $want): refused, nothing restored"
  log "the archive matches its manifest (SHA-256 $got)"

  # 2. the volume: empty and unused
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    [ -z "$(docker ps -q --filter "volume=$volume")" ] || die "a running container uses $volume: refused"
    if helper "$volume:/ca:ro" -- test -e /ca/config/ca.json; then
      die "the volume $volume already holds a CA: refused. Restore into a new, empty volume"
    fi
    [ -z "$(helper "$volume:/ca:ro" -- ls -A /ca)" ] || die "the volume $volume is not empty: refused"
  else
    docker volume create --label sick=1 "$volume" >/dev/null
    log "created the volume $volume (label sick=1)"
  fi

  # 3. unpack, then check what is in the volume against the manifest
  helper "$volume:/ca" -- tar -C /ca -xf - <"$from" || { wipe; die 'unpacking failed; the volume is empty again'; }
  local facts expected
  facts=$(helper "$volume:/ca:ro" -- sh -c "$describe") || { wipe; die 'reading the restored volume failed; the volume is empty again'; }
  expected=$(grep -E '^(root-fingerprint|intermediate-fingerprint|intermediate-not-after|files): |^file ' "$manifest")
  if [ "$facts" != "$expected" ]; then
    diff <(printf '%s\n' "$expected") <(printf '%s\n' "$facts") | sed 's/^/    /' >&2 || true
    wipe
    die 'the restored files differ from the manifest (above): the volume is empty again'
  fi
  log "restored into $volume: $(sed -n 's/^files: //p' <<<"$facts") files, each as in the manifest"
  log "$(grep '^root-fingerprint' <<<"$facts")"
  log "$(grep '^intermediate-fingerprint' <<<"$facts")"

  # 4. can it still issue?
  local end end_s now_s
  end=$(sed -n 's/^intermediate-not-after: //p' <<<"$facts")
  end_s=$(date -u -d "$end" +%s 2>/dev/null) || die "cannot read the end of validity '$end'"
  now_s=$(date -u +%s)
  if [ "$end_s" -le "$now_s" ]; then
    die "the restored intermediate expired at $end: this CA cannot issue. Renew the intermediate with the root key (see README.md)"
  fi
  log "the intermediate is valid until $end ($(( (end_s - now_s) / 86400 )) days)"
}

wipe() { helper "$volume:/ca" -- sh -c 'rm -rf /ca/* /ca/.[!.]* 2>/dev/null; true' || true; }

case $command in
  backup) backup ;;
  restore) restore ;;
  -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0" ;;
  *) die "backup or restore (--help)" ;;
esac
