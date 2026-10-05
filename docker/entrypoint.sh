#!/bin/sh
#
# Entrypoint of the sick image.
#
# Without arguments: "sick run" now and then every SICK_INTERVAL, and
# "sick trust" after every run, whatever the run ended with.
# With arguments: runs them instead - "docker compose run --rm sick sick check".
#
#   SICK_INTERVAL     pause between two runs: 1d, 12h, 30m, 90s or plain
#                     seconds (default 1d)
#   SICK_RUN_OPTIONS  options for "sick run" (default --verbose)
#   SICK_TRUST_DIR    where "sick trust" writes (default /srv/trust)
#   SICK_CONFIG       the device list (default /etc/sick/sick.yml)
#   TMPDIR            where keys exist for a moment; keep it on a tmpfs
#
# TERM and INT stop the schedule: whatever is running is sent a TERM. sick
# removes its private temporary directories - a fresh key may be in one -
# before it ends, and this script waits for that.

set -u

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

log() { printf '%s entrypoint: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# "1d", "12h", "30m", "90s", "3600" -> seconds
seconds() {
  number=${1%[smhd]}
  unit=${1#"$number"}
  case $number in '' | *[!0-9]*) return 1 ;; esac
  case $unit in
    '' | s) factor=1 ;;
    m) factor=60 ;;
    h) factor=3600 ;;
    d) factor=86400 ;;
    *) return 1 ;;
  esac
  result=$((number * factor))
  [ "$result" -ge 1 ] || return 1
  printf '%s\n' "$result"
}

interval_text=${SICK_INTERVAL:-1d}
run_options=${SICK_RUN_OPTIONS-'--verbose'}    # unset: --verbose; set and empty: none
trust_dir=${SICK_TRUST_DIR:-/srv/trust}
config=${SICK_CONFIG:-/etc/sick/sick.yml}
tmp=${TMPDIR:-/tmp}

interval=$(seconds "$interval_text") || {
  log "SICK_INTERVAL '$interval_text' is not a time span like 1d, 12h, 30m, 90s or 3600"
  exit 2
}
case $tmp in
  *[[:space:]]*)
    # acme.sh refuses a home with whitespace in its path
    log "TMPDIR '$tmp' contains whitespace"
    exit 2
    ;;
esac

child=
stopping=

# Always a TERM for the child: a background job of a shell ignores INT
# unless it says otherwise, and sick treats the two alike.
pass_on() {
  stopping=$1
  if [ -n "$child" ]; then
    log "received $1, sending TERM to $child_name (pid $child)"
    kill -s TERM "$child" 2>/dev/null
  else
    log "received $1"
  fi
}
trap 'pass_on TERM' TERM
trap 'pass_on INT' INT

# Run a command and wait for it in a way a signal can interrupt, then wait
# until it is really gone. Sets $status.
attend() {
  child_name=$1
  "$@" &
  child=$!
  while :; do
    wait "$child"
    status=$?
    # 128+n also when a trapped signal ended the wait and not the child
    kill -0 "$child" 2>/dev/null || break
  done
  child=
}

log "sick run $run_options every $interval_text (${interval}s), device list $config, trust page in $trust_dir"

while [ -z "$stopping" ]; do
  log "sick run $run_options"
  # shellcheck disable=SC2086  # the options are meant to be split
  attend sick run $run_options
  [ -z "$stopping" ] || { log "sick run ended with exit code $status"; break; }
  case $status in
    0) log 'sick run: exit 0, nothing failed' ;;
    1) log 'sick run: exit 1, at least one device failed - see the table above; the next run tries again' ;;
    2) log "sick run: exit 2, the device list or the command line is wrong - the next run will fail the same way until $config (or SICK_RUN_OPTIONS) is corrected" ;;
    *) log "sick run: exit $status" ;;
  esac

  attend sick trust "$trust_dir"
  [ -z "$stopping" ] || break
  [ "$status" -eq 0 ] || log "sick trust: exit $status, the trust page was not updated"

  log "next run in ${interval}s"
  attend sleep "$interval"
done

left=$(ls -A "$tmp" 2>/dev/null)
if [ -n "$left" ]; then
  log "stopped by $stopping; LEFT BEHIND in $tmp: $(printf '%s' "$left" | tr '\n' ' ')"
else
  log "stopped by $stopping; nothing is left in $tmp"
fi
exit 0
