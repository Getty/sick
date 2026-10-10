#!/bin/sh
#
# The "device" of t/e2e/run-local.sh: a TLS service that cannot be signalled.
#
# It starts with a certificate of its own making (the factory default of a
# real device: not from the CA), serves it on port 443 with openssl
# s_server, and once a second looks at /srv/device/cert.pem. When that file
# is there and has changed, the service is restarted with the new
# certificate - which is what the reload command of a real device does.
# SICK's files target renames cert.pem last, after key.pem, chain.pem and
# fullchain.pem, so cert.pem changing means the set is complete.
#
# s_server sends the first certificate of its -cert file and nothing else,
# like a switch that presents its certificate alone. With
# SICK_E2E_WEB_CHAIN=yes (t/e2e/ca-ceremony.sh) it sends chain.pem as well.

set -u

dir=/srv/device
run=/tmp/web
mkdir -p "$run"

log() { printf 'web: %s\n' "$*"; }

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=factory-default' \
  -keyout "$run/key.pem" -out "$run/cert.pem" 2>/dev/null || { log 'cannot make the default certificate'; exit 1; }

pid=
start() {
  if [ -n "${3:-}" ]; then
    openssl s_server -accept 443 -cert "$1" -key "$2" -cert_chain "$3" -www -quiet >/dev/null 2>&1 &
  else
    openssl s_server -accept 443 -cert "$1" -key "$2" -www -quiet >/dev/null 2>&1 &
  fi
  pid=$!
}
stop() {
  [ -z "$pid" ] || { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; pid=; }
}
trap 'stop; exit 0' TERM INT

start "$run/cert.pem" "$run/key.pem"
log 'serving the factory-default certificate'
serving=default

while :; do
  if [ -s "$dir/cert.pem" ] && [ -s "$dir/fullchain.pem" ] && [ -s "$dir/key.pem" ]; then
    now=$(sha256sum <"$dir/cert.pem")
    if [ "$now" != "$serving" ]; then
      stop
      if [ "${SICK_E2E_WEB_CHAIN:-no}" = yes ]; then
        start "$dir/fullchain.pem" "$dir/key.pem" "$dir/chain.pem"
      else
        start "$dir/fullchain.pem" "$dir/key.pem"
      fi
      serving=$now
      log "restarted with the certificate in $dir"
    fi
  fi
  sleep 1 &
  wait $!
done
