#!/bin/sh
#
# acme.sh beside nginx: fetches the certificate of nginx from the ACME
# endpoint of step-ca, installs it where nginx reads it, reloads nginx, and
# renews it. The entry point of the "acme" service in compose.yml (image
# neilpang/acme.sh), which shares the network and the process namespace of
# the nginx container: the CA's http-01 request reaches nginx, which serves
# the token from the shared webroot, and the reload is a SIGHUP to PID 1 of
# that namespace - the nginx master, what "nginx -s reload" sends as well.
#
# On a host with nginx and acme.sh installed side by side, the same is:
#
#   acme.sh --issue --server "$ACME_SERVER" --ca-bundle /path/root_ca.crt \
#     -d nginx.example.internal --webroot /var/www/acme --days -10 --keylength ec-256
#   acme.sh --install-cert -d nginx.example.internal --ecc \
#     --key-file /etc/nginx/certs/key.pem --fullchain-file /etc/nginx/certs/fullchain.pem \
#     --reloadcmd "nginx -s reload"
#
# and the cron job acme.sh installs for itself does the renewing.
#
# Settings, from the environment:
#
#   ACME_DOMAIN          the name of the certificate      (required)
#   ACME_SERVER          the ACME directory of the CA     (required)
#   ACME_CA_BUNDLE       the root of the CA, to verify the CA's TLS
#                        certificate                      (/etc/acme/root_ca.crt)
#   ACME_DAYS            acme.sh --days                   (-10)
#   ACME_CHECK_INTERVAL  time between two "acme.sh --cron" (12h)
#   ACME_RETRY_INTERVAL  time between two attempts while there is no
#                        certificate yet                  (5m)
#
# Why --days -10: acme.sh counts fixed days. A positive --days N renews N-1
# days after issuing (capped at one day before expiry); its default of 30
# would renew a 30-day certificate one day before it expires. A negative
# value counts from the expiry instead: -10 renews 10 days before the end,
# whatever the lifetime - with a third of the lifetime of a 30-day
# certificate left, the share the CA's lifetimes are chosen for. Keep it
# below the lifetime of the CA (SICK_CA_ACME_LIFETIME); a lifetime of 10
# days or less would mean a renewal at every check.

set -eu
umask 077

: "${ACME_DOMAIN:?set ACME_DOMAIN}"
: "${ACME_SERVER:?set ACME_SERVER}"
bundle=${ACME_CA_BUNDLE:-/etc/acme/root_ca.crt}
days=${ACME_DAYS:--10}
interval=${ACME_CHECK_INTERVAL:-12h}
retry=${ACME_RETRY_INTERVAL:-5m}

certs=/etc/nginx/certs
webroot=/var/www/acme

log() { printf 'acme-sidecar: %s\n' "$*" >&2; }

# nginx cannot start without the files of ssl_certificate: a self-signed
# placeholder for the time until the first real certificate (one day)
if [ ! -s "$certs/fullchain.pem" ] || [ ! -s "$certs/key.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=placeholder, no certificate from the CA yet' \
    -keyout "$certs/key.pem.new" -out "$certs/fullchain.pem.new" 2>/dev/null
  mv "$certs/key.pem.new" "$certs/key.pem"
  mv "$certs/fullchain.pem.new" "$certs/fullchain.pem"
  log "wrote a self-signed placeholder to $certs"
fi

# nginx serves the webroot on port 80 before the CA is asked to look
mkdir -p "$webroot/.well-known/acme-challenge"
chmod 755 "$webroot" "$webroot/.well-known" "$webroot/.well-known/acme-challenge"
probe=$webroot/.well-known/acme-challenge/sidecar-probe
( umask 022; echo ok >"$probe" )
i=0
until curl -fsS -o /dev/null "http://127.0.0.1/.well-known/acme-challenge/sidecar-probe" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -le 120 ] || { log 'nginx does not serve the webroot on port 80 after 120s'; exit 1; }
  sleep 1
done
rm -f "$probe"

installed=
while :; do
  if [ -z "$installed" ]; then
    rc=0
    acme.sh --issue --server "$ACME_SERVER" --ca-bundle "$bundle" \
      -d "$ACME_DOMAIN" --webroot "$webroot" --days "$days" --keylength ec-256 || rc=$?
    # 0: issued, 2: there is a certificate that is not due yet
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
      acme.sh --install-cert -d "$ACME_DOMAIN" --ecc \
        --key-file "$certs/key.pem" --fullchain-file "$certs/fullchain.pem" \
        --reloadcmd 'kill -HUP 1' && installed=yes
    else
      log "no certificate for $ACME_DOMAIN (acme.sh exit $rc), next attempt in $retry"
    fi
  else
    # renews what is due, installs it and runs the reload command saved
    # by --install-cert
    acme.sh --cron || log "acme.sh --cron ended with $?"
  fi
  if [ -n "$installed" ]; then sleep "$interval"; else sleep "$retry"; fi
done
