#!/bin/sh
# Mounted into /docker-entrypoint.d/ of the nginx image, which runs it
# before nginx starts: nginx refuses to start without the files named by
# ssl_certificate and ssl_certificate_key, and acme-sidecar.sh puts a
# placeholder there at its first start. Waits up to two minutes.

i=0
until [ -s /etc/nginx/certs/fullchain.pem ] && [ -s /etc/nginx/certs/key.pem ]; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    echo "wait-for-cert: no /etc/nginx/certs/fullchain.pem and key.pem after 120s" >&2
    exit 1
  fi
  sleep 1
done
echo "wait-for-cert: /etc/nginx/certs has a certificate and a key"
