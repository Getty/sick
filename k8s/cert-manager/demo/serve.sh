#!/bin/sh
#
# nginx with the certificate of the Secret mounted at /tls, reloaded when it
# changes. cert-manager writes a renewed certificate into the Secret, the
# kubelet replaces the files of the mounted directory (not of a subPath
# mount: those never change), and nginx reads certificate files at start
# and reload only - so this loop looks every 5 seconds and has nginx reload
# when tls.crt is another one.

set -u

nginx -g 'daemon off;' &
pid=$!
trap 'nginx -s quit; wait "$pid"; exit 0' TERM INT

seen=$(sha256sum /tls/tls.crt)
while kill -0 "$pid" 2>/dev/null; do
  sleep 5 &
  wait $!
  now=$(sha256sum /tls/tls.crt)
  if [ "$now" != "$seen" ] && nginx -t -q; then
    nginx -s reload && seen=$now && echo "serve: certificate changed, nginx reloaded"
  fi
done
wait "$pid"
