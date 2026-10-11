# A first device: nginx beside the Docker setup

A device you can run on the same host as the Compose setup of `docker/`,
to see SICK work before a switch or a hypervisor is involved: nginx, which
serves the certificate SICK writes for it (device type `files`).

| File | What |
|---|---|
| `compose.yml` | the service `web` (nginx), added on top of `docker/compose.yml` |
| `nginx.conf` | its configuration: TLS on 443, the files read at every handshake |
| `sick.yml` | the device entry for the device list |

## Running it

From the checkout, with the setup of `docker/` (lab mode is enough):

```bash
# the entry of sick.yml into the devices: section of docker/sick.yml, then
docker compose -f docker/compose.yml -f contrib/devices/files-nginx/compose.yml up -d
docker compose -f docker/compose.yml -f contrib/devices/files-nginx/compose.yml \
  run --rm sick sick check            # web  missing  yes
docker compose -f docker/compose.yml -f contrib/devices/files-nginx/compose.yml \
  run --rm sick sick run --verbose    # web  renewed  missing
curl --cacert root_ca.pem --resolve web.example.internal:8443:127.0.0.1 \
  https://web.example.internal:8443/
```

`root_ca.pem` comes from the trust page (`http://<host>:8080/root_ca.pem`),
compared with the root fingerprint the CA logged at its first start. If
the `sick` service was (re)started after `web`, its run at start may have
renewed it already: then the two commands show `ok` and `unchanged`. Give
every `docker compose` command both files, or Compose does not know `web`.
The scheduled run of the `sick` service renews it from then on.

## How it fits together

- **Where the files are:** `dir` is `/var/lib/sick/certs/web`, in the
  `state` volume of the `sick` service. `web` mounts that volume read-only.
- **Starting without a certificate:** `ssl_certificate` names a variable
  (nginx 1.15.9 or later), so nginx reads `fullchain.pem` and `key.pem` at
  every handshake instead of at its start. It starts before the first
  certificate exists; until then it completes no handshake and SICK sees the
  device as `missing` – it answers, so it is renewed. A device SICK cannot
  reach at all is `unreachable` and never renewed.
- **No reload:** the next handshake has the new certificate.
- **The chain:** nginx sends `fullchain.pem`, certificate and intermediate.
  With `cert.pem` alone a client that has only the root cannot verify it.
- **Key mode:** the handshake runs in the nginx worker, so the whole
  container runs as uid 101 with group 0 (`user: "101:0"`, no capability, a
  read-only file system), and `mode_key: 0640` lets group 0 read `key.pem`,
  which belongs to root like everything SICK writes. Nothing in `web` runs as
  root.
- **Names:** on the project's network the service is
  `web.example.internal`, a network alias; in a real network it is a DNS
  name. With `SICK_CA_ALLOW_DNS` set, the CA has to allow it. Port 443 is
  published on 127.0.0.1 only (`SICK_WEB_PORT`, default 8443).
- **Relative path:** `compose.yml` mounts
  `../contrib/devices/files-nginx/nginx.conf` – relative to `docker/`, the
  directory of the first file of the command, where Compose resolves every
  relative path.

Tried with nginx 1.30.5 and the sick image in a Compose project of its own:
`sick check` said `missing`, `sick run` renewed, a second run was
`unchanged`, and curl with the root alone verified the service.
