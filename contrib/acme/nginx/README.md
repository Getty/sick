# nginx with acme.sh and step-ca

nginx does not speak ACME itself; acme.sh (3.1.6) fetches its certificate
from the provisioner `acme` of the CA in `docker/`, installs it where nginx
reads it, reloads nginx, and renews it. SICK is not involved: this is for
services whose host can run an ACME client, not for devices that cannot.

| File | What |
|---|---|
| `default.conf` | nginx: port 80 for the challenge, port 443 with the certificate |
| `acme-sidecar.sh` | acme.sh: placeholder, issue, install with reload, renew |
| `wait-for-cert.sh` | holds nginx back until there is a certificate file |
| `compose.yml` | nginx, acme.sh beside it, a stand-in backend `app` |
| `compose.lab.yml` | for a lab without internal DNS: joins the CA's network, ports on 127.0.0.1 only |

```bash
# the root of your CA from the trust page of docker/, compared with the
# root fingerprint in ceremony.txt (or the one init-ca.sh logged, lab mode)
curl -fsS -o contrib/acme/nginx/root_ca.crt http://trust.example.internal:8080/root_ca.pem
openssl x509 -in contrib/acme/nginx/root_ca.crt -noout -fingerprint -sha256
docker compose -f contrib/acme/nginx/compose.yml up -d
```

The trust page is `http://<host>:${SICK_TRUST_PORT:-8080}/root_ca.pem` on
the host of the CA setup. In a real network internal DNS resolves
`ca.example.internal` for acme.sh and `nginx.example.internal` for the CA.

### In a lab

With the CA of `docker/` on the same Docker host and no internal DNS,
neither name resolves: this recipe is a Compose project of its own.
`compose.lab.yml` joins `nginx` to the CA's network
(`SICK_LAB_NETWORK`, default `sick_default`) under the alias
`nginx.example.internal`, and publishes its ports on 127.0.0.1 only
(`SICK_LAB_HTTP_PORT`, `SICK_LAB_HTTPS_PORT`, default 80 and 443; Compose
2.24 or later for `!override`). There the CA has the alias
`ca.example.internal` (`SICK_CA_ALIAS` in `docker/compose.yml`); it has to
be one of the CA's names (`SICK_CA_DNS=ca.example.internal`, in lab mode
as in import mode), and the CA has to allow the service's name
(`SICK_CA_ALLOW_DNS`).

```bash
docker compose -f contrib/acme/nginx/compose.yml -f contrib/acme/nginx/compose.lab.yml up -d
curl --cacert contrib/acme/nginx/root_ca.crt \
  --resolve nginx.example.internal:443:127.0.0.1 https://nginx.example.internal/
```

In Compose, `acme` shares the network and the process namespace of `nginx`,
as a sidecar in a pod: the CA's http-01 request reaches nginx, which serves
the token from the shared webroot, and the reload is `kill -HUP 1` – a
SIGHUP to the nginx master, which is what `nginx -s reload` sends. On a host
with both installed, `acme-sidecar.sh` names the two acme.sh commands to
use instead, with `--reloadcmd "nginx -s reload"`.

## Trusting the CA

`--ca-bundle` names the root for one connection only: acme.sh to the ACME
directory (`--server`). acme.sh saves it in its account configuration for
the renewals. The clients of nginx need the root in their own trust store.

## Renewal

acme.sh counts fixed days. `--days N` (positive) renews N-1 days after
issuing, capped at one day before expiry; its default of 30 would renew a
30-day certificate one day before it expires. A negative value counts from
the expiry: `--days -10` renews 10 days before the end, a third of a 30-day
certificate, the share the CA's lifetimes are chosen for (acme.sh 3.1.6,
`_calc_next_renew_time`, `_calc_validto_renew_time`). Keep it below the
CA's lifetime; with `SICK_CA_ACME_LIFETIME` of 10 days or less every check
renews. acme.sh would take an ARI window from the CA if offered; step-ca
0.30.2 offers none. `ACME_CHECK_INTERVAL` (12h) is how often
`acme.sh --cron` runs.

## Enrollment authorization

- **Challenge:** http-01 through nginx: acme.sh writes the token into
  `/var/www/acme` (`--webroot`), nginx serves it on port 80.
- **Who may ask:** the provisioner `acme` has no external account binding:
  whoever reaches the CA on port 9000 can open an account and order. What
  stops them is the challenge – the CA fetches the token from the name it is
  asked for, so the requester has to answer on port 80 under that name, as
  the CA resolves it – and the names the CA allows.
- **Which names:** the CA's policy (`SICK_CA_ALLOW_DNS`, `SICK_CA_ALLOW_IP`)
  refuses everything else at the order (`rejectedIdentifier`); the name
  constraints of the intermediate (import mode) bound the names even for
  someone who has the CA's keys.
- **Lab and real network:** in `t/e2e/acme-services.sh` the CA, nginx and the
  client sit on one Compose network on one host, and Compose's resolver is
  the DNS: the CA finds `nginx.example.internal` because it is a network
  alias. There is no public resolver and no firewall. In a real network the
  internal DNS has to resolve the service's name for the CA, the CA has to
  reach port 80 of nginx through every firewall between them, and acme.sh
  has to reach the CA on port 9000. Whoever controls internal DNS, or the
  path from the CA to port 80, can obtain certificates for those names: keep
  both as tight as the CA.

## What the test shows

`t/e2e/acme-services.sh nginx`, with `ACME_CHECK_INTERVAL=20s` and 3-minute
certificates (`--days -10` as shipped, so every check renews): obtained and
verified by curl and gnutls-cli with the root alone, serverAuth only;
renewed and reloaded within about 20 seconds, the fingerprint on port 443
changes; `acme.sh --issue -d outside.example.org` refused by the CA's policy
(exit 1); `decoy.example.internal` (an alias of another container) fails
its challenge. For a name it has no server block for, nginx presents the
certificate of its first server on port 443, which no client accepts for
that name. Not tried: lego instead of acme.sh, tls-alpn-01, several nginx
instances behind one name.

Checked against upstream on 2026-10-10: the source of acme.sh 3.1.6
(`--days`, `--ca-bundle`, `--reloadcmd`, ARI, the renewal calculation) and
the image `neilpang/acme.sh:3.1.6` (`/entry.sh`, `LE_CONFIG_HOME`); the
nginx image's `/docker-entrypoint.sh` (scripts in `/docker-entrypoint.d/`);
step-ca v0.30.2 `acme/challenge.go` (an HTTP status of 400 or more from the
target is reported as `connection` error).
