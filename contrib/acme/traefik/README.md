# Traefik with certificates from step-ca

Traefik (v3.7) gets its certificates itself, over ACME, from the provisioner
`acme` of the CA in `docker/` and renews them. SICK is not involved: this is
for services that speak ACME, not for devices that cannot.

| File | What |
|---|---|
| `traefik.yml` | static configuration: entry points, the resolver `stepca` |
| `dynamic/app.yml` | a router for `traefik.example.internal` with its certificate from `stepca` |
| `compose.yml` | Traefik and a stand-in backend `app` |
| `compose.lab.yml` | for a lab without internal DNS: joins the CA's network, ports on 127.0.0.1 only |

```bash
# the root of your CA from the trust page of docker/, compared with the
# root fingerprint in ceremony.txt (or the one init-ca.sh logged, lab mode)
curl -fsS -o contrib/acme/traefik/root_ca.crt http://127.0.0.1:8080/root_ca.pem
openssl x509 -in contrib/acme/traefik/root_ca.crt -noout -fingerprint -sha256
docker compose -f contrib/acme/traefik/compose.yml up -d
```

The trust page is `http://<host>:${SICK_TRUST_PORT:-8080}/root_ca.pem` on
the host of the CA setup. In a real network internal DNS resolves
`ca.example.internal` for Traefik and `traefik.example.internal` for the CA.

### In a lab

With the CA of `docker/` on the same Docker host and no internal DNS,
neither name resolves: this recipe is a Compose project of its own.
`compose.lab.yml` joins `traefik` to the CA's network
(`SICK_LAB_NETWORK`, default `sick_default`) under the alias
`traefik.example.internal`, and publishes its ports on 127.0.0.1 only
(`SICK_LAB_HTTP_PORT`, `SICK_LAB_HTTPS_PORT`, default 80 and 443; Compose
2.24 or later for `!override`). There the CA has the alias
`ca.example.internal` (`SICK_CA_ALIAS` in `docker/compose.yml`); it has to
be one of the CA's names (`SICK_CA_DNS=ca.example.internal`, in lab mode
as in import mode), and the CA has to allow the service's name
(`SICK_CA_ALLOW_DNS`).

```bash
docker compose -f contrib/acme/traefik/compose.yml -f contrib/acme/traefik/compose.lab.yml up -d
curl --cacert contrib/acme/traefik/root_ca.crt \
  --resolve traefik.example.internal:443:127.0.0.1 https://traefik.example.internal/
```

Replace `example.internal` by your names, `app` by your backend.

## Trusting the CA

`caCertificates` in `traefik.yml` names the root for one connection only:
Traefik to the ACME directory. Traefik's compatibility variable
`LEGO_CA_CERTIFICATES` does the same; the option is the documented way. The
clients of Traefik need the root in their own trust store (handbook, chapter 3).

## Renewal

Traefik does not look at the lifetime of the certificate it got. It renews
by `certificatesDuration`, in hours, "exclusively used to determine renewal
dates", in brackets (Traefik v3.7.14, `getCertificateRenewDurations`):

| certificatesDuration | renews before expiry | checks every |
|---|---|---|
| >= 1 year | 4 months | 1 week |
| >= 90 days (default 2160) | 30 days | 1 day |
| >= 30 days | 10 days | 12 hours |
| >= 6 days | 2 days | 2 hours |
| >= 1 day | 6 hours | 10 minutes |
| less | 20 minutes | 1 minute |

`720` matches the CA's 30 days: renewed with 10 days left, a third of the
lifetime. Left at the default, Traefik would think "renew 30 days before
expiry" and fetch a new 30-day certificate at every daily check. Change it
together with `SICK_CA_ACME_LIFETIME`.

## Enrollment authorization

- **Challenge:** http-01 on port 80 (entry point `web`). `tlsChallenge: {}`
  would use tls-alpn-01 on port 443 instead.
- **Who may ask:** the provisioner `acme` has no external account binding:
  whoever reaches the CA on port 9000 can open an account and order. What
  stops them is the challenge – the CA fetches the token from the name it
  is asked for, so the requester has to answer on port 80 under that name,
  as the CA resolves it – and the names the CA allows.
- **Which names:** the CA's policy (`SICK_CA_ALLOW_DNS`, `SICK_CA_ALLOW_IP`)
  refuses everything else at the order (`rejectedIdentifier`); the name
  constraints of the intermediate (import mode) bound the names even for
  someone who has the CA's keys. A name outside them never reaches a
  challenge.
- **Lab and real network:** in `t/e2e/acme-services.sh` the CA, Traefik and
  the client sit on one Compose network on one host, and Compose's resolver
  is the DNS: the CA finds `traefik.example.internal` because it is a
  network alias. There is no public resolver and no firewall. In a real
  network the internal DNS has to resolve the service's name for the CA, the
  CA has to reach port 80 of Traefik (443 for tls-alpn-01) through every
  firewall between them, and Traefik has to reach the CA on port 9000.
  Whoever controls internal DNS, or the path from the CA to port 80, can
  obtain certificates for those names: keep both as tight as the CA.

## What the test shows

`t/e2e/acme-services.sh traefik`, with `certificatesDuration: 1` and
3-minute certificates: obtained and verified by curl and gnutls-cli with
the root alone, serverAuth only; renewed within about a minute, the
fingerprint on port 443 changes; `outside.example.org` refused by the CA's
policy, Traefik serves its own self-signed `TRAEFIK DEFAULT CERT` for it;
`decoy.example.internal` (an alias of another container) fails its
challenge, no certificate. Not tried: tls-alpn-01, a Traefik behind another
proxy, several Traefik replicas sharing `acme.json`.

Checked against upstream on 2026-10-10: the Traefik v3 reference for ACME
certificate resolvers (doc.traefik.io) and the source of Traefik v3.7.14
(`pkg/provider/acme/provider.go`: renewal brackets, `LEGO_CA_CERTIFICATES`).
