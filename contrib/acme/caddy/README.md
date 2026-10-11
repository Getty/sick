# Caddy with certificates from step-ca

Caddy (2.11) gets its certificates itself, over ACME, from the provisioner
`acme` of the CA in `docker/` and renews them. SICK is not involved: this is
for services that speak ACME, not for devices that cannot.

| File | What |
|---|---|
| `Caddyfile` | global renewal settings, the issuer snippet `stepca`, one site |
| `compose.yml` | Caddy and a stand-in backend `app` |
| `compose.lab.yml` | for a lab without internal DNS: joins the CA's network, ports on 127.0.0.1 only |

```bash
# the root of your CA from the trust page of docker/, compared with the
# root fingerprint in ceremony.txt (or the one init-ca.sh logged, lab mode)
curl -fsS -o contrib/acme/caddy/root_ca.crt http://127.0.0.1:8080/root_ca.pem
openssl x509 -in contrib/acme/caddy/root_ca.crt -noout -fingerprint -sha256
docker compose -f contrib/acme/caddy/compose.yml up -d
```

The trust page is `http://<host>:${SICK_TRUST_PORT:-8080}/root_ca.pem` on
the host of the CA setup. In a real network internal DNS resolves
`ca.example.internal` for Caddy and `caddy.example.internal` for the CA.

### In a lab

With the CA of `docker/` on the same Docker host and no internal DNS,
neither name resolves: this recipe is a Compose project of its own.
`compose.lab.yml` joins `caddy` to the CA's network
(`SICK_LAB_NETWORK`, default `sick_default`) under the alias
`caddy.example.internal`, and publishes its ports on 127.0.0.1 only
(`SICK_LAB_HTTP_PORT`, `SICK_LAB_HTTPS_PORT`, default 80 and 443; Compose
2.24 or later for `!override`). There the CA has the alias
`ca.example.internal` (`SICK_CA_ALIAS` in `docker/compose.yml`); it has to
be one of the CA's names (`SICK_CA_DNS=ca.example.internal`, in lab mode
as in import mode), and the CA has to allow the service's name
(`SICK_CA_ALLOW_DNS`).

```bash
docker compose -f contrib/acme/caddy/compose.yml -f contrib/acme/caddy/compose.lab.yml up -d
curl --cacert contrib/acme/caddy/root_ca.crt \
  --resolve caddy.example.internal:443:127.0.0.1 https://caddy.example.internal/
```

Every site gets `import stepca`. Replace `example.internal` by your names,
`app` by your backend.

## Trusting the CA, and why not `acme_ca`

The snippet names the issuer per site: `issuer acme` with `dir` (the ACME
directory) and `trusted_roots` (the root, for the connection from Caddy to
the CA only; the clients of Caddy need the root in their own trust store).

The global options `acme_ca` and `acme_ca_root` say the same for every site,
but Caddy applies them only to names it considers public. For `localhost`
and names under `.internal`, `.local` and `.home.arpa` it takes its own
internal CA unless the site names an issuer. With both – global options and
the same issuer in the site – Caddy 2.11.7 folds the site's automation policy
into the global one, drops its names, and `.internal` names fall back to the
internal CA: the first run of the test logged `"issuer":"local"` for
`caddy.example.internal`. For names that count as public (`int.example.com`), the two
global options alone are enough.

## Renewal

Caddy renews by a share of the lifetime of the certificate it holds:
`renewal_window_ratio 0.3333` (its default, written down) renews when a
third is left – 10 days of a 30-day certificate, the share the CA's
lifetimes are chosen for. Nothing to change when `SICK_CA_ACME_LIFETIME`
changes. `renew_interval` (default 10 minutes) is how often Caddy looks. A
CA with ACME Renewal Information may move the window; step-ca 0.30.2 has no
`renewalInfo` in its directory.

## Enrollment authorization

- **Challenge:** Caddy offers http-01 (port 80) and tls-alpn-01 (port 443);
  either one that the CA can complete counts.
- **Who may ask:** the provisioner `acme` has no external account binding:
  whoever reaches the CA on port 9000 can open an account and order. What
  stops them is the challenge – the CA connects to the name it is asked for,
  so the requester has to answer there, as the CA resolves it – and the
  names the CA allows.
- **Which names:** the CA's policy (`SICK_CA_ALLOW_DNS`, `SICK_CA_ALLOW_IP`)
  refuses everything else at the order (`rejectedIdentifier`); the name
  constraints of the intermediate (import mode) bound the names even for
  someone who has the CA's keys.
- **Lab and real network:** in `t/e2e/acme-services.sh` the CA, Caddy and the
  client sit on one Compose network on one host, and Compose's resolver is
  the DNS: the CA finds `caddy.example.internal` because it is a network
  alias. There is no public resolver and no firewall. In a real network the
  internal DNS has to resolve the service's name for the CA, the CA has to
  reach port 80 and/or 443 of Caddy through every firewall between them, and
  Caddy has to reach the CA on port 9000. Whoever controls internal DNS, or
  the path from the CA to those ports, can obtain certificates for those
  names: keep both as tight as the CA.

## What the test shows

`t/e2e/acme-services.sh caddy`, with `renew_interval 10s` and 3-minute
certificates: obtained and verified by curl and gnutls-cli with the root
alone, serverAuth only (Caddy's certificates have an empty subject, the name
is in subjectAltName); renewed after about two minutes, the fingerprint on
port 443 changes; `outside.example.org` refused by the CA's policy, Caddy
retries with backoff and completes no handshake for that name (TLS alert
"internal error", no certificate); `decoy.example.internal` (an alias of
another container) fails its challenge, no certificate. Not tried: Caddy
clusters sharing storage, on-demand TLS.

Checked against upstream on 2026-10-10: the Caddyfile global options
(`renewal_window_ratio`, `renew_interval`, `acme_ca`, `acme_ca_root`) and
"Automatic HTTPS" on caddyserver.com; the source of Caddy v2.11.7
(`modules/caddyhttp/autohttps.go`, `caddyconfig/httpcaddyfile/tlsapp.go`)
for the internal issuer and the folding of policies.
