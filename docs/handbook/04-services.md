# 4. Services that speak ACME

You end this chapter with your web services and Kubernetes workloads
getting their certificates from your CA by themselves, over ACME, and
renewing them – without SICK. SICK is for the devices that cannot do this
(chapter 5); a service that speaks ACME needs only the CA, a name the CA
can reach, and trust in the root for its connection to the CA.

## What the CA offers

The ACME directory of the Docker setup is

```text
https://ca.example.internal:9000/acme/acme/directory
```

and the provisioner `acme` behind it issues **server certificates only**
(`serverAuth`) for **30 days by default, at most 90** (chapter 2,
`SICK_CA_ACME_LIFETIME`, `SICK_CA_ACME_MAX_LIFETIME`). Why 30 days: an
ACME client renews when about a third of the lifetime is left, so a
30-day certificate gives you about **ten days** in which the CA may be
down before services start to expire (chapter 7, "The CA is down"). Make
it longer if you cannot promise to bring the CA back within ten days;
shorter only together with monitoring that tells you within hours.

step-ca 0.30.2 does not offer ACME Renewal Information (ARI), so every
client schedules renewal by itself – and some count fixed days instead of
a share of the lifetime. Each recipe below sets that explicitly.

## Who may get a certificate (enrollment authorization)

The provisioner `acme` has no external account binding: **anyone who
reaches the CA on port 9000 can open an account and place an order.** What
stops them from getting a certificate for your names:

1. **The names the CA allows.** The CA policy (`SICK_CA_ALLOW_DNS`,
   `SICK_CA_ALLOW_IP`) refuses everything else at the order
   (`rejectedIdentifier`), and the name constraints of the intermediate
   (import mode, chapter 2) bound the names even for someone who has the
   CA's keys.
2. **The challenge.** For http-01 the CA fetches a token from
   `http://<name>/.well-known/acme-challenge/…` as *the CA* resolves
   `<name>`; for tls-alpn-01 it connects to port 443 of that name. Whoever
   answers there gets the certificate. So whoever controls your internal
   DNS, or can answer on port 80/443 under a name, can obtain a
   certificate for it.

**Recommendation:** reach the ACME endpoint only from the networks where
your services run (a firewall in front of port 9000), keep internal DNS in
the hands of your admins, and give the CA a policy no wider than your
domain. If the endpoint has to be reachable more widely, require external
account binding (`requireEAB` in step-ca; card k51, *not tried*), so that
only clients you gave a key can open accounts.

**Trying a recipe beside the Docker setup of chapter 2:** each recipe is a
Compose project of its own. Start it with its lab override, which joins the
CA's network under the service's name and publishes its ports on 127.0.0.1
only, and fetch the root from the trust page, compared with the ceremony's
fingerprint:

```bash
cd sick/contrib/acme/caddy
curl -fsS -o root_ca.crt http://127.0.0.1:8080/root_ca.pem
openssl x509 -in root_ca.crt -noout -fingerprint -sha256     # = the ceremony's
docker compose -f compose.yml -f compose.lab.yml up -d
```

(the recipe READMEs say the same for each service). **In the lab it is
different**, and the recipes' tests say so: the CA and
the services share one Docker network on one host; Compose's built-in
resolver (or a `coredns-custom` entry in k3d) is the "DNS", there is no
public resolver and no firewall between CA and service. In a real network
the CA has to resolve each service's name in your internal DNS and reach
it on port 80 (http-01) or 443 (tls-alpn-01).

## The services at a glance

| Service | Challenge | The root goes | Renews | CA down: lasts | Recipe |
|---|---|---|---|---|---|
| Traefik v3.7 | http-01 (port 80), or tls-alpn-01 | `caCertificates` in `traefik.yml`, for the CA connection only | by `certificatesDuration: 720` – 10 days before the end, checked every 12 h (Traefik ignores the real lifetime) | about 10 days | [contrib/acme/traefik](../../contrib/acme/traefik/) |
| Caddy 2.11 | http-01 / tls-alpn-01 (Caddy picks) | `acme_ca_root` in the site's issuer | when a third is left (`renewal_window_ratio`, default 1/3) | about 10 days | [contrib/acme/caddy](../../contrib/acme/caddy/) |
| nginx + acme.sh 3.1.6 | http-01 (webroot) | `--ca-bundle` of acme.sh | `--days -10` – 10 days before the end (the default 30 would renew a 30-day certificate one day before it expires) | about 10 days | [contrib/acme/nginx](../../contrib/acme/nginx/) |
| cert-manager v1.21 (ACME `ClusterIssuer`) | http-01 through an Ingress | `caBundle` of the issuer | `renewBefore: 240h` | about 10 days | [k8s/cert-manager](../../k8s/cert-manager/) |
| cert-manager + step-issuer 0.11 | none: a JWK provisioner of its own | `caBundle` of the `StepClusterIssuer` | `renewBefore: 240h` | about 10 days | [k8s/cert-manager](../../k8s/cert-manager/) |
| Proxmox VE | http-01 (standalone, port 80) | the node's system store | once less than 30 days are left, checked daily by `pveupdate` – so PVE uses the provisioner `acme-long` (60 days): a renewal about every 30 days | *not tried* | below |

"The root goes" is the trust the *service* needs to talk to the CA. The
clients of the service need the root as in chapter 3.

### Traefik

Traefik gets its certificates through a certificate resolver pointing at
the CA (`caServer`) and trusts the CA through `caCertificates`. The one
setting that matters beyond the obvious is **`certificatesDuration: 720`**:
Traefik does not look at the lifetime of the certificate it gets but
renews by this number in fixed brackets; left at the default (2160 hours),
it would think "renew 30 days before expiry" and fetch a new 30-day
certificate at every daily check. Change it together with the CA's
lifetime.

### Caddy

**Name the issuer per site.** Caddy 2.11 issues names under `.internal`,
`.local`, `.home.arpa` and `localhost` from its *own* internal CA unless the
site names an issuer – and if the global `acme_ca` matches the site's
issuer, it folds the site's policy into the global one and drops the
names. The recipe therefore uses a snippet (`import stepca`) per site with
`acme_ca` and `acme_ca_root` inside, and no global `acme_ca`. Caddy renews
at a third of the remaining lifetime by default, which fits any lifetime.

### nginx with acme.sh

nginx has no ACME client; acme.sh runs beside it (in the recipe in its own
container sharing nginx's network and process space), answers http-01
through a webroot, and reloads nginx after a renewal (`--reloadcmd`, in
the container `kill -HUP 1`, on a host `nginx -s reload`). **Set `--days
-10`**: acme.sh counts fixed days, and its default would renew a 30-day
certificate one day before it expires. lego works the same way and is not
covered by the test.

### Kubernetes with cert-manager

Two ways, both tested:

- **ACME `ClusterIssuer`** with `caBundle` (the root) and an http-01 solver
  through an Ingress of the cluster's Traefik. The CA must resolve the
  service names to the Ingress – in the lab a `coredns-custom` entry, in
  real life your internal DNS.
- **step-issuer** with a **JWK provisioner of its own** (`cert-manager`),
  not SICK's `sick`: copying `sick`'s password into a cluster Secret would
  widen who can issue as SICK, for up to 825 days, and rotating one would
  break the other. No challenge: whoever holds the provisioner's password –
  here the Secret `step-issuer/sick-step-provisioner` – can obtain any name
  the CA allows. Note that the step-issuer chart's ClusterRole may read
  every Secret in the cluster, and cert-manager approves all its requests:
  treat that namespace as part of the CA.

Both Certificates use `renewBefore: 240h` (a third of 30 days). **"Ready" is
not proof**: the test counts a renewal only when a probe from a pod sees
the new fingerprint on the Service. Pods trust the root through a
ConfigMap; trust-manager is *not tried*. A NetworkPolicy lets only the
cert-manager and step-issuer namespaces reach the CA.

### Proxmox VE (*not tried*)

Proxmox VE has its own ACME client. Written from the `pvenode` manual
(checked 2026-10-11), not walked through:

```bash
# on every node: trust the root (chapter 3), so pvenode accepts the CA
sudo sh trust-linux.sh install --fingerprint <sha256 from your ceremony record>

pvenode acme account register sick-ca admin@example.internal \
  --directory https://ca.example.internal:9000/acme/acme-long/directory
pvenode config set --acme account=sick-ca,domains=pve1.example.internal
pvenode acme cert order
systemctl restart pveproxy
```

The directory is that of `acme-long`, a declared provisioner with 60-day
certificates (`docker/provisioners.example.json`): PVE renews once less than
30 days are left, and would renew every day with the 30-day certificates of
`acme`. The standalone plugin answers http-01 on port 80 of the node, so the CA
must reach the node there under that name. Proxmox Backup Server has the
same mechanism (`proxmox-backup-manager acme …`, *not tried*). If the node
cannot be reached by the CA, use SICK with the device types `proxmox-ve` /
`proxmox-bs` instead (chapter 5) – not the acme.sh hooks, which do not
verify the API's TLS certificate.

## When something goes wrong

- **A name outside the policy** is refused at the order: the client logs
  `rejectedIdentifier`. Traefik then presents its self-signed default
  certificate for that name, Caddy completes no handshake for it, nginx
  presents another server's certificate – all of which a client refuses.
- **A challenge fails** when the CA cannot reach the requester under the
  name: step-ca reports `urn:ietf:params:acme:error:connection` (it uses
  that type for any HTTP status of 400 or more as well) and keeps retrying
  a connection error. Look at the CA's log, not only the client's: the
  client may show only a timeout.
- **The CA is down**: certificates stay valid; renewals fail and are
  retried by each client. You have about ten days with the defaults.
  `SickCAUnreachable` (chapter 6) tells you within half an hour.

## Test report

All e2e scripts were run against the committed state `03ef482` on
2026-10-11, at the end of this package: `run-local.sh` 33 PASS,
`ca-ceremony.sh` 101, `ca-recovery.sh` 51, `ca-rollover.sh` 125,
`trust-anchors.sh` 96 PASS and its 8 expected FAIL findings, `trust-os.sh`
465, `trust-runtimes.sh` 147, `ops.sh` 72, `acme-services.sh` 31 per
service (Traefik, Caddy, nginx), `acme-k8s.sh` all parts PASS (up 17,
issue 11, renew 7, refuse 13, down 3); each with 0 unexpected FAIL;
afterwards nothing labelled `sick=1`, no `sick-*` k3d cluster, the host's
default kubeconfig untouched. Images pulled for this package and their
versions are in the rows below. The rows are the development runs.

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/e2e/ca-ceremony.sh` (ACME part) | step / step-ca 0.30.2 | the provisioner `acme` has the serverAuth-only template and 5m / 720h / 2160h; a real ACME order gives serverAuth only and 720h; a short test value (10m) takes effect | 101 PASS | – |
| `t/e2e/acme-services.sh`, each part twice | step-ca 0.30.2, traefik v3.7.14 (lego 5.6.1), caddy 2.11.7-alpine, nginx 1.30.5-alpine with neilpang/acme.sh 3.1.6; clients curl 8.14.1 / OpenSSL 3.5.7 and gnutls-cli 3.8.9 | per service: obtains, verified with the root alone, EKU serverAuth only; renews within the test (CA lifetime 3 min) with the fingerprint on port 443 changing; `outside.example.org` refused; a challenge for `decoy.example.internal` (another container) fails; the service keeps serving its own name | 31 PASS, 0 FAIL each run; renewal after about 58 s (Traefik), 110 s (Caddy), 21 s (acme.sh) | lego; certbot; tls-alpn-01 for Traefik; the recipes' relative bind mounts (the test mounts absolute paths) |
| `t/e2e/acme-k8s.sh`, twice | k3d 5.9.0 / k3s 1.35.5, cert-manager v1.21.2, step-issuer 0.11.0 (chart 1.11.0), nginx 1.30.5-alpine, curl 8.22.0 | per issuer: Ready and a pod probe sees the Secret's fingerprint; renewal seen by the pod probe without a manual step; `web.example.org` refused; for ACME a challenge for an uncontrolled name fails (three cases); EKU serverAuth only | ALL PASSED both runs; renewal seen after about 5 min | trust-manager; Gateway API solver; a second client implementation |
| Proxmox VE, Proxmox Backup Server | – | – | – | *not tried* |
