# Roadmap: from "SICK works" to a complete internal PKI

Goal: with what is in this repository, someone can set up an internal CA from
nothing, get certificates onto every device and service, make their clients
trust the CA, and run the whole thing for years without having to look for
anything elsewhere.

SICK stays what it is (the device list, the run, the targets). Most of the
packages below are mostly recipes, scripts and proof in containers around
step-ca, `step` and acme.sh, plus a handbook. Perl code is written only where
nothing existing does the job.

Status as of 2026-10-10. Each package is a card on the karr board of this
repository (`karr list`); the card number is given in brackets.

## Inventory

Legend: **proven** = it ran here or in the lab and the result was checked;
**written** = the code, script or text exists but has not been run against the
real thing; **missing** = nothing exists yet.

| # | Area | Proven | Written, not proven | Missing |
|---|---|---|---|---|
| 1 | The CA | step-ca in Compose, made by `init-ca.sh` at first start: root, intermediate, JWK provisioner `sick` (825 days), ACME provisioner; name policy of the running CA (`SICK_CA_ALLOW_*`) refuses other names; e2e against a switch | k8s Pod with the same CA (`k8s/test`) | root made offline and its key off the machine; X.509 name constraints in the intermediate; documented choice of lifetimes and key types; key ceremony; backup and restore; renewing the intermediate; replacing the root; a decision on revocation (passive / step-ca's CRL) |
| 2 | Client trust | `sick trust`: PEM, DER, bundle, `.mobileconfig`, `index.html` with fingerprints; openssl, GnuTLS, NSS and the system stores of Debian and Fedora with the switch's certificate | the steps for Windows, macOS, iOS/iPadOS, Android, Firefox, Chrome (from vendor documentation) | install and remove scripts per platform; Ubuntu, RHEL family, Arch, Alpine; runtimes with their own store (Java, Python, Node, curl, git, Docker daemon, container images, Kubernetes pods); a container matrix that proves them; honest Android limits written down |
| 3 | Services that speak ACME | ACME provisioner exists and is reachable | nothing | recipes and container proof for Traefik, Caddy, nginx with an ACME client, cert-manager (ACME and step-issuer), Proxmox VE's custom ACME directory; ACME lifetime settings |
| 4 | Devices that cannot | `cisco-sb` (lab switch, e2e), `files`, `acmesh` with hook `localcopy` (acme.sh 3.1.6) | the `acmesh` example for `proxmoxve`; the `routeros` hook in the spec | a decision and a recipe per device class: MikroTik RouterOS, Proxmox VE, Proxmox Backup Server, Dell iDRAC 7/8, Linux hosts over SSH, Kubernetes Secrets; a deferred card for iDRAC on `WWW::iDRAC` |
| 5 | Operations | `sick run` in the Compose loop, exit codes 0/1/2, a table per run | nothing | systemd unit and timer, cron recipe, Kubernetes CronJob; machine-readable output (JSON) and Prometheus metrics for remaining lifetime; notification on failure; inventory of what was issued, for whom, until when |
| 6 | Client certificates (mTLS) | nothing | nothing | recipe with `step` for people and machines, import into browsers and OS stores, a server that checks them; no SICK code unless a gap shows |
| 7 | Handbook | nothing | README, `docker/README.md`, `k8s/README.md` cover parts | `docs/handbook/`: planning → CA → trust → first device → all devices and services → operations → emergencies; every step with command and expected output |
| 8 | House stack | nothing | cards k1–k9 here, k2–k3 in `sick-target-ciscosb` | the conversion itself |

Notes on the inventory:

- The test suite here: 172 tests green; `t/42-target-acmesh.t` runs half
  because acme.sh is not installed on this machine yet. In
  `sick-target-ciscosb` 44 tests green, `t/90-live.t` skipped (no switch).
- `t/e2e/run-lab.sh` needs a real switch. There is no end-to-end run that
  needs nothing but Docker.
- `SICK_FROM=cpan` in the Dockerfile is written and was never built.
- Checked in the Smallstep documentation (2026-10-10): step-ca revokes
  passively by default (a revoked certificate cannot be renewed and
  expires); it has a minimal CRL server (`"crl": {"enabled": true}` in
  `ca.json`, served at `/1.0/crl`) and no OCSP. Name constraints go into the
  intermediate through an X.509 template (`nameConstraints` with
  `permittedDNSDomains`, `permittedIPRanges`) when the intermediate is
  signed with `step certificate create --template`.

## Order and why

1. **P1 Lab** first: everything later is proven in containers on this
   machine, and today there is no switch-free end-to-end run.
2. **P2 House stack** before any new Perl. P4 trust (`SICK::Trust`), P5
   operations (`SICK::CLI`, `SICK::Runner`) and P7 targets (`SICK::Target`)
   all change modules that k1–k9 rewrite; doing it the other way round means
   writing those changes twice. New targets copy a Moo base class, not a
   `bless` one.
3. **P3 CA** next, because client trust, every recipe and the handbook build
   on the CA as it will finally be made (offline root, constrained
   intermediate). P3 is shell, templates and docs; it can run alongside the
   tail of P2 if budget allows.
4. **P4 Trust**, then **P5 Operations**: with these two a first real
   rollout is possible (CA, trusting clients, devices on a timer, alerts).
5. **P6 ACME services** and **P7 devices** widen the coverage.
6. **P8 mTLS** is a recipe and comes late.
7. **P9 Handbook**: every package from P3 on writes its chapter; P9 is the
   final pass that walks the whole path from zero in containers and fixes
   what does not match.

## Packages

### P1 Lab on this machine [k12]

Tools and a Docker-only end-to-end run.

- `step`, `step-ca`, `acme.sh` (pinned versions) in `~/.local/bin` or in
  a container; `prove -lr t` runs `t/42-target-acmesh.t` completely.
- `t/e2e/run-local.sh` (or an option of `run-lab.sh`): Compose up under the
  project name `sick-e2e`, ports on `127.0.0.1` only, a `files` device and a
  TLS service container as the "device", `sick run`, second run changes
  nothing, trust page served and verified with `curl --cacert`, everything
  torn down.

Done when: the full suite runs with no skip except `t/90-live.t`, and the
local e2e script passes twice in a row and leaves no container, volume or
network behind.

### P2 House stack [k1–k9 here, k2–k3 in sick-target-ciscosb]

The existing cards, in their order: Device (pilot), Temp, Bundle, Config,
issuers, targets, Runner, Trust, CLI; then in `sick-target-ciscosb` the agent
team (k2) and the device type (k3). k10 and k11 wait for the maintainer and
are not part of this package.

Done when: all nine cards are done, `prove -lr t` and `dzil test` are clean
in both repositories, and the image builds and passes the P1 e2e run.

### P3 The CA done properly [k13]

- **Root offline.** A ceremony script that makes root and intermediate
  outside step-ca (`step certificate create --profile root-ca`, then the
  intermediate with an X.509 template carrying `nameConstraints`), writes
  the root key to a place given by the operator and never into the CA
  volume. `init-ca.sh` gets a mode that takes an existing root certificate
  and intermediate instead of making its own; the current "make everything"
  mode stays for labs.
- **Name constraints** in the intermediate (DNS domains, IP ranges),
  configurable; the running-CA policy stays as the second line.
- **Lifetimes and key types** with reasons: root (e.g. 20 years, EC P-256 or
  RSA 4096), intermediate (e.g. 5 years), devices (397 days default; 825
  days is Apple's ceiling), ACME services (short, e.g. 30–90 days, renewed
  by the client). All configurable.
- **Backup and restore** of the CA volume (keys, `ca.json`, database),
  restore into an empty volume.
- **Renewing the intermediate** with the offline root, while devices keep
  their certificates; `ca.intermediates` and the trust page carry old and new
  during the overlap.
- **Replacing the root**: new root, overlap period with both on the trust
  page, re-issue, retire the old one.
- **Revocation**: passive by default, step-ca's CRL as an option; what SICK
  does instead (short lifetimes, `sick run --force` for affected devices).

Done when: a test in containers runs the ceremony, starts step-ca on the
result, issues through SICK, and shows (a) `openssl verify` refuses a
certificate for a name outside the constraints even when signed by the
intermediate directly, (b) a backup restored into a fresh volume issues
certificates that chain to the same root, (c) an intermediate rollover and
(d) a root rollover leave clients that followed the trust page able to
connect throughout. Handbook chapters "Planning" and "The CA" exist.

### P4 Clients trust the CA [k14]

- `sick trust` writes install **and** remove scripts: `install-debian.sh`
  (Debian, Ubuntu), RHEL family, Arch, Alpine, macOS (`security`), Windows
  (PowerShell, `certutil`), Firefox policy (`policies.json`) / NSS
  `certutil`; the `.mobileconfig` stays. Each script checks the fingerprint
  it was written with.
- The page gets sections for runtimes with their own store: Java
  (`keytool`), Python (`certifi`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`),
  Node (`NODE_EXTRA_CA_CERTS`), curl, git, Docker daemon
  (`/etc/docker/certs.d`), container images (a Dockerfile snippet),
  Kubernetes pods (ConfigMap / trust-manager).
- Android: what a user CA does and does not do (apps targeting API 24 or
  newer ignore it unless they opt in; Chrome uses it).

Done when: a container matrix (Debian, Ubuntu, Fedora, Rocky, Arch, Alpine;
Java, Python, Node images; a Firefox/NSS profile) installs from the trust
page, reaches a test service with a SICK certificate, removes, and fails
again – each step asserted. Windows, macOS, iOS, Android are marked "not
tried" on the page and in the handbook until someone walks them through.

### P5 Operations [k15]

- `sick check --format json` and a Prometheus text exposition of remaining
  lifetime per device (textfile collector), with tests.
- Notification on failure: a documented hook (systemd `OnFailure=`, cron
  `MAILTO`, a webhook command in the device list if a gap remains).
- systemd service and timer, cron line, Kubernetes CronJob, each in the
  repository.
- Inventory: what was issued, for which device and names, until when –
  from the run records SICK keeps in its state directory.

Done when: the JSON and Prometheus output have tests; the CronJob runs in a
throw-away k3d cluster `sick-…`; the systemd units pass
`systemd-analyze verify`; a failing device triggers the documented
notification in a container test. Handbook chapter "Operations" exists.

### P6 Services that speak ACME [k16]

Recipes against step-ca's ACME endpoint, each with root trust on the client
side: Traefik, Caddy, nginx with acme.sh (or lego), cert-manager with an
ACME `ClusterIssuer` and with `step-issuer`, Proxmox VE with its custom ACME
directory. ACME provisioner lifetimes set by `init-ca.sh`.

Done when: Traefik, Caddy, nginx and cert-manager (k3d) each obtain a
certificate from the lab CA in a test and serve it, verified with
`curl --cacert`. Proxmox VE is a written recipe marked "not tried" (no PVE
here).

### P7 Devices that cannot [k17, iDRAC k18 deferred]

Decide per device class, write the decision down, recipe plus as much test
as is possible without the device:

| Device | Expected way |
|---|---|
| MikroTik RouterOS | acme.sh hook `routeros` through `acmesh`; test with a recording fake |
| Proxmox VE, Proxmox Backup Server | native ACME (P6) where the host can reach the CA; otherwise hooks `proxmoxve`, `proxmoxbs` |
| Linux host over SSH | acme.sh hook `ssh`; test against an sshd container |
| Kubernetes Secret | cert-manager in the cluster (P6); a SICK target only if a case remains |
| Dell iDRAC 7/8 | own distribution on `WWW::iDRAC`; card k18, deferred until that module exists and a device is reachable |

Done when: every row has a recipe in the handbook, every hook that can run
against a container has a test, and the card for iDRAC lists what it needs.

### P8 Client certificates (mTLS) [k19]

Recipe: a provisioner for client certificates, `step ca certificate` for a
person and for a machine, PKCS#12 for import into browsers and OS stores,
nginx checking client certificates.

Done when: a container test issues a client certificate and nginx accepts it
and refuses a request without it.

### P9 Handbook [k20]

`docs/handbook/` in English, one path from zero to operations and
emergencies (key lost, CA compromised, certificate expired, device locked
out); every step with command and expected output; the README points to it.
Each decision that is the maintainer's (below) has a recommendation with
reasons.

Done when: the whole path has been walked once in containers from an empty
machine, the transcripts are in the handbook with neutral names, and every
"not tried" is marked as such.

## Decisions that are the maintainer's

Each is made configurable; the handbook gives a recommendation.

| Decision | Configurable through | Recommendation (draft) |
|---|---|---|
| Where the root key lives | ceremony script: output path | encrypted file on two offline media in separate places; a YubiKey or HSM when one is at hand |
| Names and networks the CA may issue for | name constraints and CA policy | only the internal domains and private ranges in use |
| Lifetimes | ceremony, `init-ca.sh`, `defaults` | root 20 y, intermediate 5 y, devices 397 d, ACME services 90 d or less |
| Visibility of the repositories | – (GitHub) | stays with the maintainer |
| CPAN release | – (`dzil release`) | stays with the maintainer |
| Image name and registry | `SICK_IMAGE` | stays with the maintainer |
| `docker/` and `t/e2e/` in the CPAN tarball | `dist.ini` | include `docker/` (it is the documented way to run SICK), leave `t/e2e/` out (it changes real equipment) |
