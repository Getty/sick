# Roadmap: from "SICK works" to a complete internal PKI

Goal: with what is in this repository, someone can set up an internal CA from
nothing, get certificates onto every device and service, make their clients
trust the CA, and run the whole thing for years without having to look for
anything elsewhere.

SICK stays what it is (the device list, the run, the targets). Most of the
packages below are mostly recipes, scripts and proof in containers around
step-ca, `step` and acme.sh, plus a handbook. Perl code is written only where
nothing existing does the job.

Status as of 2026-10-10: P1, P2 (in `sick`) and P3 done; the handbook has
chapters 1, 2 and 7. Sharpened on 2026-10-10 against the skill `ssl-tls-pki`. Each package is a card on the karr board of this
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

## How every package is tested

Taken from the skill `ssl-tls-pki` (acceptance tests, trust distribution,
rotation), and binding for P3–P9:

- **Positive and negative with the real consuming client.** Every "it
  works" has a matching "it is refused": unknown root, missing
  intermediate, wrong name, expired leaf, name outside the constraints,
  certificate removed from the store. A refusal that was expected is a
  passing test.
- **Independent implementations count, the same library twice does not.**
  curl, Python and the `openssl` CLI all use OpenSSL. Where a result
  matters (name constraints, chain building), at least one of GnuTLS, NSS,
  Go or Java checks it as well.
- **The live endpoint is the evidence.** A written file, a Secret or a
  "Ready" status proves nothing: the fingerprint presented on the port is
  compared with the one issued (SICK already does this for its devices; the
  recipes do it too).
- **Bootstrap is not operation.** Making the hierarchy, the first trust of
  a client and recovery are separate procedures from issuing and renewing,
  and each has its own test.
- **Every test record says** scope, versions, expected result, observed
  result and what it does not cover. What was not run is marked "not
  tried".

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

Bootstrap (once, offline):

- **Ceremony script.** It makes root and intermediate outside step-ca
  (`step certificate create --profile root-ca`, then the intermediate with
  an X.509 template: `nameConstraints` with DNS domains and IP ranges,
  `pathLen 0`, key usage `certSign, crlSign`). It writes the root key to a
  place the operator names and never into the CA volume. It writes a
  **ceremony record**: who ran it and when, the versions, the fingerprints,
  the constraints as read back from the certificates with `openssl x509
  -text` (an independent check of what the template produced), and where
  the root key went. The record holds no secret.
- `init-ca.sh` gets a mode that takes the existing root certificate and
  intermediate instead of making its own. The current "make everything"
  mode stays for labs and is called that.

Operation (online, step-ca):

- **Name constraints** in the intermediate as the first line, the CA policy
  (`SICK_CA_ALLOW_*`) as the second.
- **Profiles and enrollment.** A table of who may obtain what. The JWK
  provisioner `sick` holds a password that can ask for any allowed name; the
  ACME provisioner gives certificates to whoever answers the challenge.
  Server leaves get `serverAuth` only. Lifetimes per provisioner are set,
  not left at defaults.
- **Lifetimes and key types** with reasons. Root (e.g. 20 years, EC P-256 or
  RSA 4096), intermediate (e.g. 5 years), devices (397 days by default;
  825 days is Apple's ceiling), ACME services (short, renewed by the
  client). The reason for each includes the recovery budget: how long a CA
  outage the lifetime survives.
- **Backup and restore.** Restore into an isolated, empty volume without a
  second CA going live, and check that the restored intermediate is still
  valid. RTO and RPO are written down. Recovery must not depend on anything
  the CA itself issues (pinned images and tools kept independently).
- **Renewing the intermediate** with the offline root while devices keep
  their certificates. `ca.intermediates` and the trust page carry old and
  new during the overlap.
- **Replacing the root.** Distribute a bundle with both roots, verify that
  clients accept the new one, issue under the new one, re-issue all leaves,
  watch convergence, and only then remove the old one. A planned rollback
  returns to the old root; after a compromise rollback is forbidden, and
  the procedure says so.
- **Revocation.** Passive by default (`step ca revoke` blocks renewal),
  step-ca's CRL as an option. What SICK adds: short lifetimes and `sick run
  --force`. A compromise also revokes the enrollment grant: rotate the
  provisioner password, deactivate ACME accounts. Otherwise the attacker
  just asks again.
- **Compromise drills**, each as a written procedure: leaf key exposed,
  provisioner password exposed, intermediate compromised (stop issuing, new
  intermediate, `sick run --force` for every device), root compromised
  (authenticated trust replacement on every client), CA unavailable, the
  CA's own TLS certificate expired.

Done when a test in containers does all of the following:
- it runs the ceremony, starts step-ca on the result and issues through
  SICK;
- **negative, enrollment:** step-ca refuses an out-of-scope name, a CSR
  asking for `CA:true` and a lifetime above the provisioner maximum, and a
  refused request leaves no certificate;
- **negative, path:** a certificate for an out-of-scope name, signed with
  the intermediate key directly (bypassing step-ca), is refused by the
  OpenSSL CLI *and* by at least one independent implementation (GnuTLS or
  NSS, or Go if it is in the image);
- a backup restored into a fresh, isolated volume issues certificates that
  chain to the same root, and the original CA stays the only one in the
  service;
- an intermediate rollover and a root rollover leave clients that followed
  the trust page able to connect throughout, a client with only the old
  root refuses new leaves after the old root is retired, and the e2e run
  stays green;
- the provisioner password is rotated and the old one is refused.

The handbook chapters "Planning", "The CA" and "Emergencies: CA side"
exist.

### P4 Clients trust the CA [k14]

- **Authenticated bootstrap.** The trust page is served over plain HTTP, and
  a page that a client fetches before it trusts anything proves nothing by
  itself. The fingerprint from the ceremony record therefore travels by
  another channel (handbook, printout, chat), and every install script stops
  unless the root it installs has that fingerprint. The page says this
  first, not last.
- `sick trust` writes install **and** remove scripts. Covered:
  `install-debian.sh` (Debian, Ubuntu), the RHEL family, Arch, Alpine,
  macOS (`security`), Windows (PowerShell, `certutil`), Firefox (policy
  `policies.json`, or NSS `certutil`). The `.mobileconfig` stays, with the
  extra step on iOS (*Certificate Trust Settings*). Each script installs
  into the right store and nothing more: it never replaces the system
  bundle.
- **One inventory row per consumer**, with how it loads trust:
  - at start only, on reload, on every connection, or baked into the image;
  - whether a restart is needed;
  - how to remove it again.
  The consumers: the system stores, Firefox/NSS, Chrome, Java (`keytool`,
  the JDK's own `cacerts`), Python (`certifi` vs system, `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`), Node (`NODE_EXTRA_CA_CERTS`, `--use-system-ca`),
  Go, curl, git, the Docker daemon (`/etc/docker/certs.d`), BuildKit,
  container images (a Dockerfile snippet), Kubernetes pods (trust-manager or
  a ConfigMap). Where possible the page recommends a bundle for one
  application over a system-wide root.
- Android: user CAs and Network Security Configuration, written down
  honestly. Apps that target API 24 or newer ignore user CAs unless they
  opt in; Chrome uses them.

Done when a container matrix runs these steps for each consumer and asserts
every one:
1. install from the trust page, with the fingerprint checked;
2. reach a test service with a SICK certificate;
3. **refuse** a service whose certificate comes from another CA, one with
   the wrong name and one outside the name constraints;
4. remove, and fail again.

The matrix covers Debian, Ubuntu, Fedora, Rocky, Arch, Alpine, plus Java,
Python, Node and Go images, plus a Firefox/NSS profile. It records which TLS
library each consumer used. An install script given a root with a different
fingerprint stops. Windows, macOS, iOS and Android are marked "not tried" on
the page and in the handbook until someone walks them through.

### P5 Operations [k15]

- `sick check --format json` and a Prometheus text exposition (textfile
  collector). Per device: the remaining lifetime of the live leaf **and**
  of the intermediate and root in its path, and the live fingerprint. Per
  run: the time of the last successful issue and of the last full run.
- **Alert thresholds relative to lifetime** (e.g. a fraction of the
  lifetime plus the recovery budget from P3), not a fixed 30 days.
  Issuance failures alert long before expiry does.
- Notification on failure: a documented hook (systemd `OnFailure=`, cron
  `MAILTO`, a webhook command in the device list if a gap remains). A test
  shows that the alert fires and names the device.
- systemd service and timer, cron line, Kubernetes CronJob, each in the
  repository.
- **Inventory of the deployed certificates**, not only of the issued ones.
  Per device: names, issuer, serial, fingerprint, until when, how it is
  deployed, owner. It comes from the run records SICK keeps in its state
  directory and never holds a key.

Done when:
- the JSON and Prometheus output have tests, including an intermediate
  close to expiry;
- the CronJob runs in a throw-away k3d cluster `sick-…`;
- the systemd units pass `systemd-analyze verify`;
- a failing device, a device serving a stale certificate and an
  unreachable CA each trigger the documented notification in a container
  test.

The handbook chapter "Operations" exists.

### P6 Services that speak ACME [k16]

Recipes against step-ca's ACME endpoint, each with root trust on the client
side: Traefik, Caddy, nginx with acme.sh (or lego) and a reload hook,
cert-manager with an ACME `ClusterIssuer` and with `step-issuer`, Proxmox VE
with its custom ACME directory.
- **Enrollment authorization** is written down: the challenge type each
  recipe uses, who can reach the ACME endpoint, and that the CA policy
  bounds the names.
- ACME lifetimes are set by `init-ca.sh`, short enough to exercise renewal
  and long enough for the recovery budget.

Done when Traefik, Caddy, nginx and cert-manager (k3d) each do all of the
following in a test:
- they obtain a certificate from the lab CA;
- they **renew it within the test** (short test lifetime), and the
  fingerprint presented on the port changes to the new certificate without
  a manual step;
- a request for a name outside the CA policy is refused;
- a challenge for a name the client does not control fails.

Proxmox VE is a written recipe marked "not tried" (no PVE here). For
cert-manager, "Ready" counts only when a probe of the pod sees the new
fingerprint.

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

- **A separate trust set for clients.** Either a client intermediate of its
  own, or at least a provisioner whose template issues `clientAuth` only.
  The server's client-CA file is not the server's own chain; it is named
  for its role.
- `step ca certificate` for a person and for a machine, a key per holder
  (never one key shared by a fleet), PKCS#12 for import into browsers and
  OS stores.
- **Identity is not authorization.** The nginx recipe maps a specific SAN to
  an allowed principal. A valid certificate of the CA alone does not get
  in. Behind a terminating proxy, identity headers are overwritten by the
  proxy and accepted only from it.

Done when a container test has nginx accept the approved client and refuse
each of these:
- no certificate;
- a certificate from another CA;
- a `serverAuth`-only leaf presented as a client;
- an expired client certificate;
- a valid certificate for an identity that is not allowed (403, not a TLS
  error);
- a spoofed identity header sent directly to the backend.

### P9 Handbook [k20]

`docs/handbook/` in English, one path from zero to operations and
emergencies; every step with command and expected output; the README points
to it. The path:
- planning: names, networks, lifetimes, a trust graph and the
  profile/enrollment table;
- setting up the CA: the ceremony;
- clients trusting it: authenticated bootstrap first;
- the first device, then all devices and services;
- operations;
- emergencies: the recovery matrix of P3, plus certificate expired and
  device locked out.

Each decision that is the maintainer's (below) has a recommendation with
reasons, in the form of a decision record (decision, alternatives, why).

Done when:
- the whole path has been walked once in containers from an empty machine,
  and the transcripts are in the handbook with neutral names;
- every test record states scope, versions, expected and observed result;
- every proposal is marked as a proposal and every "not tried" as such;
- the restore drill and a compromise drill (intermediate) have been run
  from the handbook text alone.

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
