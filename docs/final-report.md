# SICK – final report for the maintainer

State of 2026-10-11, after the roadmap's nine packages (P1–P9). This page is
for the person who will run the CA: what exists, what only you can decide,
what to try first on real equipment, what has not been tried, and which
cards stay open.

## What exists

**Three distributions**, none released yet:

- **SICK** (`~/dev/sick`, GitHub `Getty/sick`): the device list, the run
  (check → issue → deploy → check again, by fingerprint on the port), the
  issuers (step-ca through the `step` CLI; a throwaway self-signed CA), the
  device types `files` (one generation at a time, rollback on a failed
  reload) and `acmesh` (acme.sh deploy hooks), the trust page with install
  and remove scripts per platform, state records, a lock, back-off, JSON and
  Prometheus output, an inventory.
- **SICK-Target-CiscoSB**: Cisco Small Business switches over their CLI.
  Proven against a real SG300 in the lab (phase 1).
- **SICK-Target-Proxmox**: `proxmox-ve` and `proxmox-bs` over the node's
  API, always TLS-verified. Proven against real PVE 9.2.21 and PBS 4.2.8 in
  containers.

**Around them**, in the core repository:

- `docker/`: step-ca, SICK on a schedule and the trust page in one Compose
  setup; a **ceremony** that makes an offline root and a name-constrained
  intermediate; import mode, so the root key never enters the CA; backup and
  restore; renewing the intermediate and replacing the root; declared
  provisioners (ACME for services, `clients` for mTLS, `cert-manager`,
  `acme-long` for Proxmox VE).
- `k8s/`: the same as a Pod, a CronJob, and cert-manager (ACME and
  step-issuer).
- `contrib/`: systemd units and a cron line, a failure notifier, Prometheus
  alert rules, ACME recipes (Traefik, Caddy, nginx with acme.sh), device
  recipes (Linux over SSH, RouterOS, Proxmox, a first device for Docker), an
  mTLS recipe.
- **The handbook** (`docs/handbook/`): planning → the CA → clients →
  services → devices → operations → emergencies → client certificates, every
  step with its command and output; a decision page; an HQ checklist; a page
  on how it was tested.

**How it is proven:** 245 unit tests (`prove -lr t`; 2 skipped without
`pwsh`, the syntax check of `trust-windows.ps1`), 14 container test scripts
under `t/e2e/` plus one in SICK-Target-Proxmox (`run-lab.sh`, which needs a
real switch, is not among them and was not run), all green against the
committed state at the end of each package – the last run is recorded
below and in each chapter's test report – and the handbook walked through
from zero in five rounds by agents without prior knowledge, plus the two
drills (restore, compromised intermediate) from the text alone
(`docs/handbook/walkthroughs.md`). In the fifth round every section and
both drills ran without a blocker and without a guess. The second drill found a
mistake in substance in the compromise chapter, which is now corrected: a
stolen intermediate key is cut off for clients only by a root replacement.

## The last run

All on 2026-10-11 against the committed state – SICK `164b272`,
SICK-Target-Proxmox `b9e7284` – one after the other on one host, nothing
of ours left afterwards (no container, volume or network labelled
`sick=1`, no k3d cluster `sick-*`). `prove -lr t`: 245 tests, all pass, 2
skipped (no `pwsh`).

| Script | Result |
|---|---|
| `run-local.sh` | 33 PASS |
| `ca-ceremony.sh` | 146 PASS |
| `ca-recovery.sh` | 51 PASS |
| `ca-rollover.sh` | 145 PASS |
| `trust-anchors.sh` | 96 PASS, 8 FAIL – the expected ones: curl and gnutls on Debian and Fedora accept a certificate when only the intermediate is in their CA file (case 5c2, chapter 3: install the root, never an intermediate, as an anchor) |
| `trust-os.sh` | 465 PASS |
| `trust-runtimes.sh` | 147 PASS |
| `ops.sh` | 74 PASS |
| `acme-services.sh` traefik / caddy / nginx | 31 / 31 / 31 PASS |
| `acme-k8s.sh` up / issue / renew / refuse / down | 20 / 11 / 7 / 13 / 3 PASS |
| `device-ssh.sh` | 71 PASS |
| `device-routeros.sh` | 47 PASS (stand-in and CHR) |
| `client-san.sh` | 65 PASS |
| `mtls.sh` | 79 PASS |
| SICK-Target-Proxmox `t/e2e/device-proxmox.sh` | 64 PASS (its `t/90-live.t` skipped: needs a real node) |

Not run: `run-lab.sh` (changes a real switch) and the live tests of the two
target distributions.

## What you decide

Each is a record in [`docs/handbook/decisions.md`](handbook/decisions.md)
with options, a proposal and where it is set. The ones that block or shape a
first real rollout:

1. **Where the root key lives** – proposal: an encrypted file on two
   removable media in two places, the password on a third.
2. **Names and networks of the CA** – proposal: one internal domain
   (`<site>.internal` is fine, ICANN reserved `.internal`), the private ranges
   in use, the same email domain if people get client certificates.
3. **Lifetimes** – proposal: root 20 y, intermediate 5 y (or 2–3 y, since it
   bounds the window of a stolen intermediate key), devices 397 d, ACME 30 d.
4. **Who may reach the ACME endpoint; external account binding** (card
   k51) – proposal: service networks only; EAB when wider.
5. **Release:** visibility of the three repositories, the CPAN release (core
   first, then the two target distributions pinned to `SICK 0.001`), image
   name and registry, and whether `docker/`, `k8s/`, `contrib/`, `t/e2e/`
   ship in the tarball (card k72; proposal: ship `docker/`, `contrib/`,
   `docs/`, leave `t/e2e/` out).
6. Smaller ones: signing the Apple profile, a separate client CA, OIDC
   enrolment, and cards k10 (tests on the house stack) and k11 (which
   hand-written plumbing gives way to CPAN).

## What to try at HQ, in this order

The full list with pass criteria is the
[HQ checklist](handbook/hq-checklist.md). The order that gets a working CA
with the least risk:

1. **The ceremony on a real offline machine** with the root key on its
   media (or a YubiKey, if you decide so), and the CA in import mode on the
   machine that will run it. *Passed:* chapter 2's checks.
2. **One client of each kind you use**: a Windows PC, a Mac, an iPhone, an
   Android phone – install the root from the trust page, check the
   fingerprint against the ceremony record. *Passed:* a SICK device opens
   without a warning; after removal it warns again.
3. **The first real device**: the lab switch (already proven) or a Proxmox
   node with native ACME (`acme-long`), then with `proxmox-ve` where the CA
   cannot reach the node.
4. **systemd on the host**, `sick-notify` with your mail or chat, Prometheus
   scraping the textfile – a week of runs.
5. **The other devices**: RouterOS on a physical router, Proxmox Backup
   Server, a Linux host over SSH.
6. **Client certificates** in a browser, if you use them.
7. **A restore drill** on a second machine from a real backup.

## What has not been tried

Everything on the HQ checklist, in short: Windows, macOS, iOS and Android
clients; Chrome on Linux; a signed Apple profile; Docker's registry trust;
the root on a YubiKey or HSM; a restore on another host; a planned rollback of
a root replacement; Proxmox VE and PBS under systemd, in a cluster and over a
real network (native ACME and the device types); a physical RouterOS;
systemd itself running the units for a week; a real mail server; Prometheus
and Alertmanager live; client certificates in real browsers and OS stores;
iDRAC 7/8 (needs `WWW::iDRAC` first).

## Open cards and why

| Card | What | Why open |
|---|---|---|
| k10, k11 | tests on the house stack; hand-written plumbing vs CPAN | your decision (decisions.md 10, 11) |
| k18 | SICK-Target-IDRAC | waits for certificate functions in `WWW::iDRAC` and a reachable iDRAC; the card lists what is needed |
| k34 | the other hierarchy's intermediate during a root replacement | documented limit; build only if a leaf-only device must work through phase B |
| k51 | external account binding for ACME | your decision |
| k72 | which directories ship on CPAN | agent and CI configuration are pruned; the rest is your decision |
| k73, k74 (and #6 in cisco, #8 in proxmox) | release blockers: pin `SICK 0.001` in the target dists; GitHub metadata wrong because the remotes are SSH host aliases | need the core released first, and the release machine's remote |
| k75, k76 | two small fixes (a hint in `trust-nss.sh`, an example's `mode_key`) | found in the last walkthroughs, not release-blocking |
| k77 | `docker/README.md` still shows the lab form of the secrets directory and the root-key medium on the CA host, where the handbook now uses a root-owned directory and a transfer medium | prose under `docker/`, the worker's lane; not release-blocking |
| cisco #4, #5; proxmox #9 | small findings in the target distributions | not release-blocking |
