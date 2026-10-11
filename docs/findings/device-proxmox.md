# Proxmox VE and Proxmox Backup Server through the acme.sh hooks

> **Superseded by SICK-Target-Proxmox** (`../sick-target-proxmox`, device
> types `proxmox-ve` and `proxmox-bs`), which uploads through the API of the
> node itself **over a verified TLS connection** (CA files or SHA-256 pins
> from the device list, no way to switch verification off) and keeps the
> token in the request header. It was run end to end against a real PVE
> 9.2.21 and a real PBS 4.2.8 in containers (its `t/e2e/device-proxmox.sh`).
> The stand-in test this page describes (`t/e2e/device-proxmox.sh` and
> `t/e2e/proxmox-standin.py` of this repository) modelled the API wrongly in
> eleven points and was removed on 2026-10-11; it is in the git history.
> Those points are corrected below in place, each marked **Corrected** with
> the source (`../sick-target-proxmox/docs/api-notes.md`, "Where the earlier session disagrees", which cites the Proxmox sources and its observations of
> the real products). What this page says about the acme.sh hooks
> themselves - no TLS verification, the token on curl's command line, the
> token in acme.sh's `.conf` - still describes those hooks.

Question: do the acme.sh deploy hooks `proxmoxve` and `proxmoxbs`, driven by
SICK's `acmesh` target, get a certificate of the CA onto a PVE node and a
PBS host, and what does a recipe for them have to say?

**Answer: the mechanism works against a stand-in of both APIs, and the
hooks have two security gaps a recipe must state.** They never verify the
TLS certificate of the API they send the token and the private key to, and
they put the token on curl's command line. Neither is reachable from the
device list; `SICK::Target::Acmesh` needs no change for these hooks.
Recommendation for the handbook: native ACME where the CA reaches the node,
the hooks only where it cannot (`contrib/devices/proxmox/README.md`).

Scope: the hooks' side, end to end in containers, against
`t/e2e/proxmox-standin.py`, a recording stand-in modelled on the API
schemas. **Nothing was run against a real PVE or PBS.**

## What was run

`t/e2e/device-proxmox.sh`, 2026-10-11, on agent-lab, twice in a row after
the script was final: 73 PASS, 0 FAIL each run (about 50 s), nothing of the
project `sick-proxmox` left afterwards (no container, volume or network
with its project label, nothing named `sick-proxmox*`). An earlier run had
one `compose run --rm` container still being removed at teardown; the
teardown now waits for it and removes what is left by the label `sick=1`.

| What | Version / digest |
|---|---|
| acme.sh in the sick image | 3.1.6; `deploy/proxmoxve.sh` sha256 `75a60c5e…5ea5de7b`, `deploy/proxmoxbs.sh` `329b80e1…aed7b5` |
| curl, OpenSSL in the sick image | curl 8.14.1, OpenSSL 3.5.7 (Debian trixie) |
| sick image | `sick:local` built from the working tree, `sha256:e91af933…` |
| CA | `smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270` |
| stand-ins | `python:3.14.8-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170` (Python 3.14.8, OpenSSL 3.5.7) |
| API schemas read | PVE `pve-docs/api-viewer/apidoc.js` (Last-Modified 2026-09-24, sha256 `68a8ac7b…9ce7c53`); PBS 4.2.8 `docs/api-viewer/apidoc.js` (2026-10-02) |
| sources read | proxmox-backup `src/api2/node/certificates.rs`, `src/bin/proxmox-daily-update.rs`, `pbs-api-types/src/acl.rs` at `78f77d53`; pve-manager `bin/pveupdate` at `76177f3d` |

### The stand-in

One Python script (standard library only), run as `pve` or `pbs`, in a
read-only container as nobody, reachable as `pve1.example.internal:8006`
and `pbs1.example.internal:8007` inside the project network; no port
published. It serves the API **and** the certificate on the same port, as
pveproxy and proxmox-backup-proxy do: first a self-signed certificate made
at test time (subject like PVE's own node certificate), after an accepted
upload the uploaded one - PVE two seconds after answering (pveproxy restarts
in the background), PBS at once (it reloads within the call). It checks the
token header's form, the user, realm and token id and the secret; it checks
that the key is a PEM private key matching the certificate by loading both
into a TLS context. It records one line per request and never the body, the
key or the secret. `DELETE` on the same path goes back to the self-signed
certificate. A mode file steers it to answer 500 or to answer an upload
slowly.

Where the stand-in was wrong, against the sources and the real products
(points 1-9, 12 of `../sick-target-proxmox/docs/api-notes.md`, "Where the earlier session disagrees"):

- **Corrected (1) - PBS does not check that the key matches.** PBS writes
  the files and answers 200 for a mismatched key (and for a wrongly ordered
  chain); the proxy refuses them only in its log and keeps the old
  certificate until its next start, which then fails. Source: proxmox-backup
  `certificates.rs`, `proxmox-backup-proxy.rs`; observed on PBS 4.2.8.
- **Corrected (2) - PVE's own certificate is not self-signed.**
  `pve-ssl.pem` is signed by the cluster CA (`pve-root-ca.pem`) and carries
  the cluster address as IP SAN. `sick check` still says `foreign-ca`.
  Source: pve-cluster `Setup.pm`; observed on PVE 9.2.21.
- **Corrected (3) - how PVE restarts.** The upload runs `systemctl
  reload-or-restart pveproxy` *before* it answers (SIGHUP, the master
  re-executes); if that command fails, the answer is 500 with the files
  already written. Old and new certificate then alternate on new
  connections for about 4-6 s; the stand-in switched once, 2 s after the
  answer. Source: pve-manager `Certificates.pm`, pve-common `Daemon.pm`;
  observed on PVE 9.2.21 (with a systemctl shim, not under systemd).
- **Corrected (4) - DELETE without a custom certificate.** The stand-in
  answered 500 on both. PVE answers 200 (missing files are ignored); PBS
  answers 200 and replaces its self-signed certificate with a new one.
  Source: pve-manager `Certificates.pm`, proxmox-backup `certificates.rs`;
  observed on PVE 9.2.21.
- **Corrected (6) - 401 answers.** The stand-in sent the reason
  `authentication failure`, empty body, at once. PVE: `401 Authentication
  failed!`, empty body, after 3 seconds; PBS: `401 Unauthorized` with the
  plain-text body `authentication failed`, after 3 seconds. Source:
  pve-manager `HTTPServer.pm`, proxmox-rest-server `rest.rs`; observed on
  PVE 9.2.21 and PBS 4.2.8.
- **Corrected (7) - PBS error bodies are plain text**, not JSON, also for
  400 parameter errors (the stand-in sent JSON with `errors`). Source:
  proxmox-rest-server `formatter.rs`; observed on PBS 4.2.8.
- **Corrected (8) - success answers.** The stand-in returned `filename` and
  `fingerprint` only, both upper case. The real answers carry all fields of
  the certificate info (PVE an object, PBS an array of one); PVE's
  fingerprint is upper case, PBS's lower case. Source: pve-common
  `Certificate.pm`, proxmox-backup `pbs-tools/src/cert.rs`; observed on both.
- **Corrected (9) - PVE's message for an existing custom certificate**
  without `force` is `Custom certificate file exists but force flag is not
  set.` (status 500), not the stand-in's text. Source: pve-manager
  `CertHelpers.pm`; observed on PVE 9.2.21.
- **Corrected (12) - PVE does not check the key against the certificate.**
  A key of another type than the first certificate is accepted; with a
  wrongly ordered chain pveproxy then fails every handshake. The stand-in
  refused such a key. Observed on PVE 9.2.21.

### Results

| Test | Expected | Observed |
|---|---|---|
| before: `sick check` | both `foreign-ca` (self-signed; **corrected (2)**: a real PVE presents its cluster-CA certificate, also `foreign-ca`) | as expected |
| curl in the sick image to the self-signed API, verifying | refused | exit 60, stand-in logged `TLSV1_ALERT_UNKNOWN_CA` |
| `sick run pve pbs` | both renewed through their hooks | `renewed`, exit 0; acme.sh `Success` |
| request sequence | one POST per device, nothing else | exactly one each (recorded lines below) |
| fingerprint on 8006 / 8007 | = issued (device record) = uploaded | equal, both |
| APIs after the deployment, `curl --cacert root` | verify | verify |
| second `sick run` | unchanged, no upload | `unchanged ok`, upload count unchanged |
| token on curl's command line (slow upload, `/proc/*/cmdline` counted) | found (from reading) | found in 1 process; value never printed |
| wrong token, both hooks (`--force`) | 401, device fails with a clear message | `failed`: `deploy failed: acme.sh failed (exit 1): Certificate deployment failed (HTTP status 401).; …`; port unchanged |
| API answers 500, both | device fails | `failed`: `… (HTTP status 500). stand-in answers 500; …`; port unchanged (**corrected (7)**: a real PBS answers errors in plain text, not JSON) |
| API port closed, certificate port answering | **failed** (the device was judged, the deployment broke) | `failed`: `… error code: 7; Certificate deployment failed (HTTP status ).; …` |
| node down (stand-in stopped) | **unreachable**, nothing deployed, also with `--force` | `failed unreachable … Name or service not known`, acme.sh not started, both times |
| back: `DELETE …/certificates/custom` | self-signed again; `sick check` foreign-ca; `sick run` renews | as expected |
| tokens in sick's output, the device records, the project's logs, `docker inspect` of every container | none | none |

Recorded uploads (fingerprints of one run):

```
standin pve: POST /api2/json/nodes/pve1/certificates/custom ctype=application/json
  auth=PVEAPIToken(sick@pve!sick, format ok, id ok, secret=ok)
  fields=certificates:str,force:str,key:str,node:str,restart:str
  node="pve1"(str) restart="1"(str) force="1"(str)
  certificates=2 PEM, first sha256 19050e65…3dd7eca
  key=PEM private key, RSA (traditional PEM), matches certificate: yes -> 200 (proxy reloads in 2s)
standin pbs: POST /api2/json/nodes/localhost/certificates/custom ctype=application/json
  auth=PBSAPIToken(sick@pbs!sick, format ok, id ok, secret=ok)
  fields=certificates:str,force:bool,key:str,node:str,restart:bool
  node="localhost"(str) restart=true(bool) force=true(bool)
  certificates=2 PEM, first sha256 8e1701b8…93afda7
  key=PEM private key, RSA (traditional PEM), matches certificate: yes -> 200 (proxy reloaded)
```

`certificates` is `fullchain.cer` (leaf and intermediate), `key` the key
as SICK made it. The PVE hook sends its booleans as the strings `"1"`, the
PBS hook as JSON `true`. **Answered since (10):** pveproxy takes `"1"`, `1`
and `true` in a JSON body; PBS takes only `true`. So both hooks send what
their product accepts. Source: pve-common `JSONSchema.pm`, proxmox-schema
`schema.rs`; observed on PVE 9.2.21 and PBS 4.2.8 (`../sick-target-proxmox/docs/api-notes.md`, "Where the earlier session disagrees").

## Findings

1. **The hooks do not verify TLS, and nothing can make them.** Both
   `export HTTPS_INSECURE=1` inside the hook function, right before
   `_post`; acme.sh adds `--insecure` to curl for it (`_post`, acme.sh
   3.1.6). Because it is set inside the function, the environment
   (`env:` of the device), `CA_BUNDLE` and `CA_PATH` cannot undo it, and
   `--insecure` wins over `--cacert` anyway. The test shows it: curl in the
   same image refuses the stand-in's self-signed certificate, the hook goes
   through. What goes over that unverified connection is the API token
   *and* the private key of the new certificate. After the first
   deployment the API presents a certificate of the CA and would verify
   (shown with `curl --cacert`); the hooks never use that.
   *Asked of the task: trust the stand-in "the way a real setup would". There
   is no way for these hooks; the stand-in's own certificate is
   deliberately untrusted to prove it.*
2. **The token is on curl's command line.** `_post` passes the header as
   `-H "$_H1"`; while the call runs, the header with the secret is in
   `/proc/<pid>/cmdline` of curl. Counted in the test (one process), never
   printed. It is visible to whoever can see SICK's processes - in the
   Docker setup the sick container and root on the host.
3. **The hooks save the token into acme.sh's `.conf`**
   (`_savedeployconf`). In SICK's default private temporary home that
   file is removed with the home; with a `home` of its own it stays in
   plain text (as `docs/findings/acmesh-deploy.md` says in general).
4. **SICK's side holds**: the secret only in `env_files`, hidden from the
   output, not in records, logs or the containers' configuration;
   `unreachable` (no answer on the certificate port) touches nothing, also
   with `--force`; a broken API is `failed` with the hook's own message
   (HTTP status, and for a 500 the API's `message` - **corrected (7)**: that
   was the stand-in's JSON; a real PBS answers in plain text).
5. **The wrong-token message is good enough, the closed-port one is not
   pretty**: `HTTP status 401` names the cause; a closed API port reads
   `error code: 7; Certificate deployment failed (HTTP status ).` - curl's
   exit code 7 is "could not connect". Both come from the hook; SICK
   passes them on. (**Corrected (6)**: the real nodes answer 401 after
   3 seconds, with the texts given above under "The stand-in".)

## Recipe facts for the handbook

- **Rights.** PVE: `Sys.Modify` on `/nodes/<node>` for
  `POST`/`DELETE /nodes/{node}/certificates/custom` (schema, tokens allowed).
  No smaller privilege exists, and `Sys.Modify` on a node also covers its
  network, DNS, hosts, time, APT repositories, firewall rules and service
  start/stop (same schema, endpoints listed by their permission check).
  Keep it small: a user in the `pve` realm without password, a role holding
  `Sys.Modify` only, a privilege-separated token with an expiry, the ACL on
  the one node. PBS: `Sys.Modify` on `/system/certificates`; only the
  fixed role `Admin` holds it, so `Admin` on that path, for user and token.
  **Corrected (11):** `Admin` there covers the certificate and the ACME
  settings of the host, and the ACME settings include *reading the
  credentials of the DNS plugins* (PBS API schema, `../sick-target-proxmox/docs/api-notes.md`, "Where the earlier session disagrees").
  Commands in `contrib/devices/proxmox/README.md` (from the manuals; run
  since by SICK-Target-Proxmox against PVE 9.2.21 and PBS 4.2.8, syntax
  confirmed).
- **Where the secret lives.** A file of its own named in `env_files`;
  SICK hands it to acme.sh in the environment only. Also, for the duration
  of the call, on curl's command line, and in the `.conf` of the temporary
  home (findings 2, 3).
- **What restarts.** PVE: the API writes `pveproxy-ssl.pem`/`.key`; with
  `restart=1` (the hook always sends it) pveproxy reloads - **corrected
  (3)**: *before* the answer, by `systemctl reload-or-restart pveproxy`;
  old and new certificate alternate on new connections for about 4-6 s
  afterwards (observed with a systemctl shim; under systemd not measured).
  SICK's `verify_timeout` of 30 s covers that. `force=1` (always sent)
  replaces an existing custom certificate. PBS: `proxy.pem`/`.key`, the
  proxy reloads its certificate within the call; `restart` is "UI
  compatibility parameter, ignored" (PBS source) - **corrected (5)**: so is
  `force` (proxmox-backup `certificates.rs`, observed on PBS 4.2.8).
- **How `sick check` sees success.** On the port: 8006 for PVE, 8007 for
  PBS (`host`/`port` of the device). One device per PVE node; the hook's
  `DEPLOY_PROXMOXVE_NODE_NAME` and the device's `host` must name the same
  node.
- **How to get back.** Remove the device from the list, then
  `DELETE /api2/json/nodes/<node>/certificates/custom` (PVE: with
  `restart=1`, falls back to `pve-ssl.pem` of the cluster CA; PBS:
  regenerates a self-signed certificate and reloads). In the stand-in the
  self-signed certificate is presented again, `sick check` says
  `foreign-ca`, a normal `sick run` renews. **Corrected (4):** on a node
  without a custom certificate DELETE answers 200 as well (PVE ignores the
  missing files, PBS makes a new self-signed certificate), not 500.
- **Renewal with native ACME** (for chapter 4, read in the sources): PVE
  renews an ACME certificate once it expires within **30 days**, checked by
  the daily `pveupdate`. With the CA's default ACME lifetime of 720h that
  renews every day; the recipe needs `SICK_CA_ACME_LIFETIME` above 30 days
  (2160h, the default maximum, renews after 60 days). PBS renews at a third
  of the lifetime (half below 10 days, at least 3 days before the end),
  which fits any lifetime. A node with ACME configured *and* listed in SICK
  has two renewal jobs on one certificate (PVE renews a custom certificate
  by ACME when ACME domains are set; PBS has a single certificate path).
- **Default realm.** Both hooks default to the realm `pam` and the user
  `root`. The examples set `pve` / `pbs` and `sick` explicitly.

## Not tried

- The acme.sh hooks against a real PVE or PBS. (The API's real answers,
  401 texts, PBS error bodies, `"1"` booleans on pveproxy, the restart
  behaviour of pveproxy with a systemctl shim, and the `pveum` and
  `proxmox-backup-manager` commands have since been observed by
  SICK-Target-Proxmox on PVE 9.2.21 and PBS 4.2.8 in containers -
  `../sick-target-proxmox/docs/api-notes.md`, "Where the earlier session disagrees" and its `docs/real-node-trial.md`.) Still open there: a node under
  systemd, clusters (node name vs. host, `proxyto`), the GUI path for
  deleting.
- Native ACME on PVE and PBS (handbook chapter 4, written from the manual).
- An EC key (`key: ec256`): the stand-in would take it, the real products
  were not asked.
- A hook that verifies TLS: none exists in acme.sh 3.1.6 for these
  products.
