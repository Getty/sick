# Proxmox VE and Proxmox Backup Server through the acme.sh hooks

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

### Results

| Test | Expected | Observed |
|---|---|---|
| before: `sick check` | both `foreign-ca` (self-signed) | as expected |
| curl in the sick image to the self-signed API, verifying | refused | exit 60, stand-in logged `TLSV1_ALERT_UNKNOWN_CA` |
| `sick run pve pbs` | both renewed through their hooks | `renewed`, exit 0; acme.sh `Success` |
| request sequence | one POST per device, nothing else | exactly one each (recorded lines below) |
| fingerprint on 8006 / 8007 | = issued (device record) = uploaded | equal, both |
| APIs after the deployment, `curl --cacert root` | verify | verify |
| second `sick run` | unchanged, no upload | `unchanged ok`, upload count unchanged |
| token on curl's command line (slow upload, `/proc/*/cmdline` counted) | found (from reading) | found in 1 process; value never printed |
| wrong token, both hooks (`--force`) | 401, device fails with a clear message | `failed`: `deploy failed: acme.sh failed (exit 1): Certificate deployment failed (HTTP status 401).; …`; port unchanged |
| API answers 500, both | device fails | `failed`: `… (HTTP status 500). stand-in answers 500; …`; port unchanged |
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
PBS hook as JSON `true`; whether real pveproxy takes `"1"` in a JSON body
is not tried (its parameter schema says boolean).

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
   (HTTP status, and for a 500 the API's `message`).
5. **The wrong-token message is good enough, the closed-port one is not
   pretty**: `HTTP status 401` names the cause; a closed API port reads
   `error code: 7; Certificate deployment failed (HTTP status ).` - curl's
   exit code 7 is "could not connect". Both come from the hook; SICK
   passes them on.

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
  Commands in `contrib/devices/proxmox/README.md` (from the manuals, not
  run).
- **Where the secret lives.** A file of its own named in `env_files`;
  SICK hands it to acme.sh in the environment only. Also, for the duration
  of the call, on curl's command line, and in the `.conf` of the temporary
  home (findings 2, 3).
- **What restarts.** PVE: the API writes `pveproxy-ssl.pem`/`.key`; with
  `restart=1` (the hook always sends it) pveproxy restarts after the
  answer - SICK's `verify_timeout` of 30 s covers that in the stand-in;
  the real restart time is not measured. `force=1` (always sent) replaces
  an existing custom certificate. PBS: `proxy.pem`/`.key`, the proxy reloads
  its certificate within the call; `restart` is "UI compatibility
  parameter, ignored" (PBS source).
- **How `sick check` sees success.** On the port: 8006 for PVE, 8007 for
  PBS (`host`/`port` of the device). One device per PVE node; the hook's
  `DEPLOY_PROXMOXVE_NODE_NAME` and the device's `host` must name the same
  node.
- **How to get back.** Remove the device from the list, then
  `DELETE /api2/json/nodes/<node>/certificates/custom` (PVE: with
  `restart=1`, falls back to `pve-ssl.pem` of the cluster CA; PBS:
  regenerates a self-signed certificate and reloads). In the stand-in the
  self-signed certificate is presented again, `sick check` says
  `foreign-ca`, a normal `sick run` renews.
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

- Everything against a real PVE or PBS (the HQ list): the API's real
  answers and status lines (401 text, 500 bodies), JSON with `"1"` booleans
  on real pveproxy, the restart time of pveproxy, clusters (node name vs.
  host, `proxyto`), the `pveum` and `proxmox-backup-manager` commands of
  the recipe, the GUI path for deleting.
- Native ACME on PVE and PBS (handbook chapter 4, written from the manual).
- An EC key (`key: ec256`): the stand-in would take it, the real products
  were not asked.
- A hook that verifies TLS: none exists in acme.sh 3.1.6 for these
  products.
