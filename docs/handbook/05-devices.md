# 5. Devices that cannot

You end this chapter with the devices that cannot fetch a certificate
themselves – switches, routers, hypervisors, appliances, plain Linux hosts
– served by SICK from your CA and renewed on the schedule of chapter 6.

SICK does the same four steps for every device: check what the device
presents on its port, issue, deploy, check again. **A deployment counts
only when the device presents the new certificate on the port**, compared
by fingerprint. That is not a formality: in the tests below, acme.sh
reported "Success" twice when nothing was live – RouterOS exits 0 on a
failed import, nginx exits 0 when the master cannot apply a reload – and
SICK's check caught both.

## Which way for which device

| Device | Way | Decision, and what spoke against the alternatives |
|---|---|---|
| a service that reads files (nginx, HAProxy, Grafana, …) on the SICK host | type `files` | built in, no network, one generation at a time with rollback (chapter 6). Nothing to decide |
| Cisco Small Business switch (SG300/SG500) | type `cisco-sb` (distribution SICK-Target-CiscoSB) | the switch has no ACME and no hook in acme.sh; the dialog over its CLI is the only way. Proven against a real switch in the lab (phase 1) |
| Linux host with a web server, reached over SSH | type `acmesh`, hook `ssh` | the hook exists and is small; a SICK target of our own would add nothing but code. Proven against an sshd container |
| MikroTik RouterOS | type `acmesh`, hook `routeros` | the hook exists; a target on `WWW::MikroTik` would need that module first. Proven against a real RouterOS CHR 7.24.5 in qemu |
| Proxmox VE, Proxmox Backup Server | **native ACME** (chapter 4) where the CA can reach the node on port 80; otherwise `acmesh` with the hooks `proxmoxve` / `proxmoxbs` | native ACME keeps the API token out of SICK entirely. The hooks **do not verify the API's TLS certificate** and put the token on curl's command line (card k56); use them only over a network path you trust as much as the token. Hooks proven against a stand-in API; nothing tried on a real PVE/PBS |
| Kubernetes Secret | **cert-manager in the cluster** (chapter 4); no SICK target | see below |
| Dell iDRAC 7/8 | a future distribution SICK-Target-IDRAC on `WWW::iDRAC` | that module has no certificate functions yet; card k18 lists what SICK needs and what is open. Deferred |

**Kubernetes Secrets: no SICK target.** cert-manager already does what a
target would do – issue, store in a Secret, renew – inside the cluster, with
the cluster's own access control, and it is proven against your CA in
chapter 4 (ACME and step-issuer). The cases where a target might seem
needed do not hold up: a cluster without cert-manager should get
cert-manager (one manifest, pinned); a Secret for something that is no
Ingress (a database, a webhook) is still a cert-manager `Certificate`; and a
SICK outside the cluster writing Secrets would need cluster credentials
with write access to Secrets, which is a wider grant than cert-manager's.
If a case remains, a `files` device with a `reload` that runs `kubectl
apply` under a ServiceAccount allowed to update exactly that one Secret
works without new code (*not tried*).

## How a recipe is read

Every recipe answers the same five questions:

- **Access** – which rights the account on the device needs, and how to
  keep them small;
- **Secret** – where the credential lives (always a file named in the
  device list, never the list itself, the environment of a container or a
  command line where avoidable);
- **Restart** – what the device restarts or reloads after the deployment;
- **Check** – which port `sick check` looks at (`host`, `port` of the
  device);
- **Way back** – what to do when it went wrong.

## The first device: a file-based service

The quickest first device is a service on the SICK host that reads its
certificate from files.

```yaml
devices:
  grafana:
    type: files
    names: [grafana.example.internal]
    host: grafana.example.internal      # check the port, not the file
    port: 3000
    dir: /srv/certs/grafana
    reload: [systemctl, reload, grafana-server]
```

```console
$ sick check grafana
DEVICE   STATUS   RENEW  DETAIL
grafana  missing  yes    the device presents no certificate
$ sick run grafana
DEVICE   ACTION   REASON
grafana  renewed  missing
$ sick run grafana
DEVICE   ACTION     REASON
grafana  unchanged  ok
```

(The output has this form; the names are the example's.)

- **Access:** the user SICK runs as writes `dir`; the reload command runs
  as that user.
- **Secret:** none besides the key, written 0600 into the generation
  directory.
- **Restart:** the `reload` command. The service must read the files
  through the links (`dir/cert.pem` → `.sick/current/…`); mount the
  directory into a container, not single files.
- **Check:** `host`/`port`; without `host`, SICK reads `dir/cert.pem`.
- **Way back:** automatic – a failed reload switches back to the previous
  generation and reloads again (chapter 6).

`t/e2e/run-local.sh` runs exactly this, in Docker, against the lab CA.

## Cisco Small Business switches

Type `cisco-sb`, distribution SICK-Target-CiscoSB; its README and
`docs/device-notes.md` are the reference. In short:

- **Access:** a switch user with privilege level 15 (below it the switch
  gives the unprivileged prompt, which cannot import), SSH enabled; older
  firmware needs `legacy_algorithms: true`. The host key is checked
  (`host_key_check: strict` by default).
- **Secret:** a credentials file (line 1 user, line 2 password), mode 0600,
  named in the device list.
- **Restart:** none; the switch makes the filled slot active and, with
  `save: true` (default), saves the running configuration – which saves
  *everything* unsaved on the switch.
- **Check:** port 443 of the switch. It presents the certificate **alone**
  (one slot): set `ca.intermediates`, and give clients `ca_bundle.pem` or the
  intermediate without trust (chapter 3).
- **Way back:** a refused import can empty the slot – the target compares
  public keys before it imports; a fresh `sick run --force` puts a new
  certificate in.

## Linux hosts over SSH

Recipe: [`contrib/devices/linux-ssh/`](../../contrib/devices/linux-ssh/),
evidence: [`docs/findings/device-ssh.md`](../findings/device-ssh.md).

```yaml
devices:
  www:
    type: acmesh
    hook: ssh
    names: [www.example.internal]
    host: www.example.internal
    env:
      DEPLOY_SSH_USER: sick-deploy
      DEPLOY_SSH_SERVER: www.example.internal
      DEPLOY_SSH_CMD: "ssh -i /etc/sick/secrets/www-deploy.key -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/sick/secrets/www.known_hosts"
      DEPLOY_SSH_USE_SCP: "yes"
      DEPLOY_SSH_KEYFILE: /etc/nginx/tls/key.pem
      DEPLOY_SSH_FULLCHAIN: /etc/nginx/tls/fullchain.pem
      DEPLOY_SSH_REMOTE_CMD: "sudo -n /usr/sbin/nginx -s reload"
```

(`contrib/devices/linux-ssh/sick.yml` has the complete entry, including
`DEPLOY_SSH_SCP_CMD`.)

- **Access:** an account `sick-deploy`, password locked, key only, owning
  the certificate directory and nothing else; its `.ssh` belongs to root.
  One sudo rule naming the arguments: `sick-deploy ALL=(root) NOPASSWD:
  /usr/sbin/nginx -s reload` – a rule for `nginx` with any arguments would
  let it start nginx as root with its own configuration. In
  `authorized_keys`: `restrict,from=<SICK's address>`. Without the hook's
  backup (`DEPLOY_SSH_BACKUP=no`) a forced command
  (`sick-deploy-gate`) allows exactly the two uploads and the reload, and
  the account needs no shell at all.
- **`DEPLOY_SSH_USE_SCP=yes` is required.** Without it the hook writes the
  TLS key with `echo "<key>" > file` inside the command it sends – the key
  is then in the argument list of the shell on the host and of `ssh` on the
  SICK host.
- **Secret:** the deploy key and the `known_hosts` are files in SICK's
  secrets directory, named inside `DEPLOY_SSH_CMD`. Build the `known_hosts`
  from the host key as read on the host itself (console, configuration
  management), not with `ssh-keyscan` over the network.
- **Restart:** nothing restarts; nginx reloads. `nginx -s reload` checks the
  configuration and the certificates first and keeps the old ones on an
  error.
- **Check:** port 443 of the host.
- **Way back:** a refused reload leaves the new key and certificate on
  disk, the old ones in `/etc/nginx/tls/backup/<name>-backup-<time>/` (the
  hook's backup, kept up to 180 days – they contain keys). Fix the cause and
  reload, or copy the backup back.

## MikroTik RouterOS

Recipe: [`contrib/devices/routeros/`](../../contrib/devices/routeros/),
evidence: [`docs/findings/device-routeros.md`](../findings/device-routeros.md).

- **Access:** a group of its own with `ssh,ftp,read,write` and everything
  else off (`sick-user.rsc`); each of the four was needed on RouterOS 7.24.5,
  as MikroTik's "User" page describes (read 2026-10-11). `write` is most of
  the router: limit the user by `address=` to the SICK host and use a key,
  no password.
- **Secret:** the deploy key, a file named in `ROUTER_OS_SSH_CMD` and
  `ROUTER_OS_SCP_CMD` (no spaces in those paths: the hook splits them; the
  port goes into them too, `ROUTER_OS_PORT` is then ignored). The hook has no
  password setting.
- **Restart:** none. `/ip service set www-ssl certificate=<name>.cer_0`;
  www-ssl presents the new certificate at the next connection. The hook does
  not enable www-ssl – that is setup.
- **Check:** the port of www-ssl (443 unless moved). This matters more than
  usual: RouterOS answers failures at run time with exit code 0, so
  "Success" from the hook does not mean imported.
- **Way back:** none on the router – the hook removes the previous
  `<name>.cer_0` … `_3` before it imports. Keep another certificate on the
  router (one RouterOS made itself) to point www-ssl at in an emergency.
  After a failed run the private key may stay in `/file` (readable by every
  user with `ftp`) until the next good run.

## Proxmox VE and Proxmox Backup Server

Recipe: [`contrib/devices/proxmox/`](../../contrib/devices/proxmox/),
evidence: [`docs/findings/device-proxmox.md`](../findings/device-proxmox.md).

**Recommendation: native ACME** (chapter 4) wherever the CA can reach the
node on port 80 – the node renews by itself and SICK holds no token. Two
things to know: PVE renews an ACME certificate once it expires within 30
days (checked daily), so with the CA's default 30-day ACME certificates a
PVE node renews every day; give it longer certificates or accept that
(card k57). PBS renews at a third of the lifetime and fits.

**Otherwise the hooks**, as `acmesh` devices:

- **Access:** PVE: `Sys.Modify` on `/nodes/<node>` – there is no smaller
  privilege for the custom certificate, and it also covers the node's
  network, DNS, time, APT and services. Keep it small: a user in the `pve`
  realm without password, a role with `Sys.Modify` only, a
  privilege-separated API token with an expiry, the ACL on the one node.
  PBS: `Sys.Modify` on `/system/certificates`, which only the role `Admin`
  holds – `Admin` on that path. (Commands in the recipe, from the manuals,
  *not run*.) Set the realm explicitly (`DEPLOY_PROXMOXVE_USER_REALM=pve`):
  both hooks default to `root@pam`.
- **Secret:** the token secret in a file named in `env_files`; SICK hands it
  to the hook through its environment only. **But** the hook puts it on
  curl's command line during the call, and **does not verify the API's
  TLS certificate** (`HTTPS_INSECURE=1`, cannot be switched off): the token
  and the private key go to whatever answers at that address. Card k56.
- **Restart:** PVE restarts pveproxy after the upload (the hook always
  sends `restart=1`); PBS reloads its certificate within the call.
- **Check:** port 8006 (PVE) or 8007 (PBS); one device per PVE node, with
  `DEPLOY_PROXMOXVE_NODE_NAME` naming the same node as `host`.
- **Way back:** delete the custom certificate (`DELETE
  /api2/json/nodes/<node>/certificates/custom`, in the GUI *Certificates →
  Delete custom certificate*): PVE falls back to the certificate of its
  cluster CA, PBS makes a new self-signed one. Remove the device from the
  list first, or the next run puts a new one in.

## Dell iDRAC 7/8

Not yet. A SICK-Target-IDRAC distribution on `WWW::iDRAC` needs a login with
credentials from a file, an upload of key and certificate (or a CSR with
SANs made on the iDRAC), and a reset of its web server; SICK checks the
port itself. Card k18 lists this and the questions to settle on a real iDRAC
7 and 8 first.

## A device type of your own

When none of the above fits, a device type is a distribution of its own,
`SICK-Target-<Name>`, subclassing `SICK::Target`: see the README, "Adding a
device type", and SICK-Target-CiscoSB as the worked example.

## Test report

All e2e scripts were run against the committed state `8c14cbb` on
2026-10-11, at the end of this package: `run-local.sh` 33 PASS,
`ca-ceremony.sh` 101, `ca-recovery.sh` 51, `ca-rollover.sh` 125,
`trust-anchors.sh` 96 PASS and its 8 expected FAIL findings, `trust-os.sh`
465, `trust-runtimes.sh` 147, `ops.sh` 72, `acme-services.sh` 31 per
service, `acme-k8s.sh` all parts, `device-ssh.sh` 71, `device-routeros.sh`
46 (stand-in and CHR), `device-proxmox.sh` 73; each with 0 unexpected
FAIL; afterwards nothing labelled `sick=1`, no `sick-*` k3d cluster, the
host's default kubeconfig untouched. The rows below are the development
runs.

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/e2e/run-local.sh` | step-ca 0.30.2, sick image | a `files` device renewed, checked on its port, a second run changes nothing | ALL PASSED | – |
| `t/e2e/device-ssh.sh`, twice | debian trixie-20261005-slim (nginx 1.26.3, OpenSSH 10.0p1, sudo 1.9.16p2), step-ca 0.30.2, acme.sh 3.1.6 | renewed, port fingerprint = issued; second run unchanged; the account cannot write elsewhere or sudo anything else; unknown and changed host key refused, nothing written; unauthorized key refused; reload refused → old certificate on the port, backup restores; reload accepted but not taken → SICK fails the device; unreachable → nothing issued; forced-command variant renewed | 71 PASS each run | a real host outside Docker; Apache, HAProxy |
| `t/e2e/device-routeros.sh` | stand-in on alpine 3.22 (OpenSSH 10.0p1); RouterOS CHR 7.24.5 in qemu 10.0.0 (TCG, no KVM); acme.sh 3.1.6 | stand-in: uploads and the exact command sequence recorded, no secret in any output, unknown host key refused, a failing script fails the device, an exit-0 non-import caught by the port check. CHR: missing → renewed, www-ssl presents the issued certificate, `cer_0` holds it with its key, nothing left on the router; second run unchanged; `--force` replaces; unknown host key refused; a group without `read` fails the device | 46 PASS; the CHR part three times | a physical router; RouterOS 6; a chain with an intermediate; an EC key; the ~4 s gap between `remove` and `set` |
| `t/e2e/device-proxmox.sh`, twice | python 3.14.8-slim stand-in API, step-ca 0.30.2, acme.sh 3.1.6 | one upload per device with the recorded fields; port 8006/8007 presents the issued certificate; second run uploads nothing; wrong token (401), API error (500), API port closed, node down → device fails or unreachable, port unchanged; no token in any output; DELETE brings the self-signed certificate back | 73 PASS each run | everything against a real PVE or PBS; the `pveum` / `proxmox-backup-manager` commands; native ACME on PVE/PBS |
| `t/42-target-acmesh.t` (in `prove -lr t`) | acme.sh 3.1.6 | the `acmesh` mechanism with the hook `localcopy` | green | – |
