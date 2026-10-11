# Proxmox VE and Proxmox Backup Server

Two ways to give a PVE node or a PBS host a certificate of the internal CA:

| | Native ACME | SICK with the acme.sh hook |
|---|---|---|
| How | the node's own ACME client (`pvenode acme`, `proxmox-backup-manager acme`) orders from the provisioner `acme` of the CA | SICK issues, the hook `proxmoxve` / `proxmoxbs` uploads certificate and key through the API |
| Needs | the CA reaches the node on port 80 under its name (http-01, standalone); the node trusts the root | SICK reaches the API on 8006 / 8007; an API token with `Sys.Modify` |
| Private key | made on the node, never leaves it | made by SICK, sent to the node in the API call |
| Credential | none beyond the ACME account on the node | an API token, stored with SICK |
| TLS to the node | – | **not verified** by the hooks (below) |
| Renewal | the node's daily update job | `sick run` on its schedule |
| Tried | *not tried* (handbook, chapter 4) | against a stand-in API only (`t/e2e/device-proxmox.sh`) |

**Recommendation: native ACME wherever the CA can reach the node on port
80.** The key stays on the node, there is no token with wide rights to keep,
and nothing is sent over an unverified connection. Use the hooks when the
node sits in a network the CA cannot reach (a management VLAN that only
SICK's host can talk to), and then only over a path you trust as much as
the token: see "The TLS gap".

For native ACME on PVE: the CA's ACME lifetime must be longer than 30 days.
PVE renews an ACME certificate when it expires within 30 days, checked
daily (`bin/pveupdate` of pve-manager, read 2026-10-11); with the default
`SICK_CA_ACME_LIFETIME=720h` (30 days) that is a new certificate every day.
`2160h` (the default maximum) renews after 60 days. PBS renews at a third of
the lifetime (half below 10 days, at least 3 days before the end;
`cert_renew_lead_time` in proxmox-backup, read 2026-10-11), which fits any
lifetime. Do not configure ACME on a node *and* list it in SICK: both
renewal jobs look at the same certificate.

## The TLS gap

Both hooks set `HTTPS_INSECURE=1` before their one API call (acme.sh
3.1.6, `deploy/proxmoxve.sh` and `deploy/proxmoxbs.sh`), and acme.sh turns
that into `curl --insecure`. It is set inside the hook function, so neither
the environment nor `CA_BUNDLE` / `CA_PATH` can switch it back on. The hook
sends the **API token and the private key** to whatever answers at
`DEPLOY_PROXMOX*_SERVER`. After the first deployment the node presents a
certificate of the CA, so verification *could* work; the hooks still do not
verify.

The hook also passes the token to curl as a command line argument (`-H
"Authorization: ..."`): while the call runs, any process that can read
`/proc/<pid>/cmdline` on SICK's host sees it. In the Docker setup that is
the sick container and root on the host.

What this means in practice:

- run SICK on a host in the management network of the nodes, not across a
  network you do not control;
- give the token nothing but the certificate right (below), with an expiry
  date, and replace it when in doubt;
- run SICK in its container (or on a host of its own), so that no other user
  sees its processes.

## The token and its rights

The certificate upload needs `Sys.Modify` (API schemas, read 2026-10-11:
PVE `apidoc.js` of 2026-09-24, PBS 4.2.8):

| | Endpoint | Permission |
|---|---|---|
| PVE | `POST /api2/json/nodes/{node}/certificates/custom` (and `DELETE`) | `Sys.Modify` on `/nodes/{node}`; API tokens allowed |
| PBS | `POST /api2/json/nodes/{node}/certificates/custom` (and `DELETE`) | `Sys.Modify` on `/system/certificates` |

On **PVE** there is no smaller privilege for it, and `Sys.Modify` on a node
is much more than certificates: by the same schema it also changes the
node's network, DNS, hosts file, time, APT repositories and firewall rules,
and starts and stops its services. Keep it to one node per token where you
can, and use a role that holds nothing else:

```bash
# on a PVE node (pveum, from the manual; not run by the authors)
pveum user add sick@pve --comment 'SICK: certificate upload'
pveum role add SICKCertificate --privs Sys.Modify
pveum user token add sick@pve sick --privsep 1 --expire <epoch> --comment 'SICK'
#   prints the secret once: put it into a file for SICK, nowhere else
pveum acl modify /nodes/pve1 --roles SICKCertificate --users sick@pve
pveum acl modify /nodes/pve1 --roles SICKCertificate --tokens 'sick@pve!sick'
```

The user in the `pve` realm has no password and cannot log in; a
privilege-separated token (`--privsep 1`) has only what its own ACL gives
it, and never more than its user. For a cluster: one ACL line per node
(`/nodes/<node>`), or `/nodes` for all, which is wider.

On **PBS** the path `/system/certificates` is narrow, but the role is not:
of the fixed roles of PBS only `Admin` holds `Sys.Modify`
(`pbs-api-types/src/acl.rs`). On that path it covers the certificate and the
ACME settings of the host, nothing else.

```bash
# on PBS (proxmox-backup-manager, from the manual; not run by the authors)
proxmox-backup-manager user create sick@pbs --comment 'SICK: certificate upload'
proxmox-backup-manager user generate-token sick@pbs sick
#   prints the secret once
proxmox-backup-manager acl update /system/certificates Admin --auth-id sick@pbs
proxmox-backup-manager acl update /system/certificates Admin --auth-id 'sick@pbs!sick'
```

## Where the secret lives

In a file of its own, one line, mode 0600, named in `env_files`
(`sick.example.yml` here; in the Docker setup under `docker/secrets/`). SICK
reads it, hands it to acme.sh in the environment only and blanks it in what
acme.sh prints. The hook writes it into the `.conf` of its temporary home
(`SAVED_DEPLOY_PROXMOX*_API_TOKEN_KEY`), which SICK removes after the call
- do not give these devices a `home` of their own, or it stays there in
plain text. And it is on curl's command line while the call runs (above).

## What the device does

- **PVE**: writes `pveproxy-ssl.pem` / `pveproxy-ssl.key` of the node; with
  `restart=1`, which the hook always sends, pveproxy is restarted in the
  background after the call has answered. SICK waits up to 30 seconds for
  the new certificate on the port (`verify_timeout`). `force=1` (also always
  sent) lets it replace an existing custom certificate.
- **PBS**: writes `proxy.pem` / `proxy.key` and reloads the certificate of
  the proxy within the call; `restart` is ignored ("UI compatibility
  parameter", PBS source).

## How sick check sees success

By the certificate on the port: `host` and `port` of the device, 8006 for
PVE, 8007 for PBS (or 443 when a reverse proxy in front of the GUI is what
users reach - then that proxy is the device, not the node).

## Getting back

Take the device out of the device list first, or the next run uploads
again. Then delete the custom certificate:

- **PVE**: in the GUI (node, System, Certificates, "Delete custom
  certificate"), or `DELETE /api2/json/nodes/<node>/certificates/custom`
  with `restart=1`. The node presents its `pve-ssl.pem` again, signed by
  the cluster's own CA.
- **PBS**: `DELETE /api2/json/nodes/localhost/certificates/custom`; PBS
  regenerates a self-signed certificate and reloads.

With curl, the header from a file so the token stays off the command line:
`curl -X DELETE -H @header-file https://pve1.example.internal:8006/api2/json/nodes/pve1/certificates/custom?restart=1`.

## Not tried

Everything against a real PVE or PBS: the commands above, the exact error
texts and status lines of the real APIs, pveproxy's restart time, JSON
bodies on the real pveproxy, clusters. `t/e2e/device-proxmox.sh` proves the
hooks' side against a stand-in; `docs/findings/device-proxmox.md` has what
was run.
