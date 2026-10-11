# Proxmox VE and Proxmox Backup Server

Three ways to give a Proxmox node a certificate of your CA, in this order:

1. **Native ACME** (handbook, chapter 4) – the node renews by itself, SICK
   holds no token. Use it wherever the CA can reach the node on port 80 under
   its name. PVE uses the ACME provisioner `acme-long` (60 days; PVE renews
   once less than 30 days are left), PBS fits the 30-day `acme`.
2. **SICK with the device types `proxmox-ve` / `proxmox-bs`** of
   [SICK-Target-Proxmox](https://github.com/Getty/sick-target-proxmox) –
   when the CA cannot reach the node, or you want SICK's inventory and
   monitoring for it. The node's API is **always verified**, the token is
   read from a file and goes into the request header only. Example entries:
   [`sick.example.yml`](sick.example.yml). The sick image carries the
   distribution.
3. **The acme.sh hooks `proxmoxve` / `proxmoxbs`** through the device type
   `acmesh` – **not recommended**, described below for what they are.

## The device types (way 2)

Everything that matters is in the distribution's own documentation – read
it there rather than a copy here:

- `perldoc SICK::Target::ProxmoxVE`, `perldoc SICK::Target::ProxmoxBS`:
  options, how the host is trusted, the token and its rights (with the
  `pveum` / `proxmox-backup-manager` commands, run as written on PVE 9.2.21
  and PBS 4.2.8), the way back;
- `docs/decisions/` there: why it is built this way (trust in the node,
  HTTP client, types and options, token rights);
- `docs/api-notes.md` there: what the APIs do, each statement with its
  origin – including two things that break a node: PBS answers 200 to a key
  that does not belong to the certificate, writes it, and then no longer
  starts its proxy; a wrongly ordered chain stops pveproxy. The device types
  check both before they upload.

In short:

| | PVE (`proxmox-ve`) | PBS (`proxmox-bs`) |
|---|---|---|
| Port | 8006 by default | 8007 by default |
| First upload trusted by | the cluster CA (`ca: /etc/pve/pve-root-ca.pem`, copied over SSH with a known host key) or a pin (`fingerprint`) | a pin of its self-signed certificate (`fingerprint`) |
| Afterwards trusted by | the roots of SICK's CA, which the run hands the target | the same |
| Rights | `Sys.Modify` on `/nodes/<node>`, in a role of its own; a privilege-separated token with an expiry, two ACL lines | `Admin` on `/system/certificates` (the only role holding `Sys.Modify` there); two ACL lines |
| After the upload | pveproxy restarts (old and new certificate alternate for a few seconds) | the proxy reloads its certificate |
| `sick check` looks at | port 8006 | port 8007 |
| Way back | delete the custom certificate: the node presents `pve-ssl.pem` of the cluster CA again | delete the custom certificate: PBS makes a new self-signed one |

Take the device out of the device list before you go back, or the next run
uploads again.

## The acme.sh hooks (way 3, not recommended)

acme.sh 3.1.6's hooks `proxmoxve` and `proxmoxbs` work, but they:

- **do not verify the TLS certificate of the API** (`HTTPS_INSECURE=1`
  inside the hook; nothing switches it back), so the token and the private
  key go to whatever answers at that address;
- put the token on curl's command line for the duration of the call.

That is why SICK-Target-Proxmox exists (decided by the maintainer,
2026-10-11). What was observed about the hooks is in
[`docs/findings/device-proxmox.md`](../../../docs/findings/device-proxmox.md),
corrected where the earlier stand-in differed from real nodes.
