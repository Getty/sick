# 1. Planning

Half an hour with this chapter saves a root replacement later. Nothing here
is made yet; you write down what the CA will be allowed to do, for whom, and
for how long. Chapter 2 turns it into certificates.

## What you are building

```text
 offline:   root CA  (key on removable media / token, used only in ceremonies)
               │ signs, every few years
 online:    intermediate CA in step-ca  (name-constrained, issues all leaves)
               │
     ┌─────────┴───────────────────────────┐
     │ JWK provisioner "sick"              │ ACME provisioner "acme"
     │ (password held by the sick service) │ (anyone who can prove a name)
     ▼                                     ▼
 devices that cannot help themselves   services that speak ACME
 (switches, BMCs, appliances)          (Traefik, Caddy, Proxmox, cert-manager)

 trust:  root certificate ──► every client you own (chapter 3)
```

Four separate things, each with its own failure modes:

- **issuing** – step-ca and its provisioners decide who gets which name;
- **trust** – clients have to hold the root, and only the root;
- **deployment** – a certificate counts when the device *presents* it
  (SICK compares the fingerprint on the port, not a file);
- **operations** – renewal on a schedule, monitoring, backups, rotation.

A working CA says nothing about the other three.

## Names

Pick one DNS domain for everything internal and put every internal name
below it.

**Recommendation:** a subdomain of a domain you own, such as
`internal.example.com`, or `home.arpa` for a home network (RFC 8375, reserved
for exactly this). Reasons: nobody else can ever obtain or register it, and
it gives the name constraint of the CA a single, clear value.

Avoid:

- `.local` – it belongs to multicast DNS (RFC 6762); resolvers treat it
  specially.
- invented top-level domains (`.lan`, `.corp`, `.internal` before you have
  checked its status): a TLD that is delegated later turns your names into
  someone else's.
- bare host names (`switch`): they cannot be put under the constraint of a
  domain, and a client that searches domains may reach a different machine
  than the one the certificate names. Put the full name in the device list;
  add a bare name only if people really type it, and only for that device.

A device reached by address needs the address in its certificate (an IP
SAN). Write down which devices are reached by address.

## Networks

The intermediate carries the address ranges it may issue for, like the
domains. List the private ranges your devices live in, e.g.
`192.0.2.0/24`.

Per RFC 5280 a name form without a constraint is unconstrained: an
intermediate that names DNS domains and no IP range can still sign a
certificate for *any* address. So give both. If no certificate will ever
carry an address, say so with `--exclude-all-ip` in the ceremony
(chapter 2): it excludes `0.0.0.0/0` and `::/0`.

## What you have

Make a table of every device and service that should get a certificate,
and the way it gets one. The way decides the rest of the work:

| It … | Way | Chapter |
|---|---|---|
| speaks ACME itself (Traefik, Caddy, Proxmox VE, cert-manager, an nginx with an ACME client) | the ACME endpoint of step-ca | 4 |
| has an API or SSH but no ACME, and acme.sh has a deploy hook for it | SICK, type `acmesh` with that hook | 5 |
| is a Cisco Small Business switch | SICK, type `cisco-sb` (SICK-Target-CiscoSB) | 5 |
| reads its certificate from files | SICK, type `files` with a `reload` | 5 |
| none of these | a SICK-Target-* distribution has to be written, or the device stays as it is | – |

For each row note the names (DNS and IP), how it is reached for the check
(`host`, `port`), and who to call when it breaks.

## Lifetimes and key types

The rule behind every number: **a lifetime has to survive the longest outage
you are prepared to have** – of the CA, of the network to a device, of the
person who fixes it – with room to spare. A short lifetime limits the
damage of a stolen key (step-ca revokes passively, see chapter 2), a long
one limits the work. These are the defaults; each is a setting.

| Certificate | Default | Setting | Reason |
|---|---|---|---|
| root | 20 years, EC P-256 | `ceremony.sh --root-lifetime`, `--kty` | replacing it means touching every client (chapter 2, root rollover); its key is offline and used every few years |
| intermediate | 5 years, EC P-256 | `ceremony.sh --intermediate-lifetime` | its key is online in step-ca; a rotation needs only the offline root, no client changes. Renew it at least one device lifetime before it ends |
| devices (through SICK) | 397 days, RSA 2048, renewed 30 days before the end | `defaults: lifetime`, `renew_before`, `key` in the device list; ceiling `SICK_CA_MAX_LIFETIME` (19800h = 825 days) | devices have no automation of their own; old firmware takes RSA only. The 30 days are the recovery budget: SICK may fail for a month before a device expires |
| services (ACME) | 30 days, at most 90 | `SICK_CA_ACME_LIFETIME`, `SICK_CA_ACME_MAX_LIFETIME` | an ACME client renews at about two thirds of the lifetime; with 24 hours a CA outage longer than about 8 hours breaks services, with 30 days it may last about 10 days |

Apple platforms refuse a TLS server certificate issued after 2019-07-01
that is valid for more than 825 days, or that lacks the `serverAuth`
extended key usage, or uses an RSA key below 2048 bits ([Apple,
"Requirements for trusted certificates in iOS 13 and macOS
10.15"](https://support.apple.com/en-us/103769), checked 2026-10-10). The
398-day limit applies only to publicly trusted CAs, not to yours.

EC P-256 for the CA keys: small, fast, accepted by every client this
handbook covers. Choose `--kty RSA --size 4096` only if you have clients
that cannot verify an ECDSA signature. A device that needs an RSA *leaf*
(old switch firmware) gets one from an EC intermediate; the key type of a
leaf and of its issuer are independent.

## Who may get which certificate

Write this table for your CA; it is the enrollment policy. The one below is
what the Docker setup makes.

| Provisioner | Who holds the credential | What it can obtain | Profile |
|---|---|---|---|
| JWK `sick` | the sick service only: the password is a file in the CA volume, handed over read-only | any name the intermediate's constraints and the CA policy allow | `serverAuth` only, up to `SICK_CA_MAX_LIFETIME` |
| ACME `acme` | anyone who can reach the CA and prove control of a name (HTTP-01, TLS-ALPN-01, DNS-01) | names within the constraints and the policy that they can prove | `serverAuth` only, 30 days by default, at most 90 (chapter 4) |
| JWK `clients` | the admin who enrols people and machines (chapter 8) | email identities of persons, DNS names of machines, within constraints and policy | `clientAuth` only, 30 days, at most 90 |
| root key | the person(s) named in the ceremony record | a new intermediate | ceremonies only |

Two consequences worth stating:

- Whoever has the `sick` password can obtain a certificate for any name in
  scope. Treat it like the intermediate key; rotating it is in chapter 2.
- The ACME endpoint is as open as your network. If people outside your
  admin team can reach it and answer a challenge for a name in scope, they
  get a certificate. The name constraints and the policy are what bound it.

## Decisions that are yours

The full records – options, proposal, why, where it is set – are in
[decisions](decisions.md); the table is the short form.

Each is a setting; the recommendation is ours, with the reason.

| Decision | Setting | Recommendation | Why |
|---|---|---|---|
| Where the root key lives | `ceremony.sh --root-key`, `--root-password-file` | an encrypted key file on two removable media kept in different places, password stored separately; a YubiKey/HSM when you have one (chapter 2, *not tried*) | the root is needed every few years; losing it forces a root replacement, stealing it compromises everything |
| Names and networks | `ceremony.sh --dns`, `--ip`, `--email`, `--uri`, `--exclude-all-ip`; `SICK_CA_ALLOW_DNS`, `_IP`, `_EMAIL`, `_URI` | the one internal domain and the private ranges in use, nothing wider; with client certificates also the email domain (chapter 8) | the constraint is enforced by step-ca when it issues and by clients when they verify (both proven, chapter 2) |
| Lifetimes | table above | as in the table | recovery budget |
| Key types | `--kty`, device `key` | EC P-256 for the CA, RSA 2048 for device leaves | compatibility with old device firmware |
| Who may use ACME | network access to port 9000, policy, external account binding (`requireEAB`, card k51) | the CA reachable from the service networks only, policy no wider than your domain; EAB when it must be reachable more widely | the ACME endpoint issues to whoever proves a name – chapter 4 |
| Visibility of the repositories, CPAN release, image name and registry | – | the maintainer's | – |
| `docker/` and `t/e2e/` in the CPAN tarball | `dist.ini` | ship `docker/`, keep `t/e2e/` out | `docker/` is a documented way to run SICK; `t/e2e/run-lab.sh` changes a real switch |

## Test report

This chapter makes nothing and runs nothing. The figures in it are checked
where they take effect: the constraints, the profile of `sick` and the
ceremony in [chapter 2](02-the-ca.md#test-report); the Apple requirements
against Apple's page (2026-10-10). Not covered: whether *your* clients
accept ECDSA – list the old ones and try one before the ceremony.
