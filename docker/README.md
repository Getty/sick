# SICK with Docker Compose

A certificate authority, SICK on a schedule and a page that hands your
clients what they have to trust – three containers, one `docker compose up`.

```
            ┌───────────────┐   step ca certificate   ┌────────────────┐   ssh, API, files   ┌─────────┐
            │ ca            │◄────────────────────────│ sick           │────────────────────►│ devices │
            │ step-ca       │   root, intermediate,   │ sick run       │                     └─────────┘
 :9000 ◄────│ + init-ca.sh  │   provisioner password  │ every interval │
 (ACME,     └───────────────┘────── volume ──────────►│ sick trust     │
  step)                                               └───────┬────────┘
                                                              │ volume
                                                      ┌───────▼────────┐
                                              :8080 ◄─│ trust          │
                                                      │ busybox httpd  │
                                                      └────────────────┘
```

| Service | Image | What it does |
|---|---|---|
| `ca` | the official `smallstep/step-ca` | the CA. `init-ca.sh` sets it up at the first start – root and intermediate made there (lab mode) or imported from a ceremony (import mode) –, a JWK provisioner `sick` that grants up to 825 days, an ACME provisioner `acme` |
| `sick` | built here: Debian, Perl, `SICK`, `SICK-Target-CiscoSB`, `step`, `acme.sh` with its deploy hooks, `openssl`, `ssh` | `sick run` now and then every `SICK_INTERVAL`, `sick trust` after every run |
| `trust` | `busybox` (its `httpd`) | serves what `sick trust` wrote: `index.html`, the root (`root_ca.pem`, `root_ca.crt`), the intermediate (`intermediate_ca.pem`, `intermediate_ca.crt`), both in one file (`ca_bundle.pem`) and a profile for Apple devices with both (`root_ca.mobileconfig`) |

Run on Debian 13 with Docker Engine 26.1 and Compose 2.26 against an
SG300-20 switch, and nowhere else so far; the transcript is
[at the end](#the-proof). The health check of the CA uses `start_interval`,
which Docker Engine has since version 25, and the build needs BuildKit.

## Quick start

SICK and SICK-Target-CiscoSB are not on CPAN yet, so the image is built from
two checkouts that lie next to each other:

```
somewhere/
  sick/                   this repository
  sick-target-ciscosb/
```

```bash
cd somewhere/sick/docker
cp sick.example.yml sick.yml         # your devices; see below
mkdir -m 700 secrets                 # the credential files sick.yml names
docker compose up -d --build
docker compose logs -f sick
```

`sick.yml` and `secrets/` are yours and are ignored by git. To keep them
somewhere else – outside the checkout is the better place – name them in an
`.env` file next to `compose.yml`, or in the environment:

```bash
# docker/.env
SICK_CONFIG_FILE=/etc/sick/sick.yml
SICK_SECRETS_DIR=/etc/sick/secrets
SICK_CA_NAME=Example Internal CA
SICK_CA_DNS=ca.example.internal,192.0.2.5
SICK_CA_ALLOW_DNS=*.example.internal
SICK_CA_ALLOW_IP=192.0.2.0/24
```

Then:

- the CA is at `https://<host>:9000` – for `step`, and for everything that
  speaks ACME itself: `https://<host>:9000/acme/acme/directory`;
- the trust page is at `http://<host>:8080/`.

Everyday commands:

```bash
docker compose run --rm sick sick check          # what does every device present?
docker compose run --rm sick sick run --verbose  # renew what is due, now
docker compose run --rm sick sick run --force switch
docker compose logs sick                         # what the schedule did
```

## Settings

All of them are optional.

| Variable | Default | |
|---|---|---|
| `SICK_CONFIG_FILE` | `./sick.yml` | the device list on the host; mounted read-only as `/etc/sick/sick.yml` |
| `SICK_SECRETS_DIR` | `./secrets` | directory on the host with the secret files the list names; mounted read-only as `/etc/sick/secrets` |
| `SICK_INTERVAL` | `1d` | pause between two runs: `1d`, `12h`, `30m`, `90s` or seconds |
| `SICK_RUN_OPTIONS` | `--verbose` | options of the scheduled `sick run`; set it to nothing for the table alone |
| `SICK_CA_NAME` | `SICK Internal CA` | name of the CA. Used once, when the CA is made |
| `SICK_CA_DNS` | | further names and addresses under which the CA is reached, comma separated – for its own TLS certificate. Lab mode adds `ca` and `localhost`; import mode requires the list and takes it alone. Used once |
| `SICK_CA_IMPORT` | | import mode, with `compose.import.yml`: the output directory of `ceremony.sh`. Read at the first start only |
| `SICK_CA_MAX_LIFETIME` | `19800h` | the longest lifetime the provisioner `sick` grants (825 days, the most Apple accepts from a private CA). Hours, minutes, seconds – step-ca knows no days |
| `SICK_CA_ACME_LIFETIME` | `720h` | the lifetime the ACME provisioner `acme` gives a certificate (30 days, see below) |
| `SICK_CA_ACME_MAX_LIFETIME` | `2160h` | the longest lifetime `acme` grants a client that asks for one (90 days) |
| `SICK_CA_ACME_MIN_LIFETIME` | `5m` | the shortest (step-ca's own default). Go durations, like the lifetime of `sick`; minimum ≤ lifetime ≤ maximum, or the CA does not start |
| `SICK_CA_ACME_CHALLENGES` | | the challenge types `acme` offers, comma separated, out of `http-01`, `tls-alpn-01`, `dns-01`. Empty: all three (step-ca's default) |
| `SICK_CA_PROVISIONERS` | | further provisioners, with `compose.provisioners.yml`: a JSON file on the host (see "Further provisioners") |
| `SICK_CA_ALLOW_DNS` | | names the CA may issue for, comma separated: `*.example.internal`, `host.example.org` |
| `SICK_CA_ALLOW_IP` | | addresses and networks the CA may issue for: `192.0.2.0/24`. Both empty: no restriction. One of them set: nothing but what is listed |
| `SICK_CA_PORT` | `9000` | published port of the CA |
| `SICK_TRUST_PORT` | `8080` | published port of the trust page |
| `SICK_BUILD_CONTEXT` | `../..` | the directory that holds both checkouts |
| `SICK_FROM` | `local` | `cpan` installs SICK from CPAN instead of the checkouts |
| `SICK_IMAGE` | `sick:local` | name of the image that is built and run |
| `STEP_VERSION` | `0.30.2` | version of step-ca and of the `step` in the sick image |

## The device list and its secrets

`sick.example.yml` is a start. The `ca` section fits this setup as it is; the
paths are those inside the `sick` container:

| Path in the container | |
|---|---|
| `/etc/sick/sick.yml` | your device list |
| `/etc/sick/secrets/` | your secrets directory |
| `/etc/sick/ca/root_ca.crt`, `intermediate_ca.crt`, `provisioner.pw` | handed over by the `ca` service |
| `/var/lib/sick/` | state: the `known_hosts` of `ssh`, the lock of `sick run` (`sick.lock`) and one record per device (`devices/<name>.json`, never a key). A good place for the `dir` of a `files` device, too |
| `/srv/trust/` | output of `sick trust` |
| `/tmp/` | memory only; where a new key lies for a moment |

Secrets are files, never environment variables and never part of the image:

- **Device credentials** – in your secrets directory, `chmod 600`, owned by
  root. `sick` runs as root inside its container so that it can read them
  without you opening them up; in exchange it has no capability at all
  (`cap_drop: ALL`), a read-only file system and no way to gain privileges.
  Without capabilities, root cannot read past file modes either: the device
  list and the secrets have to be owned by root (or readable by everyone, which
  is fine for a `sick.yml` without secrets). A list owned by your user with mode
  `0600` ends in `cannot read config file '/etc/sick/sick.yml': Permission denied`.
- **The provisioner password** – generated by `init-ca.sh`, kept in the
  volume of the CA and handed to the `sick` service through a volume the two
  share (`handover`), readable by root alone.
- **The password of the CA keys** – generated by `init-ca.sh`, in the volume
  of the CA (`secrets/password`), where step-ca needs it at every start.

To choose the two passwords yourself, put them into the `ca` volume as
`secrets/password` and `secrets/provisioner_password` before the first start.

### The intermediate certificate

step-ca signs with an intermediate certificate, never with its root. A device
with room for exactly one certificate – a switch – presents its certificate
alone, and without the intermediate nobody can tell that it leads to the
root. That is what `intermediates:` in the `ca` section is for: without it
such a device is `foreign-ca` on every run and gets a new certificate every
time. The example list has it.

Your clients are in the same position. A browser that trusts the root and
nothing else still refuses a device that does not send the intermediate
along. The same key of the `ca` section takes care of that: with
`intermediates:` set, `sick trust` publishes the intermediate next to the
root, and [the trust page](#the-trust-service) tells every platform where it
may go without becoming a trust anchor.

## The CA

`init-ca.sh` runs in front of step-ca at every start of the `ca` service.

At the **first start** (no `config/ca.json` in the volume) it generates the
provisioner password and sets the CA up in one of two modes (below): root
and intermediate certificate, the JWK provisioner `sick`, the ACME
provisioner `acme`.

At **every start** it

- sets the longest lifetime of the provisioner `sick` to
  `SICK_CA_MAX_LIFETIME` (step-ca would grant 24 hours),
- gives that provisioner a template that issues server certificates with
  `serverAuth` as their only extended key usage (step-ca's default adds
  `clientAuth`),
- gives the ACME provisioner `acme` the same template and its lifetimes:
  `SICK_CA_ACME_LIFETIME` (30 days) for a certificate, between
  `SICK_CA_ACME_MIN_LIFETIME` and `SICK_CA_ACME_MAX_LIFETIME` (90 days) for a
  client that asks for a lifetime of its own (step-ca would issue for 24
  hours, with `clientAuth`), and the challenge types of
  `SICK_CA_ACME_CHALLENGES`,
- makes the provisioners declared in `SICK_CA_PROVISIONERS` that are missing
  and gives each its template, lifetimes and challenge types (below),
- sets the names the CA may issue for from `SICK_CA_ALLOW_DNS` and
  `SICK_CA_ALLOW_IP`, when at least one of them is given,
- copies root certificate, intermediate certificate and provisioner password
  into the `handover` volume,

and each of these only when it is not so already. A start that finds
everything in place changes nothing and says so:

```
init-ca: the CA in /home/step exists: nothing to make
init-ca: configuration unchanged: 'sick' grants up to 19800h, serverAuth only, names not restricted; 'acme' issues for 720h (5m to 2160h), serverAuth only, challenges http-01, dns-01, tls-alpn-01 (all, step-ca's default)
init-ca: root fingerprint (SHA-256): af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc
```

A changed setting takes effect with `docker compose up -d` (which restarts the
CA). Taking `SICK_CA_ALLOW_*` away again does *not* lift the restriction:
`init-ca.sh` never removes what it finds. Edit `authority.policy` in
`config/ca.json` for that.

Why 30 days for ACME: an ACME client renews at about two thirds of the
lifetime, so a 30-day certificate is renewed with about 10 days left. That
is the time the CA may be down – restore from backup included – before
services start to expire. A longer lifetime buys more of that time and keeps
a mistake (a wrong name, a key that leaked) around longer; a shorter one the
reverse. Clients that count fixed days instead of a share of the lifetime
need that set to match; the recipes in [contrib/acme/](../contrib/acme/) and
[k8s/cert-manager/](../k8s/cert-manager/) say how (handbook, chapter 4).

The container starts as root for `init-ca.sh`, which hands over the three
files and then starts step-ca as the unprivileged user `step` of the image.

### Further provisioners

Besides `sick` (SICK's own) and `acme`, the CA can have provisioners for
other jobs: client certificates, step-issuer in Kubernetes, ACME clients
that want a longer lifetime. Declare them in a JSON file and start with
`compose.provisioners.yml`:

```bash
cp provisioners.example.json provisioners.json     # then edit
SICK_CA_PROVISIONERS=$PWD/provisioners.json \
  docker compose -f compose.yml -f compose.provisioners.yml up -d
```

```json
{ "provisioners": [
  { "name": "clients", "type": "JWK", "profile": "client",
    "lifetime": "720h", "max": "2160h",
    "password_file": "secrets/provisioner_clients_password" },
  { "name": "acme-long", "type": "ACME", "profile": "server",
    "lifetime": "1440h", "max": "2160h", "challenges": ["http-01"] }
] }
```

| Key | | |
|---|---|---|
| `name` | required | letters, digits, `.`, `_`, `-`; not `sick` or `acme`, whose settings come from the environment |
| `type` | required | `JWK` (a password signs tokens: SICK, scripts, step-issuer, `step ca certificate`) or `ACME` |
| `profile` | required | `server`: `serverAuth` alone, the template of `sick`; `client`: `clientAuth` alone, key usage `digitalSignature` |
| `lifetime`, `max`, `min` | `720h`, `2160h`, `5m` | Go durations; `min` ≤ `lifetime` ≤ `max` |
| `challenges` | all three | ACME only: a subset of `http-01`, `tls-alpn-01`, `dns-01` |
| `password_file` | `secrets/provisioner_<name>_password` | JWK only: a path in the volume `ca`, relative to `/home/step`. Generated when missing (40 characters, no newline at the end – step-issuer takes a Secret byte for byte); read when the provisioner is made, never logged |
| `comment` | | free text; JSON has no comments |

At every start `init-ca.sh` makes what is missing, brings template,
lifetimes and challenge types of each declared one in line, and says so:

```
init-ca: made the declared JWK provisioner 'clients' (password generated in /home/step/secrets/provisioner_clients_password)
init-ca: made the declared ACME provisioner 'acme-long'
init-ca: configuration updated: 'sick' grants up to 19800h, serverAuth only, ...
init-ca: declared provisioner 'clients' (JWK) issues for 720h (5m to 2160h), clientAuth only
init-ca: declared provisioner 'acme-long' (ACME) issues for 1440h (5m to 2160h), serverAuth only, challenges http-01
```

It never removes a provisioner. One that is in `ca.json` but neither built
in nor declared stays, and every start names it (`provisioner 'old' (JWK)
is neither built in nor declared in …: left as it is, not removed`);
remove it with `step ca provisioner remove` in the `ca` container. A
mistake in the file (an unknown key, a lifetime above `max`, a password
file outside the volume) stops the start before anything is changed. A
declared JWK provisioner whose password file is gone, or no longer opens
its key, gets a `WARNING` and keeps its key; `--rotate-provisioner`
rotates `sick` alone.

The password of a JWK provisioner stays in the volume until you take it out
for whoever is to issue with it – over a channel you trust, never through a
log:

```bash
docker compose cp ca:/home/step/secrets/provisioner_clients_password ./clients.pw
```

The three of [`provisioners.example.json`](provisioners.example.json), and
why:

- **`clients`** – client certificates (mTLS) for people and machines,
  `clientAuth` only, so that a client certificate is never a server
  certificate and the reverse (`sick` and `acme` issue `serverAuth` only).
  30 days by default: a client certificate is a credential that may sit on
  a laptop, and the shorter it lives the shorter a lost one is useful –
  there is no revocation in this setup that a server would check. At most
  90 days, for a holder that cannot renew monthly; a longer lifetime should
  be a decision, not a default. Holders renew with `step ca renew` (their
  certificate authenticates the renewal; step-ca allows it until the
  certificate has expired) or ask again with the password. A person's
  certificate carries the email address (`step ca certificate
  jane@example.internal`), a machine's a URI (`--san
  spiffe://example.internal/machine/backup1`). Two things decide whether
  that works, both in [docs/findings/client-san.md](../docs/findings/client-san.md):
  the CA policy (`SICK_CA_ALLOW_DNS`/`_IP`) refuses email and URI SANs
  altogether, and Java takes a single-label subject such as `backup1` for a
  DNS name and checks it against the DNS constraints.
- **`cert-manager`** – for step-issuer in Kubernetes
  ([k8s/cert-manager](../k8s/cert-manager/)): `serverAuth`, 30 days, at most
  90, a password of its own, so that the cluster never holds `sick`'s.
- **`acme-long`** – ACME for clients that renew at a fixed number of days
  instead of a share of the lifetime. Proxmox VE (`pveupdate`) renews once
  less than 30 days are left: with the 30 days of `acme` that is every day,
  with 60 days about every 30. http-01 only, the challenge such clients use.
  Its directory is `https://ca.example.internal:9000/acme/acme-long/directory`.

### Lab mode and import mode

| | lab mode | import mode |
|---|---|---|
| when | nothing to import: the default | `SICK_CA_IMPORT` names the output of `ceremony.sh` (`-f compose.import.yml`) |
| root and intermediate | made by `step ca init` in the volume | made beforehand by `ceremony.sh`, offline |
| root key | in the volume (`secrets/root_ca_key`) | never in the volume: where the operator put it |
| name constraints | none | in the intermediate (`nameConstraints`, critical) |
| names of the CA | `ca`, `localhost` and `SICK_CA_DNS` | `SICK_CA_DNS` alone – they have to lie inside the constraints |
| log line | `init-ca: lab mode: …` | `init-ca: import mode: …` |

Lab mode is for trying things out. For anything else, run the ceremony
on a machine without network – the sick image has the tools – and give the
CA its output:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/ceremony.sh:/ceremony.sh:ro" -v /media/offline:/work \
  --entrypoint bash sick:local /ceremony.sh --operator 'A. Admin' \
  --out /work/for-the-ca --root-key /work/root/root_ca_key \
  --root-password-file /work/root/root.pw \
  --dns example.internal --ip 192.0.2.0/24
SICK_CA_IMPORT=/media/offline/for-the-ca SICK_CA_DNS=ca.example.internal \
  docker compose -f compose.yml -f compose.import.yml up -d
```

`ceremony.sh --help` lists the options (key type, lifetimes – 20 years for
the root, 5 for the intermediate by default –, names). It refuses a root key
inside the output for the CA, warns when DNS domains come without IP ranges
(an unconstrained name form stays open; `--exclude-all-ip` closes it;
`--email` and `--uri` constrain the email addresses and URIs of client
certificates, see [docs/findings/client-san.md](../docs/findings/client-san.md)), and
writes `ceremony.txt`: operator, date, versions, fingerprints, and the
constraints read back with `openssl x509 -text`, checked against what was
asked for. Keep the root key and its password apart from the CA. After the
first start the import directory is no longer read; the volume holds its
contents.

The CA's own names have to lie inside the constraints, or clients refuse its
TLS certificate – and SICK reaches it as `https://ca.example.internal:9000`,
not `https://ca:9000`. `t/e2e/ca-ceremony.sh` runs all of this in containers.

### Restricting the names

Recommended. With

```bash
SICK_CA_ALLOW_DNS=*.example.internal
SICK_CA_ALLOW_IP=192.0.2.0/24
```

the CA refuses everything else, through whichever provisioner it is asked,
and SICK reports it in the words of the CA:

```
DEVICE   ACTION   REASON   ERROR
inside   renewed  missing
outside  failed   missing  issuing failed: step failed (exit 1): The request was forbidden by the certificate authority: dns name "outside.example.org" not allowed
address  failed   missing  issuing failed: step failed (exit 1): The request was forbidden by the certificate authority: ip name "198.51.100.9" not allowed
```

`*.example.internal` covers the hosts below `example.internal`, not
`example.internal` itself. As soon as one of the two variables is set,
everything that is not listed is refused: with names only, no certificate
gets an address; with networks only, none gets a host name.

Know what this is: a *policy of the running CA*
(`authority.policy.x509.allow` in `ca.json`). It keeps mistakes and a stolen
provisioner password inside your names. It is not an X.509 name constraint in
the CA certificates, so it does nothing against somebody who has the CA keys.
Name constraints have to be in the intermediate certificate from the start:
import mode with a ceremony puts them there, lab mode cannot. With both, the
constraints are the first line – step-ca refuses what lies outside them
(`DNS name "outside.example.org" is not permitted by any constraint`) and
clients refuse a certificate outside them even when it was signed with the
stolen intermediate key – and the policy, narrower if you like, the second.

### The keys

The volume `ca` holds everything the CA is: both private keys (encrypted),
the password that decrypts them, the configuration, the database of what was
issued. Back it up, and protect the backup like the keys.

step-ca only ever uses the intermediate key. The root key is needed again
when the intermediate is replaced, in five or ten years or after an
incident. In lab mode it lies in the volume (`secrets/root_ca_key`); import
mode never has it there.

### Backup, restore, rotating the provisioner

```bash
docker/ca-backup.sh backup  --volume sick_ca --to /safe/ca-2026-10-10.tar
docker/ca-backup.sh restore --from /safe/ca-2026-10-10.tar --volume NEW_VOLUME
```

`backup` stops the containers that use the volume for the copy (step-ca
holds its Badger database open; the lab CA was down for 1-2 seconds),
starts them again and writes the archive with mode 0600 plus
`FILE.manifest`: SHA-256 of the archive and of every file, root and
intermediate fingerprint, end of the intermediate's validity – no secret.
The archive is the whole CA, keys *and* their passwords: keep it like the
keys, and keep the manifest (or its `archive-sha256` line) apart from it.

`restore` checks the archive against the manifest before it touches
anything, refuses a volume that holds a CA, anything else, or is in use, and
checks the restored files and fingerprints again. It starts no CA. A drill
runs the restored CA on a network of its own without published ports – never
beside the live one: two CAs with one key and two databases drift apart. To
replace a lost volume, `docker compose create ca`, restore into its volume,
`docker compose up -d`.

Observed in the lab (`t/e2e/ca-recovery.sh`, one host, images cached, an
archive of 28 KB): 3–4 seconds from `restore` to the first certificate of
the restored CA. That is the floor; the real RTO is finding the archive, a
host and the decision. The RPO is the time since the last backup: what was
issued after it is missing from the restored database; the certificates
themselves stay valid.

**The provisioner password** of `sick` is rotated on the running CA with

```bash
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner
```

It replaces the key pair, not only the password: the CA hands the encrypted
provisioner key to anybody who asks, so whoever knew the old password may
have the key itself. The new password goes to the `sick` service through the
handover volume and step-ca reloads; SICK issues with it at once, and a
token signed with the old key is refused.

**ACME accounts** (not tried yet, P6): an ACME client deactivates its own
account (RFC 8555, 7.3.6 – `certbot unregister`, `acme.sh
--deactivate-account`). step-ca without remote administration has no command
to deactivate somebody else's account; what cuts them all is replacing the
provisioner (`step ca provisioner remove acme`, then `add acme --type ACME`)
or requiring external account binding (`--require-eab`). Until then the
policy (`SICK_CA_ALLOW_*`) and the name constraints bound what any account
can obtain.

### Renewing the intermediate, replacing the root

**A new intermediate under the same root** (import mode; the root key comes
out of its safe place for this):

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/ceremony.sh:/ceremony.sh:ro" -v /media/offline:/work \
  --entrypoint bash sick:local /ceremony.sh --renew-intermediate --operator 'A. Admin' \
  --out /work/new-intermediate --root-cert /work/for-the-ca/root_ca.crt \
  --root-key /work/root/root_ca_key --root-password-file /work/root/root.pw \
  --intermediate /work/for-the-ca/intermediate_ca.crt
docker compose cp /media/offline/new-intermediate/. ca:/home/step/switch
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate
```

The ceremony makes a new key and copies the name constraints and the key
type from the current intermediate (`--dns`, `--ip`, `--kty` override them),
and its record says what it followed. `--switch-intermediate` checks that the
new intermediate leads to the CA's root and that the key is its own and new,
re-encrypts the key with the CA's password, keeps the old intermediate as the
previous one, has step-ca reload and removes `/home/step/switch`, also when it
refuses. From then on the handover's `intermediate_ca.crt` holds both, new
first: devices under the old one stay `ok`, the trust page shows both, new
certificates come from the new one. After the overlap:

```bash
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate
```

Devices that present their certificate alone are `foreign-ca` from then on
and renewed by the next run; a device that sends the old intermediate along
stays `ok` as long as that intermediate is valid – after a compromise,
`sick run --force`.

**A new root**, in three phases:

| Phase | What happens |
|---|---|
| A, announce | a new ceremony makes the new hierarchy; the device list gets `ca.additional_roots: [/etc/sick/secrets/root_ca_2.crt]` (any file the `sick` service can read; the secrets directory is mounted already); `sick trust` publishes both roots. Clients take the new page |
| B, switch | `docker compose stop ca`, then the CA on a second volume in import mode: `SICK_CA_IMPORT=<new hierarchy> docker compose -f compose.yml -f compose.import.yml -f compose.ca-next.yml up -d ca`. The volume `ca` stays as it is, unused. `ca.root` follows the handover to the new root; `additional_roots` names the old one; `sick run --force` re-issues every device |
| C, retire | `additional_roots` emptied, `sick trust`; clients remove the old root |

From phase B on, every `docker compose` command names
`compose.ca-next.yml`, or Compose goes back to the old volume – which is the
planned rollback: without that file the old CA is back, `additional_roots`
returns to the new root, `sick run --force`. After a compromise of the old
root there is no rollback and no overlap: its volume is destroyed and
clients remove the old root at once.

What the overlap does not carry: the trust page holds the intermediates of
the current hierarchy only (`ca.intermediates` must lead to `ca.root`). A
device that presents its certificate alone and is still under the other root
is refused by a client that has only the page's `ca_bundle.pem` – in phase A
a leaf of the new hierarchy, in phase B one of the old. Devices that send
their chain are not affected.

`t/e2e/ca-rollover.sh` runs both procedures in containers, with curl
(OpenSSL) and gnutls-cli (GnuTLS) as clients.

## The sick service

The entrypoint runs `sick run` at once and then every `SICK_INTERVAL`, and
`sick trust /srv/trust` after every run, whatever the run ended with:

```
2026-10-05T05:29:32Z entrypoint: sick run --verbose every 1d (86400s), device list /etc/sick/sick.yml, trust page in /srv/trust
2026-10-05T05:29:32Z entrypoint: sick run --verbose
DEVICE  ACTION     REASON  ERROR
switch  unchanged  ok
2026-10-05T05:29:34Z entrypoint: sick run: exit 0, nothing failed
wrote root_ca.pem, root_ca.crt, intermediate_ca.pem, intermediate_ca.crt, ca_bundle.pem, root_ca.mobileconfig, index.html to /srv/trust
2026-10-05T05:29:35Z entrypoint: next run in 86400s
```

| `sick run` ends with | The log says | |
|---|---|---|
| `0` | `nothing failed` | |
| `1` | `at least one device failed - see the table above; the next run tries again` | a device that was down is picked up by a later run |
| `2` | `the device list or the command line is wrong - the next run will fail the same way until ... is corrected` | waiting does not help. Fix `sick.yml`; the next run reads it again, `docker compose restart sick` runs at once |

The container keeps running in all three cases: a restart loop would help
nobody.

**Stopping.** `docker compose stop` sends TERM; the entrypoint passes it to
the `sick` that is running and waits until it has ended. `sick` removes its
private temporary directories on the way out – a fresh key may lie in one –
and the entrypoint looks and reports:

```
entrypoint: received TERM, sending TERM to sick (pid 11)
entrypoint: sick run ended with exit code 143
entrypoint: stopped by TERM; nothing is left in /tmp
```

A device that was being worked on at that moment is left wherever its type's
dialog was; the next run starts from what the device presents. `/tmp` is a
tmpfs: whatever a `kill -9` leaves there is gone with the container.

**ssh.** The host keys `ssh` has seen are kept in the state volume
(`/var/lib/sick/known_hosts`), for `cisco-sb` devices as for acme.sh hooks
that use `ssh` and `scp`. With `host_key_check: accept-new` the first
connection to a switch pins its key, and a changed key is refused from then
on. To pin it yourself, write the file before the first run.

**acme.sh** is in the image for its deploy hooks (`type: acmesh`) and for
nothing else: unpacked next to its `deploy/` directory, on the `PATH`, never
installed, no cron job, no account. Do not run `acme.sh --cron` in this
container.

## The trust service

`busybox httpd` as an unprivileged user on a read-only file system, over the
volume `sick trust` writes into. `trust-httpd.conf` gives the downloads the
media types that make a browser or a phone offer to install them
(`application/x-x509-ca-cert`, `application/x-pem-file`,
`application/x-apple-aspen-config`).

| On the page | For |
|---|---|
| `root_ca.pem`, `root_ca.crt` (DER) | the root: what a client trusts |
| `intermediate_ca.pem`, `intermediate_ca.crt` (DER) | the intermediate: what a client has to know for a device that presents its certificate alone. Never a trust anchor: it goes only where a platform keeps it without trust (Firefox and Chrome on Linux with nothing ticked, the Windows store of intermediates, the macOS keychain, the profile). The system store of Linux and Android get the root alone |
| `ca_bundle.pem` | both in one file, as a program's own CA file: `curl --cacert`, `git config http.sslCAInfo`, `openssl -CAfile`, `SSL_CERT_FILE`. Inside it the intermediate is an anchor for OpenSSL and GnuTLS programs; replace the file when the intermediate is replaced |
| `root_ca.mobileconfig` | iPhone, iPad, Mac: the root as trusted root, the intermediate as a plain certificate, one installation. On iPhone and iPad full trust for the root has to be switched on afterwards; the page says where |
| `index.html` | fingerprints of both, and the steps for iPhone and iPad, Android, macOS, Windows, Linux, Firefox and Chrome: where the root goes, where the intermediate goes, and whether that takes a trust setting |

One visit to that page is meant to be all a browser, a phone or a tablet
needs to accept every device SICK looks after. A device that sends its chain
needs the root alone. The switch that sends no intermediate is reached
through `ca_bundle.pem` in a program, or through an intermediate kept
without trust (Firefox, Chrome on Linux, Windows, macOS, iPhone and iPad) –
on Android not at all: there every installed CA certificate is an anchor,
and the page installs none but the root. Why an intermediate must not go
into a store of anchors: it stays trusted when the root is gone
([docs/findings/trust-anchors.md](../docs/findings/trust-anchors.md)).
From the client's side, with the two files of the page and nothing else:

```text
$ curl -sO http://<host>:8080/ca_bundle.pem -O http://<host>:8080/root_ca.pem
$ openssl s_client -connect switch.example.internal:443 -CAfile ca_bundle.pem -no-CApath -no-CAstore </dev/null 2>&1 | grep 'Verify return'
    Verify return code: 0 (ok)
$ openssl s_client -connect switch.example.internal:443 -CAfile root_ca.pem -no-CApath -no-CAstore </dev/null 2>&1 | grep 'Verify return'
    Verify return code: 21 (unable to verify the first certificate)
```

What has been tried and what has not: `openssl` as above, against the lab
switch. With the files of the lab's page and the certificate that switch
presents, in throwaway containers: the system store of Debian 13
(`update-ca-certificates`; OpenSSL and GnuTLS accept the certificate with
root and intermediate installed and refuse it with the root alone), of
Fedora 44 (`update-ca-trust`, and `trust anchor --store` with both files) –
the placement the page has dropped since, because the intermediate is an
anchor there –, and an NSS database – what Firefox keeps its certificates in – with the root
trusted and the intermediate present without any trust (`certutil -V`:
valid; without the intermediate: issuer not recognized). The steps for
iPhone, iPad, Android, macOS, Windows and the browsers themselves are
written from the documentation of those platforms and have not been walked
through on a device yet.

It speaks plain HTTP, and it has to: it is where a client gets the root from
that it would need to trust a TLS page. The page shows the fingerprints for
that reason – compare them with what your device shows during the
installation, or with `docker compose logs ca | grep fingerprint`. Behind a
reverse proxy with a certificate your clients already trust it is better off.

## Building the image

```bash
docker compose build                       # from docker/, checkouts side by side
```

The build context is the directory *above* the two checkouts
(`SICK_BUILD_CONTEXT`, default `../..`), because the image needs both.
`Dockerfile.dockerignore` lets nothing but `sick/lib`, `sick/bin/sick`,
`sick/docker/entrypoint.sh` and `sick-target-ciscosb/lib` into it, however
much else lies in that directory. Keep your secrets out of it all the same.

Without Compose:

```bash
cd somewhere
docker build -f sick/docker/Dockerfile -t sick:local .
```

Once both distributions are on CPAN, `SICK_FROM=cpan` (build argument and
Compose variable) installs them with `cpanm SICK SICK::Target::CiscoSB`
instead; the second checkout is not needed then. That stage of the
`Dockerfile` cannot have been built yet.

Pinned by build argument: `STEP_VERSION` (0.30.2, the binary is copied out of
`smallstep/step-cli`), `ACME_SH_VERSION` with `ACME_SH_SHA256` (3.1.6, the
release archive from GitHub), `DEBIAN_RELEASE` (trixie).

## What is open

- **The trust page on real clients.** What it tells a phone, a Mac, a
  Windows machine and the browsers to do with root and intermediate has been
  checked with `openssl`, GnuTLS, NSS and the system stores of Debian and
  Fedora, not yet on those devices – see
  [the trust service](#the-trust-service).
- **Name constraints** in the CA certificates themselves – see
  [Restricting the names](#restricting-the-names).
- **The root key** stays in the volume unless you move it.
- **`SICK_FROM=cpan`** is written and not built.
- Only the `cisco-sb` type (in the proof below), `files` and the `localcopy`
  hook of `acmesh` have run in this image. Other acme.sh hooks may want
  programs the image does not have.

## The proof

`t/e2e/run-lab.sh` in this repository builds the image, starts a brand-new CA
and walks through everything above against a real switch. It **replaces the
certificate of that switch, saves its configuration, and destroys the Compose
project it is pointed at**; its header says what it needs.

```bash
SICK_E2E_SWITCH_HOST=192.0.2.10 \
SICK_E2E_SWITCH_NAMES=switch.example.internal,switch.hq.example.org,192.0.2.10 \
SICK_E2E_SWITCH_CREDENTIALS=/root/sick-e2e/secrets/switch.cred \
SICK_E2E_PROJECT=sick SICK_E2E_CA_NAME='SICK Lab CA' SICK_E2E_CA_DNS=lab.example.internal,192.0.2.5 \
t/e2e/run-lab.sh
```

What follows is its output from the lab on 2026-10-05: Debian 13, Docker
26.1.5, Compose 2.26.1, a Cisco SG300-20 with firmware 1.4.11.5. Names and
addresses of the lab are replaced by neutral ones, nothing else is changed.
The switch came into this run with a certificate of the lab's *previous* CA,
which had the same name – `foreign-ca` is decided by signatures, not by
names.

That run is older than the intermediate on the trust page: its step 7 looked
at the root alone, and its `wrote ...` lines name four files. The script now
checks the intermediate, the bundle and the profile there, and has a step 8
that connects to the switch with nothing but a file from the trust page. A
full run replaces the certificate of the switch, so these two steps were run
on their own against the stack the transcript left running, with the new
image, on the same day; their output follows the transcript.

```text
project sick, working directory /root/sick-e2e, switch 192.0.2.10 as device "switch"

=== 1. build, and start the CA from nothing
--- docker compose build
PASS  the image is built from the two source trees
--- what is in it
     Network sick_default  Creating
     Network sick_default  Created
     Volume "sick_handover"  Creating
     Volume "sick_handover"  Created
     Volume "sick_state"  Creating
     Volume "sick_state"  Created
     Volume "sick_trust"  Creating
     Volume "sick_trust"  Created
     Volume "sick_ca"  Creating
     Volume "sick_ca"  Created
    sick 0.001
    SICK::Target::CiscoSB 0.001
    Smallstep CLI/0.30.2 (linux/amd64)
    acme.sh v3.1.6, 60 deploy hooks next to it
    OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
    OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.7 9 Jun 2026
    cron: none
PASS  sick, the Cisco target, step, acme.sh with its hooks, openssl and ssh are there
PASS  no cron in the image
--- docker compose up -d --wait ca trust
    init-ca: no CA in /home/step yet: making 'SICK Lab CA'
    init-ca: made the CA: root and intermediate certificate, JWK provisioner 'sick', ACME provisioner 'acme'
    init-ca: configuration updated: 'sick' grants up to 19800h, names not restricted
    init-ca: root fingerprint (SHA-256): af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc
    init-ca: handed over root_ca.crt
    init-ca: handed over intermediate_ca.crt
    init-ca: handed over provisioner.pw
PASS  init-ca.sh made the CA
PASS  ... with the JWK provisioner and the ACME provisioner
PASS  ... and raised the lifetime the provisioner grants
PASS  ... and handed root, intermediate and password to the sick service
    [{"type":"JWK","name":"sick","max":"19800h"},{"type":"ACME","name":"acme","max":null}]
PASS  ca.json: JWK provisioner sick with 19800h (825 days)
PASS  ca.json: an ACME provisioner
--- root fingerprint af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc

=== 2. a second start changes nothing
--- docker compose up -d ca trust (again)
     Container sick-trust-1  Running
     Container sick-ca-1  Running
PASS  the second "up" leaves the running CA alone
--- docker compose restart ca: init-ca.sh runs again
    init-ca: the CA in /home/step exists: nothing to make
    init-ca: configuration unchanged: 'sick' grants up to 19800h, serverAuth only, names not restricted
    init-ca: root fingerprint (SHA-256): af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc
PASS  init-ca.sh finds the CA
PASS  ... and its configuration as it should be
PASS  ... and hands nothing over again
PASS  ca.json, the certificates, the handed over files and the secrets directory are the same as before
PASS  the root fingerprint is the same

=== 3. sick check: the switch is due
--- docker compose run --rm sick sick check
     Container sick-ca-1  Running
    DEVICE  STATUS      RENEW  DETAIL
    switch  foreign-ca  yes    issued by CN=SICK Lab CA Intermediate CA,O=SICK Lab CA
PASS  the certificate of the switch is not from this CA
PASS  the detail is readable: no backslash

=== 4. sick run switch: the switch gets a certificate of the CA
--- docker compose run --rm sick sick run --verbose switch
     Container sick-ca-1  Running
    switch: foreign-ca (issued by CN=SICK Lab CA Intermediate CA,O=SICK Lab CA)
    switch: issuing a certificate for switch.example.internal, switch.hq.example.org, 192.0.2.10
    switch: deploying
    switch: the switch stores one certificate: the chain (1 certificate) is not installed
    switch: connecting to 192.0.2.10 port 22
    switch: logged in, the switch calls itself sw1
    switch: sending: terminal datadump
    switch: sending: configure terminal
    switch: importing the certificate and its key into slot 1
    switch: sending: crypto certificate 1 import
    switch: pasting 54 lines
    switch: making certificate 1 the active one
    switch: sending: ip https certificate 1
    switch: sending: end
    switch: sending: show ip https
    switch: saving the configuration
    switch: sending: copy running-config startup-config
    switch: answering 'Overwrite file [startup-config].... (Y/N)[N] ?' with Y
    switch: renewed, the device presents the new certificate
    DEVICE  ACTION   REASON      ERROR
    switch  renewed  foreign-ca
PASS  renewed
PASS  ssh stored the host key of the switch
PASS  the host key of the switch is pinned in the state volume (1 line)
--- what 192.0.2.10:443 presents now, seen from this machine with openssl s_client
    subject=CN=switch.example.internal
    issuer=O=SICK Lab CA, CN=SICK Lab CA Intermediate CA
    notAfter=Nov  6 05:09:50 2027 GMT
    X509v3 Subject Alternative Name: 
        DNS:switch.example.internal, DNS:switch.hq.example.org, IP Address:192.0.2.10
PASS  issued by the intermediate of the new CA
PASS  DNS name switch.example.internal
PASS  DNS name switch.hq.example.org
PASS  IP address 192.0.2.10
PASS  exactly the 3 names of the list
--- the switch sends 1 certificate(s) in the handshake
    /root/sick-e2e/presented.pem: OK
PASS  openssl verify: root as anchor, intermediate as help -> OK
--- with the root alone: fails, the switch sends no intermediate - which is what ca.intermediates is for:
    CN=switch.example.internal
    error 20 at 0 depth lookup: unable to get local issuer certificate
    error /root/sick-e2e/presented.pem: verification failed

=== 5. a second run changes nothing
--- docker compose run --rm sick sick run
     Container sick-ca-1  Running
    DEVICE  ACTION     REASON  ERROR
    switch  unchanged  ok
PASS  unchanged
--- docker compose run --rm sick sick check
     Container sick-ca-1  Running
    DEVICE  STATUS  RENEW  DETAIL
    switch  ok      no     valid until 2027-11-06 05:09:50 UTC, 396 days left
PASS  ok, no renewal due
PASS  the switch still presents the same certificate

=== 6. the schedule: sick run every 20 seconds, sick trust after every run
--- SICK_INTERVAL=20s docker compose up -d sick
    2026-10-05T05:10:25Z entrypoint: sick run --verbose every 20s (20s), device list /etc/sick/sick.yml, trust page in /srv/trust
    2026-10-05T05:10:25Z entrypoint: sick run --verbose
    DEVICE  ACTION     REASON  ERROR
    switch  unchanged  ok
    2026-10-05T05:10:28Z entrypoint: sick run: exit 0, nothing failed
    wrote root_ca.pem, root_ca.crt, root_ca.mobileconfig, index.html to /srv/trust
    2026-10-05T05:10:28Z entrypoint: next run in 20s
    2026-10-05T05:10:48Z entrypoint: sick run --verbose
    DEVICE  ACTION     REASON  ERROR
    switch  unchanged  ok
    2026-10-05T05:10:50Z entrypoint: sick run: exit 0, nothing failed
    wrote root_ca.pem, root_ca.crt, root_ca.mobileconfig, index.html to /srv/trust
    2026-10-05T05:10:51Z entrypoint: next run in 20s
PASS  the entrypoint announces the schedule
PASS  two scheduled runs, the switch unchanged in both
PASS  sick trust after each of them
PASS  the pause is the interval

=== 7. the trust page serves the root of the CA
    http://localhost:8080/index.html  Content-type: text/html  8212 bytes
    http://localhost:8080/root_ca.pem  Content-type: application/x-pem-file  639 bytes
    http://localhost:8080/root_ca.crt  Content-type: application/x-x509-ca-cert  431 bytes
    http://localhost:8080/root_ca.mobileconfig  Content-type: application/x-apple-aspen-config  2083 bytes
PASS  index.html (also as /), root_ca.pem, root_ca.crt and root_ca.mobileconfig are served
--- SHA-256 of the served root_ca.pem: af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc
PASS  root_ca.pem has the fingerprint of the root of the CA
PASS  root_ca.crt is the same certificate in DER
PASS  the profile carries a root certificate, the page shows the fingerprint
PASS  the profile is served as a configuration profile

=== 8. docker compose stop in the middle of a run
--- the sick service with a device list whose one "device" is always due and takes two minutes to deploy
--- in /tmp of the container while the hook sleeps (names and modes only):
    drwx------ ./sick-OQsYmkoK_1
    drwx------ ./sick-OQsYmkoK_1/held.example.internal
    -rw-r--r-- ./sick-OQsYmkoK_1/held.example.internal/ca.cer
    -rw-r--r-- ./sick-OQsYmkoK_1/held.example.internal/fullchain.cer
    -rw-r--r-- ./sick-OQsYmkoK_1/held.example.internal/held.example.internal.cer
    -rw------- ./sick-OQsYmkoK_1/held.example.internal/held.example.internal.conf
    -rw------- ./sick-OQsYmkoK_1/held.example.internal/held.example.internal.key
--- docker compose stop sick
--- stopped after 0s
    2026-10-05T05:10:54Z entrypoint: sick run --verbose every 1h (3600s), device list /etc/sick/sick.yml, trust page in /srv/trust
    2026-10-05T05:10:54Z entrypoint: sick run --verbose
    held: names (missing DNS name held.example.internal; unexpected DNS names ca, localhost, lab.example.internal; unexpected IP address 192.0.2.5)
    held: issuing a certificate for held.example.internal
    held: deploying
    held: running acme.sh --deploy -d held.example.internal --deploy-hook localcopy --home /tmp/sick-OQsYmkoK_1 --config-home /tmp/sick-OQsYmkoK_1 --cert-home /tmp/sick-OQsYmkoK_1
    2026-10-05T05:10:57Z entrypoint: received TERM, sending TERM to sick (pid 11)
    2026-10-05T05:10:57Z entrypoint: sick run ended with exit code 143
    2026-10-05T05:10:57Z entrypoint: stopped by TERM; nothing is left in /tmp
PASS  the entrypoint passes the signal on to the running sick
PASS  sick ends through its own handler
PASS  no temporary directory, no key is left
PASS  ... says the entrypoint, which looks
PASS  the container ended with exit code 0

=== 9. leave the stack running: the real device list, sick run every 1d
    2026-10-05T05:11:00Z entrypoint: sick run --verbose every 1d (86400s), device list /etc/sick/sick.yml, trust page in /srv/trust
    2026-10-05T05:11:00Z entrypoint: sick run --verbose
    DEVICE  ACTION     REASON  ERROR
    switch  unchanged  ok
    2026-10-05T05:11:02Z entrypoint: sick run: exit 0, nothing failed
    wrote root_ca.pem, root_ca.crt, root_ca.mobileconfig, index.html to /srv/trust
    2026-10-05T05:11:03Z entrypoint: next run in 86400s
PASS  the switch is unchanged
    NAME           IMAGE                      COMMAND                  SERVICE   CREATED              STATUS                        PORTS
    sick-ca-1      smallstep/step-ca:0.30.2   "/bin/bash /usr/loca…"   ca        About a minute ago   Up About a minute (healthy)   0.0.0.0:9000->9000/tcp, :::9000->9000/tcp
    sick-sick-1    sick:local                 "sick-entrypoint"        sick      6 seconds ago        Up 5 seconds                  
    sick-trust-1   busybox:1.37               "httpd -f -v -p 8080…"   trust     About a minute ago   Up About a minute             0.0.0.0:8080->8080/tcp, :::8080->8080/tcp

The stack "sick" is running. To work with it:
  docker compose --env-file /root/sick-e2e/compose.env -p sick -f /root/sick-build/sick/docker/compose.yml <command>
CA:          https://<this host>:9000   (root fingerprint af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc)
Trust page:  http://<this host>:8080/

ALL STEPS PASSED
```

Steps 7 and 8 as they are now:

```text
=== 7. the trust page serves what a client needs: root, intermediate, bundle, profile
    http://localhost:8080/index.html  Content-type: text/html  13183 bytes
    http://localhost:8080/root_ca.pem  Content-type: application/x-pem-file  639 bytes
    http://localhost:8080/root_ca.crt  Content-type: application/x-x509-ca-cert  431 bytes
    http://localhost:8080/intermediate_ca.pem  Content-type: application/x-pem-file  696 bytes
    http://localhost:8080/intermediate_ca.crt  Content-type: application/x-x509-ca-cert  472 bytes
    http://localhost:8080/ca_bundle.pem  Content-type: application/x-pem-file  1335 bytes
    http://localhost:8080/root_ca.mobileconfig  Content-type: application/x-apple-aspen-config  3495 bytes
PASS  index.html (also as /) and root_ca.pem root_ca.crt intermediate_ca.pem intermediate_ca.crt ca_bundle.pem root_ca.mobileconfig are served
--- SHA-256 of the served root_ca.pem: af22556f14379ec5a8db1ec01db94434c7a25282331cf01caa7e33916ffd6afc
PASS  root_ca.pem has the fingerprint of the root of the CA
PASS  root_ca.crt is the same certificate in DER
--- SHA-256 of the intermediate of the CA: b53e2cc1c237c38d7b6a660750bf75f0ba4ce77b5a268a09cb59ad8313335c5e
PASS  intermediate_ca.pem is the intermediate of the CA, intermediate_ca.crt the same in DER
PASS  ca_bundle.pem is the two of them in one file
PASS  no key is served
PASS  the profile carries the root and the intermediate, the page shows the fingerprint and offers both
PASS  the profile is served as a configuration profile

=== 8. a client that has what the page serves, and nothing else, accepts the switch
--- openssl s_client -connect 192.0.2.10:443 -CAfile ca_bundle.pem -no-CApath -no-CAstore -verify_ip 192.0.2.10
    Verify return code: 0 (ok)
PASS  with ca_bundle.pem from the trust page: the chain is built and the name fits
--- the same with -CAfile root_ca.pem
    Verify return code: 21 (unable to verify the first certificate)
PASS  with root_ca.pem alone it is refused: the switch sends no intermediate, the client has to have it
PASS  ... and for that reason, not for another
```
