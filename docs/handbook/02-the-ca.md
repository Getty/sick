# 2. The CA

You end this chapter with an offline root, an intermediate in step-ca that
may issue only for your names, a ceremony record, and a backup you have
restored once. The tools are in [`docker/`](../../docker/README.md); every
step below ran in a container test, named in the [test report](#test-report).

You need the decisions of [chapter 1](01-planning.md): the domain, the
address ranges, where the root key goes.

## Lab mode or ceremony

`docker compose up` without anything else starts the CA in **lab mode**:
step-ca makes root and intermediate itself, the root key lies in the CA
volume, and there are no name constraints. Good for trying SICK out; not for
a CA that your clients will trust.

For the real one, run the **ceremony** first. It makes root and
intermediate on a machine without network, puts the root key where you say,
and leaves a directory the CA imports at its first start (**import mode**).
The root key never enters the CA.

## The ceremony

What you need on the table:

- the `sick` image, built once on a machine with network from the three
  checkouts side by side (`sick`, `sick-target-ciscosb`,
  `sick-target-proxmox`; `docker/README.md`, "Quick start"):

  ```bash
  cd sick/docker && docker compose build sick && cd ../..
  ```

  It has `step` and `openssl`; `t/e2e/install-tools.sh` installs pinned
  versions instead, if you prefer a laptop without Docker;
- a machine without network for the ceremony itself (a laptop with Wi-Fi
  off, or a container with `--network none` as below);
- the removable medium for the root key (`/media/offline` below), and a
  second one for its copy;
- a password for the root key in a file **on a different medium** than the
  key (`/media/pwstick` below), later kept apart from the key (a password
  manager, a sealed envelope);
- `docker/ceremony.sh` from this repository.

Make the directories and the password first; the ceremony refuses to start
without them (`ceremony: …/root.pw: no password in it, or not readable`):

```bash
mkdir -p /media/offline/root /media/pwstick
chmod 700 /media/offline /media/offline/root /media/pwstick
(umask 077; openssl rand -base64 32 > /media/pwstick/root.pw)
```

From the directory that holds the `sick` checkout:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/sick/docker/ceremony.sh:/ceremony.sh:ro" \
  -v /media/offline:/work -v /media/pwstick:/pw:ro \
  --entrypoint bash sick:local /ceremony.sh \
  --operator 'A. Operator' \
  --out /work/for-the-ca \
  --root-key /work/root/root_ca_key \
  --root-password-file /pw/root.pw \
  --root-name 'Example Root CA' --intermediate-name 'Example Intermediate CA' \
  --dns example.internal --ip 192.0.2.0/24
```

It prints (fingerprints differ every time):

```text
ceremony: making the root 'Example Root CA' (EC P-256, 175320h)
ceremony: making the intermediate 'Example Intermediate CA' (EC P-256, 43830h)
ceremony: root fingerprint (SHA-256): 9c3289606dff96f99812f9cf9f90a499b4d32b674234de2212218ecb47d74a4c
ceremony: root key: /work/root/root_ca_key - take it off this machine and keep it with its password, apart from the CA
ceremony: for the CA (SICK_CA_IMPORT): /work/for-the-ca - the record is /work/for-the-ca/ceremony.txt
```

and leaves:

| Where | What | Goes to |
|---|---|---|
| `root/root_ca_key` | the root key, encrypted with `root.pw` | the removable media, two copies, two places |
| `for-the-ca/root_ca.crt` | the root certificate | the CA, and later every client |
| `for-the-ca/intermediate_ca.crt`, `intermediate_ca_key`, `password` | the intermediate, its encrypted key and that key's password | the CA (import) |
| `for-the-ca/ceremony.txt` | the record | your records, printed |

The record, abridged:

```text
asked for:
  key type              EC P-256
  root                  Example Root CA, 175320h
  intermediate          Example Intermediate CA, 43830h
  permitted DNS         example.internal
  permitted IP          192.0.2.0/24

intermediate: intermediate_ca.crt
  SHA-256 fingerprint   080dcc8f76cfa71756e9a8239afd92f089d5ad35ce259f60dc316d58dd2994ce
  valid                 2026-10-10 17:37:15Z .. 2031-10-10 23:37:15Z
  read back with openssl x509 -text:
    X509v3 Basic Constraints: critical
      CA:TRUE, pathlen:0
    X509v3 Key Usage: critical
      Certificate Sign, CRL Sign
    X509v3 Name Constraints: critical
      Permitted:
      DNS:example.internal
      IP:192.0.2.0/255.255.255.0

result: every value read back matches what was asked for; openssl verifies the intermediate against the root.
```

The ceremony reads every value back from the finished certificates with
`openssl`, a second tool besides the `step` that made them, and stops with
exit 1 when anything differs from what was asked. It refuses a root key
destination inside the output for the CA, never overwrites a key, and warns
when you give DNS domains without IP ranges (see
[chapter 1, Networks](01-planning.md#networks)).

**Write the root fingerprint down by hand** and keep it apart from the
machine: it is what clients check the root against in chapter 3, over a
channel an attacker on your network does not control.

**Afterwards:** copy `root/root_ca_key` to the second medium and check that
each copy belongs to the root certificate – compare the public keys, never
print the private one (`step crypto key inspect` would show it):

```bash
docker run --rm --network none -v /media/offline:/work:ro -v /media/pwstick:/pw:ro \
  --entrypoint sh sick:local -c \
  'step crypto key public /work/root/root_ca_key --password-file /pw/root.pw | sha256sum;
   openssl x509 -in /work/for-the-ca/root_ca.crt -noout -pubkey | sha256sum'
```

(with `step` and `openssl` on the laptop, the two commands inside the quotes
work as they are, with the host paths).

Both lines must print the same sum – and the same again for the copy: mount
the second medium's `root/` over `/work/root` (`-v /media/copy/root:/work/root:ro`)
and run the first line again. Keep
`for-the-ca/root_ca.crt` and `for-the-ca/intermediate_ca.crt` (public) on the
root medium as well: the next intermediate renewal needs them. Then store the
two key media and the password medium in three places, and wipe any working
copy of `for-the-ca/intermediate_ca_key` and `password` once the CA has
imported them (after the first start, next section).

### On a YubiKey or an HSM instead of a file

*Not tried.* step supports keys on a YubiKey (PIV) and in PKCS#11 tokens
through `step-kms-plugin`; the root is then created with `step certificate
create --profile root-ca --kms 'yubikey:' --key 'yubikey:slot-id=9c'` (or a
`pkcs11:` URI) instead of a key file, and later intermediates are signed
with the same `--kms`/`--key` pair. The ceremony script does not do this
yet. If you go this way: keep a second token or an encrypted file backup of
the root, or losing the token means a root replacement. Check the commands
against Smallstep's current documentation for your token before the
ceremony.

## Starting the CA on the result

Put the settings into `docker/.env`, so that every later `docker compose`
command uses the same ones – a variable given only on one command line is
gone at the next, and Compose then recreates the CA with defaults:

```bash
cd sick/docker
cp sick.example.yml sick.yml        # then set ca.url to https://ca.example.internal:9000;
                                    # the device examples are commented out until you add yours
sudo install -d -m 0700 -o root secrets   # credential files: owned by root, 0600 (docker/README.md)
cat > .env <<'END'
SICK_CA_IMPORT=/media/offline/for-the-ca
SICK_CA_DNS=ca.example.internal
SICK_CA_ALIAS=ca.example.internal
SICK_CA_ALLOW_DNS=*.example.internal
SICK_CA_ALLOW_IP=192.0.2.0/24
SICK_CA_PORT=127.0.0.1:9000         # or the address your clients reach; without one: all interfaces
SICK_TRUST_PORT=127.0.0.1:8080
END
docker compose -f compose.yml -f compose.import.yml up -d
docker compose -f compose.yml -f compose.import.yml logs ca | grep init-ca
```

The log, abridged:

```text
init-ca: staged root_ca.crt intermediate_ca.crt intermediate_ca_key password from /import for the import
init-ca: import mode: no CA in /home/step yet: building it on the hierarchy in /home/step/import (no root key)
init-ca: made the CA on the imported hierarchy: JWK provisioner 'sick', ACME provisioner 'acme'; no root key in /home/step
init-ca: configuration updated: 'sick' grants up to 19800h, serverAuth only, names allowed: *.example.internal, 192.0.2.0/24; …
init-ca: root fingerprint (SHA-256): 9c3289606dff96f99812f9cf9f90a499b4d32b674234de2212218ecb47d74a4c
```

The root fingerprint must be the one of the ceremony. Now wipe
`for-the-ca/intermediate_ca_key` and `password` from the offline media: the
CA holds them. (`SICK_CA_PORT` and
`SICK_TRUST_PORT` take `address:port` or a port alone, which publishes on
all interfaces; put a firewall in front of 9000 either way, chapter 4.
Comparing fingerprints: `openssl x509 -fingerprint -sha256` prints them with
colons and in capitals – `| tr -d : | tr A-F a-f` makes them comparable.) In lab mode the log
would say `init-ca: lab mode:`. Import mode checks that the root signed the
intermediate and that the key belongs to the intermediate, refuses an
import directory that holds any other private key (a root key put there by
mistake), and builds the CA without its own throwaway keys ever touching
the volume. After the first start the import directory is not read again,
and later commands may leave out `-f compose.import.yml` – keeping it does
no harm. The first command without it recreates the `ca` container once
(`Recreate … Started`); that is harmless: the log says `the CA in
/home/step exists: nothing to make`, with the same root fingerprint.

**The CA's own names** (`SICK_CA_DNS`) have to lie inside the constraints:
`ca` and `localhost` do not, and a client refuses the CA's TLS certificate
if it names them. So in import mode SICK reaches the CA as
`https://ca.example.internal:9000`. Inside Compose that name resolves
through the network alias `SICK_CA_ALIAS` (default `ca.example.internal`)
that `compose.yml` gives the `ca` service – in `compose.yml`, not in
`compose.import.yml`, so it stays after the first start; on your network the
name needs an entry in your DNS.

**Names in the policy:** `*.example.internal` allows exactly one label below
`example.internal` – `www.example.internal`, not `a.b.example.internal`,
and not `example.internal` itself. List every level you use, comma
separated (`*.example.internal,*.machines.example.internal`).

## What the CA will and will not issue

Two lines of defence, both active in the setup above:

1. **The name constraints in the intermediate.** step-ca 0.30.2 checks them
   when it issues, without any policy configured:
   `DNS name "outside.example.org" is not permitted by any constraint`
   (HTTP 403). And a client refuses a certificate outside them even if it
   was signed with a stolen intermediate key: `openssl verify` says
   `permitted subtree violation`, GnuTLS says `The certificate chain violates
   the signer's constraints`.
2. **The policy of the running CA** (`SICK_CA_ALLOW_DNS`, `_EMAIL`, `_URI`,
   `SICK_CA_ALLOW_IP`): refuses with `dns name "..." not allowed`. It can be
   narrower than the constraints and changed without a ceremony; it does
   nothing against someone who has the CA keys.

**Try it** – one name inside, one outside, from the `sick` container with
the provisioner password the CA handed over (in `sick/docker`):

```bash
docker compose run --rm --entrypoint sh sick -c 'cd /tmp && step ca certificate \
  www.example.internal c.crt c.key --ca-url https://ca.example.internal:9000 \
  --root /etc/sick/ca/root_ca.crt --provisioner sick --password-file /etc/sick/ca/provisioner.pw'
```

prints `✔ Certificate: c.crt`; with `outside.example.org` instead its error
(the line before `Re-run with STEPDEBUG=1`) is
`DNS name "outside.example.org" is not permitted by any constraint`, with
`198.51.100.7` in `IP address "198.51.100.7" is not permitted by any
constraint`, with `a.b.example.internal` in `dns name "a.b.example.internal"
not allowed` (the policy).

What the provisioner `sick` gives out:

- **`serverAuth` only.** step-ca's default leaf template adds
  `clientAuth`; `init-ca.sh` sets a template without it at every start, in
  both modes.
- **No CA certificates.** A request (CSR) that asks for `CA:true` gets a
  plain leaf: the template decides, not the request.
- **No longer than `SICK_CA_MAX_LIFETIME`** (19800h = 825 days): a request
  for more is refused.

The ACME provisioner `acme` issues `serverAuth` only as well, for 30 days by
default and at most 90 (`SICK_CA_ACME_LIFETIME`, `SICK_CA_ACME_MAX_LIFETIME`,
`SICK_CA_ACME_MIN_LIFETIME`); chapter 4 says why and how services use it.

## Revocation

step-ca revokes **passively** by default: `step ca revoke <serial>` makes
the CA refuse to *renew* that certificate, and it stays valid until it
expires (Smallstep, "Active vs. passive revocation", checked 2026-10-10).
step-ca also has a minimal CRL server (`"crl": {"enabled": true}` in
`ca.json`, served at `/1.0/crl`) and no OCSP.

**Recommendation:** passive revocation, and lifetimes that make it enough.
A CRL helps only with clients that fetch and enforce it; check that for the
clients that matter to you before relying on it. What replaces it here:

- the device lifetimes of chapter 1, and `sick run --force <device>`, which
  gives a device a new key and certificate at once;
- for anything wider, the emergency procedures of [chapter 7](07-emergencies.md):
  a compromised intermediate is *replaced*, not revoked.

## Backup and a restore drill

In `sick/docker`; the CA's volume is called `<project>_ca` – `sick_ca` for
the default project `sick` (`docker volume ls` shows it):

```bash
./ca-backup.sh backup  --volume sick_ca --to /safe/ca-2026-10-10.tar
./ca-backup.sh restore --from /safe/ca-2026-10-10.tar --volume sick_ca_drill
```

`backup` prints, among others, `ca-backup: the CA was stopped for 2s` and
`ca-backup: wrote /safe/ca-2026-10-10.tar (… bytes, mode 0600) and
/safe/ca-2026-10-10.tar.manifest`; `restore` prints `the archive matches its
manifest`, `restored into sick_ca_drill: 11 files, each as in the manifest`
and how long the intermediate is still valid. Move the `.manifest` to a
different place than the archive afterwards (see below).

`backup` stops the CA for the copy (step-ca keeps its Badger database open
and Smallstep documents no online backup; the lab CA was down for 1–2
seconds), starts it again, and writes the archive (mode 0600) and
`FILE.manifest`: checksums of the archive and of every file, the root and
intermediate fingerprints, the end of the intermediate's validity. No
secret in the manifest – but the archive is the whole CA, keys and their
passwords. Keep it like the keys, and keep the manifest apart from it: the
manifest only catches a tampered archive if nobody could change both.

`restore` checks the archive against the manifest first, refuses a volume
that holds a CA, holds anything, or is in use, and checks every file and
both fingerprints after unpacking. It starts nothing.

**A drill** runs the restored CA on a network of its own with no published
port, never beside the live one: two CAs with the same key and two
databases drift apart.

```bash
docker network create --internal sick-drill
docker run -d --rm --name sick-drill-ca --network sick-drill \
  --network-alias ca.example.internal -v sick_ca_drill:/home/step smallstep/step-ca:0.30.2
docker logs -f sick-drill-ca 2>&1 | grep -m1 'Serving HTTPS'   # wait until it serves
docker run --rm --network sick-drill -v sick_ca_drill:/ca:ro --entrypoint sh sick:local -c \
  'cd /tmp && step ca certificate drill.example.internal c.crt c.key \
     --ca-url https://ca.example.internal:9000 --root /ca/certs/root_ca.crt \
     --provisioner sick --password-file /ca/secrets/provisioner_password \
   && openssl verify -CAfile /ca/certs/root_ca.crt -untrusted /ca/certs/intermediate_ca.crt c.crt'
docker stop sick-drill-ca && docker network rm sick-drill && docker volume rm sick_ca_drill
```

The last line of the second command is `c.crt: OK`: the restored CA issues
under the same root. (The container test also checks that the restored
database holds a certificate issued before the backup and not one issued
after, and that the live CA stayed the only one serving; that needs a look
into its Badger files and is left to the test, `t/e2e/ca-recovery.sh`.)

Recovery figures observed in the lab: 3–4 seconds from `restore` to the
first certificate (one host, images cached, 28 KB archive). That is the
floor. Your RTO is dominated by finding the archive, a host and the
decision; write those down. The RPO is the time since the last backup:
what was issued after it is missing from the restored database, and those
certificates simply stay valid. **Recommendation:** a backup after every
change to the CA (new provisioner, rotation, intermediate) and once a week,
kept off the CA host.

To replace a lost volume for real: `docker compose create ca`, restore into
its volume, `docker compose up -d`.

## Rotating the provisioner `sick`

```bash
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner
```

This replaces the provisioner's **key pair**, not only its password. The CA
serves the encrypted provisioner key to anyone who asks
(`/provisioners/<kid>/encrypted-key`), so whoever knew the old password may
have the key itself; a new password on the same key would not lock them
out. The new password reaches the `sick` service through the handover
volume, step-ca reloads, and SICK issues with it at once. A token signed
with the old key is refused (HTTP 401).

Check it with the issuing command of "What the CA will and will not issue"
above: it issues with the new password the `sick` container now has. To see
the old one fail, save it **before** rotating, in a private directory, and
delete it after the check:

```bash
mkdir -m 700 ~/rot && docker compose exec -T sick cat /etc/sick/ca/provisioner.pw > ~/rot/old.pw
chmod 711 ~/rot && chmod 644 ~/rot/old.pw              # the container's user must read it
docker compose run --rm -v ~/rot/old.pw:/old.pw:ro --entrypoint sh sick -c 'cd /tmp && \
  step ca certificate www.example.internal c.crt c.key --ca-url https://ca.example.internal:9000 \
  --root /etc/sick/ca/root_ca.crt --provisioner sick --password-file /old.pw'
rm -r ~/rot
```

It ends in `failed to decrypt JWE: invalid password` – step can no longer
open the provisioner key with it. (That the CA itself refuses a token signed
with the old key, HTTP 401, the container test shows.) The rotation prints
`rotated provisioner 'sick': key … replaces key …`, `handed over
provisioner.pw` and `step-ca reloads its configuration (SIGHUP)`.

Rotate after anyone who had access to the CA volume or the `sick` container
leaves, and whenever the password may have been seen.

(For the record: `step ca provisioner update --create`, the documented
rekey, fails in step 0.30.2 against a local `ca.json` with `provisioner …
not found`; `init-ca.sh` removes and re-adds the provisioner instead.)

## Renewing the intermediate

Do it at least one device lifetime before the intermediate ends – with the
defaults, in year four of five – or at once after its key may have been
exposed. The root key comes out of its safe place for this, on the offline
machine, from the directory that holds the `sick` checkout, with the root
medium and the password medium mounted as for the first ceremony:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/sick/docker/ceremony.sh:/ceremony.sh:ro" \
  -v /media/offline:/work -v /media/pwstick:/pw:ro \
  --entrypoint bash sick:local /ceremony.sh --renew-intermediate \
  --operator 'A. Operator' --out /work/new-intermediate \
  --root-cert /work/for-the-ca/root_ca.crt \
  --root-key /work/root/root_ca_key --root-password-file /pw/root.pw \
  --intermediate /work/for-the-ca/intermediate_ca.crt
```

It prints, among others, `ceremony: making the intermediate 'Example
Intermediate CA 2026-10-11' (EC P-256, 43830h)` – the new name carries the
date unless you give `--intermediate-name` – and the new intermediate's
fingerprint.

Before it makes anything it checks that the root is self-signed, that the
current intermediate verifies against it, and that the root key belongs to
the root. It makes a **new key**, copies the name constraints and the key
type from the current intermediate (read back with openssl; `--dns`, `--ip`,
`--kty` override them), refuses an intermediate that would outlive the root,
and writes a record that says which intermediate it follows. The root key
is only read.

On the CA host:

```bash
docker compose cp /media/offline/new-intermediate/. ca:/home/step/switch
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate
```

`--switch-intermediate` checks that the new intermediate leads to the CA's
own root and that the key is its own and new, re-encrypts the key with the
CA's password, keeps the old intermediate as the previous one, and has
step-ca reload – no restart. It removes `/home/step/switch` afterwards, also
when it refuses, because that directory held a key. It prints `init-ca:
switched the intermediate: 'CN=Example Intermediate CA 2026-10-11' (…) signs
from now on` and `init-ca: handed over intermediate_ca.crt: the new and the
previous intermediate`. Wipe `new-intermediate/intermediate_ca_key` and
`password` from the root medium, and replace `for-the-ca/intermediate_ca.crt`
there by `new-intermediate/intermediate_ca.crt` – the next renewal follows
the current intermediate.

During the overlap the page offers the intermediates as `intermediate_ca_1.*`
and `intermediate_ca_2.*` (and both in `intermediate_ca.pem` and
`ca_bundle.pem`); `intermediate_ca.crt` comes back after the retire. Publish
the page now rather than at the next scheduled run (up to a day):

```bash
docker compose run --rm sick sick trust /srv/trust
```

**The overlap.** From now on the handover file `intermediate_ca.crt` holds
both intermediates, new first, and so does the trust page after the next
`sick trust`. Devices with a certificate under the old intermediate stay
`ok` and are renewed on their normal schedule, under the new one. Clients
that use the page's `ca_bundle.pem` accept both. Re-issue everything at once
instead with `sick run --force` if you prefer a short overlap.

**The end of the overlap:**

```bash
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate
docker compose run --rm sick sick trust /srv/trust
```

It prints `init-ca: retired the previous intermediate 'CN=Example
Intermediate CA' (…): out of the handover, its key deleted from
/home/step`.

Devices that present their certificate alone are `foreign-ca` from then on
and are renewed by the next run. A device that sends the old intermediate
along stays `ok` while that intermediate is valid, because SICK judges by
the root – after a **compromise**, run `sick run --force` for every device
instead of waiting. Replace `ca_bundle.pem` wherever a program uses it
(chapter 3).

## Replacing the root

A root replacement changes what every client trusts, so it is slow by
nature: the new root has to reach every client *before* anything depends on
it, and the old one may go only when nothing does. Three phases:

**Phase A, announce.** A second ceremony makes the new hierarchy, with its
own paths so that nothing of the first is overwritten (the ceremony refuses
to overwrite a key anyway), from the directory that holds the `sick`
checkout:

```bash
mkdir -p /media/offline/root2 && chmod 700 /media/offline/root2
(umask 077; openssl rand -base64 32 > /media/pwstick/root2.pw)
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/sick/docker/ceremony.sh:/ceremony.sh:ro" \
  -v /media/offline:/work -v /media/pwstick:/pw:ro \
  --entrypoint bash sick:local /ceremony.sh --operator 'A. Operator' \
  --out /work/for-the-ca-2 --root-key /work/root2/root_ca_key \
  --root-password-file /pw/root2.pw \
  --root-name 'Example Root CA 2' --intermediate-name 'Example Intermediate CA 2' \
  --dns example.internal --ip 192.0.2.0/24
```

Handle its output as for the first: write the root fingerprint down, copy
`root2/root_ca_key` to the second medium and compare the public keys (the
command of "The ceremony", with `root2` and `for-the-ca-2`), keep
`for-the-ca-2/*.crt` on both media. Put the new root where the `sick`
service can read it – the secrets directory is mounted already and owned by
root; a root is public, so mode 0644 – and announce it:

```bash
cd sick/docker
sudo install -m 0644 -o root /media/offline/for-the-ca-2/root_ca.crt secrets/root_ca_2.crt
# in sick.yml, ca section:   additional_roots: [/etc/sick/secrets/root_ca_2.crt]
docker compose up -d --force-recreate sick          # it reads sick.yml at start
docker compose run --rm sick sick trust /srv/trust
```

The trust page now carries both roots (`root_ca_2.pem`/`.crt`, both in
`ca_bundle.pem` and the Apple profile). Clients install the new root the
same way as the first, its fingerprint checked over the second channel.
Wait until the clients that matter have it.

**Phase B, switch.** The CA of the new root runs on a second volume; the old
volume stays, unused, for a planned rollback:

```bash
sudo install -m 0644 -o root /media/offline/for-the-ca/root_ca.crt secrets/root_ca_old.crt
# .env:     SICK_CA_IMPORT=/media/offline/for-the-ca-2
# sick.yml: additional_roots: [/etc/sick/secrets/root_ca_old.crt]
docker compose stop ca
docker compose -f compose.yml -f compose.import.yml -f compose.ca-next.yml up -d
docker compose -f compose.yml -f compose.ca-next.yml logs ca | grep 'root fingerprint'   # the new one
docker compose -f compose.yml -f compose.ca-next.yml up -d --force-recreate sick
docker compose -f compose.yml -f compose.ca-next.yml run --rm sick sick run --force
docker compose -f compose.yml -f compose.ca-next.yml run --rm sick sick trust /srv/trust
```

`ca.root` follows the handover to the new root; every device gets a
certificate of the new hierarchy (`renewed forced` – with no device yet,
the table stays empty; devices come in chapter 5). Wipe
`for-the-ca-2/intermediate_ca_key` and `password` from the offline media now
that the CA has imported them. Note that the file names on the trust page
follow the roles: from phase B on `root_ca.*` is the **new** root and
`root_ca_2.*` the old one – the fingerprints on the page say which is
which. Clients change nothing –
they trust both roots. From now on every `docker compose` command names
`compose.ca-next.yml`; without it Compose goes back to the old volume.

**Phase C, retire** – when every device presents the new hierarchy
(`sick inventory --live`): set `additional_roots: []` in `sick.yml`,
recreate `sick`, run `sick trust`, and have clients remove the old root
(chapter 3, "Taking trust away"). Then the old volume can go (`docker volume
rm sick_ca`, the project's `_ca` volume – keep its last backup until you are
sure), and so can `secrets/root_ca_2.crt` and `secrets/root_ca_old.crt`.
Point `SICK_CA_IMPORT` in `.env` at `for-the-ca-2`, so the file says what the
CA is built on, and back up the new volume (`./ca-backup.sh backup --volume
sick_ca-next --to …`). Clients remove the old root with a script from a page
**from before phase A**, or by file name – the phase-A scripts carry both
roots.

**Rollback.** In a *planned* replacement, going back is starting without
`compose.ca-next.yml` (the old CA is back), pointing `additional_roots` at
the new root again, recreating `sick` and `sick run --force`.

**After a compromise** (of the old root, or of an intermediate whose names
you cannot leave exposed – chapter 7): there is no rollback and no waiting.
Do phase A without waiting for clients, phase B at once, then phase C at
once: destroy the old volume, and have every client remove the old root – a
client that keeps it still accepts certificates signed with the stolen key.
Tested from the text by a newcomer: after phase C a client with only the new
root refused a certificate signed with the old intermediate key, also with
the old intermediate sent along.

**After every edit of `sick.yml`** recreate the `sick` service (`docker
compose up -d --force-recreate sick`): the file is mounted on its own, and an
editor that writes a new file leaves the running service on the old one.

**What the overlap does not carry.** The trust page holds the intermediates
of the current hierarchy only. A device that presents its certificate alone
(a one-slot switch) and is still under the *other* root is refused by a
client that has only the page's `ca_bundle.pem`: in phase A a pilot device
of the new hierarchy, in phase B a device not yet re-issued (unreachable
during the forced run). Devices that send their chain are not affected.
Keep phase B short and check that the forced run reached every device
(publishing the other hierarchy's intermediate too is a possible addition,
not built).

## The CA's logs are sensitive

step-ca logs the one-time token (`ott=…`) of a request it refuses, at
warning level. The token is single-use and short-lived, but treat the CA's
logs like its configuration: not world-readable, not shipped to a system
everybody can search.

## Test report

All e2e scripts were run against the committed state `8be6ed2` on
2026-10-10, after the changes of this chapter: `run-local.sh` 32 PASS,
`ca-ceremony.sh` 81 PASS, `ca-recovery.sh` 51 PASS, `ca-rollover.sh` 125
PASS and 6 RECORD, `trust-anchors.sh` done (its 8 FAIL lines are the
expected findings of case 5c2, see `docs/findings/trust-anchors.md`); no
resource labelled `sick=1` left afterwards. The rows below are the
development runs.

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/e2e/ca-ceremony.sh`, run twice | step / step-ca 0.30.2, OpenSSL 3.5, GnuTLS 3.8 (Debian 13) | ceremony record matches the certificates; CA starts in import mode without the root key in its volume; SICK issues for a device in scope, the device presents it; out-of-scope DNS name and IP refused by constraints and by policy, no certificate left; CSR with `CA:true` yields a plain leaf; lifetime above the maximum refused; out-of-scope leaves signed directly with the intermediate key refused by OpenSSL and GnuTLS, in-scope leaf accepted by both | 81 PASS, 0 FAIL, both runs; errors as quoted above | NSS and Go as path validators; RSA hierarchy; the YubiKey/HSM variant; "no certificate left" rests on the CA log and the absence of output, the database was not inspected |
| `t/e2e/ca-recovery.sh`, run twice | same | backup with manifest; restore into a fresh isolated volume, original CA still the only one serving; restored CA issues under the same root; database holds the pre-backup certificate, not the post-backup one; tampered archive and occupied volume refused; provisioner rotation: SICK issues with the new password, old password and old key refused | 51 PASS, 0 FAIL, both runs; RTO 3–4 s | restore onto another host; a large database; ACME account deactivation |
| `t/e2e/ca-rollover.sh`, run twice | same; clients curl 8.14.1 / OpenSSL 3.5.7 and gnutls-cli 3.8.9 | intermediate renewal: old-intermediate device stays `ok`, new issuance from the new one, both accepted with the page's bundle and refused with the root alone; a switch to a foreign intermediate and a second switch during the overlap refused; after retire the old device is renewed and verifies. Root replacement: clients that followed the page accept old and new hierarchy in phases A and B; a client with only the old page refuses new leaves; after C old leaves refused, new accepted; a further run changes nothing | 125 PASS, 0 FAIL, 6 RECORD (the overlap gap above), both runs | the planned rollback itself; a switch while the CA is stopped; RSA hierarchies; NSS and Go as clients |
| `t/e2e/run-local.sh` | same | lab mode unchanged after all changes | ALL PASSED | – |
| the ceremony above, by hand | step 0.30.2, OpenSSL 3.5.7 | output and record as shown | as shown | – |
