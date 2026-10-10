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

- a machine without network (a laptop with Wi-Fi off, or a container with
  `--network none`) that has `step` and `openssl` – the `sick` image has
  both, and `t/e2e/install-tools.sh` installs pinned versions;
- the removable medium for the root key, and a second one for its copy;
- a password for the root key in a file, kept apart from the key (a
  password manager, a sealed envelope);
- `docker/ceremony.sh` from this repository.

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/docker/ceremony.sh:/ceremony.sh:ro" -v /media/offline:/work \
  --entrypoint bash sick:local /ceremony.sh \
  --operator 'A. Operator' \
  --out /work/for-the-ca \
  --root-key /work/root/root_ca_key \
  --root-password-file /work/root/root.pw \
  --root-name 'Example Root CA' --intermediate-name 'Example Intermediate CA' \
  --dns example.internal --ip 192.0.2.0/24
```

It prints (fingerprints differ every time):

```text
ceremony: making the root 'Example Root CA' (EC P-256, 175320h)
ceremony: making the intermediate 'Example Intermediate CA' (EC P-256, 43830h)
ceremony: root fingerprint (SHA-256): 9c3289606dff96f99812f9cf9f90a499b4d32b674234de2212218ecb47d74a4c
ceremony: root key: /work/root/root_ca_key - take it off this machine and keep it with its password, apart from the CA
ceremony: for the CA (SICK_CA_IMPORT_DIR): /work/for-the-ca - the record is /work/for-the-ca/ceremony.txt
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

Afterwards: move `root/` to the media, check that the copy reads back (`step
crypto key inspect` asks for the password and shows the public key), and
wipe the working copy.

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

```bash
cd docker
cp sick.example.yml sick.yml          # the ca section: url https://ca.example.internal:9000
SICK_CA_IMPORT=/media/offline/for-the-ca \
SICK_CA_DNS=ca.example.internal \
SICK_CA_ALLOW_DNS='*.example.internal' SICK_CA_ALLOW_IP=192.0.2.0/24 \
  docker compose -f compose.yml -f compose.import.yml up -d --build
docker compose logs ca | grep init-ca
```

The log starts with `init-ca: import mode:` – in lab mode it would say
`init-ca: lab mode:`. Import mode checks that the root signed the
intermediate and that the key belongs to the intermediate, refuses an
import directory that holds any other private key (a root key put there by
mistake), and builds the CA without its own throwaway keys ever touching
the volume. After the first start the import directory is not read again.

**The CA's own names** (`SICK_CA_DNS`) have to lie inside the constraints:
`ca` and `localhost` do not, and a client refuses the CA's TLS certificate
if it names them. So in import mode SICK reaches the CA as
`https://ca.example.internal:9000`, and that name has to resolve – in
Compose through a network alias, on your network through DNS.

## What the CA will and will not issue

Two lines of defence, both active in the setup above:

1. **The name constraints in the intermediate.** step-ca 0.30.2 checks them
   when it issues, without any policy configured:
   `DNS name "outside.example.org" is not permitted by any constraint`
   (HTTP 403). And a client refuses a certificate outside them even if it
   was signed with a stolen intermediate key: `openssl verify` says
   `permitted subtree violation`, GnuTLS says `The certificate chain violates
   the signer's constraints`.
2. **The policy of the running CA** (`SICK_CA_ALLOW_DNS`,
   `SICK_CA_ALLOW_IP`): refuses with `dns name "..." not allowed`. It can be
   narrower than the constraints and changed without a ceremony; it does
   nothing against someone who has the CA keys.

What the provisioner `sick` gives out:

- **`serverAuth` only.** step-ca's default leaf template adds
  `clientAuth`; `init-ca.sh` sets a template without it at every start, in
  both modes.
- **No CA certificates.** A request (CSR) that asks for `CA:true` gets a
  plain leaf: the template decides, not the request.
- **No longer than `SICK_CA_MAX_LIFETIME`** (19800h = 825 days): a request
  for more is refused.

The ACME provisioner still has step-ca's defaults (both usages, 24 hours);
chapter 5 (P6) narrows it.

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

```bash
docker/ca-backup.sh backup  --volume sick_ca --to /safe/ca-2026-10-10.tar
docker/ca-backup.sh restore --from /safe/ca-2026-10-10.tar --volume sick_ca_drill
```

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
databases drift apart. The drill in `t/e2e/ca-recovery.sh` checks that the
restored CA issues leaves under the same root, that its intermediate is
still valid, that its database holds a certificate issued before the backup
and not one issued after, and that the live CA stayed the only one serving.

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

Rotate after anyone who had access to the CA volume or the `sick` container
leaves, and whenever the password may have been seen.

(For the record: `step ca provisioner update --create`, the documented
rekey, fails in step 0.30.2 against a local `ca.json` with `provisioner …
not found`; `init-ca.sh` removes and re-adds the provisioner instead.)

## Renewing the intermediate

Do it at least one device lifetime before the intermediate ends – with the
defaults, in year four of five – or at once after its key may have been
exposed. The root key comes out of its safe place for this, on the offline
machine:

```bash
docker run --rm --network none --label sick=1 --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/docker/ceremony.sh:/ceremony.sh:ro" -v /media/offline:/work \
  --entrypoint bash sick:local /ceremony.sh --renew-intermediate \
  --operator 'A. Operator' --out /work/new-intermediate \
  --root-cert /work/for-the-ca/root_ca.crt \
  --root-key /work/root/root_ca_key --root-password-file /work/root/root.pw \
  --intermediate /work/for-the-ca/intermediate_ca.crt
```

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
when it refuses, because that directory held a key.

**The overlap.** From now on the handover file `intermediate_ca.crt` holds
both intermediates, new first, and so does the trust page after the next
`sick trust`. Devices with a certificate under the old intermediate stay
`ok` and are renewed on their normal schedule, under the new one. Clients
that use the page's `ca_bundle.pem` accept both. Re-issue everything at once
instead with `sick run --force` if you prefer a short overlap.

**The end of the overlap:**

```bash
docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate
```

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

| Phase | On the CA side | On the clients |
|---|---|---|
| **A, announce** | a new ceremony (chapter 2, as for the first one) makes the new hierarchy. The device list gets `ca.additional_roots: [/etc/sick/secrets/root_ca_2.crt]`; `sick trust` publishes both roots, `root_ca_2.pem`/`.crt`, both in `ca_bundle.pem` and the Apple profile | install the new root the same way as the first, the fingerprint checked over the second channel. Wait until the clients that matter have it |
| **B, switch** | `docker compose stop ca`; start the CA of the new root on a second volume: `SICK_CA_IMPORT=<new hierarchy> docker compose -f compose.yml -f compose.import.yml -f compose.ca-next.yml up -d ca`. The old volume stays, unused. `ca.root` follows the handover to the new root; set `additional_roots` to the old root; `sick run --force` re-issues every device | nothing; both roots are trusted |
| **C, retire** | empty `additional_roots`, `sick trust` | remove the old root (chapter 3) |

From phase B on, every `docker compose` command names
`compose.ca-next.yml`; without it Compose goes back to the old volume.

**Rollback.** In a *planned* replacement, going back is starting without
`compose.ca-next.yml` (the old CA is back), pointing `additional_roots` at
the new root again, and `sick run --force`. After a **compromise** of the
old root there is no rollback and no overlap: destroy its volume, skip
phase A's waiting, and have clients remove the old root at once (chapter 7).

**What the overlap does not carry.** The trust page holds the intermediates
of the current hierarchy only. A device that presents its certificate alone
(a one-slot switch) and is still under the *other* root is refused by a
client that has only the page's `ca_bundle.pem`: in phase A a pilot device
of the new hierarchy, in phase B a device not yet re-issued (unreachable
during the forced run). Devices that send their chain are not affected.
Keep phase B short and check that the forced run reached every device
(card k34 tracks publishing the other intermediate if this matters to you).

## The CA's logs are sensitive

step-ca logs the one-time token (`ott=…`) of a request it refuses, at
warning level. The token is single-use and short-lived, but treat the CA's
logs like its configuration: not world-readable, not shipped to a system
everybody can search.

## Test report

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/e2e/ca-ceremony.sh`, run twice | step / step-ca 0.30.2, OpenSSL 3.5, GnuTLS 3.8 (Debian 13) | ceremony record matches the certificates; CA starts in import mode without the root key in its volume; SICK issues for a device in scope, the device presents it; out-of-scope DNS name and IP refused by constraints and by policy, no certificate left; CSR with `CA:true` yields a plain leaf; lifetime above the maximum refused; out-of-scope leaves signed directly with the intermediate key refused by OpenSSL and GnuTLS, in-scope leaf accepted by both | 81 PASS, 0 FAIL, both runs; errors as quoted above | NSS and Go as path validators; RSA hierarchy; the YubiKey/HSM variant; "no certificate left" rests on the CA log and the absence of output, the database was not inspected |
| `t/e2e/ca-recovery.sh`, run twice | same | backup with manifest; restore into a fresh isolated volume, original CA still the only one serving; restored CA issues under the same root; database holds the pre-backup certificate, not the post-backup one; tampered archive and occupied volume refused; provisioner rotation: SICK issues with the new password, old password and old key refused | 51 PASS, 0 FAIL, both runs; RTO 3–4 s | restore onto another host; a large database; ACME account deactivation |
| `t/e2e/ca-rollover.sh`, run twice | same; clients curl 8.14.1 / OpenSSL 3.5.7 and gnutls-cli 3.8.9 | intermediate renewal: old-intermediate device stays `ok`, new issuance from the new one, both accepted with the page's bundle and refused with the root alone; a switch to a foreign intermediate and a second switch during the overlap refused; after retire the old device is renewed and verifies. Root replacement: clients that followed the page accept old and new hierarchy in phases A and B; a client with only the old page refuses new leaves; after C old leaves refused, new accepted; a further run changes nothing | 125 PASS, 0 FAIL, 6 RECORD (the overlap gap above), both runs | the planned rollback itself; a switch while the CA is stopped; RSA hierarchies; NSS and Go as clients |
| `t/e2e/run-local.sh` | same | lab mode unchanged after all changes | ALL PASSED | – |
| the ceremony above, by hand | step 0.30.2, OpenSSL 3.5.7 | output and record as shown | as shown | – |
