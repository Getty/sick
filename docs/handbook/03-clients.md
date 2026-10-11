# 3. Clients trust the CA

You end this chapter with every machine and program you care about
trusting your root – checked against a fingerprint that did not come over
the network – and with a way to take that trust away again.

Two rules run through it:

- **The root, and only the root, becomes a trust anchor.** An intermediate
  put into a store of anchors stays trusted after the root is removed or
  replaced ([evidence](../findings/trust-anchors.md)). Intermediates reach
  clients through the chain a server sends, through `ca_bundle.pem` given to
  one program, or through stores that keep them *without* trust (NSS,
  Windows, macOS, the Apple profile).
- **The fingerprint comes from a second channel.** The trust page is served
  over plain HTTP; a client that fetches its root there before it trusts
  anything has proven nothing. The SHA-256 fingerprint of the root is in the
  ceremony record (chapter 2). Hand it out on paper, read it out on the
  phone, put it into your password manager or wiki – anywhere an attacker on
  your network cannot change it.

## Publishing what clients need

```bash
sick trust /srv/www/trust
```

writes, next to the certificates and the page:

| File | For |
|---|---|
| `root_ca.pem`, `root_ca.crt` | the root, PEM and DER |
| `intermediate_ca.pem`/`.crt`, `ca_bundle.pem` | the intermediate, and root plus intermediate for one program's CA file (when the CA has an intermediate) |
| `root_ca_2.pem`/`.crt` … | further roots during a root replacement (`ca.additional_roots`, chapter 2) |
| `root_ca.mobileconfig` | iPhone, iPad, Mac |
| `trust-linux.sh`, `trust-macos.sh`, `trust-windows.ps1`, `trust-nss.sh` | install and remove scripts |
| `index.html` | the page: the out-of-band check first, then each platform |

The Docker setup runs `sick trust` after every run and serves the page on
port 8080.

## The scripts

Each script carries the certificates inside it – one download is enough –
and installs only when you give it the fingerprint of **every** root it
carries, as you got it over the second channel:

```console
$ sudo sh trust-linux.sh install --fingerprint 9c3289606dff96f99812f9cf9f90a499b4d32b674234de2212218ecb47d74a4c
```

The scripts need the store's own tools: `ca-certificates` on Debian,
Ubuntu and Alpine (`update-ca-certificates`), `ca-certificates`/p11-kit on
Fedora and Arch, `libnss3-tools` (`certutil`) for `trust-nss.sh`; they say
which one is missing. Colons and capitals in the fingerprint do not matter. A wrong, missing or
extra fingerprint ends the script with exit 1 and nothing written; it
prints the fingerprints it computed, and tells you not to copy them from
there. `remove` takes out exactly what `install` put in, says so, and can be
run twice. (On Debian, `update-ca-certificates` then prints its own `0
added, 0 removed; done.` – its count does not include the file the script
just deleted; the root is gone.)

**Check it** with a program the store serves, against a service with a
certificate of your CA – before install it is refused, after install
accepted, after remove refused again:

```bash
curl -fsS https://ca.example.internal:9000/health        # Linux system store
certutil -L -d sql:<db>                                  # NSS: the root with C,,
``` No script restarts anything; each tells you what still needs a
restart.

| Script | Where it puts what |
|---|---|
| `trust-linux.sh install\|remove` | roots only: Debian, Ubuntu, Alpine `/usr/local/share/ca-certificates/` + `update-ca-certificates`; Fedora, RHEL, Rocky, Alma `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust extract`; Arch and other p11-kit systems `trust anchor --store` |
| `trust-nss.sh install\|remove <profile or NSS db>` | Firefox profile or NSS database: roots `C,,` (trusted for websites), intermediates `,,` (known, not trusted) |
| `trust-macos.sh install\|remove` | roots into the System keychain as trusted roots, intermediates without trust (*not tried*) |
| `trust-windows.ps1 install\|remove` | roots into `LocalMachine\Root`, intermediates into `LocalMachine\CA` (*not tried*; run from an elevated PowerShell with `-ExecutionPolicy Bypass -File`) |

## Per platform

### Linux

`trust-linux.sh` as above. This covers what reads the system store:
curl, wget, Python's `ssl` and `urllib`, Go, git, most distribution
packages. It does **not** cover Java, Node or Python `requests` – see
[programs with their own store](#programs-with-their-own-store).

### Firefox

Firefox keeps its own store (NSS) per profile. `trust-nss.sh install
--fingerprint … ~/.mozilla/firefox/<profile>` with Firefox closed, or by
hand: *Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import*, root with "trust this CA to identify websites", the
intermediate with nothing ticked. Since Firefox 120 it also uses roots
from the operating system store on Windows, macOS and Android by default
(release notes, checked 2026-10-10); on Linux it does not.

### Chrome and Chromium

On Windows and macOS Chrome uses the operating system store. On Linux it
uses the NSS database in `~/.pki/nssdb`: `trust-nss.sh install
--fingerprint … $HOME/.pki/nssdb` (the directory, without `sql:`; create
the database first if Chrome has not, `mkdir -p $HOME/.pki/nssdb && certutil
-N -d sql:$HOME/.pki/nssdb --empty-password`; *not tried* with Chrome
itself), or
`chrome://certificate-manager` (Chrome 134 and later).

### macOS

`sudo sh trust-macos.sh install --fingerprint …`, or the profile
(`root_ca.mobileconfig`): open it, then *System Settings → Privacy &
Security → Profiles* to install. *Not tried.*

### iPhone, iPad

Open `root_ca.mobileconfig` in Safari, install it under *Settings →
General → VPN & Device Management*, then turn on full trust under
*Settings → General → About → Certificate Trust Settings* (Apple, "Trust
manually installed certificate profiles", checked 2026-10-10). The profile
is **not signed**, so the device shows it as "Not Verified": compare the
root's fingerprint shown after installing with the one you got over the
second channel. *Not tried.*

### Android

*Settings → Security → Encryption & credentials → Install a certificate →
CA certificate*, `root_ca.crt`, **root only**. Android has one list of CA
certificates and every entry is trusted by itself – the intermediate does
not go there. Apps that target Android 7 (API 24) or later trust user CAs
only if they opt in through a Network Security Configuration
(`<certificates src="user"/>`; Android documentation, updated 2026-08-28);
Chrome and Firefox do. A device that presents its certificate without the
intermediate is not accepted on Android; only one that sends the chain.
*Not tried.*

### Windows

`trust-windows.ps1 install --fingerprint …` from an elevated PowerShell,
or by hand: `root_ca.crt` → *Install Certificate → Local Machine → Trusted
Root Certification Authorities*; `intermediate_ca.crt` → *Intermediate
Certification Authorities*. Chrome and Edge use this store; Firefox does
since version 120. *Not tried.*

## Programs with their own store

Installing the root in the system store does **not** make every program
trust it. Observed in containers ([evidence](../findings/trust-runtimes.md),
2026-10-10):

| Program | Takes trust from | Sees a change without restart | Install the root | Remove |
|---|---|---|---|---|
| curl (OpenSSL) | system store; `--cacert`, `SSL_CERT_FILE` | new process per command | `trust-linux.sh`, or `--cacert root_ca.pem` | the same way back |
| git (GnuTLS in Debian) | system store; `http.sslCAInfo` replaces it | new process per command | system store, or `git config http.sslCAInfo /path/root_ca.pem` | unset it |
| Python `ssl`, `urllib` | system store, loaded once per context | no – restart | system store, or `SSL_CERT_FILE` | restart after removal |
| Python `requests` | **certifi only**; ignores the system store and `SSL_CERT_FILE` | no – restart | `REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt` (or the root file), or `truststore.inject_into_ssl()` | unset, restart |
| Java (Temurin) | its own `cacerts`; did **not** read the Debian store | no – restart | `keytool -importcert -cacerts -alias example-root -file root_ca.pem` – it shows the SHA-256 and asks `Trust this certificate?`: compare it with the fingerprint from the second channel; in a script `-noprompt`; or `-Djavax.net.ssl.trustStore=` | `keytool -delete -cacerts -alias example-root`, restart |
| Node | its bundled list | no – restart | `NODE_EXTRA_CA_CERTS=/path/root_ca.pem` (read at start), or `--use-system-ca` (Node 23.8+, on Linux 23.9+) | unset, restart |
| Go | system store or `SSL_CERT_FILE`, loaded once | no – restart | system store | restart after removal |
| container images | what was baked at build time | – | `COPY root_ca.pem /usr/local/share/ca-certificates/example-root.crt` + `RUN update-ca-certificates` (tested on Debian) | rebuild and redeploy |
| Kubernetes pods | a mounted file | a ConfigMap **directory** mount follows after about 70–85 s; a `subPath` mount never | ConfigMap with the root, mounted as a directory, plus `SSL_CERT_FILE` / `--cacert` | change the ConfigMap; re-create pods with `subPath` mounts |
| Docker daemon, BuildKit (registry trust) | `/etc/docker/certs.d/<registry>/ca.crt` | – | as named | *not tried* |
| trust-manager | – | – | – | *not tried* |

Every one of these stacks – OpenSSL, GnuTLS, Java's JSSE, Go – refused a
certificate outside the intermediate's name constraint, also when the root
was trusted. That makes the constraint a real limit for these clients;
older versions and other stacks (.NET, Rust, Ruby, PHP) were not tried.

**Recommendation:** where a program only talks to your own services, give
it a file for that program (`--cacert`, `http.sslCAInfo`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, a Java trust store, a
ConfigMap) instead of the whole machine. The trust stays inside that
program, and removing it is removing one file. Note that most file-based
routes *replace* the default list, so such a program no longer trusts
public CAs – except `NODE_EXTRA_CA_CERTS`, which adds, and Debian's curl,
which keeps reading `/etc/ssl/certs` beside `--cacert` (Fedora's does not;
tested 2026-10-11).

## Devices that present their certificate alone

A one-slot switch sends its certificate without the intermediate. A client
that trusts the root only cannot build the chain. For a program, give it
`ca_bundle.pem` as its CA file: inside that one file OpenSSL- and
GnuTLS-based programs treat the intermediate as an anchor, so replace the
file when the intermediate rotates. For browsers, keep the intermediate
without trust: Firefox (`trust-nss.sh`), Windows and macOS (their scripts)
and the Apple profile do that. Android cannot be helped: there, only
devices that send the chain work.

## Taking trust away

Run the script with `remove`, then **restart** what loaded the root before:
Java, Node, Go and Python services keep a root they have loaded until they
restart, images until they are rebuilt and redeployed, pods with a
`subPath` mount until they are re-created. A root is gone from a machine
only when no process from before the removal is still running.

During a root replacement (chapter 2), the new page carries both roots and
its scripts install both. After the replacement, the new script's `remove`
removes only what *it* carries; the old root goes with the old script, or
by hand (the file name or nickname contains the first 16 hex digits of its
SHA-256).

## To try at HQ

The steps for Windows, macOS, iPhone/iPad, Android, Chrome on Linux, the
Apple profile and Docker's registry trust that could not be walked through
here are on the [HQ checklist](hq-checklist.md#chapter-3--clients).

## Test report

All e2e scripts were run against the committed state `a4ef5e6` on
2026-10-10, at the end of this package: `run-local.sh` 32 PASS,
`ca-ceremony.sh` 81, `ca-recovery.sh` 51, `ca-rollover.sh` 125,
`trust-anchors.sh` 96 PASS and its 8 expected FAIL findings (case 5c2),
`trust-os.sh` 465 PASS, `trust-runtimes.sh` 147 PASS, each with 0
unexpected FAIL; afterwards nothing labelled `sick=1` and no `sick-*` k3d
cluster was left. The rows below are the development runs.

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/50-trust.t` (in `prove -lr t`) | OpenSSL 3.5 | scripts carry exactly the roots (Linux) or roots and intermediates (NSS, macOS, Windows); wrong, missing, partial, extra fingerprint refused with nothing written; right one accepted; remove exact and idempotent; never an intermediate in an anchor directory; page puts the out-of-band check first | green; pwsh syntax tests skipped (no pwsh on the host) | real systems – see the next rows |
| `t/e2e/trust-anchors.sh` | Debian 13, Fedora 44; curl/OpenSSL, s_client, GnuTLS, NSS | which placements turn an intermediate into an anchor | anchor stores of Debian, Fedora, p11-kit do; NSS `,,` and a program's CA file are bounded | Android, Windows, macOS, iOS |
| `t/e2e/trust-runtimes.sh`, run twice | see [evidence](../findings/trust-runtimes.md) | per program: refused before, accepted after install, wrong name / out-of-constraint / foreign CA refused, refused after removal; loading behaviour | 145 PASS, 0 FAIL, 51 RECORD, both runs; table above | Docker daemon, BuildKit, trust-manager; older versions; .NET, Rust, Ruby, PHP |
| `t/e2e/trust-os.sh` | Debian 13, Ubuntu 26.04, Fedora 44, Rocky 9.3, Arch, Alpine 3.24; curl/OpenSSL, s_client, GnuTLS, NSS `tstclnt` ([evidence](../findings/trust-os.md)) | the real `trust-linux.sh` and `trust-nss.sh` as root: refused before; wrong, missing, partial, malformed fingerprint refused with the store unchanged; install, clients accept; wrong name, out-of-constraint, foreign CA refused; the intermediate is no anchor (a leaf-only service is refused); remove; remove again says "not installed" | all steps ok on all six after one fix (a second `remove` on Arch claimed "removed"; fixed, regression test in `t/50`); `trust-windows.ps1` parses with PowerShell 7.4, `trust-macos.sh` with `sh -n` | Firefox and Chrome themselves; NSS clients on Arch and Alpine (database only); behaviour of the macOS and Windows scripts; `sudo` instead of root |
