# Intermediates as trust anchors: which placements are safe

Question (karr k28): the trust page tells people to put the intermediate
certificate of the CA next to the root in the system store (Debian
`/usr/local/share/ca-certificates`, Fedora `ca-trust/source/anchors`, p11-kit
`trust anchor --store`). Does the intermediate become a trust anchor there,
does it stay trusted after the root is removed, and what are the safe places
for it, given that a device like the switch presents its leaf certificate alone?

**Answer: yes, the claim of k28 is real.** After the root is removed, an
intermediate left in the system store is still accepted by curl (OpenSSL),
GnuTLS and NSS. It is refused only by `openssl s_client`, because OpenSSL does
not accept a partial chain unless asked to. Details, the table and what follows
for the page are below.

Run by `t/e2e/trust-anchors.sh` (read its header for the case list). Run twice
on 2026-10-10 with identical tables; both runs ended with the containers gone.
No key or certificate is stored anywhere: the PKI is made inside each container
at run time.

## What was run

Two containers, `debian:trixie` and `fedora:latest`, named `sick-e2e-trust-*`,
removed at the end. In each: the clients are installed from the distribution
(`openssl`, `curl`, `gnutls-bin` / `gnutls-utils`, `libnss3-tools` /
`nss-tools`, `p11-kit`), then

- a throwaway PKI of EC P-256 keys: root, intermediate (CA, pathlen 0), leaf
  for `device.example.internal` (SAN, serverAuth), and a second, unrelated root
  with a leaf for the same name; the name resolves to 127.0.0.1 through
  `/etc/hosts` of the container;
- three `openssl s_server -www` on ports the system picks: **leaf** (the leaf
  only, what a switch does), **chain** (leaf and intermediate), **other** (the
  leaf of the unrelated root). The script checks that they send 1, 2 and 1
  certificates;
- the clients, each one asked for every case, with hostname verification on:

  | Column | Program | Library | Trust source |
  |---|---|---|---|
  | `curl` | `curl` | OpenSSL | the system bundle, or `--cacert` |
  | `s_client` | `openssl s_client -verify_return_error` | OpenSSL, no PARTIAL_CHAIN | system, or `-CAfile` |
  | `gnutls` | `gnutls-cli` | GnuTLS | the system store, or `--x509cafile` |
  | `nss-sys` | `tstclnt` (Fedora only) | NSS | empty database plus `p11-kit-trust.so`, the system store |
  | `nss-db` | `tstclnt` | NSS | a database made with `certutil`, no module with roots |

Stores: Debian `update-ca-certificates --fresh`; Fedora `update-ca-trust`;
Fedora p11-kit `trust anchor --store` / `--remove`. Files are named as the page
names them (`internal-root-ca.*`, `internal-intermediate-ca.*`).

## Versions

| | Debian 13 (trixie) | Fedora 44 |
|---|---|---|
| curl / OpenSSL in curl | 8.14.1 / 3.5.7 | 8.18.0 / 3.5.9 |
| openssl | 3.5.7 | 3.5.9 |
| GnuTLS | 3.8.9 | 3.8.13 |
| NSS | 3.110 | 3.130 |
| ca-certificates | 20250419 | 2025.2.80_v9.0.304-7 |
| p11-kit | 0.25.5 | 0.26.5 |

## Result

`accepted` / `refused` is the verdict on the server certificate. `-` is a
combination that does not exist for that client (NSS on Debian does not read the
system store; a CAfile or an NSS database is not read by the other clients).
The table is identical on both distributions for the columns they share, except
that Debian has no `nss-sys`, no `3p`/`4p`, no `5b`.

| Case | What | server | curl | s_client | gnutls | nss-sys (Fedora) | nss-db |
|---|---|---|---|---|---|---|---|
| 1 | root anchored | chain | accepted | accepted | accepted | accepted | accepted |
| 2 | root anchored | leaf | refused | refused | refused | refused | refused |
| 3 | root **and** intermediate in the anchors, as the page said | leaf | accepted | accepted | accepted | accepted | - |
| 4 | root removed, intermediate left in the anchors | leaf | **accepted** | refused | **accepted** | **accepted** | - |
| 4c | the same | chain | **accepted** | refused | **accepted** | **accepted** | - |
| 3p / 4p / 4pc | as 3 / 4 / 4c, with `trust anchor --store` (Fedora) | leaf / leaf / chain | accepted / **accepted** / **accepted** | accepted / refused / refused | accepted / **accepted** / **accepted** | accepted / **accepted** / **accepted** | - |
| 5a | intermediate in no store, root removed | chain | refused | refused | refused | refused | - |
| 5b | (Fedora) root anchored, intermediate a p11-kit non-anchor certificate | leaf | refused | refused | refused | **accepted** | - |
| 5b2 / 5b2c | (Fedora) root removed, non-anchor intermediate left | leaf / chain | refused | refused | refused | refused | - |
| 5c | CAfile with root + intermediate (`ca_bundle.pem`) | leaf | accepted | accepted | accepted | - | - |
| 5c2 / 5c2c | CAfile with the **intermediate only**, root absent | leaf / chain | **accepted** | refused | **accepted** | - | - |
| 5d | NSS db: root `C,,`, intermediate `,,` | leaf | - | - | - | - | accepted |
| 5d2 / 5d2c | NSS db: root absent, intermediate `,,` left | leaf / chain | - | - | - | - | refused |
| 4x / 4xc | NSS db: intermediate `C,,` (trusted CA), root absent | leaf / chain | - | - | - | - | **accepted** |
| 6 | the leaf of the unrelated CA, in every state above (Debian 6, Fedora 10 states; 4 NSS-db states) | other | refused | refused | refused | refused | refused |

Bold marks a result that is not what a safe placement would give. The
cells that contradicted the safety expectation are the only `FAIL` lines of the
script (4 per distribution, all in 5c2/5c2c); the case 4 family is `RECORD`:
it was recorded, not judged.

## What the cells say

- **The k28 claim is real, for three of four libraries.** Case 4: with the root
  gone and the intermediate left in the system anchors, curl, GnuTLS and NSS
  still accept the leaf, whether the server sends the chain (4c) or not (4).
  Only `openssl s_client` refuses ("unable to get issuer certificate"), since
  OpenSSL accepts a non-self-signed trust anchor only with `X509_V_FLAG_PARTIAL_CHAIN`;
  curl accepts the partial chain (not checked whether it sets that flag itself, or how), `s_client` does not. A program on Python, Go or
  Java is not tried (see below); do not expect it to be like `s_client`.
- **Case 3 and case 1+2 together are the switch case.** A leaf-only server is
  accepted only because the intermediate is a store entry (2 refused, 3
  accepted). Nothing in 3 distinguishes "helps build the chain" from "is an
  anchor"; 4 shows it is the second one.
- **A system-store entry that is not an anchor does not help the OpenSSL and
  GnuTLS clients (5b).** On Fedora a p11-kit file with `trusted: false` makes the
  certificate `trust: unspecified, category: authority` in `trust list
  --filter=certificates`. It is not written to `tls-ca-bundle.pem`; curl,
  `s_client` and `gnutls-cli` read that bundle (GnuTLS 3.8.13 did not use the
  p11-kit module here) and refuse the leaf-only server as in case 2. Only NSS,
  which reads the module live, accepts it and refuses again once the root is
  gone (5b2). So p11-kit non-anchors are a placement for NSS programs, not a
  general answer.
- **No placement in the Debian or Fedora bundle store helps a leaf-only device
  without anchoring the intermediate.** The bundle is a list of anchors.
- **A per-application CAfile has the same property inside the file.** 5c: root +
  intermediate in one file works for all three (and is how a leaf-only device
  gets verified at all). 5c2: with the intermediate alone in the file, curl and
  GnuTLS accept the device; they treat an intermediate in a CAfile as an anchor.
  `s_client` does not. The effect stays inside that file: take the intermediate
  out of the file and it is gone, there is no store that keeps it behind. The
  rotation procedure is "replace the file", the page already offers a fresh
  `ca_bundle.pem`.
- **NSS has a safe way (5d).** A database entry with trust flags `,,` helps
  build the chain (5d: accepted) and is refused once the root is gone (5d2).
  Marking the intermediate as a trusted CA (`C,,`, 4x) anchors it: accepted
  without the root. That is the flag the Firefox step of the page already
  leaves unticked.
- **The unrelated CA never gets in (6).** Refused in every client and every
  state (Debian 6 states, Fedora 10, NSS db 4).

## What follows for the page

Mapped to what `lib/SICK/Trust.pm` says today (platform blocks `DEBIAN`,
`FEDORA`, `ANDROID`, `WINDOWS`, `FIREFOXSTEP`, `LINUX`):

- **Debian, Fedora and `trust anchor --store` turn the intermediate into an
  anchor** (cases 3, 4, 4p). Safe there: the root alone. The page's own
  sentence "the intermediate is trusted there directly, next to the root.
  Take it out again together with the root" is true and a leftover is exactly
  the bug.
- **For a device that sends only its leaf (the switch)** no system-store
  placement on Debian or Fedora is both safe and working for curl, OpenSSL
  programs and GnuTLS programs (2, 3, 5b). What works safely: (a) the device
  sends the chain, (b) the program is handed `ca_bundle.pem` as its own CAfile,
  with the knowledge that curl and GnuTLS anchor the intermediate inside that
  file (5c, 5c2), so the file is the thing to rotate, (c) NSS programs: the
  intermediate with no trust flags (5d), or on Fedora as a p11-kit non-anchor
  (5b). Whether the device could be given the intermediate through its own
  chain setting is a question for its target, not for the clients.
- The page cannot honestly claim that "an intermediate is no second root" for
  the Debian, Fedora and p11-kit stores; it is a second root there. Either
  the platform blocks drop the intermediate and send the leaf-only case to
  `ca_bundle.pem`, or they keep it with a warning that it must be removed
  with the root.
- The Firefox step ("tick nothing") is the one platform block confirmed safe
  by this run, for NSS as tested with `tstclnt`.
- A name constraint on the intermediate would limit what a stale anchored
  intermediate can sign. Not tried: the PKI here has none.

## Not tried

- **Android** (user CA store, Network Security Configuration), **Windows**
  (including the *Intermediate Certification Authorities* store), **macOS**,
  **iOS** and **Chrome's own store** (Chrome root store, Linux NSS use):
  nothing was run, nothing in this document is a statement about them.
- Firefox itself and Chromium: only `tstclnt`, which shares NSS but not
  Firefox's preloaded intermediates, AIA fetching or enterprise-roots logic.
- Java, Python (`ssl`), Go, Node, Rust (rustls): not run.
- Debian with p11-kit anchors (`trust anchor` on Debian writes where
  `update-ca-certificates` does not look); Arch and other distributions.
- AIA fetching, CRL/OCSP, name constraints, expired certificates, TLS 1.2
  only, RSA keys, and `curl` built with GnuTLS or NSS.
- Clients that are given an intermediate as "untrusted" (OpenSSL
  `-untrusted`): the point of the table is what a bundle or store can do.
