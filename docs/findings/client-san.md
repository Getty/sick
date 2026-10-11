# Client certificates under a name-constrained intermediate

Question (karr k58, P8): the provisioner `clients` (JWK, `clientAuth` only)
would issue under the same intermediate as the servers. That intermediate
comes from the ceremony with name constraints for DNS names
(`example.internal`) and IP addresses (`192.0.2.0/24`) only. Does step-ca
issue a client certificate with an email SAN or a URI SAN under it, and do
the validators of the stacks a server is built on accept such a chain? And
what changes when the intermediate constrains email addresses and URIs as
well?

**Short answer.** step-ca 0.30.2 issues email and URI SANs under a DNS/IP
intermediate without looking at them – any domain, and URIs without a host.
OpenSSL and GnuTLS accept all of those chains. Java refuses those whose
subject CN is a single label (`backup1`): it checks the CN against the DNS
constraints. Go refuses every URI without a host (`urn:…`) under any
name-constrained chain. With email and URI constraints in the intermediate,
step-ca refuses what lies outside them at issuance, and OpenSSL, Go and
Java refuse it in the path; GnuTLS does not check URI constraints at all.
The CA policy (`SICK_CA_ALLOW_DNS`/`_IP`) refuses email and URI SANs
outright. The decision itself is the maintainer's; what follows from the
facts is at the end.

Run by `t/e2e/client-san.sh` (parts `narrow` and `wide`; its header lists
the cases) on 2026-10-11, both parts ALL PASSED, everything removed at the
end. No key or certificate is kept: the ceremony, the CA and every leaf are
made at run time in a private directory and Docker volumes that the script
removes.

## What was run

- **The intermediate.** `docker/ceremony.sh` in the sick image without
  network: `--dns example.internal --ip 192.0.2.0/24` (part `narrow`, the
  hierarchy of `t/e2e/ca-ceremony.sh`), and additionally `--email
  example.internal --uri example.internal` (part `wide`; the two options are
  new in `ceremony.sh` and read back with `openssl x509 -text` like the
  others).
- **The CA.** step-ca in import mode on that hierarchy with
  `docker/provisioners.example.json`: the provisioner `clients` (JWK, profile
  `client`: `clientAuth` alone, key usage `digitalSignature`, 720h). Each
  case is asked with `step ca certificate` inside the CA container; the
  server control through `sick`.
- **What step-ca refused** was signed with the intermediate key directly
  (`openssl x509 -req`, bypassing step-ca) with the same names and the
  client profile, so that the validators judge every name form.
- **The validators**, each with the root alone as trust anchor, the
  intermediate as untrusted chain, for the purpose TLS client:

  | Column | How | Library |
  |---|---|---|
  | OpenSSL | `openssl verify -purpose sslclient` | OpenSSL 3.5.7 (Debian 13) |
  | GnuTLS | `certtool --verify --verify-purpose 1.3.6.1.5.5.7.3.2` | GnuTLS 3.8.9 (Debian 13) |
  | Go | `x509.Certificate.Verify` with `ExtKeyUsageClientAuth` (`t/e2e/client-san-verify.go`) | Go 1.27.2 |
  | Java | the PKIX `X509TrustManager.checkClientTrusted` a JSSE server uses (`t/e2e/ClientSanVerify.java`): path validation with name constraints, then the TLS-client checks of the leaf | Temurin 25.0.4.1 |

  Python was not asked: its `ssl` module is OpenSSL again. NSS was not
  asked (*not tried*).

## Versions

| | |
|---|---|
| step-ca, step | 0.30.2 (`smallstep/step-ca:0.30.2@sha256:a2b17872…bc8270`) |
| OpenSSL, GnuTLS | 3.5.7, 3.8.9 – `debian:trixie-20261005-slim@sha256:a29215f6…f49f11f`, packages of that day |
| Go | go1.27.2 – `golang:1@sha256:e432b43a…a40602` |
| Java | Temurin 25.0.4.1+1-LTS – `eclipse-temurin:25-jdk@sha256:8c0a84ea…72dcc` |

Full digests in the script.

## The cases

The subject is what `step ca certificate` makes of its arguments: the email
address itself for `person@…`; `backup1` for the URI cases, where the URI is
given with `--san` and becomes the only SAN. `c9` and `d0` repeat `c4` and
`c6` with the subject `backup1.example.internal`, to tell the CN apart from
the URI.

| Case | SAN | Subject CN |
|---|---|---|
| c1-dns-in | `DNS:backup1.example.internal` | backup1.example.internal |
| c2-email-in | `email:person@example.internal` | person@example.internal |
| c3-email-out | `email:person@example.org` | person@example.org |
| c4-spiffe-in | `URI:spiffe://example.internal/machine/backup1` | backup1 |
| c5-spiffe-out | `URI:spiffe://example.org/machine/backup1` | backup1 |
| c6-urn | `URI:urn:example:machine:backup1` | backup1 |
| c7-dns-out | `DNS:outside.example.org` | outside.example.org |
| c8-server-leaf | `DNS:web.example.internal`, `serverAuth` only (from `sick`) | web.example.internal |
| c9-spiffe-cn | `URI:spiffe://example.internal/machine/backup1` | backup1.example.internal |
| d0-urn-cn | `URI:urn:example:machine:backup1` | backup1.example.internal |

## Results

`issued` / `refused`: step-ca at issuance. The validator columns judge the
certificate step-ca issued, or – where step-ca refused – the one signed
directly.

**narrow** – intermediate constrains DNS `example.internal` and IP
`192.0.2.0/24` only:

| Case | step-ca | OpenSSL | GnuTLS | Go | Java |
|---|---|---|---|---|---|
| c1-dns-in | issued | accepted | accepted | accepted | accepted |
| c2-email-in | issued | accepted | accepted | accepted | accepted |
| c3-email-out | **issued** | accepted | accepted | accepted | accepted |
| c4-spiffe-in | issued | accepted | accepted | accepted | **refused** |
| c5-spiffe-out | **issued** | accepted | accepted | accepted | refused |
| c6-urn | issued | accepted | accepted | **refused** | refused |
| c7-dns-out | refused | refused | refused | refused | refused |
| c8-server-leaf | issued | refused | refused | refused | refused |
| c9-spiffe-cn | issued | accepted | accepted | accepted | accepted |
| d0-urn-cn | issued | accepted | accepted | **refused** | accepted |

**wide** – the same, plus email `example.internal` and URI
`example.internal`:

| Case | step-ca | OpenSSL | GnuTLS | Go | Java |
|---|---|---|---|---|---|
| c1-dns-in | issued | accepted | accepted | accepted | accepted |
| c2-email-in | issued | accepted | accepted | accepted | accepted |
| c3-email-out | refused | refused | refused | refused | refused |
| c4-spiffe-in | issued | accepted | accepted | accepted | **refused** |
| c5-spiffe-out | refused | refused | **accepted** | refused | refused |
| c6-urn | refused | refused | **accepted** | refused | refused |
| c7-dns-out | refused | refused | refused | refused | refused |
| c8-server-leaf | issued | refused | refused | refused | refused |
| c9-spiffe-cn | issued | accepted | accepted | accepted | accepted |
| d0-urn-cn | refused | refused | **accepted** | refused | refused |

**narrow with the CA policy** `SICK_CA_ALLOW_DNS=*.example.internal`,
`SICK_CA_ALLOW_IP=192.0.2.0/24`: c1 issued; c2, c3, c4, c5, c6, c9, d0
refused – `email name "person@example.internal" not allowed`, `uri name
"spiffe://example.internal/machine/backup1" not allowed`.

The messages, as the validators gave them:

- step-ca: `DNS name "outside.example.org" is not permitted by any
  constraint`; `Email address "person@example.org" is not permitted by any
  constraint`; `URI "spiffe://example.org/machine/backup1" is not permitted
  by any constraint`; `URI with empty host ("urn:example:machine:backup1")
  cannot be matched against constraints`.
- OpenSSL: `permitted subtree violation` (error 47); for the URN under a URI
  constraint `unsupported or invalid name syntax` (error 53); the server
  leaf `unsuitable certificate purpose` (26).
- GnuTLS: `The certificate chain violates the signer's constraints`; the
  server leaf `does not match the intended purpose`.
- Go: `x509: a root or intermediate certificate is not authorized to sign
  for this name: URI with empty host ("urn:example:machine:backup1") cannot
  be matched against constraints`; the server leaf `certificate specifies
  an incompatible key usage`.
- Java: `CertPathValidatorException: name constraints check failed` (no
  detail); the URN under a URI constraint fails with a
  `NullPointerException` ("otherHost" is null) inside the check – refused,
  but by accident; the server leaf `Extended key usage does not permit use
  for TLS client authentication`.

## Why, per implementation

- **step-ca** (`authority/internal/constraints` in smallstep/certificates
  v0.30.2, read in the module source): it collects the constraints of its
  intermediate per name form and checks each SAN against the list of its
  own form only; an empty list lets the form through (`checkNameConstraints`
  starts with "permitted" and only a non-empty list can make it false). So
  DNS/IP constraints say nothing about email and URI SANs. With a URI list,
  a URI without a host is an error (RFC 5280, 4.2.1.10). The CA policy
  (`authority/policy`) is the other way round: once anything is allowed,
  every name form without an allow rule is refused
  (`numberOfURIDomainConstraints == 0 && totalNumberOfPermittedConstraints >
  0`). `init-ca.sh` sets DNS and IP rules only.
- **OpenSSL and GnuTLS** follow RFC 5280 for a form without constraints:
  unconstrained. OpenSSL did not take the single-label CN `backup1` for a
  host name. GnuTLS 3.8.9 accepted URIs outside a URI constraint and a URN
  under one: it does not enforce URI constraints (observed; its source was
  not read).
- **Go 1.27** (`crypto/x509/constraints.go`, `checkChainConstraints` →
  `parseURIs`): as soon as any certificate of the chain has name
  constraints, every URI SAN of the leaf is parsed for its host, and one
  without a host (or with an IP address as host) is an error – whether or
  not there is a URI constraint. Email and URIs with a host are checked
  against their own form only.
- **Java 25**: refused c4 and c5 in both parts and accepted c9, which
  differs from c4 only in the subject CN. The refusal follows the
  single-label CN `backup1`, which lies outside the DNS constraint;
  consistent with the JDK checking the subject CN as a DNS name when the
  certificate carries no DNS SAN (interpretation – the JDK source was not
  read). With a CN inside the DNS constraint (`backup1.example.internal`)
  or no host-like CN (`person@example.internal`) Java behaves like OpenSSL.

## What follows for the decision

The decision – a `clientAuth` provisioner under the server intermediate, or
a client intermediate of its own – is the maintainer's. The facts it rests
on:

1. **Under the server intermediate, the constraints do not bound client
   identities.** An email address or a URI in any domain is issued and
   accepted (c3, c5); whoever holds the `clients` password, or the
   intermediate key, can make a client certificate for
   `admin@example.org`. What bounds them then is the server's own
   authorization (it must map a specific SAN to a principal, P8), and the
   provisioner.
2. **The CA policy as SICK sets it blocks email and URI SANs.** With
   `SICK_CA_ALLOW_DNS` or `_IP` set – the recommended setup – `clients` can
   issue DNS identities only. Email/URI client certificates under the same
   CA need policy rules for those forms (step-ca has `allow.email` and
   `allow.uri`; `init-ca.sh` does not set them – a gap noted on k58), or a
   provisioner-level policy, or no policy.
3. **Adding email and URI constraints to the intermediate works where it is
   checked** (step-ca at issuance; OpenSSL, Go, Java in the path), but
   GnuTLS ignores URI constraints, and the constraints go into a
   certificate that also signs servers: changing them means a new
   intermediate (`ceremony.sh --renew-intermediate` copies email and URI
   constraints now).
4. **Name forms to avoid**, whatever the hierarchy: a URI without a host
   (`urn:…`) – Go refuses it under any constrained chain; a single-label
   subject CN with only URI SANs – Java checks it against the DNS
   constraints. A person: CN and SAN = the email address (c2). A machine: a
   host-based URI (`spiffe://example.internal/…`) and a CN inside the DNS
   constraint (c9), or a DNS SAN (c1).
5. **The purpose check holds everywhere.** A `serverAuth`-only leaf from
   `sick` is refused as a client certificate by all four (c8), so a server
   certificate cannot double as a client credential under either design.
6. A separate client intermediate would carry constraints for client name
   forms only (and a server could trust it alone as its client CA, the
   role-named trust set of P8); the cost is a second intermediate in the
   ceremony and a way for the CA to sign with it: a `ca.json` names one
   intermediate, as `init-ca.sh` sets it up, so that would be a second
   step-ca instance or a feature of step-ca not looked at here (*not
   tried*).

## Not covered

NSS, Python (OpenSSL again), Windows CryptoAPI and macOS; a real TLS
handshake with client authentication (the validators were asked directly;
the nginx container test is P8's); directoryName and otherName (UPN)
constraints; excluded subtrees for email and URI; renewal of client
certificates under constraints; revocation.
