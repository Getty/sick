# 8. Client certificates (mTLS)

You end this chapter with certificates for people and machines that
services check before they let anyone in – and with the understanding that
a valid certificate proves *who* is knocking, not that they may enter.

Everything here is a recipe around step-ca and nginx; SICK itself is not
involved. Recipe: [`contrib/mtls/`](../../contrib/mtls/), evidence:
[`docs/findings/mtls.md`](../findings/mtls.md) and
[`docs/findings/client-san.md`](../findings/client-san.md).

## Decision record: where client certificates come from

**Decision (2026-10-11):** a provisioner of its own, `clients`, under the
same intermediate as the server certificates, whose template issues
**`clientAuth` only** (declared in `provisioners.json`, chapter 2, managed
by `init-ca.sh` like the others).

**Alternatives considered:**

1. *A second, client-only intermediate under the root.* Cleaner on paper:
   servers could be told "only this intermediate issues clients". In
   practice an OpenSSL-based server anchors at the root anyway, so the
   separation would come from checking the issuer name, not from the trust
   store; and it costs a second intermediate to make in every ceremony, to
   renew, to rotate, and a second trust set to keep apart. Worth it when
   client certificates gate administrative access for many people, or need
   a different lifetime or revocation regime than servers – not before.
2. *Client certificates from the existing provisioner `sick`.* Rejected:
   its template issues `serverAuth`, and its password belongs to the
   machine that runs SICK.

**Why the provisioner is enough here:**

- **The purpose separates them.** Server certificates carry `serverAuth`
  only, client certificates `clientAuth` only. nginx (OpenSSL) refuses a
  server certificate presented as a client (`unsuitable certificate
  purpose`, tested), and the other way round.
- **Authorization is the real control anyway.** A server lets in a mapped
  identity, not "any certificate of our CA" (below).
- **The name constraints need care, and that is the same for both
  options.** Tested (`client-san.md`): an intermediate constrained to DNS
  names and IP ranges does **not** constrain email or URI SANs at all –
  RFC 5280 says a name form without constraints is unconstrained, step-ca
  checks each form only against its own constraints, and OpenSSL and Go
  accept such certificates. So:
  - make the intermediate with `ceremony.sh --email example.internal` (and
    `--uri` if you use URI identities) – then step-ca refuses
    `person@example.org` and the validators reject it;
  - list the same forms in the CA policy (`SICK_CA_ALLOW_EMAIL`,
    `SICK_CA_ALLOW_URI`): once any policy is set, a form that is not listed
    is refused, which otherwise blocks every person certificate.

## Identities

| Holder | SAN | CN | Why |
|---|---|---|---|
| a person | email: `person@example.internal` | the same | the form people know; constrained by `--email` |
| a machine | DNS: `backup1.machines.example.internal` | the same | every stack tested accepts it (OpenSSL, GnuTLS, Go, Java); URI identities trip Go (no host) and Java (a single-label CN taken as a DNS name) |

Machines live under their own subdomain, which needs its own policy entry
(`*.machines.example.internal`: `*.example.internal` covers one label only).
step-ca also checks the CN against the policy, so the CN must be one of the
SANs. `enroll.sh` refuses a certificate unless CN = SAN = the identity and
`clientAuth` is its only purpose.

## Issuing, one key per holder

```bash
# a person: certificate, key and a PKCS#12 for the browser
contrib/mtls/enroll.sh person person@example.internal
# a machine
contrib/mtls/enroll.sh machine backup1.machines.example.internal
```

Each holder gets a key of its own – never one key shared by a fleet; a
shared key makes every holder indistinguishable and every loss total.
Passwords (the provisioner's, the PKCS#12's) come from files, never from a
command line.

**Who may issue:** whoever holds the password of `clients`. The recipe's
bootstrap: an admin issues the certificate and hands the PKCS#12 to the
person, the PKCS#12 password over a second channel. An OIDC provisioner,
where people log in with their own account and get their own certificate,
is the better long-term way and *not tried*.

**Importing:** the PKCS#12 (`step certificate p12`: AES-256, PBKDF2,
SHA-256 MAC, leaf and intermediate) goes into the browser or OS store.
Tested with NSS (`pk12util`, then `tstclnt` presents it and gets in; a wrong
password imports nothing). Browsers and OS stores themselves: HQ
checklist.

## The server: nginx

```nginx
ssl_client_certificate /etc/nginx/tls/client-ca-bundle.pem;  # trust set for CLIENTS: root + intermediate
ssl_verify_client      on;
ssl_verify_depth       2;

map $ssl_client_s_dn $principal {          # exact subject DN -> principal
    "CN=person@example.internal"            person;
    "CN=backup1.machines.example.internal"  backup1;
    default                                 "";
}

location / {
    if ($principal = "") { return 403; }   # authenticated, but not allowed
    ...
}
```

(the full configuration is in `contrib/mtls/nginx/`).

- The client CA file is named for its **role**: it is the trust set for
  clients, not the server's own chain.
- **Mapping the exact subject DN is safe here** because step-ca takes the
  CN from the token, the template puts nothing else into the subject, and a
  request (CSR) cannot override it – tested: another CN or SAN in the CSR is
  refused by the CA. nginx has no variable for the SAN; parsing it would
  need njs with a DER parser or an extra authorization service. Use
  lower-case identities (nginx compares map strings without regard to case,
  according to its documentation; not tested).
- A certificate the server does not accept ends in **HTTP 400** from nginx
  (it completes the TLS handshake with `ssl_verify_client on` and then
  refuses); an accepted certificate whose identity is not mapped gets
  **403**.

**Behind a terminating proxy** the backend's peer is the proxy, not the
person. The proxy **overwrites** `X-Client-Identity` (`proxy_set_header`,
never passing one the client sent) and talks to the backend over **mTLS
with a certificate of its own** (`proxy.machines.example.internal`); the
backend accepts the header only from that certificate. A source-address
allow would trust anyone who gets that address, and leaves the header in
clear text on the network.

## Lifetime, renewal, and losing a device

**Recommendation:** 30 days (720 h, the default of `clients`) for people and
machines; 90 days only as an exception.

- **Machines renew themselves**: `step ca renew --expires-in 240h` from a
  daily timer (`contrib/mtls/systemd/mtls-renew@.timer`). Renewal goes over
  mTLS with the certificate itself, keeps the key and the identity, and is
  refused once the certificate has expired.
- **People renew** the same way with `step ca renew`, or are re-issued by
  the admin. Whoever is responsible for a person's access is responsible
  for that – write it down per team.

**Revocation is passive** with step-ca: `step ca revoke` stops a certificate
from being renewed, and **it stays valid until it expires**. So the
lifetime is the bound on a lost or stolen device. Tested, and important:

- a certificate the lost device renewed *before* you revoked the old serial
  keeps renewing – revoking a serial does not reach its successors;
- the CA policy is not checked at renewal: taking a name out of the policy
  does not stop its holder from renewing.

**When a device is lost:**

1. Put the serial into `revoked-serials.map` (nginx refuses it with 403)
   and reload nginx – the immediate block.
2. `step ca revoke <serial>`.
3. Look up later serials of that identity in the CA log (it names subject
   and serial of every renewal) and do 1–2 for each.
4. If in doubt, take the identity out of `principals.map`: no certificate
   of it gets in, whatever its serial.

## Test report

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/e2e/client-san.sh` | step-ca 0.30.2, OpenSSL 3.5.7, GnuTLS 3.8.9, Go 1.27.2, Temurin 25.0.4.1 | what step-ca issues and the stacks accept for email and URI SANs under DNS/IP constraints, with email/URI constraints, and with the policy | as tabled in `client-san.md`: DNS/IP constraints do not bound email/URI; Go refuses hostless URIs, Java a single-label CN; with email/URI constraints and policy, outside names are refused | other stacks (.NET, Rust) |
| `t/e2e/mtls.sh`, twice | step-ca 0.30.2, nginx 1.30.5-alpine, curl 8.14.1 / OpenSSL 3.5.7, NSS 3.110, Go 1.27.2 | approved person and machine 200 with their principal; refused: no certificate (400), another CA (400), serverAuth leaf (400), expired (400), not allowed (403); spoofed header through the proxy overwritten, straight to the backend refused; Go client the same; PKCS#12 into NSS, `tstclnt` gets in, wrong password imports nothing; `step ca renew` over mTLS; a revoked serial blocked by nginx's map | 79 PASS, 0 FAIL, both runs | real browsers and OS stores; CRL/OCSP in nginx; OIDC enrolment; Traefik as the proxy |
