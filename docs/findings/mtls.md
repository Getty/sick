# Client certificates with nginx: the mTLS recipe in containers

Question (karr k59, P8): with client certificates from the provisioner
`clients` of the lab CA, does nginx let in the approved person and the
approved machine and refuse each case of P8's done-when – no certificate,
another CA, a `serverAuth`-only leaf, an expired certificate, a valid
certificate of an identity that is not allowed (403, not a TLS error), a
spoofed identity header sent to the backend? Does a second client stack get
the same answers, does the PKCS#12 work in NSS, does renewal work over
mTLS? The recipe is [contrib/mtls](../../contrib/mtls/README.md).

**Short answer.** Yes to all. nginx refuses the four certificate cases
with **HTTP 400 after a completed handshake**, not with a TLS alert; the
verify result it logs names the reason (`NONE`, `FAILED:unable to verify
the first certificate`, `FAILED:unsuitable certificate purpose`,
`FAILED:certificate has expired`). The not-allowed identity gets a 403 with
`verify=SUCCESS`. Behind the proxy the header is replaced, and the backend
refuses everybody but the proxy's certificate. Go answers like curl; NSS
imports the PKCS#12 from `step certificate p12` and `tstclnt` gets in.
`step ca renew` works with a `clientAuth`-only certificate. Revocation is
passive, and it does not reach a certificate renewed before it.

Run by `t/e2e/mtls.sh` (all seven parts; its header lists the cases) on
2026-10-11, twice in a row, both ALL PASSED, everything removed at the end.
No key or certificate is kept: the ceremony, the CA and every certificate
are made at run time in a private directory and Docker volumes the script
removes.

## What was run

- **The hierarchy.** `docker/ceremony.sh` without network: `--dns
  example.internal --ip 192.0.2.0/24 --email example.internal`, read back
  with `openssl x509 -ext nameConstraints`. The stand-in root key is
  deleted before the CA starts.
- **The CA.** step-ca in import mode on it, `docker/provisioners.example.json`
  (`clients`: JWK, `clientAuth` only, `digitalSignature`, 720h, at most
  2160h), the policy `SICK_CA_ALLOW_DNS=*.example.internal,*.machines.example.internal`,
  `SICK_CA_ALLOW_IP=192.0.2.0/24`, `SICK_CA_ALLOW_EMAIL=@example.internal`.
- **Enrolment** as the README describes it: the admin takes the `clients`
  password out of the volume (`docker compose cp`) and runs
  `contrib/mtls/enroll.sh` in the sick image (step 0.30.2) for
  `person@example.internal` (with PKCS#12), `backup1.machines.example.internal`,
  `other@example.internal` (valid, not in `principals.map`) and
  `proxy.machines.example.internal` (the proxy's own identity); a second
  certificate for `person@example.internal` with 5 minutes. Server
  certificates for the three nginx and `web.example.internal` (the
  `serverAuth`-only leaf of case 3) through `sick`. The certificate of
  another CA is made with openssl: same CN and email SAN as the approved
  person, `clientAuth`, its own self-signed root.
- **nginx.** `contrib/mtls/compose.yml` with the confs as shipped: `mtls`
  (mtls.conf), `proxy` (proxy.conf), `backend` (backend.conf); only
  `revoked-serials.map` of `mtls` is a copy the script appends to. Nothing
  is published; the clients sit on the Compose network, whose resolver is
  the lab's DNS.
- **Clients.** curl (OpenSSL) in a Debian container; Go `crypto/tls`
  (`t/e2e/mtls-client.go`) in the golang image – an implementation that
  shares no code with OpenSSL; NSS `pk12util`, `certutil` and `tstclnt` in
  the Debian container. Python was not used: its `ssl` module is OpenSSL
  again.
- **Expired** (case 4): a certificate issued by step-ca through `clients`
  with `--not-after 5m` (the provisioner's minimum), and the script waits
  for its end – not one signed directly with past dates.

## Versions

| | |
|---|---|
| step-ca, step | 0.30.2 (`smallstep/step-ca:0.30.2@sha256:a2b17872…bc8270`; step in the sick image from `smallstep/step-cli:0.30.2`) |
| nginx | 1.30.5 (`nginx:1.30.5-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94`) |
| curl, OpenSSL | 8.14.1 with OpenSSL 3.5.7 – `debian:trixie-20261005-slim@sha256:a29215f6…f49f11f`, packages of that day |
| NSS | 3.110 (Debian `2:3.110-1+deb13u4`) |
| Go | go1.27.2 – `golang:1@sha256:e432b43a…a40602` |

Full digests in the script and in `t/e2e/mtls-compose.yml`.

## Results

`layer`: where the refusal happened. "HTTP 400" means the TLS handshake
completed and nginx answered the request with 400 (its internal 495/496);
the location – and with it the authorization – was never reached.
`verify=` is what nginx logged as `$ssl_client_verify`.

| # | Case | Client | Expected | Observed | Layer |
|---|---|---|---|---|---|
| | approved person | curl | 200 | 200 `principal=person` | – |
| | approved machine | curl | 200 | 200 `principal=backup1` | – |
| 1 | no certificate | curl | refused | 400 | HTTP 400, `verify=NONE` |
| 2 | another CA (same CN and SAN) | curl | refused | 400 | HTTP 400, `verify=FAILED:unable to verify the first certificate` |
| 3 | `serverAuth`-only leaf of the CA | curl | refused | 400 | HTTP 400, `verify=FAILED:unsuitable certificate purpose` |
| 4 | expired certificate of the CA | curl | refused | 400 | HTTP 400, `verify=FAILED:certificate has expired` |
| 5 | valid, identity not allowed | curl | 403 | 403 `not allowed` | authorization, `verify=SUCCESS`, no principal |
| | through the proxy: person, machine | curl | 200 | 200 `principal=person`, `principal=backup1` | – |
| 6 | spoofed `X-Client-Identity: admin` through the proxy | curl | replaced | 200 `principal=person` | proxy |
| 6 | the same twice, `X-Client-Identity` and `x-client-identity` | curl | replaced | 200 `principal=person` | proxy |
| 6 | not allowed, with `X-Client-Identity: person`, through the proxy | curl | 403 | 403 | proxy, authorization |
| 6 | spoofed header straight to the backend, no certificate | curl | refused | 400 | backend, HTTP 400, `verify=NONE` |
| 6 | the same with the approved person's valid certificate | curl | refused | 403 `not the proxy` | backend, authorization |
| 6 | the same with a `serverAuth` leaf | curl | refused | 400 | backend, HTTP 400 |
| | approved person, machine | Go | 200 | 200 with the principal | – |
| 5 | not allowed | Go | 403 | 403 | authorization |
| | person through the proxy | Go | 200 | 200 `principal=person` | – |
| 1 | no certificate | Go | refused | 400 | HTTP 400, `verify=NONE` |
| 2 | another CA | Go | refused | 400 | HTTP 400, **`verify=NONE`**: Go did not send it |
| 3 | `serverAuth` leaf | Go | refused | 400 | HTTP 400, `verify=FAILED:unsuitable certificate purpose` |
| 4 | expired | Go | refused | 400 | HTTP 400 |
| 6 | person's certificate straight to the backend | Go | refused | 403 `not the proxy` | backend |
| | PKCS#12 into NSS, wrong password file | pk12util | refused | exit 17, `SEC_ERROR_BAD_PASSWORD`, nothing imported | PKCS#12 MAC |
| | PKCS#12 into NSS, right password file | pk12util | imported | key and certificate `u,u,u`, intermediate | – |
| | tstclnt `-n person@example.internal` | NSS | 200 | 200 `principal=person` | – |
| | tstclnt without `-n` | NSS | (observed) | 200 `principal=person` | NSS chose the certificate itself |
| | `step ca renew --expires-in 240h`, fresh 720h certificate | step | not renewed | `certificate not renewed: expires in 719h59m…`, exit 0, files untouched | – |
| | `step ca renew` over mTLS | step | renewed | new serial, same CN, SAN, `clientAuth`, **same key**; nginx 200 | – |
| | old serial revoked (token of `clients`), its renewal | step | refused | 401 `certificate has been revoked` | CA |
| | the revoked certificate at nginx | curl | (passive) | **200** – still accepted | – |
| | its serial in `revoked-serials.map`, reload | curl | 403 | 403 `revoked`; the renewed certificate 200 | authorization |
| | a certificate renewed from the old one **before** the revocation | step | (observed) | **renewed** | CA |
| 4 | renewal of the expired certificate | step | refused | `certificate expired on …` | CA |
| | CSR with another CN than its token (`step ca sign`) | step-ca | refused | `token subject 'person@example.internal' and CSR CommonName 'admin@example.internal' do not match` | CA |
| | CSR with another SAN than its token | step-ca | refused | `certificate request does not contain the valid email addresses - got [admin@example.internal], want [person@example.internal]` | CA |
| | policy `*.example.internal` alone: `backup2.machines.example.internal` | step-ca | (observed) | refused, `dns name "…" not allowed` – one label only | CA policy |
| | policy without the machines' name: renewal of `backup1.machines…` | step-ca | (observed) | **renewed** – the policy is not checked at renewal | CA |

Further observations:

- **The PKCS#12** of `step certificate p12`: AES-256-CBC with PBKDF2
  (hmacWithSHA256, 2048 iterations) for key and certificates, SHA-256 MAC;
  NSS 3.110 imports it. It holds leaf and intermediate when the certificate
  file is step's bundle; an additional `--ca` with the intermediate puts it
  in twice. Without a friendly name, pk12util names the certificate after
  its CN.
- **Every key file mode 0600, one key per holder**: four holders, four
  distinct public keys.
- **The CA log** names subject and serial of every renewal
  (`path=/renew … serial=<decimal> … subject=person@example.internal`) –
  where the serials of renewals made by a lost device can be found.
- Any JWK provisioner can revoke any certificate (step's help; the
  revocation here used a token of `clients`).

## The mapping decision

nginx gives the subject DN (`$ssl_client_s_dn`), no SAN. The recipe maps
the **exact subject DN** to a principal (`map` with `principals.map`)
instead of parsing the SAN in njs or an auth subrequest. It holds because
the CN of a `clients` certificate is the token's subject, the DN holds
nothing else (template of `init-ca.sh`: `"subject": {{ toJson .Subject }}`,
filled from the token), a CSR cannot change it (both refusals above), the
policy judges the CN, and `enroll.sh` refuses a certificate whose CN is not
its only SAN – CN = SAN is enforced at issuance. njs has no X.509 parser,
and a subrequest adds a service in the path of every login, for nothing as
long as that holds. Limits: the mapping trusts the issuance procedure (who
holds the `clients` password can choose a CN), and nginx compares map
strings without regard to case (from its source and documentation; not
tested here).

## The proxy decision

The backend accepts `X-Client-Identity` from the proxy only, recognised by
**the proxy's own client certificate on an mTLS hop**, not by its source
address. The proxy replaces the header (`proxy_set_header`), verifies the
backend's certificate and name, and presents
`proxy.machines.example.internal`; the backend maps that DN alone. A
source-address allow trusts whoever holds the address – any container of
the network, anything after a renumbering – and leaves the header in clear
on the wire. The test reaches the backend directly from the client's
network on purpose: the refusal does not depend on the network keeping
anybody out.

## Not tried

- **Real browsers and system stores** – for the HQ checklist: Firefox (NSS,
  but its own certificate selection dialog), Chrome and Edge (system store
  on Windows and macOS, NSS on Linux), Safari and the macOS keychain
  (import of a PKCS#12 with AES/PBKDF2, identity preference per site),
  Windows (certmgr import, CNG; older Windows wants the legacy RC2/3DES
  encoding, `step certificate p12 --legacy`), iOS and Android (profile or
  file import, the system's certificate picker).
- CRL or OCSP in nginx (`ssl_crl`); a server's behaviour on TLS session
  resumption after a revocation; long-lived connections.
- OIDC enrolment; a token handed to a machine so that its key never leaves
  it.
- Traefik or another proxy; Java and GnuTLS as clients (they were asked as
  validators in [client-san.md](client-san.md)); RSA client keys; URI (SPIFFE)
  identities at nginx.
- Whether nginx's case-insensitive map lets `CN=PERSON@example.internal` in
  as `person` (not issued).
