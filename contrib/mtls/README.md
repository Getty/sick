# Client certificates (mTLS) with nginx and step-ca

People and machines prove who they are with a client certificate of the
internal CA; nginx checks it, maps the identity to a principal, and lets
in only the principals it lists. SICK is not involved: the certificates
come from the provisioner `clients` of the CA in `docker/`
(`provisioners.example.json`: JWK, `clientAuth` only, 30 days, at most 90),
under the same intermediate as the servers.

| File | What |
|---|---|
| `enroll.sh` | the admin enrols one holder: key, certificate, checks, PKCS#12 for a person |
| `nginx/mtls.conf` | nginx as the door of the application: client certificate, principal, 403 |
| `nginx/maps.conf` | subject DN → principal, revoked serials, a log format with the verify result |
| `nginx/principals.map` | who is allowed: one line per holder |
| `nginx/revoked-serials.map` | single certificates refused before they expire |
| `nginx/proxy.conf`, `nginx/backend.conf` | the same behind a terminating proxy, identity header over a hop with mTLS |
| `compose.yml` | the three nginx of the examples |
| `systemd/mtls-renew@.service`, `.timer` | daily renewal of a machine's certificate |

`t/e2e/mtls.sh` runs all of it against the lab CA; the record is
[docs/findings/mtls.md](../../docs/findings/mtls.md).

## Identities

| Holder | Subject CN | SAN | Example |
|---|---|---|---|
| person | the email address | `email:` the same | `person@example.internal` |
| machine | the host name | `DNS:` the same | `backup1.machines.example.internal` |

Machines get a DNS name in a subdomain of their own (`machines.example.internal`),
not a SPIFFE URI: a DNS SAN with a CN inside the DNS constraints is
accepted by every stack checked so far (OpenSSL, GnuTLS, Go, Java –
[client-san.md](../../docs/findings/client-san.md), case c1), needs no
`SICK_CA_ALLOW_URI` and no URI constraint (which GnuTLS ignores), and the
subdomain keeps machine names apart from server names. A URI works too
(`--san spiffe://example.internal/machine/backup1` with the FQDN as CN),
but a URI without a host (`urn:…`) is refused by Go, and a single-label CN
by Java and the CA's policy.

The CA has to allow those names. With the policy of `docker/` (recommended):

```bash
SICK_CA_ALLOW_DNS=*.example.internal,*.machines.example.internal
SICK_CA_ALLOW_IP=192.0.2.0/24
SICK_CA_ALLOW_EMAIL=@example.internal
```

(`*.example.internal` covers one label below it: without
`*.machines.example.internal` the CA refuses
`dns name "backup2.machines.example.internal" not allowed`, observed), and,
in import mode, an intermediate whose constraints cover them
(`ceremony.sh --dns example.internal --ip 192.0.2.0/24 --email example.internal`).

**One key per holder.** Every person and every machine is enrolled on its
own, with a key of its own. A fleet that shares one key shares one
identity: you can neither tell its members apart nor take one of them out.

## Enrolment

Who holds the password of `clients` can make a client certificate for any
identity the CA allows. That is the admin, nobody else; the password stays
in the volume of the CA until the admin takes it out
([docker/README.md](../../docker/README.md), "Further provisioners"):

```bash
docker compose cp ca:/home/step/secrets/provisioner_clients_password ./clients.pw
```

The bootstrap chosen here: **the admin enrols, the holder receives.**

```bash
export CLIENTS_PASSWORD_FILE=$PWD/clients.pw STEP_ROOT=$PWD/root_ca.crt
contrib/mtls/enroll.sh person  person@example.internal            out/person
contrib/mtls/enroll.sh machine backup1.machines.example.internal  out/backup1
```

`enroll.sh` makes a new key, has the CA issue the certificate
(`step ca certificate ID crt key --san ID --provisioner clients`), and
refuses the result unless the subject is `CN=<identity>`, the identity is
the only SAN and `clientAuth` the only extended key usage. For a person it
adds a PKCS#12 file (`step certificate p12`: key, certificate and
intermediate; AES-256-CBC with PBKDF2, SHA-256 MAC) and a random password
for it. Passwords reach `step` and `openssl` as files, never on a command
line.

- **A person** gets the `.p12` on one channel (handed over, or a file
  share they log in to) and the password on another (in person, by phone).
  They import it into the browser or the store of their system. Whoever
  renews with `step` (below) gets `.crt` and `.key` as well.
- **A machine** gets `.crt`, `.key` and the root over ssh into
  `/etc/mtls/` (key mode 0600, owned by the service that uses it).
- Then the admin removes `out/…`: the admin does not keep holders' keys.

Better options, **not tried** here: an OIDC provisioner (a person enrols
with their login, nobody else sees the key), or a one-time token from the
admin (`step ca token ID --provisioner clients`) with which a machine makes
its own key and certificate, so that the key never leaves it.

## Identity to principal

nginx verifies the chain, the validity and the purpose, and gives the
certificate's subject DN (`$ssl_client_s_dn`), not its SAN – nginx has no
variable for the SAN. Two ways were weighed:

- **Map the exact subject DN** (`maps.conf`, `principals.map`): what nginx
  has, without code. It is safe here because the subject of a `clients`
  certificate is what the admin put into the token: the CN is the token's
  subject, nothing else is in the DN (the template of `init-ca.sh` writes
  `.Subject` from the token), a CSR that asks for another CN or SAN is
  refused by the CA (`token subject … and CSR CommonName … do not match`;
  `certificate request does not contain the valid email addresses`, both
  observed), the policy judges the CN as well, and `enroll.sh` refuses a
  certificate whose CN is not its only SAN. The whole DN is compared, so
  `CN=person@example.internal,O=x` is not `person`.
- **Parse the SAN** in njs or in an auth subrequest: njs has no X.509
  parser (DER would have to be taken apart by hand, in the request path),
  and a subrequest adds a service that has to be up for anybody to get in.
  It buys nothing as long as CN = SAN is enforced at issuance.

Hence the DN. Limits: the mapping trusts the issuance procedure – a
certificate made by somebody with the `clients` password and a CN that
differs from its SAN would be mapped by its CN. And nginx compares map
strings **without regard to case**: `CN=PERSON@example.internal` would be
`person` too. Never enrol identities that differ in case only (`enroll.sh`
accepts lower case only).

**Authenticated is not authorized:** a valid certificate of the CA whose DN
is not in `principals.map` gets a **403** from the location – the TLS
layer has accepted it.

## nginx

```nginx
ssl_client_certificate /etc/nginx/certs/client-ca-bundle.pem;   # root + intermediate
ssl_verify_client      on;
ssl_verify_depth       2;
```

- `client-ca-bundle.pem` is the **trust set for clients**, named for that
  role: the root (the anchor) and the intermediate (so that a client may
  send its leaf alone). It is not the server's chain (`server.crt` = leaf +
  intermediate), even though it holds the same intermediate today: the day
  clients get an intermediate of their own, only this file changes. nginx
  sends the names in it to the client as acceptable CAs.
- Because servers and clients share the intermediate, the trust set also
  accepts the chain of a server certificate; what refuses a server leaf as
  a client is its purpose (`serverAuth` only: `unsuitable certificate
  purpose`), observed with curl and Go.
- `ssl_verify_depth 2`: leaf, one intermediate, root.
- **nginx completes the handshake and answers 400** when the certificate is
  missing (`$ssl_client_verify` = `NONE`, internally 496) or does not verify
  (`FAILED:<reason>`, 495); the request never reaches the location. The log
  format `mtls` records the verify result, DN, serial and principal of every
  request. It is not a TLS alert: a client sees an HTTP error page.

## Behind a terminating proxy

`proxy.conf` terminates the client's TLS, checks the certificate and the
principal exactly like `mtls.conf`, and forwards to the backend with
`proxy_set_header X-Client-Identity $mtls_principal`. nginx passes no client
header of a name that `proxy_set_header` sets: a spoofed `X-Client-Identity`
is replaced, twice-sent or in another case as well (observed).

The backend believes the header **from the proxy only**, recognised by
**the proxy's own client certificate** (`proxy.machines.example.internal`
from `clients`), on a TLS hop on which the proxy verifies the backend's
certificate too (`proxy_ssl_verify on`, `proxy_ssl_name`). `backend.conf`
answers 403 to every other certificate and 400 to none – also to a valid
client certificate of a person who goes round the proxy.

A source-address allow (`allow 192.0.2.5; deny all;`) was the alternative:
simpler, but it trusts whoever has that address – any container on the
same network, anything after a change of addresses – and it lets the
header cross the network in clear. The certificate travels with the proxy
and needs no knowledge of the network. Your application listens behind
such a hop: nginx in front of it on the same host, or its own TLS listener
with the same rule.

## Lifetime and renewal

| | lifetime | renewal |
|---|---|---|
| machine | 720h (30 days, the default of `clients`) | `mtls-renew@<id>.timer`: daily, renews when less than 240h are left |
| person | 720h | `step ca renew --expires-in 240h` on their own computer, or a new enrolment before the end |

`step ca renew` authenticates with the certificate itself (mTLS to the CA;
works for `clientAuth`-only certificates, observed), keeps the key and
gives a new serial; not due, it leaves the files alone and exits 0. An
expired certificate is not renewed (the CA's default): the holder is
enrolled again. A browser or system store holds a copy: after a renewal
the person exports and imports again
(`step certificate p12 new.p12 person.crt person.key --password-file …`).

The `clients` provisioner allows up to 2160h (90 days). Take that only for
a holder that cannot do better; it is three times as long for a lost
device to be useful.

## Losing a device

There is **no active revocation** in this setup: nginx asks neither a CRL
nor OCSP. `step ca revoke` marks a certificate revoked **at the CA** – it
stops its renewal (observed), nothing else; the certificate stays valid
everywhere until it expires. What to do:

1. **At once, on every nginx:** the serial into `revoked-serials.map`
   (`openssl x509 -in lost.crt -noout -serial`), `nginx -s reload` → 403 for
   that certificate (observed). If you do not have the certificate, remove
   the identity from `principals.map` instead – that blocks every
   certificate of the identity, the holder's replacement too, until you put
   it back.
2. **At the CA:** revoke the serial with a token of `clients`:
   ```bash
   TOKEN=$(step ca token --revoke --provisioner clients \
     --provisioner-password-file clients.pw <decimal serial>)
   step ca revoke --token "$TOKEN" <decimal serial>
   ```
   (`step certificate inspect --format json lost.crt` gives the decimal
   serial.) Any JWK provisioner can revoke any certificate of the CA – the
   `clients` password included.
3. **Enrol the holder again** – new key, new serial.

What bounds the rest is the lifetime, with one gap that was observed: a
certificate the lost device renewed **before** the revocation has another
serial, and it renews on – the revocation of its predecessor does not
reach it. A device that can still reach the CA (inside the network, a VPN)
can keep its identity alive that way, its renewal timer does it on its
own. The CA logs subject and serial of every renewal; look for the
identity there and treat every serial since the loss as in step 1 and 2:

```bash
docker compose logs ca | grep 'path=/renew' | grep 'subject=person@example.internal' | grep -o 'serial=[0-9]*'
```

nginx wants the serial in hexadecimal as OpenSSL prints it: `echo
'obase=16; <decimal>' | bc`, with a leading `0` when the number of digits
is odd (`086AC8…`).

Taking the name out of the CA's policy does not help: step-ca renewed a
certificate whose name the policy no longer allowed (observed). Where you
cannot be sure to have every serial, take the identity out of
`principals.map` and leave it out, or give the holder a new identity. A
device that cannot reach the CA any more is bounded by the 30 days.

## Not tried

Real browsers and system stores (Firefox, Chrome, Safari, Windows, the
macOS keychain, iOS, Android): the PKCS#12 import was checked with NSS's
`pk12util` and `tstclnt` only. CRL or OCSP in nginx (`ssl_crl`); OIDC
enrolment; Traefik or another proxy instead of nginx; client certificates
with RSA keys; TLS session resumption after a revocation.
