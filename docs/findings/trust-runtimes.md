# Runtime trust matrix: who trusts the root, how, and who forgets it

Question (karr k36, part of P4/k14): the trust page gets a root onto a machine.
Which programs on that machine then trust it, how do they load it (system
store, an own store, a bundled one; at start or on every connection; restart
needed), and do they refuse what they must refuse: a leaf with the wrong name,
a leaf outside the name constraint of the intermediate, a leaf of an unrelated
CA, and everything again once the root is removed?

Run by `t/e2e/trust-runtimes.sh` (read its header for the case list). Run
twice on 2026-10-10 against the same images, about four and a half minutes
each: identical tables, 145 PASS, 0 FAIL, 51 RECORD, and both runs ended with
nothing left behind. No key or certificate is stored anywhere: the PKI is made
by `openssl` at run time into a private temporary directory and is mounted
read-only into the containers.

## What was run

- A throwaway PKI of EC P-256 keys: root R, an intermediate I **name-constrained
  to `DNS:example.internal`** (pathlen 0), and leaves. One container runs five
  `openssl s_server -www` listeners on a labelled Docker network and answers to
  `service.example.internal` and `outside.example.org`:

  | Port | Leaf | Signed by | What it is for |
  |---|---|---|---|
  | 4431 | `service.example.internal` | I (chain sent) | the good service |
  | 4432 | `wrong.example.internal` | I | called as `service.example.internal`: wrong name |
  | 4433 | `outside.example.org` | I | **out of the name constraint** (the client calls the name the leaf carries, so the name matches and only the constraint can refuse it) |
  | 4434 | `service.example.internal` | an unrelated root | unrelated CA |
  | 4435 | `outside.example.org` | I2, an **unconstrained** second intermediate of R | control for 4433: the same name is accepted when the constraint is absent |

  Before any client runs, `openssl s_client` with R confirms all five (accepted,
  refused for hostname, refused for "permitted subtree violation", refused,
  accepted) and that the good server sends leaf and intermediate, never the root.
- Per consumer the steps **1** before the install (refused), **2** install the
  documented way, **3** wrong name, **4** outside the constraint, **4k** the
  control through the unconstrained intermediate, **5** unrelated CA, **6**
  remove (refused again). The negatives 3, 4, 5 and 6 are asserted (`PASS` /
  `FAIL`); step 2 is asserted where the result is known beforehand and recorded
  where it is not; 4k and the loading probes are recorded.
- **Loading probes** for programs that live on: **wA**, a process started
  *before* the install, trying once a second: does it see the root without a
  restart? **wB**, a process started *while* installed: does it still trust the
  root after the removal?
- Consumers ran in `python:3`, `eclipse-temurin:25-jdk`, `node:lts` and
  `golang:1` containers, in an image built from a Dockerfile, and in pods of a
  k3d cluster. Client programs are small and ours (`HttpsURLConnection`, Node
  `https.request`, Go `http.Client`, Python `ssl`/`urllib`/`requests`); curl and
  git are the real binaries. A hostname check is always on.
- Everything the script creates carries `--label sick=1` and
  `--label sick-e2e=trust-runtimes` and is removed by those labels; the k3d
  cluster `sick-p4-rt` has a kubeconfig of its own and is deleted by that exact
  name (k3d cannot put `sick=1` on its network or its image volume; it deletes
  both with the cluster, and the script's check looks for them by name).

## Versions

| | |
|---|---|
| Python image | Debian 13 (trixie), Python 3.14.8, OpenSSL 3.5.7, requests 2.34.2, urllib3 2.8.0, certifi 2026.7.22, truststore 0.10.4 |
| curl (same image) | 8.14.1, libcurl with OpenSSL 3.5.7 |
| git (same image) | 2.47.3, links `libcurl-gnutls` and **GnuTLS 3** (Debian's git), not OpenSSL |
| Java image | Ubuntu 26.04.1, Temurin 25.0.4.1+1 (OpenJDK 25), JSSE |
| Node image | Debian 12 (bookworm), Node v24.21.0, OpenSSL 3.5.8 inside Node; `--use-system-ca` exists in this version |
| Go image | Debian 13 (trixie), go1.27.2 (`crypto/x509`, no C library) |
| Docker | 26.1.5, buildx 0.13.1 (BuildKit builder) |
| k3d / k3s | k3d v5.9.0, k3s v1.35.5+k3s1, containerd 2.2.3 |
| pod client | `buildpack-deps:stable-curl`, Debian 13, curl 8.14.1 / OpenSSL 3.5.7 |
| pod server | `alpine/openssl`, OpenSSL 3.5.9 |

Image digests are in the script's output (`=== VERSIONS`).

## Result

`accepted` / `refused` is the verdict on the server certificate. `!` would mark a
result that is not what was expected; the only one is the expectation that
Temurin picks up the Debian store (see below).

| Consumer | TLS library | 1 before | 2 install | 3 wrong name | 4 outside constraint | 4k control | 5 other CA | 6 removed |
|---|---|---|---|---|---|---|---|---|
| curl, system store (`update-ca-certificates`) | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| curl `--cacert` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| curl, `SSL_CERT_FILE` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| git, system store | GnuTLS (libcurl-gnutls) | refused | accepted | refused | refused | accepted | refused | refused |
| git `http.sslCAInfo` | GnuTLS | refused | accepted | refused | refused | accepted | refused | refused |
| Python `urllib`, system store | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| Python `ssl` default context, system store | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| Python `ssl`, `SSL_CERT_FILE` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| `requests` (certifi), root in the **system** store | OpenSSL, certifi bundle | refused | **refused** | refused * | refused * | refused * | refused * | refused |
| `requests`, `REQUESTS_CA_BUNDLE` = system bundle | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| `requests`, `REQUESTS_CA_BUNDLE` = the root only | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| `requests`, `SSL_CERT_FILE` | OpenSSL | refused | **refused** | refused * | refused * | refused * | refused * | refused |
| `requests` + `truststore.inject_into_ssl()` | OpenSSL via truststore | refused | accepted | refused | refused | accepted | refused | refused |
| Java, root in the **system** store | JSSE (PKIX) | refused | **refused !** | refused * | refused * | refused * | refused * | refused |
| Java, `keytool -importcert -cacerts` | JSSE | refused | accepted | refused | refused | accepted | refused | refused |
| Java, `-Djavax.net.ssl.trustStore` (own PKCS12) | JSSE | refused | accepted | refused | refused | accepted | refused | refused |
| Node, root in the system store, no flag | OpenSSL (bundled in Node) | refused | **refused** | refused * | refused * | refused * | refused * | refused |
| Node `--use-system-ca` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| Node `NODE_EXTRA_CA_CERTS` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused |
| Go, system store | Go `crypto/x509` | refused | accepted | refused | refused | accepted | refused | refused |
| Go, `SSL_CERT_FILE` | Go `crypto/x509` | refused | accepted | refused | refused | accepted | refused | refused |
| Container image (`COPY` root, `RUN update-ca-certificates`), curl in it | OpenSSL | refused (base image) | accepted | refused | refused | accepted | refused | refused (image rebuilt without the `COPY`) |
| Pod, ConfigMap as `/etc/ssl/certs/ca-certificates.crt` (`subPath`) | OpenSSL (curl) | refused | accepted | refused | refused | accepted | refused | refused (pod re-created without it) |
| Pod, ConfigMap directory + `curl --cacert` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused (same) |
| Pod, ConfigMap directory + `SSL_CERT_FILE` | OpenSSL | refused | accepted | refused | refused | accepted | refused | refused (same) |

`*` The root is not trusted in that row, so 3 to 5 refuse for the wrong reason
(unknown issuer); those rows say nothing about the checks. The script labels
them.

### Name constraints: all eight stacks enforce them

Step 4 is refused, and 4k (the same name through the unconstrained
intermediate) is accepted, wherever step 2 was accepted. So the refusal is the
constraint's doing and not the name's. The stacks and what they said:

| Stack | Message for step 4 |
|---|---|
| curl, Python, Node, pods (OpenSSL) | `permitted subtree violation` |
| git (GnuTLS) | `server verification failed: certificate error, no details available` |
| Java (JSSE) | `CertPathValidatorException: name constraints check failed` |
| Go | `x509: a root or intermediate certificate is not authorized to sign for this name` |

Independent implementations are among them: GnuTLS (git), JSSE (Java) and Go's
own X.509 code check the constraint as well as OpenSSL does. Only a DNS
constraint was tried (not IP, email or URI names), and only a permitted subtree
on a non-root CA.

## How each consumer loads trust

Observed with the **wA / wB** probes (long-running process, no restart) unless
the cell says otherwise. "Per process" means that every new process reads the
source again; for curl and git that is every command.

| Consumer | Loads trust from | When | Without a restart, after the install (wA) | After the removal, a process that started with it (wB) | To remove |
|---|---|---|---|---|---|
| curl | the system bundle `/etc/ssl/certs/ca-certificates.crt` and the hashed directory (OpenSSL default paths); `--cacert` / `SSL_CERT_FILE` replace it | per process | n/a (new process per command) | n/a | `rm` + `update-ca-certificates --fresh`, or stop passing the file |
| git | the system store through libcurl-gnutls; `http.sslCAInfo` replaces it | per process | n/a | n/a | same |
| Python `ssl` / `urllib` | system store through OpenSSL's default paths, `SSL_CERT_FILE` | context creation, but see below | **yes: accepted** | **still accepted** | restart the process |
| Python `requests` | the **certifi** bundle that ships with the package; `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` replace it; **not** the system store, **not** `SSL_CERT_FILE` | per request (the environment is read for each request) | n/a | n/a | unset the variable / remove the file |
| Python + `truststore` | the system store | once injected | not probed | not probed | unset/remove as the store |
| Java | the JDK's own `cacerts` (`$JAVA_HOME/lib/security/cacerts`) or `-Djavax.net.ssl.trustStore`; **not** the Debian store in this image | at the first use of the default `SSLContext` | **no: refused** | **still accepted** | `keytool -delete -cacerts -alias ...`, then restart the JVM |
| Node | its **bundled** Mozilla list; `NODE_EXTRA_CA_CERTS` adds one file; `--use-system-ca` adds the system store | start of the process (extra file) / first use (system store) | **no: refused** (`--use-system-ca`) | **still accepted** (`--use-system-ca`, `NODE_EXTRA_CA_CERTS`) | remove, then restart the process |
| Go | the system bundle and `/etc/ssl/certs` (or `SSL_CERT_FILE` / `SSL_CERT_DIR`); no C library | once, on the first TLS use of the process | **no: refused** | **still accepted** | restart the process |
| Container image | what was baked into the image at build time | at build | n/a | **the old image still trusts it**: removal is a rebuild and a redeploy | rebuild without the `COPY`; the old tag keeps trusting |
| Pod, ConfigMap directory mount | the file in the volume, read by the program in it | the file follows the ConfigMap after **about 70 to 85 s** (kubelet sync); the program reads it per process | n/a | the next `curl` in the running pod saw the new content without a restart | change or delete the ConfigMap, wait for the kubelet |
| Pod, ConfigMap with `subPath` | the file, mounted over the system bundle | the file **never** follows the ConfigMap | n/a | **the running pod kept the old root** after the ConfigMap lost it (checked after the same wait) | re-create the pod |

Details behind the cells that are not obvious:

- **Python's `urllib.request.urlopen` builds its `SSLContext` once**: the
  `HTTPSHandler` of the cached global opener creates it at construction
  (`urllib/request.py`, Python 3.14). A long-running script that calls `urlopen`
  therefore behaves like a process with a single context. The `ssl` row used a
  context created once; both gave the same result.
- **Python sees a root installed later without a restart, and keeps it after
  the removal.** The default verify paths of Debian's OpenSSL include the hashed
  directory `/etc/ssl/certs`, which OpenSSL searches lazily and caches in the
  context. A root added there is found by an existing context (wA: accepted); a
  root found once stays in that context's store (wB: accepted after the removal).
  Not tried: other Python versions, other OpenSSL builds, a context that loads
  only a `cafile`.
- **Java did not see the Debian store in this image.** `cacerts` is a plain file
  in `$JAVA_HOME/lib/security`, not a link to `/etc/ssl/certs/java/cacerts`;
  `ca-certificates-java` is not installed and `/etc/ca-certificates/update.d`
  holds no hook, so `update-ca-certificates` never reaches the JVM. This is the
  expectation the script marks `!`, a finding about this image, not about
  Debian's own Java packages, which wire that hook up (not tried here).
  `keytool -importcert -cacerts` works, and a later `update-ca-certificates`
  does not wipe the entry here (it would, with the Debian hook).
- **`-Djavax.net.ssl.trustStore` replaces `cacerts`.** The store the script
  makes holds the root only. The script does not check that public roots stop
  being trusted; that follows from the property's definition, not from this run.
- **Node without `--use-system-ca` never looks at the system store**: step 2 is
  refused after the documented Debian install. With the flag the store is
  loaded at the first TLS use, the same as Go.
- **curl honours `SSL_CERT_FILE`** (Debian's build uses OpenSSL's default
  locations, no compiled-in bundle that would override it).
- **`requests` ignores both the system store and `SSL_CERT_FILE`**, in this
  version with certifi 2026.7.22. The two documented switches, `REQUESTS_CA_BUNDLE`
  and `truststore`, work.

## What follows for the page and the handbook

- **There is no one install.** The system store covers curl, Python's `ssl` and
  `urllib`, Go and the pods' curl; it does not cover `requests`, Java (in this
  image) and Node. The page needs one line per consumer, not one per platform,
  and must say so first: "installing the root in the system store does not make
  your JVM, your Node service or your `requests` script trust it".
- **A name-constrained intermediate is a real scope, in every stack tried.** None
  ignored the constraint. The CA hierarchy and the handbook can offer "this CA
  can only ever sign `*.example.internal`" and mean it for these clients. State
  the limits: DNS names only, these versions, a client that lacks the check is
  not ruled out (not tried: older JDK, Node, Go, Python builds; .NET, Rust,
  Ruby, PHP).
- **Prefer a bundle for one application.** The tests show every per-application
  route works and stays inside the application: `curl --cacert`, `git -c
  http.sslCAInfo=`, `SSL_CERT_FILE` (curl, Python `ssl`, Go),
  `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, a Java trust store, a ConfigMap
  mounted into the pod. `NODE_EXTRA_CA_CERTS` adds to Node's own list; the other
  file-based routes replace the default for that program (they also drop the
  public roots, which matters if the program talks to both).
- **"Remove" is not finished until the process restarted.** Java, Node, Go and
  Python keep a root they have loaded. The removal text of the page must say
  "restart the service", and the handbook's emergency chapter should not count
  a root as withdrawn from a machine while a long-running process from before
  the removal is alive. Images keep it until rebuilt and redeployed; pods keep
  a `subPath` mount until they are re-created, and a directory mount follows
  the ConfigMap after about a minute and a half.
- **Dockerfile snippet works as written** (Debian base): `COPY root.crt
  /usr/local/share/ca-certificates/sick-root.crt` and `RUN
  update-ca-certificates`. Not tried on Alpine, `scratch` or distroless.
- **Kubernetes:** mounting the root as a whole `ca-certificates.crt` over the
  system bundle makes the pod trust the root and nothing else (one file, the
  public roots gone); a directory mount plus `SSL_CERT_FILE` / `--cacert` keeps
  the system bundle. trust-manager was not tried.
- **Fingerprint check:** this matrix installs from the harness; the fingerprint
  step of the install scripts is covered by the tests of `SICK::Trust` and the
  package for the page, not here.

## Notes for whoever runs it again

- `k3d cluster delete` rewrites the default kubeconfig (`~/.kube/config`) even
  when the cluster is not in it, unless `KUBECONFIG` points elsewhere. The
  script exports `KUBECONFIG` to a file in its private directory for every k3d
  and kubectl call, `--kubeconfig-update-default=false` for the create, and
  checks at the end that `~/.kube/config` is unchanged by modification time.
- On a host whose `/dev/kmsg` is a symlink (as here) the k3s node dies with
  `open /dev/kmsg: no such file or directory`. The script adds
  `--volume /dev/null:/dev/kmsg@server:0` in that case; the other k3d cluster
  on this host does the same. `--no-image-volume` made k3d 5.9.0 fail with
  "failed to ensure tools node", so the image volume stays (named
  `k3d-sick-p4-rt-images`, deleted with the cluster).
- A full run needs about 4.5 minutes with the images pulled; the first run pulls
  roughly 4 GB. The script takes `SICK_E2E_RT_ONLY=python,java,node,go,image,pods`.

## Not tried

- **Docker daemon registry trust (`/etc/docker/certs.d`) and BuildKit.** Both
  need a daemon of their own. The host's daemon is shared and not ours to
  configure; a daemon in a container needs `--privileged` (or an equivalent
  list of capabilities and an unconfined seccomp profile), which the rules of
  this run forbid. A registry on `127.0.0.1` would prove nothing: Docker treats
  the `127.0.0.0/8` registries as insecure by default. Marked "not tried" on the
  page until someone runs a daemon of their own for it.
- **trust-manager** (needs cert-manager and Helm charts from the internet), and
  the pod pattern with an init container that runs `update-ca-certificates`
  into an `emptyDir`.
- **Other platforms of these runtimes:** Alpine/musl, Fedora, Windows, macOS,
  Android; Debian's own Java packages with `ca-certificates-java`; older or
  other versions of JDK, Node, Go and Python; `.NET`, Rust (rustls), Ruby, PHP,
  Perl (`IO::Socket::SSL`), `wget`, Firefox and Chrome (the Firefox/NSS profile
  is a separate card).
- **Other certificate properties:** revocation (CRL, OCSP), expired leaves, IP
  and email name constraints, excluded subtrees, key usage and EKU mismatches,
  RSA keys, TLS 1.2 only, intermediates a server does not send, AIA fetching.
- **Public roots stay trusted** where a program is pointed at a root-only file
  (`--cacert`, `REQUESTS_CA_BUNDLE`, `trustStore`): by construction, not asserted.
