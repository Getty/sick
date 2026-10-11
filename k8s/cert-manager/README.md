# cert-manager against the SICK CA

Two ways for cert-manager to get certificates from the step-ca of
[`k8s/test`](../test/): its own ACME client (a `ClusterIssuer`) and
smallstep's `step-issuer` (a `StepClusterIssuer`). Proven in a k3d cluster
by [`t/e2e/acme-k8s.sh`](../../t/e2e/acme-k8s.sh).

| Directory | Holds |
|---|---|
| [`ca/`](ca/) | the CA of `k8s/test` alone (no `sick`, no trust page), named `ca.dev-sick.svc`, policy `*.example.internal`, the provisioner `cert-manager` declared in `provisioners.json`, a NetworkPolicy on who reaches it |
| [`issuers/`](issuers/) | `ClusterIssuer sick-acme` (ACME, http-01) and `StepClusterIssuer sick-step` |
| [`demo/`](demo/) | per issuer a `Certificate`, an nginx Deployment serving it and its Service; a client Pod that trusts the CA through a ConfigMap |

## Versions

| | Version | How |
|---|---|---|
| cert-manager | v1.21.2 | `cert-manager.yaml` of the release, sha256 `e03b668e…1879f` |
| step-issuer | chart 1.11.0, image `cr.step.sm/smallstep/step-issuer:0.11.0` | `https://smallstep.github.io/helm-charts/step-issuer-1.11.0.tgz`, sha256 = digest of the chart index `ab8e85f3…f697ef` |
| helm | v3.22.0 | only to install step-issuer |
| step-ca | 0.30.2 | as in `k8s/test` |
| k3d / k3s | v5.9.0 / v1.35.5-k3s1 | the test cluster |

The full checksums are in `t/e2e/acme-k8s.sh`.

## Setting it up

    kubectl apply -k k8s/cert-manager/ca
    kubectl apply -f cert-manager.yaml               # the pinned release
    helm install step-issuer step-issuer-1.11.0.tgz -n step-issuer --create-namespace \
      --set image.tag=0.11.0

then the provisioner for step-issuer (below), and the issuers and the demo
in an overlay that fills in what exists only once the CA does:

- `caBundle` of both issuers: base64 of `root_ca.crt` (one PEM block);
- `kid` of `sick-step`: the key id of the provisioner `cert-manager`;
- the ConfigMap `acme-demo/sick-root` with `root_ca.crt`.

The root comes out of the CA through the Kubernetes API
(`kubectl -n dev-sick exec deploy/sick -c ca -- cat /home/step/certs/root_ca.crt`),
an authenticated channel; compare its fingerprint with the one `init-ca.sh`
logs. Not from the CA's own HTTPS port: that would be trusting what you
have not verified yet.

The test writes exactly such an overlay (see the script); http-01 also
needs the names to reach the ingress (below).

## Enrollment authorization

What has to be true before the CA signs a name, per issuer.

**ACME (`sick-acme`)**

- *Challenge:* http-01. The CA fetches
  `http://<name>/.well-known/acme-challenge/<token>` on port 80; cert-manager
  answers through a solver Pod behind an Ingress of class `traefik` (the one
  k3s ships). Ingress and not Gateway: k3s has Traefik with Ingress ready, the
  Gateway API would need its CRDs and a Gateway first, for the same result.
  dns-01 would need an API to an internal DNS zone, which the lab does not
  have.
- *Who reaches the endpoint:* the NetworkPolicy `ca-clients` lets the
  namespaces `cert-manager` and `step-issuer` reach port 9000 and nobody
  else (proven: a Pod in `acme-demo` gets no connection). There is no
  external account binding: whoever reaches the directory may open an
  account. The policy is what keeps an account from being worth much.
- *Names:* the policy of the CA (`SICK_CA_ALLOW_DNS=*.example.internal`)
  refuses everything else when the order is made, before any challenge
  (`rejectedIdentifier`). Inside the policy, a name is issued to whoever can
  answer for it on port 80 **as the CA resolves it**: through the cluster
  DNS. Whoever may create an Ingress for a host name, or change the cluster
  DNS, can get a certificate for that name. That is the trust http-01 puts
  in your cluster.
- *Lab vs real:* here the cluster DNS (a `coredns-custom` entry made by the
  test) points `web-acme.example.internal` at Traefik. In a real setup the
  internal DNS does that, and the CA must resolve the names the same way the
  clients do - never through a public resolver. Note that step-ca offers
  dns-01, http-01 and tls-alpn-01 for every order unless the provisioner is
  limited: `SICK_CA_ACME_CHALLENGES=http-01` in the environment of the `ca`
  container would do that (not set here, *not tried* in this cluster; the
  Compose setup proves it in `t/e2e/ca-ceremony.sh`).

**step-issuer (`sick-step`)**

- *Challenge:* none. A one-time token signed with the key of the JWK
  provisioner `cert-manager`; whoever holds its password may have the CA sign
  any name in the policy, for up to 90 days.
- *Who holds it:* the Secret `step-issuer/sick-step-provisioner`. step-issuer
  itself may read every Secret in the cluster (its ClusterRole from the
  chart); who can read Secrets in `step-issuer` can issue. cert-manager
  approves every CertificateRequest for step-issuer (the chart's approver
  role); add an approver policy if that is too wide.
- *Names:* the same policy of the CA, enforced at signing (`dns name
  "web.example.org" not allowed`).

### step-issuer: which provisioner

A provisioner of its own, `cert-manager`, not SICK's `sick`:

- `sick`'s password stays where SICK runs; a copy in a cluster Secret would
  widen who can issue as SICK, with up to 825 days.
- `init-ca.sh --rotate-provisioner` replaces `sick`'s key and password - that
  would silently break step-issuer, and its rotation would break SICK.
- Its own lifetimes: 30 days by default, at most 90, like ACME.

It is declared in [`ca/provisioners.json`](ca/provisioners.json), a
ConfigMap the `ca` container reads as `SICK_CA_PROVISIONERS_FILE`:
`init-ca.sh` makes it at the first start with a password it generates in
the CA volume (`secrets/provisioner_cert-manager_password`), and brings its
template (serverAuth only) and lifetimes (5m / 720h / 2160h) back in line
at every start (`docker/README.md`, "Further provisioners"). The password
goes into the Secret through the Kubernetes API, and from nowhere else:

    kubectl -n dev-sick exec deploy/sick -c ca -- \
      cat /home/step/secrets/provisioner_cert-manager_password >password-file
    kubectl -n step-issuer create secret generic sick-step-provisioner \
      --from-file=password=password-file
    rm password-file

The key id (`kid` of the issuer) is in `step ca provisioner list`. The
password must not end in a newline: `step` strips it from a file,
step-issuer takes the Secret byte for byte and fails with "error decrypting
provisioner key"; `init-ca.sh` writes it without one. `t/e2e/acme-k8s.sh`
does all of it (part `up`).

## Renewal

Both Certificates have `renewBefore: 240h` (ten days, one third of 30
days) and `rotationPolicy: Always`; `certificates.yaml` says why. The ACME
issuer asks for no lifetime - the CA's 720h apply; step-issuer passes
`duration: 720h` to the CA.

cert-manager writes the renewed certificate into the Secret. The kubelet
updates the mounted directory (a `subPath` mount would never change), and
`demo/serve.sh` has nginx reload when `tls.crt` changes. Without such a step
nginx keeps serving the old certificate.

The test shortens the lifetimes: the ACME provisioner issues for 8 minutes
(cert-manager renews at two thirds when `renewBefore` is longer than the
certificate), the step Certificate gets `duration: 1h` (cert-manager's
minimum) and `renewBefore: 55m`. Both renew about five minutes in.

## Trust in Pods

The root as a ConfigMap (`sick-root`), mounted as a file and given to the
program as its trust anchor (`demo/client.yaml`: `curl --cacert`). The
ConfigMap is per namespace and has to be made in each one that needs it.
trust-manager would copy one bundle into many namespaces: not tried.

## What the test proves

`t/e2e/acme-k8s.sh` (parts `up issue renew refuse down`), per issuer:

1. the Certificate becomes Ready, and the client Pod - curl with the root
   alone, against the Service, checking `web-*.example.internal` - sees the
   certificate that is in the Secret (same SHA-256 fingerprint); without the
   root curl refuses it; extended key usage `serverAuth` alone;
2. within about five minutes and without anything done by hand the client
   sees a new fingerprint, from the next revision of the Certificate;
3. `web.example.org`, outside the policy, is refused by the CA: ACME at the
   order (`rejectedIdentifier`), step-issuer at signing (`not allowed`);
4. ACME only: a name the CA resolves to somebody else's web server
   (`elsewhere.example.internal`) - the challenge becomes invalid; a name
   the CA reaches nothing at (`unreachable.example.internal`) - the CA reports
   `urn:ietf:params:acme:error:connection` and keeps the challenge pending,
   retrying (step-ca does not make a connection error final); a name nobody
   resolves (`noroute.example.internal`) - cert-manager's self check never
   passes and the CA is not asked. No certificate in any of them.

Not covered: a second client implementation (curl is OpenSSL), trust-manager,
the Gateway API solver, dns-01, a cluster with more than one node.
