# SICK on Kubernetes

The Compose setup of [`docker/`](../docker/) as a test environment in one
namespace: step-ca, `sick` on a schedule, and the trust page.

    kubectl apply -k k8s/daten     # once: the two volumes that stay
    kubectl apply -k k8s/test      # start
    kubectl delete -k k8s/test     # stop; the CA and SICK's state are kept

Everything lands in the namespace `dev-sick`. An account that may do the
usual things in that one namespace is enough (the built-in role `edit`);
nothing here is cluster-wide, and the Pod passes the `baseline` Pod Security
level.

## What runs

One Deployment with one Pod and three containers, because they share volumes
as the Compose services do. Inside the Pod `ca` is a name for localhost, so a
device list written for Compose works unchanged.

| Container | Image | Does |
|---|---|---|
| `ca` | `smallstep/step-ca` | the CA; `init-ca.sh` creates it at the first start |
| `sick` | `sick:local` | `sick run` every `SICK_INTERVAL`, then `sick trust` |
| `trust` | `busybox` | serves what `sick trust` wrote, port 8080 |

Two Services, `ca` (9000) and `trust` (8080), both inside the cluster only.
For a look from your machine:

    kubectl -n dev-sick port-forward svc/trust 8080:8080
    kubectl -n dev-sick exec deploy/sick -c sick -- sick check

## Yours to set

Do it in an overlay that names `k8s/test` as its resource:

- **The image.** `sick:local` is what `docker/Dockerfile` builds. Push it to
  a registry your cluster pulls from and name it with `images:`.
- **The device list.** Replace the ConfigMap `sick-config`
  (`configMapGenerator` with `behavior: replace`). The one in this directory
  has a single device of type `files` that needs nothing but the volume.
- **Credentials of the devices.** A Secret `sick-secrets` you create
  yourself; its keys appear as files in `/etc/sick/secrets/`. Without it the
  directory is empty.
- **How the CA and the trust page are reached from outside**: a Service of
  type LoadBalancer, a route at your gateway. Give the CA its outside names
  in `SICK_CA_DNS` before the first start; later they are changed in
  `config/ca.json` on the CA volume.

## What stays

`k8s/daten` holds the claims `sick-ca` (keys, configuration and database of
the CA) and `sick-state` (`known_hosts`, and what devices of type `files`
are given). Whoever has `sick-ca` has the CA: back it up, and delete it only
when you mean to end that CA.
