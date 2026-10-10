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

## `sick run` as a CronJob

[`k8s/cronjob`](cronjob/) is `k8s/test` with the loop replaced by a CronJob:

    kubectl apply -k k8s/daten       # once
    kubectl apply -k k8s/cronjob     # instead of k8s/test
    kubectl -n dev-sick create job --from=cronjob/sick-run sick-run-now    # a run now
    kubectl -n dev-sick logs job/sick-run-now

The CronJob `sick-run` starts a Job at 04:17 UTC that does `sick run`, then -
whatever it ended with - `sick check --format prometheus` and `sick trust`, as
`contrib/systemd/sick.service` does on a machine. The Deployment keeps `ca`
and `trust`, loses `sick` and gains `metrics`.

- **One run at a time.** `concurrencyPolicy: Forbid` holds back a schedule
  while a Job is active. A Job made by hand (`kubectl create job --from`) is
  not held back; sick's own lock then ends the second run with exit code 3,
  which the Job counts as success - nothing was done, and the run that holds
  the lock reports its own failure.
- **No retries by Kubernetes** (`backoffLimit: 0`): sick backs off a failing
  device itself, from one hour to a day. A missed start is made up within
  four hours (`startingDeadlineSeconds`), a Job that hangs ends after one
  (`activeDeadlineSeconds`). Three succeeded and three failed Jobs are kept
  with their logs.
- **Shared volumes.** What the CA hands over (`sick-handover`), the trust
  page (`sick-trust`) and the metrics (`sick-metrics`) are claims of their
  own instead of `emptyDir`, so that the Job's Pod sees them; `sick-state`
  is the one of `k8s/daten`. They are `ReadWriteOnce`: the Job's Pod is
  placed on the node of the Deployment's Pod (`podAffinity`) and waits while
  that Pod is not running. All three are written again - the handover at
  every start of the CA, the others by every run - and go with
  `kubectl delete -k k8s/cronjob`.
- **Metrics.** The Job writes `sick.prom`; the container `metrics` (busybox
  httpd) serves it as `http://sick-metrics:9101/sick.prom` with the
  Content-Type Prometheus 3 insists on. The Service carries the usual
  `prometheus.io/*` annotations; for the Prometheus Operator write a
  ServiceMonitor for port `metrics`, path `/sick.prom`. A file that stops
  changing is what `SickCheckStale` of
  [`contrib/prometheus/sick-alerts.yml`](../contrib/prometheus/sick-alerts.yml)
  catches. Not a Pushgateway: a pushed value stays forever, and the alerts
  of a device would outlive it. Not node_exporter's textfile collector: it
  reads a directory of the node, not a claim.
- **Alerts on the Job.** [`cronjob/sick-job-alerts.yml`](cronjob/sick-job-alerts.yml)
  has two rules over kube-state-metrics: `SickJobFailed`
  (`kube_job_status_failed`, names the Job whose log says which device) and
  `SickCronJobNotSucceeding` (no success for two days). They are no part of
  the kustomization, because the PrometheusRule kind exists only with the
  Prometheus Operator; the file says how to wrap them.
  `promtool test rules cronjob/sick-job-alerts.test.yml` tests them.

`t/e2e/ops.sh k8s` runs all this in a throw-away k3d cluster.

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
