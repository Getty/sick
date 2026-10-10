# 6. Operations

You end this chapter with SICK running on a schedule, telling you when a run
fails, exporting the state of every device and of the CA for Prometheus,
with alert rules whose thresholds follow each device's own settings, and
with an inventory of what is deployed where.

The idea behind all of it (skill `ssl-tls-pki`, "Renewal is an end-to-end
deployment transaction"): a renewal job that ran is not a valid certificate
on the device. SICK only counts a device as done when the device presents
the certificate it issued, compared by fingerprint – and monitoring looks at
the same thing, the live certificate, not a file.

## A run, its exit codes and its records

| Exit code | Means | Notify? |
|---|---|---|
| `0` | nothing failed | no |
| `1` | at least one device failed, was deferred, or could not be checked | yes |
| `2` | the command line or the device list is wrong | yes |
| `3` | another `sick run` holds the lock; this one did nothing | no – the other run reports its own result |

`sick run` takes a lock (`<state>/sick.lock`), so a timer and a run by hand
never work on the same device at once. It keeps one record per device in
the state directory (`state:` in the device list, default `/var/lib/sick`;
`devices/<name>.json`): the last look, the last certificate issued (serial,
fingerprint, names, until, issuer), the last deployment, failures in a row,
the next attempt. Never a key. `sick check`, `sick inventory`, `sick run
--dry-run` and `sick trust` take no lock and write no record.

**Back-off.** A device whose deployment or check after deployment failed is
not given a new certificate on every run: it is deferred for 1, 2, 4 … at
most 24 hours (less a grace of 15 minutes, so a daily timer does not skip a
day), shown as `deferred`, and counts as failed for the exit code. `sick
run --force <device>` tries at once. The certificate of the failed attempt
is not revoked: its key never left a private temporary directory and is
gone, so the certificate is useless to anyone.

**Devices of type `files`** get each new certificate as one generation:
`cert.pem`, `chain.pem`, `fullchain.pem` and `key.pem` are links into
`dir/.sick/current`, switched in one step. If the `reload` command fails,
SICK switches back to the previous generation, runs the reload again, and
reports the device as failed. Mount the directory into containers, not the
single files.

## The schedule

Pick one.

**systemd** (recommended on a host): copy the three units from
[`contrib/systemd/`](../../contrib/systemd/) to `/etc/systemd/system/` and
`contrib/notify/sick-notify` to `/usr/local/bin/`, then

```bash
systemctl daemon-reload
systemctl enable --now sick.timer
systemctl list-timers sick.timer
```

- `sick.timer` runs at 04:17 plus a random delay of up to an hour, fixed
  per machine (a delay drawn anew every day could put two runs 23 hours
  apart), and catches up after downtime (`Persistent=true`).
- `sick.service` runs `sick run`, then – whatever the result – writes the
  Prometheus file and the trust page. Exit code 3 counts as success
  (`SuccessExitStatus=3`).
- A failure starts `sick-notify@sick.service`, which sends that run's
  journal lines.
- The service is sandboxed (`ProtectSystem=strict`, no capabilities,
  `systemd-analyze security` 3.4). A `files` device needs its directory
  added with a drop-in: `ReadWritePaths=/srv/certs/grafana`.

**cron**: [`contrib/cron/sick`](../../contrib/cron/sick) into
`/etc/cron.d/`. It notifies on every exit code but 0 and 3, and writes the
Prometheus file and the trust page after each run.

**Kubernetes**: [`k8s/cronjob/`](../../k8s/cronjob/) runs `sick run` as a
CronJob (`concurrencyPolicy: Forbid`, no retries, `activeDeadlineSeconds:
3600`), serves the Prometheus file over HTTP for scraping, and brings two
alert rules for failed Jobs (`SickJobFailed`, `SickCronJobNotSucceeding`).
See `k8s/README.md`.

**Docker Compose**: the `sick` service of `docker/` runs `sick run` every
`SICK_INTERVAL` and `sick trust` after each run (chapter 2). It has no
notification of its own: scrape its metrics, or run the cron line on the
host against `docker compose run --rm sick sick run`.

## Notification when a run fails

`contrib/notify/sick-notify` sends a subject and the run's output to a
webhook and/or by mail. Its configuration, `/etc/sick/notify.conf`, holds
paths and addresses only; the webhook URL – often a secret – is the first
line of the file it names:

```ini
webhook_url_file = /etc/sick/notify-webhook.url
#webhook_cacert  = /etc/sick/root_ca.pem
#mail_to         = ops@example.org
```

The configuration is parsed, never executed; an unknown key is an error.
The URL reaches curl on its standard input, never as an argument, and
neither the URL nor curl's error text appears in any output. Exit 0 when the
message was delivered somewhere, 1 when nowhere, 2 for a wrong configuration
or command line. **Test it once:** `echo test | sick-notify "sick test"`.

## Monitoring with Prometheus

```bash
sick check --format prometheus --output /var/lib/prometheus/node-exporter/sick.prom
```

(the systemd service and the cron line do this after every run). The file
is replaced in one step, for node_exporter's textfile collector. It
contains, per device, the live certificate (end, remaining and total
lifetime), the device's `renew_before`, the earliest end along its chain
to the root, whether it is the certificate issued last, failures in a row
and the last success; for the CA, whether it answers (`step ca health`) and
when root and intermediates end. `sick check --format json` gives the same
as JSON.

The alert rules in
[`contrib/prometheus/sick-alerts.yml`](../../contrib/prometheus/sick-alerts.yml):

| Alert | Fires when | Why that threshold |
|---|---|---|
| `SickRenewalLate` | remaining < `renew_before` / 2 | SICK should have renewed at `renew_before`; half the window has passed without it |
| `SickCertificateExpiring` (critical) | remaining < `renew_before` / 4 | a quarter of the window is the last margin for a human |
| `SickDeviceStale` | the device presents another certificate than the last one issued, for 1 h | a reload or rollback went wrong, or someone replaced it |
| `SickDeviceUnreachable` | for 1 day | SICK cannot judge it – and cannot renew it |
| `SickDeviceFailing` | 3 failures in a row | the back-off has started |
| `SickCAUnreachable` | for 30 min | nothing renews while the CA is down |
| `SickIntermediateExpiring` | < 365 days left | time to renew it (chapter 2) |
| `SickRootExpiring` | < 730 days left | a root replacement takes long (chapter 2) |
| `SickCheckStale` | the file is older than 2 days | the schedule itself stopped |

The thresholds are relative to each device's `renew_before`, not a fixed
number of days: a fixed 30 days means nothing for a certificate that lives
a week, and is noise for one that lives two years. With the defaults (397
days, renew 30 days before), `SickRenewalLate` fires 15 days before the
end and `SickCertificateExpiring` 7.5 days before.

Note what `sick run` does **not** fix: a device that presents an *older*
valid certificate of your CA with the right names counts as `ok` and is
left alone; only `SickDeviceStale` notices (card k44 decides whether SICK
should redeploy).

## The inventory

```bash
sick inventory                  # from the records alone, no network
sick inventory --live           # and a look at every device
sick inventory --format json
```

Per device: the names, issuer, serial and fingerprint of the certificate
issued last, until when, when it was deployed and when a run last saw the
device present it; with `--live`, whether the device presents it right now.
This is the list to go through when an intermediate or the root is
replaced, or a device is retired (remove it from the device list – SICK then
stops renewing it, and its certificate expires).

## Logs

`sick run --verbose` reports each step on standard error; the systemd
service and the CronJob keep it in the journal or the Job's log. No line
carries a key or a password. step-ca's own log is sensitive (chapter 2):
keep it as you keep the CA's configuration.

## Test report

| Test | Versions | Expected | Observed | Not covered |
|---|---|---|---|---|
| `t/40-runner.t`, `t/41-cli.t` (in `prove -lr t`) | – | records after run; check and dry run write none; back-off 1, 2, 4 … 24 h, grace 15 min, `--force`, reset on success; unreachable not counted; broken record reported; exit 3 with the lock held, lock free after a die; no key in a record | green | – |
| `t/32-target-files.t` | – | one generation at a time; a reader never sees a key and certificate of different generations (589 reads during 30 deploys); rollback on a failed reload; migration from plain files; at most two generations | green | services that open the files separately during a switch (documented) |
| `t/43-report.t` | – | table unchanged; JSON shape; Prometheus lines parse back; atomic `--output`; inventory from records and `--live`; CA up/down; no key in any output | green | – |
| `promtool` on the rule files | promtool 3.15.0 | `check rules`; `test rules` with synthetic series, every alert firing and not yet firing around its `for:` | SUCCESS | – |
| `t/e2e/ops.sh`, run four times | systemd 257, promtool 3.15.0, k3d 5.9.0 / k3s 1.35.5 | `systemd-analyze verify` of the units; a failing device notified through the cron line (webhook and mail) and through `sick-notify -u`; exit 3 notifies nothing; the webhook URL in no output; real `sick check` output makes `SickDeviceStale` and `SickCAUnreachable` fire, a healthy one nothing; the CronJob completes in k3d, a second Job ends with exit 3 as Complete, Forbid refuses a concurrent run | 72 PASS each run | systemd itself running the units (no systemd in a container); a real MTA; Pushgateway; kube-state-metrics in the cluster |
