# SICK

**Ship Internal Certificates & Keys** – bring certificates of an internal CA to
devices that cannot fetch them themselves, and keep them current.

Switches, routers, management controllers, appliances: they serve HTTPS with a
self-signed certificate that expired years ago, they cannot answer an ACME
challenge, and their names are internal anyway. SICK asks your
[step-ca](https://smallstep.com/docs/step-ca/) for a certificate, installs it
on the device, and does it again before it expires. A device list is the whole
configuration.

SICK is not a CA and not an ACME client. The CA is step-ca, X.509 is done by
the `openssl` command line, and where [acme.sh](https://github.com/acmesh-official/acme.sh)
already has a deploy hook for a device, SICK uses that hook. What SICK adds is
the device list, the decision, the connections to the devices and the run that
ties them together. Besides core Perl, the core depends on `Moo`,
`namespace::autoclean` and `Type::Tiny` for its classes, `Path::Tiny` for files
and `YAML::PP` for the device list.

> Status: complete for a first release, not released yet. The command line
> (check, run, trust, inventory; JSON and Prometheus output), the device
> types `files` and `acmesh` here and `cisco-sb`, `proxmox-ve`, `proxmox-bs`
> in their own distributions, a Docker Compose setup with an offline-root
> ceremony ([docker/](docker/README.md)), Kubernetes manifests, recipes in
> [contrib/](contrib/), and the [handbook](docs/handbook/README.md), which
> leads from planning to operations and emergencies. What is still to be
> tried on real devices is on the handbook's
> [HQ checklist](docs/handbook/hq-checklist.md); the
> [final report](docs/final-report.md) sums up what exists and what is open.

## A minimal device list

```yaml
# /etc/sick/sick.yml
ca:
  url: https://ca.example.internal:9000
  root: /etc/sick/root_ca.crt
  intermediates: /etc/sick/intermediate_ca.crt
  provisioner: sick
  password_file: /etc/sick/provisioner.pw
devices:
  grafana:
    type: files
    names: [grafana.example.internal]
    dir: /srv/certs/grafana
    reload: "docker restart grafana"
```

To try SICK without a step-ca, let it make a throwaway CA out of plain
`openssl`:

```yaml
ca:
  type: selfsigned
  dir: /var/lib/sick/test-ca
```

## The commands

```bash
sick check                      # what does every device present? changes nothing
sick run                        # renew what is due
sick inventory                  # what was issued, deployed and last seen, from the records
sick trust /srv/www/trust       # root certificate and instructions for clients
```

```text
$ sick check
DEVICE   STATUS       RENEW  DETAIL
switch   ok           no     valid until 2027-11-06 03:02:18 UTC, 396 days left
router   unreachable  ?      router.example.internal:443: Connection refused
grafana  missing      yes    the device presents no certificate

$ sick run
DEVICE   ACTION     REASON       ERROR
switch   unchanged  ok
router   failed     unreachable  unreachable: router.example.internal:443: Connection refused
grafana  renewed    missing
```

- **`sick check [--format table|json|prometheus] [--output <file>] [device ...]`**
  – one line per device: `ok`, `missing`,
  `foreign-ca` (not from your CA), `names` (not exactly the names of the list),
  `expiring` (less than `renew_before` left), or `unreachable` – which is not
  the same as having no certificate. `--format json` and `--format prometheus`
  say the same for machines, together with the records of the runs and the
  state of the CA ([Monitoring](#monitoring)); `--output` writes to a file,
  replaced at once.
- **`sick run [--force] [--dry-run] [--verbose] [device ...]`** – check, issue,
  deploy, check again. A device that fails does not stop the others.
  `--dry-run` only says what would be renewed, `--force` renews also what is
  fine and ignores the back-off, `--verbose` reports each step on standard
  error. A device whose last attempts failed is `deferred` until its back-off
  is over ([below](#how-it-works)).
- **`sick inventory [--format table|json] [--live] [device ...]`** – per
  device the certificate issued last (names, issuer, serial, fingerprint,
  until when), when it was deployed and when a run last saw the device
  present it. From the records alone, without asking anybody; `--live` looks
  at the devices as well and shows whether each presents that certificate.
- **`sick trust <directory>`** – writes `root_ca.pem`, `root_ca.crt` (DER),
  `root_ca.mobileconfig` (a profile for iPhone, iPad and Mac), install and
  remove scripts (`trust-linux.sh`, `trust-macos.sh`, `trust-windows.ps1`,
  `trust-nss.sh`) and an `index.html` with the fingerprints and the steps to
  install and remove for Firefox, Chrome, Linux, macOS, Windows, iOS and
  Android. With `ca.intermediates` set
  it adds `intermediate_ca.pem`, `intermediate_ca.crt` and `ca_bundle.pem`,
  with `ca.additional_roots` set `root_ca_2.pem`, `root_ca_2.crt` … and
  `ca_bundle.pem`.
  Put the directory behind a web server and send people the link. More
  [below](#what-clients-have-to-trust).

The list is `--config <file>`, else `$SICK_CONFIG`, else `/etc/sick/sick.yml`.

| Exit code | |
|---|---|
| `0` | nothing failed |
| `1` | at least one device failed, was deferred, or could not be checked (`check`, `inventory --live`); `--output` could not be written |
| `2` | the command line or the device list is wrong |
| `3` | `sick run` only: another `sick run` holds the lock of the state directory; nothing was done |

One `sick run` at a time: a run takes an exclusive lock on
`<state>/sick.lock` and a second one ends at once with
`another sick run holds the lock '/var/lib/sick/sick.lock' (pid 4242)` and
exit code 3. The lock goes with the process, also when it dies or is killed;
there is nothing to clean up. `sick check`, `sick inventory`,
`sick run --dry-run` and `sick trust` take no lock and write no record.

SICK is no daemon. Renewal is `sick run` in a timer or a cron job; a run
changes nothing when everything is current. Ready-made: a systemd service
and timer with a failure notification in [contrib/systemd/](contrib/systemd/),
a cron line in [contrib/cron/sick](contrib/cron/sick), a Kubernetes CronJob
in [k8s/cronjob/](k8s/cronjob/), and the notifier they use in
[contrib/notify/](contrib/notify/). The handbook's chapter on
[operations](docs/handbook/06-operations.md) puts them together.

## Monitoring

`sick check --format prometheus` writes the state of every device, of its
chain and of the CA in the text format of Prometheus; with `--output` into a
file that is replaced at once (written beside it, mode `0644`, renamed), for
the textfile collector of node_exporter:

```bash
sick check --format prometheus --output /var/lib/prometheus/node-exporter/sick.prom
```

(the directory of Debian's `prometheus-node-exporter` package; the systemd
service and the cron line in `contrib/` write it after every run).

```text
$ sick check --format prometheus switch
# HELP sick_check_timestamp_seconds When sick check looked, as epoch seconds.
# TYPE sick_check_timestamp_seconds gauge
sick_check_timestamp_seconds 1791668818
# HELP sick_ca_up Whether the CA answered its health check (step ca health); absent for a CA that cannot be asked.
# TYPE sick_ca_up gauge
sick_ca_up 1
# HELP sick_ca_certificate_not_after_seconds End of validity of a certificate of the CA, as epoch seconds.
# TYPE sick_ca_certificate_not_after_seconds gauge
sick_ca_certificate_not_after_seconds{role="intermediate",subject="CN=Example Intermediate CA"} 1808948817
sick_ca_certificate_not_after_seconds{role="root",subject="CN=Example Root CA"} 2107028817
# HELP sick_device_info A device of the list, its type and the status of its certificate.
# TYPE sick_device_info gauge
sick_device_info{device="switch",type="files",status="ok",owner="Netzwerk-Team"} 1
...
sick_certificate_remaining_seconds{device="switch"} 7775999
sick_device_renew_before_seconds{device="switch"} 2592000
sick_chain_not_after_seconds{device="switch"} 1808948817
sick_device_matches_last_issue{device="switch"} 1
sick_device_consecutive_failures{device="switch"} 0
sick_device_last_success_timestamp_seconds{device="switch"} 1791665217
```

| Metric | |
|---|---|
| `sick_check_timestamp_seconds` | when the check ran |
| `sick_ca_up` | `step ca health` answered `ok` (1) or not (0); absent for `selfsigned` |
| `sick_ca_certificate_not_after_seconds{role,subject}` | end of the root and of each intermediate |
| `sick_device_info{device,type,status,owner}` | `1`; `status` is that of `sick check`; `owner` only where the device list sets one |
| `sick_device_reachable{device}` | `0` for `unreachable`; absent for `error` |
| `sick_device_renew_due{device}` | `sick run` would renew now |
| `sick_certificate_not_after_seconds`, `_remaining_seconds`, `_lifetime_seconds` | of the certificate the device presents; absent without one |
| `sick_device_renew_before_seconds{device}` | `renew_before` of the device |
| `sick_chain_not_after_seconds{device}` | the earliest end along the path to the root: intermediate or root |
| `sick_device_matches_last_issue{device}` | the device presents the certificate issued last; only with a record of an issue |
| `sick_device_consecutive_failures{device}` | failed attempts to renew in a row |
| `sick_device_last_success_timestamp_seconds{device}` | the last run that ended `unchanged` or `renewed`; only when known |

`sick check --format json` holds the same and a bit more – the serial and
issuer of the live certificate, the last issue as on record, the back-off –
with times in ISO 8601 UTC and as epoch seconds:

```json
{
   "ca" : {
      "detail" : null,
      "intermediates" : [ { "not_after" : "2027-04-28T21:46:57Z", "not_after_epoch" : 1808948817, "subject" : "CN=Example Intermediate CA" } ],
      "reachable" : true,
      "root" : { "fingerprint_sha256" : "adfea3f6...", "not_after" : "2036-10-07T21:46:57Z", "not_after_epoch" : 2107028817, "subject" : "CN=Example Root CA" },
      "type" : "step-ca"
   },
   "devices" : [
      {
         "chain_not_after" : "2027-04-28T21:46:57Z", "chain_not_after_epoch" : 1808948817,
         "consecutive_failures" : 0,
         "detail" : "valid until 2027-01-08 21:46:57 UTC, 90 days left",
         "device" : "switch", "host" : null, "owner" : "Netzwerk-Team", "port" : 443, "type" : "files",
         "last_issue" : { "fingerprint_sha256" : "c914b5c9...", "issuer" : "CN=Example Intermediate CA",
                          "names" : [ "switch.example.internal" ], "not_after" : "2027-01-08T21:46:57Z",
                          "serial" : "03EA", "time" : "2026-10-09T21:46:57Z" },
         "last_success" : "2026-10-10T20:46:57Z", "last_success_epoch" : 1791665217,
         "live" : { "fingerprint_sha256" : "c914b5c9...", "issuer" : "CN=Example Intermediate CA",
                    "lifetime_seconds" : 7776000, "not_after" : "2027-01-08T21:46:57Z", "not_after_epoch" : 1799444817,
                    "not_before" : "2026-10-10T21:46:57Z", "not_before_epoch" : 1791668817,
                    "remaining_seconds" : 7776000, "serial" : "03EA" },
         "matches_last_issue" : true,
         "names" : [ "switch.example.internal" ],
         "next_attempt" : null, "next_attempt_epoch" : null,
         "renew" : false, "renew_before_seconds" : 2592000,
         "state_error" : null, "status" : "ok"
      }
   ],
   "generated_at" : "2026-10-10T21:46:57Z",
   "generated_at_epoch" : 1791668817
}
```

(shortened: the real output has one key per line.) The table stays what it
was, and only the two other formats ask the CA. `sick check` reads the
records and writes none.

`contrib/prometheus/sick-alerts.yml` has alert rules whose thresholds follow
each device's own `renew_before` instead of a fixed number of days – the
certificate is late when half of `renew_before` is gone, critical at a
quarter – plus a device that does not present its last issue, does not
answer, keeps failing, a CA that does not answer, an intermediate or root
that ends within one or two years, and metrics that are older than two
days. `contrib/prometheus/sick-alerts.test.yml` tests them
(`promtool test rules`).

`sick inventory` is the list of what is out there, from the records alone:

```text
$ sick inventory --live
DEVICE   STATUS  LIVE  SERIAL  FINGERPRINT       UNTIL             DEPLOYED          VERIFIED          ISSUER                      NAMES                    OWNER
switch   ok      yes   03EA    c914b5c9d64480bd  2027-01-08 21:46  2026-10-09 21:47  2026-10-10 20:46  CN=Example Intermediate CA  switch.example.internal  Netzwerk-Team
printer  ok      -     -       -                 -                 -                 -                 -                           -                        -
```

Times are UTC. `DEPLOYED` is the last deployment (`failed …` when it
failed), `VERIFIED` the last time a run saw the device present the
certificate issued last. Without `--live` there is no `LIVE` column, and
`STATUS` is that of the last run. `--format json` gives the same per device.

## What clients have to trust

A certificate helps as much as the browsers, phones and tablets that accept
it. `sick trust` writes what they need, and one page that says where it goes.

| File | |
|---|---|
| `root_ca.pem`, `root_ca.crt` | the root certificate, as PEM and as DER – what a client trusts |
| `root_ca_2.pem`, `root_ca_2.crt`, … | the further roots of a root replacement (`ca.additional_roots`), each as PEM and as DER – trusted like the root for the time of the replacement |
| `intermediate_ca.pem`, `intermediate_ca.crt` | the intermediate certificate – what a client has to know, not to trust |
| `ca_bundle.pem` | root and intermediate in one PEM file, for programs that take one file: `curl --cacert ca_bundle.pem` |
| `root_ca.mobileconfig` | a configuration profile for iPhone, iPad and Mac with the root as trusted root and the intermediate as a plain certificate: one installation |
| `trust-linux.sh`, `trust-macos.sh`, `trust-windows.ps1`, `trust-nss.sh` | install and remove scripts with the certificates in them, see below |
| `index.html` | fingerprints, downloads, the scripts and the steps to install and remove for each platform |

**The fingerprint comes by another channel.** The page is served to clients
that do not trust anything yet, so it proves nothing about itself: whoever
can change it can change the fingerprint on it too. Hand out the SHA-256
fingerprint of the root yourself – on paper, by phone, in a chat people
already trust – and the page says so before anything else. The scripts
refuse to install unless they are given the fingerprint of every root they
carry, and no other; colons and case do not matter:

```sh
sudo sh trust-linux.sh install --fingerprint <sha256> [--fingerprint <sha256> ...]
sudo sh trust-linux.sh remove
sudo sh trust-macos.sh install --fingerprint <sha256> ...       # and remove
powershell -ExecutionPolicy Bypass -File trust-windows.ps1 install --fingerprint <sha256> ...   # and remove
sh trust-nss.sh install --fingerprint <sha256> ... <firefox profile or NSS database>           # and remove <dir>
```

| Script | Where | Root | Intermediate |
|---|---|---|---|
| `trust-linux.sh` | Debian, Ubuntu, Alpine (`update-ca-certificates`), Fedora, RHEL, Rocky (`update-ca-trust`), Arch and other p11-kit systems (`trust anchor`) | a file `sick-root-<fingerprint>` in the anchors | not carried – a store of anchors |
| `trust-macos.sh` | System keychain (`security`) | `add-trusted-cert -r trustRoot` | `add-certificates`, no trust |
| `trust-windows.ps1` | local machine (`Import-Certificate`) | `LocalMachine\Root` | `LocalMachine\CA` |
| `trust-nss.sh` | a Firefox profile, Chrome's `~/.pki/nssdb` (`certutil`) | trust `C,,` | trust `,,` |

Each script computes the fingerprints itself (`openssl`, or `base64` and
`sha256sum`/`shasum`; `Get-FileHash` on Windows) and prints them; a missing
or wrong fingerprint is exit code 1 with nothing changed. `remove` takes out
what `install` put in – by file name, keychain hash, thumbprint or nickname,
all derived from the fingerprints – is content when there is nothing left,
and needs no fingerprint. No script replaces a system bundle or restarts
anything; each says what still needs a restart. `SICK_TRUST_ROOT` in the two
Unix system scripts is for the test suite only.

The three files in the middle are there when the `ca` section names
`intermediates`, and this is why. step-ca signs through its intermediate, and
a server normally sends that along with its own certificate. A device with
room for exactly one certificate – a Cisco Small Business switch – presents
the certificate alone. A client that has installed the root and nothing else
cannot build the chain and goes on refusing the device:

```text
$ openssl s_client -connect switch.example.internal:443 -CAfile root_ca.pem -no-CApath -no-CAstore
Verify return code: 21 (unable to verify the first certificate)
$ openssl s_client -connect switch.example.internal:443 -CAfile ca_bundle.pem -no-CApath -no-CAstore
Verify return code: 0 (ok)
```

The better way is the device sending the chain; then nothing but the root is
needed. For a device that cannot, the intermediate has to reach the client –
but never as a trust anchor. In a store that knows nothing but trusted
certificates (the system stores of Linux, the CA list of Android), an
intermediate is trusted by itself and stays trusted after the root is
removed or replaced: curl, GnuTLS and NSS still accept what it signed
([docs/findings/trust-anchors.md](docs/findings/trust-anchors.md)). So the
page puts the root alone there and hands the intermediate over in one of
three ways:

1. **the device sends the chain** – preferred, and the only way on Android;
2. **`ca_bundle.pem` as a program's own CA file** (`curl --cacert`,
   `git config http.sslCAInfo`, `openssl -CAfile`). Inside that one file
   OpenSSL- and GnuTLS-based programs take the intermediate as an anchor;
   the risk stays with that file, and the file is replaced when the
   intermediate is;
3. **a place that keeps it without trust**: Firefox with nothing ticked
   (tried, NSS), Chrome on Linux under *Intermediate certificates*, the
   Windows store of intermediates, the macOS keychain, the Apple profile.

| Platform | Root | Intermediate |
|---|---|---|
| iPhone, iPad | the profile, then full trust under *Certificate Trust Settings* | in the same profile, as a plain certificate; no setting (not tried) |
| macOS | the profile, or `security add-trusted-cert` | in the same profile, or `security add-certificates`; no trust setting (not tried) |
| Windows | *Trusted Root Certification Authorities* | *Intermediate Certification Authorities* (not tried) |
| Android | *Install a certificate → CA certificate* | nowhere – Android has one list, and everything in it is an anchor. A device that sends no chain is not accepted there |
| Linux system store | `update-ca-certificates`, `update-ca-trust`, `trust anchor --store` | nowhere – such a store knows nothing but anchors. A program that has to reach a device without chain gets `ca_bundle.pem` as its CA file |
| Firefox | *Authorities → Import*, trusted for websites | imported the same way, nothing ticked |
| Chrome on Linux | certificate manager, as a trusted certificate | certificate manager, under *Intermediate certificates*, no trust (NSS, as Firefox; not tried) |

A CA with several intermediates gets `intermediate_ca.pem` with all of them
and `intermediate_ca_1.pem`, `intermediate_ca_1.crt`, `intermediate_ca_2.pem`
… for the places that take one certificate at a time. Without
`ca.intermediates` there are the four files for the root and a page that
speaks of the root alone. Writing twice produces the same bytes, so the
command can follow every `sick run`.

While the root itself is replaced, clients have to trust two roots for a
while: the next one before the switch, so that they accept what the CA
issues after it, and the previous one after the switch, until every device
has its certificate from the new root. `ca.additional_roots` lists them, and
`sick trust` publishes each as `root_ca_2.pem` and `root_ca_2.crt`,
`root_ca_3.pem` … in the order of the list. `ca_bundle.pem` then holds the
current root, the additional ones and the intermediates, in that order; the
profile carries each as a trusted root; and the page names the current root,
lists the others with their fingerprints and says to remove the one that is
no longer listed once the replacement is over. When the key goes out of the
list again, the next `sick trust` takes their files away.

What of this has been tried: `openssl` with the bundle, with a directory of
certificates, and with the root alone (the test suite, and a real switch in
the lab); the system stores of Debian and Fedora and an NSS database – what
Firefox keeps its certificates in – with the certificate of that switch
([docker/README.md](docker/README.md#the-trust-service)); and which of these
places turn an intermediate into an anchor, with curl, `openssl s_client`,
GnuTLS and NSS on Debian 13 and Fedora 44
([docs/findings/trust-anchors.md](docs/findings/trust-anchors.md)). The steps for
iPhone, iPad, Android, macOS, Windows and the browsers themselves are written
from the documentation of those platforms and have not been walked through
on a device yet. The scripts have been run in the test suite against
recording stand-ins for `update-ca-certificates`, `update-ca-trust`, p11-kit
`trust`, `certutil` and `security`; on the real platforms not yet.

## The handbook

[docs/handbook/](docs/handbook/README.md) leads from nothing to a running
internal CA: planning, the CA with an offline root, clients, devices,
services, operations and emergencies. It grows with the
[roadmap](docs/roadmap.md); the chapters on planning, the CA and the CA side
of emergencies are there.

## With Docker

[docker/](docker/README.md) is the whole thing in three containers: a step-ca
that sets itself up at the first start, SICK on a schedule, and a small web
server for the page of `sick trust`.

```bash
cd docker
cp sick.example.yml sick.yml    # your devices
docker compose up -d --build
```

Its README has the settings, what to know about the CA it makes, and the
transcript of a run against a real switch.

## Installation

```bash
cpanm SICK
```

From a checkout:

```bash
cpanm --installdeps .
prove -lr t
perl -Ilib bin/sick --help
```

At run time SICK calls `openssl` (1.1.1 or newer), for a step-ca
[`step`](https://smallstep.com/docs/step-cli/), and for `acmesh` devices
`acme.sh`. They are prerequisites of a run, not of the installation; when one
is missing, the error says which.

## How it works

For every device the same four steps:

1. **Check** – which certificate does the device present right now? A device
   that cannot be reached is none of the states above: nothing is known,
   nothing is done.
2. **Issue** – `step ca certificate` for the names, the lifetime and the key
   type. A device that makes its own key hands over a certificate request
   instead (`step ca sign`), and the key never leaves it.
3. **Deploy** – the target of the device type installs certificate, chain and
   key.
4. **Check again** – the device has to present exactly the certificate that was
   issued, by fingerprint. Otherwise the run has failed for this device.

A new key exists in memory and, for a moment, in a private temporary
directory (mode 0700). That directory is removed when the step is over, also
when it fails or `sick` is interrupted or terminated – only a `kill -9` leaves
it behind.

`sick run` keeps one record per device in the state directory
(`/var/lib/sick/devices/<name>.json`, JSON): the last look (status,
fingerprint, until when), the last certificate issued (serial, fingerprint,
names, until when, issuer), the last deployment and its result, the last
success, the number of failures in a row and the back-off. Never a key or the
path of one. A record that cannot be read is reported and counts as empty.

When an attempt fails after the decision to renew – the CA refuses or cannot
be reached, the deployment or the second look fails – the next attempt for
that device waits 1 hour, then 2, 4, 8, 16 and at most 24 hours, less a
grace of 15 minutes, so that a daily timer does not skip a day. Until then
`sick run` reports it as `deferred` (`back-off after 3 failures, next
attempt 2026-10-11 08:17:00 UTC`), issues nothing for it and exits with 1.
`--force` tries anyway; `unchanged` or `renewed` ends the back-off. A device
that is unreachable changes nothing: it never got a certificate.

The certificate of a failed attempt is thrown away, not revoked: its key
existed only in that private temporary directory and is gone, so the
certificate is of no use to anybody and expires unused. The back-off keeps a
device that keeps failing from collecting such certificates on every run.

## The device list

| Section | Keys |
|---|---|
| `ca` | `type` (`step-ca`, the default, or `selfsigned`), `name`, `url`, `root`, `intermediates`, `additional_roots`, `provisioner`, `password_file`, `step`, `dir` |
| `defaults` | `lifetime` (`397d`), `renew_before` (`30d`), `key` (`rsa2048`) |
| `devices.<name>` | `type` and `names` (required), `host`, `port` (`443`), `lifetime`, `renew_before`, `key`, `owner`, plus the options of the type |
| `state` | the state directory: lock and records of `sick run` (`/var/lib/sick`) |

Durations are a number with a unit: `397d`, `12h`, `45m`, `90s`. Key types are
`rsa2048`, `rsa3072`, `rsa4096` and `ec256`. Host names end up as DNS SANs, IP
addresses as IP SANs. `host` and `port` are where SICK looks at the certificate;
without `host` it is the first name. `ca.name` is what the CA is called on the
page of `sick trust`. `owner` is free text, one line of at most 200 characters,
for whoever has to ask about the device: `sick inventory` shows it, and
`sick check --format prometheus` puts it on `sick_device_info` as the label
`owner` where it is set. No secret goes there.

`ca.root` is the root certificate of the CA and nothing else: it is what `step`
verifies the CA with, what a certificate has to lead back to, and what
`sick trust` hands to clients. `ca.intermediates` is the intermediate
certificate the CA signs with (step-ca: `certs/intermediate_ca.crt`). A
step-ca never signs with its root, and many devices present their certificate
without the intermediate – a switch has room for exactly one. Without
`ca.intermediates` SICK cannot tell that such a certificate is its own: the
device stays `foreign-ca` and is renewed on every run. And `sick trust` has no
intermediate to hand to the clients, which then
[refuse the device](#what-clients-have-to-trust) although they trust the root.

`ca.additional_roots` is a list of paths of further root certificates, for
the time of a root replacement: the next root before the switch, the previous
one after it (either issuer type). Each file holds one self-signed CA
certificate, and none is the root of the CA. They are published by
`sick trust` and nothing else: `step` does not see them, and a device is not
judged by them – a device whose certificate leads to an additional root only
is `foreign-ca` and gets a new certificate, which after a switch is the
re-issue under the new root.

```yaml
ca:
  root: /etc/sick/root_ca.crt
  intermediates: /etc/sick/intermediate_ca.crt
  additional_roots:
    - /etc/sick/root_ca_previous.crt
```

Secrets are never in the list, only the paths of the files that hold them. An
unknown key is an error with its place (`devices.switch: missing 'type'`), not
something that is skipped.

## Device types

`type: foo-bar` loads `SICK::Target::FooBar`. Two are built in.

### `files`

Publishes `cert.pem`, `chain.pem`, `fullchain.pem` and `key.pem` in `dir` as
one generation, then runs `reload`.

| Option | |
|---|---|
| `dir` | required; the directory |
| `reload` | a command to run afterwards: a list (started directly) or a string (run by `/bin/sh -c`) |
| `mode_key` | file mode of `key.pem`, default `0600` |

The four names are relative links into `.sick/current`, which points to a
generation directory holding all four files:

```
dir/
  cert.pem       -> .sick/current/cert.pem        (chain.pem, fullchain.pem, key.pem alike)
  .sick/
    current      -> 20261010T211500.123456Z-1a2b3c4d
    previous     -> 20260905T030000.654321Z-9f8e7d6c
    20261010T211500.123456Z-1a2b3c4d/   cert.pem chain.pem fullchain.pem key.pem
    20260905T030000.654321Z-9f8e7d6c/   cert.pem chain.pem fullchain.pem key.pem
```

A deploy writes the new generation completely, then renames a new
`current` link over the old one. The names lead to the old four files or to
the new four, never to a new key beside the old certificate. A program that
opens them one after the other can still straddle a switch; to be sure,
resolve the generation once (the real path of `cert.pem`) and read all four
from there. The previous generation stays, older ones are removed. Plain
files of an earlier SICK become a generation of their own on the first
deploy, and the names become links.

When `reload` fails, `current` goes back to the previous generation,
`reload` runs once more for it, the new generation is removed and the
device is reported as failed, with a message that says whether the old
certificate was restored. On the first deploy there is nothing to go back
to; the new files stay.

Mount the directory into a container, not the single files: a bind mount of
one file pins the file of the generation it found at start and never sees a
later one.

Without `host`, the certificate in `cert.pem` counts as the one the device
presents. Set `host` to have SICK ask the service itself.

### `acmesh`

Hands the certificate to one of the deploy hooks of acme.sh (`routeros`,
`proxmoxve`, `proxmoxbs`, `fritzbox`, `synology_dsm`, ... – some sixty of
them). acme.sh issues nothing here and contacts no CA; SICK lays the
certificate out the way acme.sh keeps its own and runs `acme.sh --deploy`.

```yaml
devices:
  hypervisor:
    type: acmesh
    hook: proxmoxve
    host: pve.example.internal
    port: 8006
    names: [pve.example.internal]
    env:
      DEPLOY_PROXMOXVE_SERVER: pve.example.internal
      # both default to root@pam; the token below belongs to sick@pve
      DEPLOY_PROXMOXVE_USER: sick
      DEPLOY_PROXMOXVE_USER_REALM: pve
      DEPLOY_PROXMOXVE_API_TOKEN_NAME: sick
    env_files:
      DEPLOY_PROXMOXVE_API_TOKEN_KEY: /etc/sick/pve.token
```

User and realm are set on purpose: without them the hooks `proxmoxve` and
`proxmoxbs` log in as `root@pam`. Token, rights, the PBS variant and why the
node's own ACME client is usually the better choice:
[contrib/devices/proxmox/](contrib/devices/proxmox/README.md).

| Option | |
|---|---|
| `hook` | required; the name of the deploy hook |
| `env` | environment variables for the hook – its settings |
| `env_files` | environment variables read from files (first line): everything secret. They reach the hook through its environment only and are blanked out of what it prints |
| `acme_sh` | the program, default `acme.sh` from the `PATH` |
| `home` | the directory acme.sh works in; default is a private temporary one per deployment. Never the home of an acme.sh that runs as a cron job |

The mechanism is verified against acme.sh 3.1.6 with its `localcopy` hook
([docs/findings/acmesh-deploy.md](docs/findings/acmesh-deploy.md)). No other
hook has been run by the authors: a hook is somebody else's shell script with
your credentials, so read it first.

## Adding a device type

A device type that needs more than the core brings – SSH, an HTTP client, a vendor
API – is a distribution of its own, `SICK-Target-*`, so that the core stays
small. `SICK-Target-CiscoSB` (Cisco Small Business switches) is the first,
`SICK-Target-Proxmox` (`proxmox-ve`, `proxmox-bs`: Proxmox VE and Proxmox
Backup Server over their API, always verified) the second; the Docker image
carries both.

A target is a subclass of `SICK::Target` in the namespace `SICK::Target::`.
Installing it is all it takes: `type: my-box` finds `SICK::Target::MyBox`
(type and module name are compared without case and punctuation).

```perl
package SICK::Target::MyBox;
use strict;
use warnings;
use parent 'SICK::Target';

sub required_options { qw( credentials ) }    # keys of the device entry
sub optional_options { qw( slot ) }

# required: install certificate, chain and - if the bundle has one - key
sub deploy {
  my ( $self, $bundle ) = @_;
  my $device = $self->device;                 # SICK::Device: host, port, names ...
  my ( $user, $password ) = ...;              # from the file $self->option('credentials')
  $self->log('importing the certificate');    # never log a secret
  ...                                         # $bundle->cert, ->chain, ->fullchain, ->key
  die "the device said: $answer\n" unless $ok;
  return;
}

# optional: the device makes its own key and hands out a request (PEM).
# The certificate is then signed for it and the bundle has no key.
sub csr {
  my ( $self, $spec ) = @_;                   # { names => [...], lifetime => $s, key => 'rsa2048' }
  ...
}

# optional: the default asks host:port over TLS, which is right for most devices
# sub presented_cert { ... }                  # SICK::Bundle, undef, or die "unreachable: ..."

# optional: seconds the device may take until it presents the new certificate
sub verify_timeout { 60 }

# optional: the port of a device without 'port' in its entry (443 by default)
sub default_port { 8443 }

1;
```

What the core expects of a target:

- `deploy` dies with a message for humans when it fails. It does not need to
  check the result itself: SICK looks at the device afterwards and only
  believes the fingerprint.
- `presented_cert` has three outcomes that are not the same thing – a bundle,
  `undef` (reached, but no certificate), and an exception starting with
  `unreachable: ` (no connection; nothing is done to the device then).
- Options are validated in `validate` (call `$self->SUPER::validate` first)
  and errors carry the place in the list: `devices.switch: missing 'credentials'`.
- Secrets come from files named in the device list and never appear in a
  message, a log line or a command line.
- A device that is sent a secret – a password, a token, the key – is verified
  first. `$self->trust_roots` holds the roots of the CA as PEM, the issuer's root
  first, then the additional roots of a root replacement: once the device
  presents one of our certificates, that is what it chains up to. The
  intermediates are in `$bundle->chain`.
- `$self->device->port` is the `port` of the entry or the type's `default_port`;
  `$self->device->has_port` tells a `port: 443` that was written from one that
  was not.

`SICK::Target::Files` and `SICK::Target::Acmesh` are the examples to read.

## Issuers

- **`step-ca`** – `step ca certificate` / `step ca sign` against a JWK
  provisioner. The provisioner has to allow the lifetimes you ask for; step-ca
  grants 24 hours unless its `maxTLSCertDuration` is raised
  (`step ca provisioner update sick --x509-max-dur 19800h`). The password is
  handed to `step` as the path of its file and never appears on a command line.
  Verified against step 0.30.2 and step-ca 0.30.2.
- **`selfsigned`** – a throwaway CA in a directory, made with plain `openssl`.
  For tests and for trying SICK out, not for real devices.

## From Perl

```perl
use SICK::Config;
use SICK::Issuer;
use SICK::Runner;

my $config = SICK::Config->load('/etc/sick/sick.yml');
my $runner = SICK::Runner->new(
  config => $config,
  issuer => SICK::Issuer->from_ca( %{ $config->ca } ),
);

for my $result ( $runner->run ) {
  print "$result->{device}: $result->{action}\n";
}
```

## License

This is free software; you can redistribute it and/or modify it under the same
terms as the Perl 5 programming language system itself.
