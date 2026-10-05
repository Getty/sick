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
ties them together. The core depends on core Perl and `YAML::PP`.

> Status: early, not released. The command line, the `files` and `acmesh`
> targets and `sick trust` are here; the Docker setup is being built.

## A minimal device list

```yaml
# /etc/sick/sick.yml
ca:
  url: https://ca.example.internal:9000
  root: /etc/sick/root_ca.crt
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

## The three commands

```bash
sick check                      # what does every device present? changes nothing
sick run                        # renew what is due
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

- **`sick check [device ...]`** – one line per device: `ok`, `missing`,
  `foreign-ca` (not from your CA), `names` (not exactly the names of the list),
  `expiring` (less than `renew_before` left), or `unreachable` – which is not
  the same as having no certificate.
- **`sick run [--force] [--dry-run] [--verbose] [device ...]`** – check, issue,
  deploy, check again. A device that fails does not stop the others.
  `--dry-run` only says what would be renewed, `--force` renews also what is
  fine, `--verbose` reports each step on standard error.
- **`sick trust <directory>`** – writes `root_ca.pem`, `root_ca.crt` (DER),
  `root_ca.mobileconfig` (a profile for iPhone, iPad and Mac) and an
  `index.html` with the fingerprints and the installation steps for Firefox,
  Chrome, Linux, macOS, Windows, iOS and Android. Put the directory behind a web
  server and send people the link.

The list is `--config <file>`, else `$SICK_CONFIG`, else `/etc/sick/sick.yml`.

| Exit code | |
|---|---|
| `0` | nothing failed |
| `1` | at least one device failed, or could not be checked |
| `2` | the command line or the device list is wrong |

SICK is no daemon. Renewal is `sick run` in a timer or a cron job; a run
changes nothing when everything is current.

```cron
17 4 * * *  root  sick run && sick trust /srv/www/trust
```

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

## The device list

| Section | Keys |
|---|---|
| `ca` | `type` (`step-ca`, the default, or `selfsigned`), `name`, `url`, `root`, `provisioner`, `password_file`, `step`, `dir` |
| `defaults` | `lifetime` (`397d`), `renew_before` (`30d`), `key` (`rsa2048`) |
| `devices.<name>` | `type` and `names` (required), `host`, `port` (`443`), `lifetime`, `renew_before`, `key`, plus the options of the type |

Durations are a number with a unit: `397d`, `12h`, `45m`, `90s`. Key types are
`rsa2048`, `rsa3072`, `rsa4096` and `ec256`. Host names end up as DNS SANs, IP
addresses as IP SANs. `host` and `port` are where SICK looks at the certificate;
without `host` it is the first name. `ca.name` is what the CA is called on the
page of `sick trust`.

Secrets are never in the list, only the paths of the files that hold them. An
unknown key is an error with its place (`devices.switch: missing 'type'`), not
something that is skipped.

## Device types

`type: foo-bar` loads `SICK::Target::FooBar`. Two are built in.

### `files`

Writes `cert.pem`, `chain.pem`, `fullchain.pem` and `key.pem` into `dir`, each
one atomically, then runs `reload`.

| Option | |
|---|---|
| `dir` | required; the directory |
| `reload` | a command to run afterwards: a list (started directly) or a string (run by `/bin/sh -c`) |
| `mode_key` | file mode of `key.pem`, default `0600` |

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
      DEPLOY_PROXMOXVE_USER: sick
      DEPLOY_PROXMOXVE_API_TOKEN_NAME: sick
    env_files:
      DEPLOY_PROXMOXVE_API_TOKEN_KEY: /etc/sick/pve.token
```

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

A device type that needs more than core Perl – SSH, an HTTP client, a vendor
API – is a distribution of its own, `SICK-Target-*`, so that the core stays
small. `SICK-Target-CiscoSB` (Cisco Small Business switches) is the first.

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

`SICK::Target::Files` and `SICK::Target::Acmesh` are the examples to read.

## Issuers

- **`step-ca`** – `step ca certificate` / `step ca sign` against a JWK
  provisioner. The provisioner has to allow the lifetimes you ask for; step-ca
  grants 24 hours unless its `maxTLSCertDuration` is raised. The password is
  handed to `step` as the path of its file and never appears on a command line.
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
