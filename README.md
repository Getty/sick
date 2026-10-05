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
the `openssl` command line, and SICK adds the device list, the decision and the
connections to the devices. The core depends on core Perl and `YAML::PP`.

> Status: early. The library parts below exist; the `sick` command line, the
> acme.sh target and the Docker setup are being built.

## Synopsis

```yaml
# /etc/sick/sick.yml
ca:
  url: https://ca.example.internal:9000
  root: /etc/sick/root_ca.crt
  provisioner: sick
  password_file: /etc/sick/provisioner.pw
defaults:
  lifetime: 397d
  renew_before: 30d
  key: rsa2048
devices:
  switch:
    type: cisco-sb                  # SICK::Target::CiscoSB, its own distribution
    host: 192.0.2.199
    names: [switch.example.internal, 192.0.2.199]
    credentials: /etc/sick/switch.cred
  grafana:
    type: files                     # built in
    names: [grafana.example.internal]
    dir: /srv/certs/grafana
    reload: "docker restart grafana"
```

```perl
use SICK::Config;
use SICK::Decision;
use SICK::Issuer::StepCA;
use SICK::Target;

my $config = SICK::Config->load('/etc/sick/sick.yml');
my $issuer = SICK::Issuer::StepCA->new( %{ $config->ca } );

for my $device ( $config->devices ) {
  my $target = SICK::Target->class_for( $device->type )->new( device => $device );
  $target->validate;

  my $decision = SICK::Decision::evaluate(
    device    => $device,
    presented => $target->presented_cert,
    root_pem  => $issuer->root_pem,
  );
  next unless $decision->{renew};

  $target->deploy( $issuer->issue( $device->spec ) );
}
```

## Installation

```bash
cpanm SICK
```

From a checkout:

```bash
cpanm --installdeps .
prove -lr t
```

At run time SICK calls `openssl` (1.1.1 or newer) and, for a step-ca,
[`step`](https://smallstep.com/docs/step-cli/). They are prerequisites of a
run, not of the installation; when one is missing, the error says which.

## How it works

For every device the same four steps:

1. **Check** – which certificate does the device present right now?
   `SICK::Decision` answers with `ok`, `missing`, `foreign-ca` (not from your
   CA), `names` (not exactly the names of the list) or `expiring` (less than
   `renew_before` left). A device that cannot be reached is none of these:
   nothing is known, nothing is done.
2. **Issue** – `SICK::Issuer::StepCA` has a certificate issued for the names,
   the lifetime and the key type. A device that makes its own key hands over a
   certificate request instead, and the key never leaves it.
3. **Deploy** – the target of the device type installs certificate, chain and
   key.
4. **Check again** – the device has to present the new certificate now.

A run changes nothing when everything is current.

## The device list

| Section | Keys |
|---|---|
| `ca` | `type` (`step-ca`, the default, or `selfsigned`), `url`, `root`, `provisioner`, `password_file`, `step`, `dir` |
| `defaults` | `lifetime` (`397d`), `renew_before` (`30d`), `key` (`rsa2048`) |
| `devices.<name>` | `type` and `names` (required), `host`, `port` (`443`), `lifetime`, `renew_before`, `key`, plus the options of the type |

Durations are a number with a unit: `397d`, `12h`, `45m`, `90s`. Key types are
`rsa2048`, `rsa3072`, `rsa4096` and `ec256`. Host names end up as DNS SANs, IP
addresses as IP SANs.

Secrets are never in the list, only the paths of the files that hold them. An
unknown key is an error with its place (`devices.switch: missing 'type'`), not
something that is skipped.

## Device types

`type: foo-bar` loads `SICK::Target::FooBar`. Built in:

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

Everything else is a distribution of its own, `SICK-Target-*`, with its own
dependencies – for example `SICK-Target-CiscoSB` for Cisco Small Business
switches.

## Issuers

- **`step-ca`** – `step ca certificate` / `step ca sign` against a JWK
  provisioner. The provisioner has to allow the lifetimes you ask for; step-ca
  grants 24 hours unless its `maxTLSCertDuration` is raised. The password is
  handed to `step` as the path of its file and never appears on a command line.
- **`selfsigned`** – a throwaway CA in a directory, made with plain `openssl`.
  For tests and for trying SICK out, not for real devices.

## License

This is free software; you can redistribute it and/or modify it under the same
terms as the Perl 5 programming language system itself.
