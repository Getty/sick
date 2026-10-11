---
name: sick-core
description: Load before editing anything under lib/SICK/ or writing a SICK-Target-* device type — the run and its per-device results, the three outcomes of presented_cert, the Target and Issuer contracts, root versus intermediates, SICK::Command.
user-invocable: false
---

# SICK — Distribution Internals

The rules on dependencies, the shell, secrets and the layout are in `CLAUDE.md`. This
skill holds the contracts between the parts: what a change has to keep, in the core and
in every `SICK-Target-*` distribution built on it.

## The run: four steps, one result per device

`SICK::Runner` does check → issue → deploy → check again for each device
(`_run_device`).

- **A failure is the result of that device**, never an exception of the run. Every step
  sits in its own `eval` and ends in `{ action => 'failed', reason, error }`; the other
  devices go on. New steps follow that shape.
- **A deployment counts when the device presents the issued certificate**, compared by
  SHA-256 fingerprint, asked again and again for `verify_timeout` seconds. A `deploy`
  that returned without dying has proven nothing yet.
- **`SICK::Decision::evaluate` is pure**: nothing but its arguments decides the answer,
  the clock included (`now`). The checks run in a fixed order and the first that applies
  is the answer: `missing`, `foreign-ca`, `names`, `expiring`, `ok`. `ok` is the only
  one with `renew => 0`.
- Exit codes of `sick`: `0` nothing failed, `1` a device failed or could not be checked,
  `2` the command line or the device list is wrong.

## `presented_cert` has three outcomes

| Outcome | Means | The run then |
|---|---|---|
| a `SICK::Bundle` | the device answered with a certificate | judges it |
| an explicit `undef` | reached, but no TLS there or no certificate | `missing`, renews |
| croak `unreachable: <host>:<port>: <reason>` | no connection | touches nothing |

The runner tells them apart by the prefix `unreachable: ` and by nothing else. An
override in a target keeps exactly these three:

- no connection reported as `undef` makes the device `missing`, and SICK deploys onto a
  device it knows nothing about;
- no connection croaked without the prefix becomes reason `error` instead of
  `unreachable`.

`undef` is returned as `return undef`, in list context too: the value is used as one
element of an argument list. The same holds for `csr` and `intermediates_pem`.

## Target contract

A device type is a subclass of `SICK::Target`. `type: cisco-sb` loads
`SICK::Target::CiscoSB`: type and module name are compared without case and without
anything that is not a letter or digit, among the modules directly below `SICK/Target/`
in `@INC`. `class_for` is the one place a module is loaded at run time.

| Method | Default | Contract |
|---|---|---|
| `deploy($bundle)` | croaks | required; dies unless the device ends up serving the certificate |
| `required_options`, `optional_options` | `()` | the type-specific keys of the device; everything else is an unknown key |
| `validate` | checks those | an override calls `$self->SUPER::validate` first; croaks with `$device->path` |
| `csr($spec)` | `undef` | PEM when the device makes its own key; the bundle handed to `deploy` then has no key |
| `presented_cert` | `openssl s_client` | the three outcomes above |
| `endpoint` | `host` or first name, `port` or `default_port` | where `presented_cert` connects |
| `default_port` | `443` | class method; the port of a device without `port`. `SICK::Config` asks it through `class_for` for `Device::port`, so a type whose devices listen elsewhere (Proxmox: 8006) need not have every entry repeat it |
| `trust_roots` | `[]` | attribute set by the Runner in `run` and `check`: issuer root first, then the additional roots, one PEM certificate each. For a target that verifies the device before it sends a secret; once the device presents our certificate, these are what it chains to. No intermediates: `deploy` has them in `$bundle->chain`. The core uses them for nothing else |
| `connect_timeout` | `10` | seconds |
| `verify_timeout` | `30` | seconds after `deploy`; `0` where waiting cannot change the answer |

`$self->log($line)` reports one line and never carries a secret; `$self->option($name)`
reads a type-specific setting. `$device->has_port` is true only when the entry wrote
`port` (also `port: 443`): a type can tell a port somebody chose from its default.

These are a published interface: the Runner passes `trust_roots` to every target's
`new`, so a subclass's own `BUILDARGS` or `new` passes unknown arguments through
(Moo ignores them). `class_for` keeps the reason a module did not compile and repeats
it: Config already tried to load it, and perl answers a second `require` with
"Attempt to reload".

## Issuer contract

`issue($spec)` returns a bundle with a key, `sign($csr_pem, $spec)` one without,
`root_pem` the trust anchor, `intermediates_pem` the intermediates or `undef`. A spec is
`{ names => [...], lifetime => $seconds, key => 'rsa2048' }` (`SICK::Device::spec`): host
names become DNS SANs, IP addresses IP SANs, the first name is the subject.

**Root and intermediates are two files with two jobs.** `ca.root` holds the root alone:
`step` refuses a `--root` file with more than one PEM block. `ca.intermediates` are no
trust anchors; `SICK::Bundle::is_issued_by` uses them to build the chain when a device
presents its certificate alone. Without them such a device is `foreign-ca` on every run
and is renewed forever. A change to chain building keeps both halves: the anchor is the
root only, the chain may run through intermediates the device did not send.

## External programs

`SICK::Command::run( \@argv, stdin => , env => , umask => , timeout => )` returns
`( $stdout, $stderr, $exit )`.

- **A non-zero exit code is not an exception.** The caller decides what it means;
  `SICK::OpenSSL::run_checked` is the variant that croaks.
- It croaks in two cases only, and callers match on the text: `cannot run '<program>':
  <reason>` and `'<program>' timed out after <N>s`.
- A program that writes a key gets `umask => 077` and a `SICK::Temp` directory.
- What reaches a program as a secret goes through a file or its environment (`env`),
  never through `@argv`: the argument list is readable by every user of the machine.

## Device list

Unknown keys are an error with their path (`devices.grafana: unknown key 'colour' for
type 'files'`), never ignored. Keys the core does not know end up in `$device->options`
and are judged by the target's `validate`. A secret is a path in the list;
`SICK::Config->read_secret($path)` reads its first line and croaks with path and system
reason only.

## What the fakes know

`t/bin/fake-step` and `t/bin/fake-acme-sh` record observed behaviour of the real
programs; the header of each lists what was observed and with which version, and
`docs/findings/acmesh-deploy.md` does so for acme.sh. Before changing a command line in
`Issuer::StepCA` or `Target::Acmesh`, read that header. A fake changes when the real
program was seen to behave differently, and the header gets that observation.

## Where the house stack stops

Moo, `Types::Standard` and `Path::Tiny` are the rule (CLAUDE.md). Three places
deviate on purpose and stay that way; a conversion that "tidies" them back is a
regression:

- **A key file is created with `sysopen` and `O_CREAT|O_EXCL` and its mode**
  (`SICK::Temp::write`). `Path::Tiny`'s `spew` writes a temporary file and
  renames it with a mode from the umask, so for a moment the key exists with
  wider permissions.
- **A finished file is published with CORE `rename`, not `Path::Tiny->move`.**
  `move` is `File::Copy::move`: when `rename` fails it copies – not atomic,
  and the copy gets a mode from the umask – and when the destination is a
  directory it moves the file into it. Written next to the destination
  (`tempfile` in the same directory, mode set before content, `append_raw`),
  then `rename`d.
- **What goes to an external program is a plain string.** `SICK::Temp` hands
  out `path` and `file` as strings, and `SICK::Command::run` refuses anything
  in `@argv` that is a reference. Do not teach it to accept objects that
  stringify: what reaches `exec` is exactly what was checked.
- **No Type::Tiny type where its message would repeat the value.** A
  Type::Tiny failure appends the value it rejected, even with a custom
  `message`. Attributes that may hold a secret or raw user input (the `key` of
  `SICK::Bundle`, the `data` of `SICK::Config`) get a coderef `isa` with a
  fixed text, or none, and the domain check in `BUILDARGS`/`BUILD` comes first
  with the message the tests pin. Elsewhere the type is the second line behind
  that check.

## Copies that must stay identical

`k8s/test/init-ca.sh` and `k8s/test/trust-httpd.conf` are copies of the files in
`docker/`, because a kustomization reads nothing above its own directory.
`t/60-k8s.t` compares them. Edit the file in `docker/`, then copy it.
