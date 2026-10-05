# CLAUDE.md — SICK

Ship Internal Certificates & Keys: bring certificates of an internal CA (step-ca)
to devices that cannot fetch them themselves. Dist `SICK`, CLI `sick` (in `bin/`).
Design and phase plan live in the hub: `~/dev/perl-developer/docs/superpowers/specs/2026-10-05-sick-design.md`
and `.../plans/2026-10-05-sick-phase-1.md`.

Build and test: `prove -lr t` while iterating (`-r` — the suite is serial on purpose,
no `-j`), `dzil build`, `dzil test`. Never `dzil release` without explicit permission.
`LICENSE` is committed (`dzil genlicense`); `[@Author::GETTY]` gathers tracked files only.

## Rules of this repo

- **Runtime dependencies: core Perl plus `YAML::PP`. Nothing else.** No Moo, no LWP, no
  SSH module, no Path::Tiny, no Try::Tiny. Classes are plain `bless`. Tests use
  `Test::More` and core modules only. A device type that needs more is its own
  distribution (`SICK-Target-*`).
- **X.509 goes through the `openssl` CLI** (`SICK::OpenSSL`), never a Perl X.509 module.
- **No shell.** Every external program is started through `SICK::Command::run`
  (fork + list-form `exec`). The one exception is a `reload` given as a single string
  in the device list, which is the user's own shell command.
- **No secrets** in code, tests, fixtures, logs or error messages. Test keys and
  certificates are generated at test time into temporary directories (`t/lib/Test/SICK/PKI.pm`);
  the only checked-in fixture is `t/fixtures/sick.example.yml`. Messages about a secret
  file carry the path and the system's reason, never content.
- **Private keys on disk** only inside a `SICK::Temp` directory (0700, files 0600, removed
  on scope exit) or where a target deliberately installs them.
- **`# ABSTRACT:` lines are plain ASCII**; every file under `lib/` and `bin/` carries its
  own `our $VERSION`.
- Tests talk to `127.0.0.1` only. No test touches a real device or a real CA.

## Layout

```
lib/SICK.pm                    overview
lib/SICK/Config.pm, Device.pm  device list (YAML) and one entry
lib/SICK/Decision.pm           ok | missing | foreign-ca | names | expiring
lib/SICK/Issuer.pm             base; Issuer/StepCA.pm (step CLI), Issuer/SelfSigned.pm (openssl ca)
lib/SICK/Target.pm             base + plugin loader; Target/Files.pm
lib/SICK/Bundle.pm             cert + chain + key, facts via openssl
lib/SICK/OpenSSL.pm, Command.pm, Temp.pm, Names.pm, Duration.pm   plumbing
t/NN-*.t                       10s core, 20s issuers, 30s targets and decision
t/bin/fake-step                stand-in for the step CLI
```
