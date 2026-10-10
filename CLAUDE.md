# CLAUDE.md — SICK

Ship Internal Certificates & Keys: bring certificates of an internal CA (step-ca)
to devices that cannot fetch them themselves. Dist `SICK`, CLI `sick` (in `bin/`).
Design and phase plan live in the hub: `~/dev/perl-developer/docs/superpowers/specs/2026-10-05-sick-design.md`
and `.../plans/2026-10-05-sick-phase-1.md`.

Build and test: `prove -lr t` while iterating (`-r` — the suite is serial on purpose,
no `-j`), `dzil build`, `dzil test`. Never `dzil release` without explicit permission.
`LICENSE` is committed (`dzil genlicense`); `[@Author::GETTY]` gathers tracked files only.

Environment on agent-lab, in every shell (also for `karr`, which otherwise dies with
`Can't locate App/karr/SyncGuard.pm`):

```bash
eval "$(perl -I$HOME/perl5/lib/perl5 -Mlocal::lib)"
export PATH=$HOME/.local/bin:$PATH      # step, step-ca, acme.sh, xmllint
```

`t/e2e/install-tools.sh` puts step, step-ca and acme.sh there in pinned, checksummed
versions; with them `prove -lr t` runs without a skip. `xmllint` (for `t/50-trust.t`)
was unpacked by hand from Debian's `libxml2-utils` (`apt-get download`, `dpkg -x`).
`skilletor` is not in the `PATH`: `~/.claude/plugins/cache/getty/skilletor/*/bin/skilletor`
(`skilletor sync` installs the skills named in `.claude/skilletor.json`).

## Rules of this repo

- **Perl follows the house rules** (skills `getty-perl-core`, `getty-perl-moo`): Moo for
  classes, `Path::Tiny` for files, `JSON::MaybeXS` for JSON, and what CPAN already has is
  taken from there. Where the code does otherwise it is on purpose, and `sick-core`
  says why ("Where the house stack stops").
- **A device type is its own distribution** (`SICK-Target-*`), with its own dependencies.
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

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself — the
principle, the lanes and this repo's hazards are in `.claude/rules/sick-rules.md`.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/`, `bin/`, `docker/`, `k8s/` | `sick-worker` (default) |
| Write or extend tests in `t/` | `sick-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `sick-release-manager` |

The agents carry their conventions via `briefing.skills` (see `.claude/agents/`); the main
agent delegates rather than loading them. `.claude/skills/sick-core` holds the internals
and is this repo's own; the other skills there are installed by skilletor
(`.claude/skilletor.json`) and are changed in their source, never here.

One of them is domain knowledge rather than convention: `ssl-tls-pki` (CA hierarchy,
name constraints, revocation, trust stores per platform, ACME, mTLS, debugging a
handshake). The main agent loads it too — before a design decision on the CA, on trust
distribution or on a service recipe, and before writing the handbook chapter for it.
What it says about a client or a policy is dated; check the claim before it goes into
the handbook.

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
t/bin/fake-step                stand-in for the step CLI, modelled on step 0.30.2
docker/                        compose.yml (ca, sick, trust), Dockerfile, init-ca.sh, entrypoint.sh
t/e2e/run-lab.sh               the Docker setup against a real switch; changes the switch
t/e2e/run-local.sh             the same proof with Docker only: web container as device, project sick-e2e, 127.0.0.1
t/e2e/install-tools.sh         step, step-ca, acme.sh in pinned versions into ~/.local (no sudo)
```

## Docker

- The image is built from the directory above this checkout: it needs
  `../sick-target-ciscosb` as well. `docker/Dockerfile.dockerignore` is an allow list.
- `prove` never starts a container. agent-lab has Docker: `t/e2e/run-local.sh` is the
  end-to-end proof there (project `sick-e2e`, ports on 127.0.0.1, torn down at exit).
  Other people's containers run on that host: touch nothing that is not `sick-*`, no
  `prune`. `t/e2e/run-lab.sh` changes a real switch and is not run unasked.
- Secrets reach containers as files in volumes. Nothing secret in the
  environment, in an image layer, in `docker/README.md` or in the e2e script.
- `docker/README.md` ends with the transcript of an e2e run. Names and addresses
  in it are neutral; keep it that way when it is refreshed.
