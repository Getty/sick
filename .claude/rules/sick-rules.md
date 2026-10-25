# SICK House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Ship internal certificates and keys to devices that cannot fetch them themselves. Read first:
`SICK::Runner` (`_run_device`) and the base class you extend (`SICK::Target`,
`SICK::Issuer`); the run, the decision and the targets are one mechanism. Internals: skill
`sick-core`.

**Who decided what:** this repo's own decisions are written down in `CLAUDE.md` ("Rules of
this repo"); a choice of yours goes on record as yours. Where code and those rules disagree,
say so; the disagreements that are meant are listed under hazards.

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/`, `bin/`, `docker/`, `k8s/` | `sick-worker` (default) |
| Write or extend tests in `t/` | `sick-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `sick-release-manager` |
| Read-only research, audit, gap analysis | `sick-worker` ("read-only, change nothing") |

Behavior-relevant = everything under `lib/`, `bin/`, `t/`, `docker/` and `k8s/`. Prose in
`README.md`, `docs/` and `CLAUDE.md` is not.

Work on a device type belongs on the board of its own repository (`../sick-target-ciscosb`):
create the card there and leave a pointer here.

## Release

Outward here also means pushing an image of the lab and any change to the visibility of the
GitHub repository — both under the publish gate.

## Hazards

Short form; the mechanisms live in skill `sick-core` ("The lab") and in the agents' own lane
notes.

- **Where `lib/` leaves the house stack, it is on purpose** — `sysopen`/`O_EXCL` for key files, plain strings for external programs, no type where the message would repeat a secret, core `rename` for finished files. Never "tidy" one of them back to `Path::Tiny` or a `Types::Standard` type.
- **Three things here change real equipment** — `t/e2e/run-lab.sh`, the live test in `../sick-target-ciscosb/t/90-live.t` and the lab in `k8s/`/`docker/`. Edit them, never run or apply them unasked.
- **`prove` never starts a container** — a change under `docker/` needs a run of `t/e2e/run-local.sh`, one under `k8s/` a run in a k3d cluster `sick-*`; without that report it stays unverified. Everything of ours carries the label `sick=1` and is removed by that label alone; what has no label stays.
- **The default kubeconfig of a host is not ours** — every `kubectl`, `k3d` and `helm` call, also one typed by hand while debugging, runs with `KUBECONFIG` set to a private file. Without it the call acts on the host's own context — on a shared host somebody else's cluster, with admin rights — and `k3d` rewrites that file.
- **`unreachable` is not `missing`** — a device that does not answer must not be renewed; the prefix `unreachable: ` of the exception alone tells the two apart.
- **A green run may have run nothing** — most tests `skip_all` without `openssl`, half of `t/42-target-acmesh.t` without `acme.sh`. Read the summary line.
- **`prove -lr t`, serial** — `prove -l t` is not recursive; `-j` breaks tests that listen on ports.
- **An untracked file does not exist for `dzil`** — `[@Author::GETTY]` gathers tracked files only; `prove` runs the untracked test and stays green. `git add` early.
- **No secret anywhere** — not in code, tests, fixtures, logs, messages, the environment of a container or an image layer. Test keys and certificates are made at test time; a message about a secret file holds the path and the system's reason.

## Perl specifics — reference, don't restate

The internals of the run live in skill `sick-core`; house style, Moo, POD and release
mechanics in `getty-perl-core`, `getty-perl-moo`, `getty-perl-pod` and
`getty-perl-release-author-getty`. `.claude/agents/` defines which agent briefs which.
