# SICK House Rules

Apply to every task in this repository unless explicitly overridden. Bias: caution over speed on non-trivial
work. Skill content is never restated here: the agents get their skills force-loaded via `briefing.skills`. The
internals of the run live in skill `sick-core`; house style, Moo, POD and release mechanics in `getty-perl-core`,
`getty-perl-moo`, `getty-perl-pod` and `getty-perl-release-author-getty`. `.claude/agents/` defines which agent
briefs which.

## Engineering discipline

1. **Think before coding** — State assumptions; ask rather than guess. Push back when a simpler approach exists. Stop when confused; name what's unclear.
2. **Your design choice is not the maintainer's requirement** — write down who decided what; the house rules of this repository are in `CLAUDE.md`.
3. **Simplicity first, surgically applied** — Minimum code that solves the problem, nothing speculative. Touch only what you must.
4. **Read before you write** — Before new code, read `SICK::Runner` (`_run_device`) and the base class you extend (`SICK::Target`, `SICK::Issuer`); the run, the decision and the targets are one mechanism.
5. **Tests verify intent, not just behavior** — Reproduce a bug before fixing it; leave the regression test behind. A red test is a claim: say what it asserts before you turn it green.
6. **Checkpoint and fail loud** — Summarize done / verified / left after each significant step. "Tests pass" is wrong if any were skipped — say which.
7. **Surface conflicts, don't average them** — Where code and house rules disagree, say so, don't blend; the disagreements that are meant are listed under hazards.

## Delegation

Depends on whether the Agent/Task tool is available to you.

If you can spawn subagents (orchestrating main agent): do NOT touch behavior-relevant code yourself — delegate. Your
lane: coordinate, inspect, plan, review diffs, run tests, edit prose. When in doubt, delegate. You get no briefing —
only the `sick-*` agents see the run, the decision and the targets.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/`, `bin/`, `docker/`, `k8s/` | `sick-worker` (default) |
| Write or extend tests in `t/` | `sick-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `sick-release-manager` |

If you ARE a `sick-*` agent, the delegation lock does not apply to you — implement, refactor, debug and test per these rules.

Behavior-relevant = everything under `lib/`, `bin/`, `t/`, `docker/` and `k8s/`. Prose in `README.md`, `docs/` and `CLAUDE.md` is not.

**Only `sick-release-manager` commits.** A worker leaves a commit-ready tree and hands its card to `review`; you then dispatch the release-manager.

## Coordination — karr board (always in scope)

Ticket coordination is the orchestrating agent's job, so `karr` is always in scope — don't invoke the skill first, just
use it. Git-native kanban; state lives in `refs/karr/*` in this repo.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail · `karr create "Title" --priority high --tags a,b --body '…'` · `karr edit ID -a "note"` · `--claim NAME` · `karr move ID in-progress` — full surface: skill `kanban-issues-karr-coordination`

Work on a device type belongs on the board of its own repository (`../sick-target-ciscosb`): create the card there and
leave a pointer here. **Serialize board mutations when fanning out** — parallel implementation is fine, but collect
results and then loop `karr move`/`handoff`/`sync` sequentially.

## Release and everything outward — never without permission

`dzil build` / `dzil test` are fine anytime. `dzil release`, `git push`, pushing an image and any change to the
visibility of the GitHub repository are STRICTLY forbidden without the maintainer's explicit go-ahead — even if a plan
lists them as the next step. For anything heading toward release: stop and ask.

## Public issues (GitHub) — never act without instruction

`github.com/Getty/sick` is a **public tracker**. Never act on an issue there on your own initiative — not even to read
it. No listing, viewing, commenting, editing, closing or creating unless explicitly told to handle a specific issue.
karr is the internal agent board; GitHub Issues carries real humans' reports written under the maintainer's account.

## Hazards specific to this repository

Short form; the mechanisms live in skill `sick-core` ("The lab") and in the agents' own lane notes.

- **Where `lib/` leaves the house stack, it is on purpose** — `sysopen`/`O_EXCL` for key files, plain strings for external programs, no type where the message would repeat a secret, core `rename` for finished files. Never "tidy" one of them back to `Path::Tiny` or a `Types::Standard` type.
- **Three things here change real equipment** — `t/e2e/run-lab.sh`, the live test in `../sick-target-ciscosb/t/90-live.t` and the lab in `k8s/`/`docker/`. Edit them, never run or apply them unasked.
- **`prove` never starts a container** — a change under `docker/` needs a run of `t/e2e/run-local.sh`, one under `k8s/` a run in a k3d cluster `sick-*`; without that report it stays unverified. Everything of ours carries the label `sick=1` and is removed by that label alone; what has no label stays.
- **The default kubeconfig of a host is not ours** — every `kubectl`, `k3d` and `helm` call, also one typed by hand while debugging, runs with `KUBECONFIG` set to a private file. Without it the call acts on the host's own context — on a shared host somebody else's cluster, with admin rights — and `k3d` rewrites that file.
- **`unreachable` is not `missing`** — a device that does not answer must not be renewed; the prefix `unreachable: ` of the exception alone tells the two apart.
- **A green run may have run nothing** — most tests `skip_all` without `openssl`, half of `t/42-target-acmesh.t` without `acme.sh`. Read the summary line.
- **`prove -lr t`, serial** — `prove -l t` is not recursive; `-j` breaks tests that listen on ports.
- **An untracked file does not exist for `dzil`** — `[@Author::GETTY]` gathers tracked files only; `prove` runs the untracked test and stays green. `git add` early.
- **No secret anywhere** — not in code, tests, fixtures, logs, messages, the environment of a container or an image layer. Test keys and certificates are made at test time; a message about a secret file holds the path and the system's reason.
