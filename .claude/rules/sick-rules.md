# SICK House Rules

Apply to every task in this repository unless explicitly overridden. Bias: caution over
speed on non-trivial work. Subagents get their conventions from the skills force-loaded
via `briefing.skills` — this file is for the orchestrating agent.

## Engineering discipline

1. **Think before coding** — State assumptions; ask rather than guess. Push back when a
   simpler approach exists. Stop when confused; name what's unclear.
2. **A design choice of yours is not a requirement of the maintainer.** Write down who
   decided what. This repository was built on "core Perl only", recorded as the
   maintainer's rule; what he had said was "take as much from others as possible".
3. **Simplicity first, surgically applied** — Minimum code that solves the problem,
   nothing speculative. Touch only what you must.
4. **Read before you write** — Before new code, read `SICK::Runner` (`_run_device`) and
   the base class you extend (`SICK::Target`, `SICK::Issuer`). The run, the decision and
   the targets are one mechanism.
5. **Tests verify intent, not just behavior** — Reproduce a bug before fixing it; leave
   the regression test behind. A red test is a claim: say what it asserts before you
   change code to turn it green.
6. **Checkpoint and fail loud** — Summarize done / verified / left after each significant
   step. "Tests pass" is wrong if any were skipped — say which.
7. **Surface conflicts, don't average them** — Where code and house rules disagree here,
   the house rules are right (see hazards); say so, don't blend.

## Delegation

Depends on whether the Agent/Task tool is available to you.

- **You can spawn subagents** (orchestrating main agent): Do NOT touch behavior-relevant
  code yourself — delegate. Your lane: coordinate, inspect, plan, review diffs, run
  tests, edit prose. When in doubt, delegate. Why: only the `sick-*` agents get their
  skills force-loaded via `briefing.skills`; you get no briefing.

  | Task | Agent |
  |---|---|
  | Implement / refactor / debug anything under `lib/`, `bin/`, `docker/`, `k8s/` | `sick-worker` (default) |
  | Write or extend tests in `t/` | `sick-test-writer` |
  | Commits, `Changes`, card → done, pre-release audit | `sick-release-manager` |

- **You cannot spawn subagents** (you ARE a `sick-*` agent): the lock does not apply —
  work per these rules.

Behavior-relevant = everything under `lib/`, `bin/`, `t/`, `docker/` and `k8s/`. Prose in
`README.md`, `docs/` and `CLAUDE.md` is not.

**Only `sick-release-manager` commits.** A worker leaves a commit-ready tree and hands
its card to `review`; you then dispatch the release-manager.

## Coordination — karr board (always in scope)

`karr` is always in scope — just use it. State lives in `refs/karr/*` of this repo.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail
- `karr create "Title" --priority high --tags a,b --body '…'` · `karr edit ID -a "note"`
  · `karr move ID in-progress --claim NAME` — full surface: skill
  `kanban-issues-karr-coordination`

Work on a device type belongs on the board of its own repository
(`../sick-target-ciscosb`): create the card there and leave a pointer here.
**Serialize board mutations when fanning out** — collect results, then loop
`karr move`/`handoff`/`sync` one after the other.

## Release and everything outward — never without permission

`dzil build` / `dzil test` are fine anytime. `dzil release`, `git push`, pushing an image
and any change to the visibility of the GitHub repository need the maintainer's explicit
go-ahead, also when a plan lists them as the next step. GitHub issues are not a queue:
never read, comment on or close one unasked.

## Hazards specific to this repository

- **The code contradicts the house rules, and the house rules are right.** `lib/` is
  plain `bless` on core Perl plus `YAML::PP`; the target is Moo, `Path::Tiny`,
  `JSON::MaybeXS` (skills `getty-perl-core`, `getty-perl-moo`). The conversion goes
  module by module on cards. Never "fix" `CLAUDE.md` or an agent back to match the code,
  and never convert a module in passing.
- **Three things here change real equipment.** `t/e2e/run-lab.sh` installs a certificate
  on a real switch; `../sick-target-ciscosb/t/90-live.t` does so once its two
  `SICK_LIVE_CISCOSB_*` variables are set; `k8s/` and `docker/` describe a running lab.
  Edit them, never run or apply them without being told to.
- **Docker only where the host has it.** `prove` never starts a container. A change under
  `docker/` is verified by `t/e2e/run-local.sh` (project `sick-e2e`, ports on 127.0.0.1,
  torn down at exit), one under `k8s/` only in a k3d cluster `sick-*` with its own
  kubeconfig, never an existing context. Without such a run report the change as
  unverified. On a shared Docker host touch nothing that is not `sick-*` and prune nothing.
- **`unreachable` is not `missing`.** A device that does not answer must not be renewed.
  The runner tells the two apart by the prefix `unreachable: ` of the exception alone.
- **A green run may have run nothing.** Most tests `skip_all` without `openssl`, half of
  `t/42-target-acmesh.t` without `acme.sh`. Read the summary line.
- **`prove -lr t`, serial.** `prove -l t` is not recursive; `-j` breaks tests that
  listen on ports.
- **An untracked file does not exist for `dzil`.** `[@Author::GETTY]` gathers tracked
  files only; `prove` runs the untracked test and stays green. `git add` early.
- **No secret anywhere**: not in code, tests, fixtures, logs, messages, the environment
  of a container or an image layer. Keys and certificates for tests are made at test
  time. A message about a secret file holds the path and the system's reason.

## Perl conventions — reference, don't restate

House style, Moo patterns, POD and release mechanics live in skills `getty-perl-core`,
`getty-perl-moo`, `getty-perl-pod`, `getty-perl-release-author-getty`; the internals in
`sick-core`. `.claude/agents/` defines which agent briefs which.
