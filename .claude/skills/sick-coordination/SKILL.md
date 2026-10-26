---
name: sick-coordination
description: Use when work in one SICK repository touches another — which of sick, sick-target-ciscosb and sick-target-proxmox owns what, how a card moves between their boards, how a core change is checked against the targets.
user-invocable: false
---

# SICK family — who owns what, how work crosses

The SICK family is three independent repositories and CPAN distributions, checked out
side by side: `sick` (the core, dist `SICK`), `sick-target-ciscosb` (`SICK-Target-CiscoSB`)
and `sick-target-proxmox` (`SICK-Target-Proxmox`). Each has its own karr board; there is no
shared board and no workspace above them. Work crosses as a card on the other repository's
board — never as an edit over there.

## Repo ownership

| Concern | Owning repo |
|---------|-------------|
| The run, the device list, `SICK::Decision`, the issuers, the built-in targets (`files`, `acmesh`), the trust page, `bin/sick` | `sick` |
| `SICK::Target` and the plumbing the targets use: `SICK::Bundle`, `Command`, `OpenSSL`, `Temp`, `Names`, `Config` | `sick` |
| `docker/` (the image holds all three distributions), `k8s/`, `contrib/`, `t/e2e/`, the handbook | `sick` |
| Device type `cisco-sb`: `SICK::Target::CiscoSB`, its session and transports, `docs/device-notes.md` | `sick-target-ciscosb` |
| Device types `proxmox-ve`, `proxmox-bs`: `SICK::Target::ProxmoxVE`/`ProxmoxBS`, the client, `docs/api-notes.md` | `sick-target-proxmox` |
| A new device type | a new `sick-target-<type>` repository — the maintainer's decision; until then a card on `sick` |
| Family skills `sick-core`, `sick-coordination`, the agent `karr-coordinator` | `sick` (skilletor source `sick`; the targets install them, never edit them) |

## Decision rule when a card arrives

```
the run, a decision, an issuer, a built-in target, packaging, handbook  -> sick
what SICK::Target or the plumbing accepts or returns                    -> sick; each target that must follow gets its own card
one device type's dialog, API, transport or notes                       -> its sick-target-* repository
a new dependency of a target                                            -> that target, plus a card on sick for docker/Dockerfile
needs both sides                                                        -> two cards, each naming the other
```

## Moving a card to another board

Board names are the directory names: `sick`, `sick-target-ciscosb`, `sick-target-proxmox`.
Workers never create cards: a worker notes on its own card what belongs where, and the
dispatching agent (the main agent or `karr-coordinator`) files it.

```bash
# in sick-target-ciscosb, for card #5 here
( cd ../sick && karr list && karr create --title "<what the target needs>" --priority medium \
    --tags from:sick-target-ciscosb --body "From sick-target-ciscosb#5: <why it matters there>" )
karr edit 5 -t -a "Filed as sick#<new id>"   # read the id from the create output
```

A card here that cannot go on until the other one is done waits on it with
`--needs sick#<id>` (mechanics: skill `kanban-issues-karr-coordination`, cross-board).
When the other card is done, note the commit on the originating card and resolve the need.

Loop prevention:

1. `karr list` on the receiving board first; if a card already covers it, add a note
   (`karr edit <id> -t -a ...`) instead of a new card.
2. Tag with `from:<repo>` and name the originating `<repo>#<id>` in the body.
3. Hold no claim across a wait on another board — release it and pick it up again.

## A change in the core that the targets see

The targets build on `SICK::Target`, `SICK::Bundle`, `SICK::Command`, `SICK::OpenSSL`,
`SICK::Temp`, `SICK::Names` and `SICK::Config->read_secret`; their tests drive
`SICK::Runner`, `SICK::Config`, `SICK::Device` and the issuers. A change to what these
accept or return is a change to a published interface: additive where possible, named in
the report, and checked against both target suites without editing anything there:

```bash
S=$PWD; for t in ../sick-target-ciscosb ../sick-target-proxmox; do
  ( cd "$t" && PERL5LIB=$S/lib:$PERL5LIB prove -lr t ) || echo "RED: $t"
done
```

A red target suite is a card on that target's board with the failing test named, unless
the core change is wrong — then the core change goes back.

In the other direction a target suite runs against `../sick/lib`
(`PERL5LIB=../sick/lib:$PERL5LIB prove -lr t`). When it turns red without a change in the
target, look at `git -C ../sick log` first.

## Releasing the family

The three are released together, core first. A target's `cpanfile` pins `SICK` at the
version `../sick` carries, ahead of CPAN: that is the family's normal state, and waiting
for `SICK` on CPAN is never a blocker. The image under `sick/docker/` is built from the
directory above the checkouts and needs all three beside each other.

## What not to do

- Edit code, docs or the board of another repository from this one's agent.
- File a card without reading the receiving board first.
- Treat the directory above the checkouts as a workspace: it holds them, nothing more.
- Change `sick-core` or `sick-coordination` in a target: their source is `sick`.
