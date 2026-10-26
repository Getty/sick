# CLAUDE.md — SICK

Ship Internal Certificates & Keys: bring certificates of an internal CA (step-ca) to devices
that cannot fetch them themselves. Dist `SICK`, CLI `sick` (in `bin/`). The core of a family:
the device types live in `../sick-target-ciscosb` and `../sick-target-proxmox`. The handbook
is under `docs/handbook/` (open decisions: `docs/handbook/decisions.md`), the plan in
`docs/roadmap.md`, the state in `docs/final-report.md`.

Build and test: `prove -lr t` while iterating (`-r`; serial on purpose, no `-j`),
`dzil build`, `dzil test`. Never `dzil release` without explicit permission. `LICENSE` is
committed (`dzil genlicense`).

The suite runs without a skip only with `step`, `step-ca`, `acme.sh` and `xmllint` on the
`PATH`: `t/e2e/install-tools.sh` puts the first three into `~/.local/bin` in pinned,
checksummed versions, `xmllint` (`t/50-trust.t`) comes from the system's libxml2 tools.

The repository's decisions and hazards are in `.claude/rules/sick-rules.md`, the internals
in skill `sick-core`, the family's routing in skill `sick-coordination`.

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself —
principle in the shared rule `getty-agent-delegation` (skilletor bundle
`getty-cpan-dist@getty`), lanes in `.claude/rules/sick-rules.md`.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/`, `bin/`, `docker/`, `k8s/` | `sick-worker` (default) |
| Write or extend tests in `t/` | `sick-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `sick-release-manager` |
| Route a card to another repository of the family | `karr-coordinator` |
| Read-only research, audit, gap analysis | `sick-worker` ("read-only, change nothing") |

Every subagent is one of these agents — never the built-in `general-purpose`/`Explore`/`Plan`.

The agents carry their skills via `briefing.skills` (see `.claude/agents/`); the main agent
delegates rather than loading them. `sick-core` and `sick-coordination` under
`.claude/skills/` are this family's own and are installed from here into the targets; the
other skills come from `.claude/skilletor.json` and are changed in their source, never here.

One of them is domain knowledge rather than convention: `ssl-tls-pki` (CA hierarchy, name
constraints, revocation, trust stores per platform, ACME, mTLS, debugging a handshake). The
main agent loads it too — before a design decision on the CA, on trust distribution or on a
service recipe, and before writing the handbook chapter for it. What it says about a client
or a policy is dated; check the claim before it goes into the handbook.

## Layout

```
lib/SICK.pm                    overview
lib/SICK/CLI.pm, Runner.pm     the command line; check, issue, deploy, check again
lib/SICK/Report.pm, State.pm   JSON and Prometheus output; what a run remembers, its lock
lib/SICK/Trust.pm, Trust/      the CA's certificates for clients and the page explaining them
lib/SICK/Config.pm, Device.pm  device list (YAML) and one entry
lib/SICK/Decision.pm           ok | missing | foreign-ca | names | expiring
lib/SICK/Issuer.pm             base; Issuer/StepCA.pm (step CLI), Issuer/SelfSigned.pm (openssl ca)
lib/SICK/Target.pm             base + plugin loader; Target/Files.pm, Target/Acmesh.pm
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

- The image is built from the directory above this checkout and needs
  `../sick-target-ciscosb` and `../sick-target-proxmox` beside it.
  `docker/Dockerfile.dockerignore` is an allow list.
- `prove` never starts a container. Where the host has Docker, `t/e2e/run-local.sh` is the
  end-to-end proof (project `sick-e2e`, ports on 127.0.0.1, torn down at exit). Other
  people's containers may run on that host: touch nothing that is not `sick-*`, no `prune`.
  `t/e2e/run-lab.sh` changes a real switch and is not run unasked.
- Secrets reach containers as files in volumes. Nothing secret in the environment, in an
  image layer, in `docker/README.md` or in the e2e script.
- `docker/README.md` ends with the transcript of an e2e run. Names and addresses in it are
  neutral; keep it that way when it is refreshed.
