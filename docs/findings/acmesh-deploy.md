# acme.sh `--deploy` with certificates it did not issue

Question: can SICK put a certificate from step-ca into the directory layout of
acme.sh and let `acme.sh --deploy --deploy-hook <hook>` install it, so that the
deploy hooks of acme.sh can be used without acme.sh ever issuing anything?

**Answer: yes.** The approach holds. `SICK::Target::Acmesh` is built on it.

Examined: acme.sh **3.1.6** (git `807da64`, 2026-09-20), run from a plain git
checkout (not installed), on Debian 13 with dash as `/bin/sh`. Method: reading
`acme.sh` and `deploy/localcopy.sh`, then experiments with hand-made
certificate directories, most of them inside an empty network namespace
(`unshare -n`) to see whether anything needs the network. Verified end to end
by `t/42-target-acmesh.t` against the real program (see the end).

Only the `localcopy` hook was run. Everything said about other hooks below
comes from reading their source.

## What `acme.sh --deploy` needs

`deploy()` in `acme.sh` does four things: `_initpath <domain>`, check that the
certificate directory exists, source `<domain>.conf` if it is there, call the
hook function with five file paths.

- **A directory** `<cert-home>/<domain>`. That is the only hard requirement.
  Without it: `The domain '<d>' is not a cert name. ... Cannot find path:
  '<path>'`, exit 1.
- **The files the hook reads**, at fixed names inside that directory:

  | File | Content | Hook argument |
  |---|---|---|
  | `<domain>.key` | private key | `$2` `_ckey` |
  | `<domain>.cer` | the certificate | `$3` `_ccert` |
  | `ca.cer` | intermediate certificates | `$4` `_cca` |
  | `fullchain.cer` | certificate + intermediates | `$5` `_cfullchain` |
  | `<domain>.pfx` | PKCS#12, only made by `--to-pkcs12` | `$6` `_cpfx` |

  acme.sh does not check them. A missing file only fails when the hook reads
  it (`cat: ...: No such file or directory`, exit 1) - by then `localcopy` had
  already truncated its destination. SICK writes the first four. `.pfx` is not
  written: of the hooks in 3.1.6, `localcopy` and `docker` read it, both only
  when asked to, and `openstack` creates it itself.
- **No `<domain>.conf` - in 3.1.6.** It sources the file only when it exists
  ("the cert was placed here manually", says the comment). The releases
  looked at before that - 2.8.8, 3.0.7 and 3.1.0 - source it unconditionally
  (`. "$DOMAIN_CONF"`), and a POSIX shell gives up on a missing file there.
  SICK therefore creates the file when it is not there, with the entries that
  hooks read from it without having saved them themselves:

  | Entry | Value | Read by |
  |---|---|---|
  | `Le_Domain` | the first name | - (acme.sh's own) |
  | `Le_Alt` | the other names, comma separated; `no` when there are none, as acme.sh writes it | `cpanel_uapi` |
  | `Le_Keylength` | `2048`, `3072`, `4096`, `ec-256` | `haproxy`, `lighttpd`, `unifios`, `zyxel_gs1900` (RSA or EC?) |

  `haproxy` and `lighttpd` also look at `Le_OCSP_Staple`; SICK leaves it out,
  which means "no".
- **No account, no CA, no network.** A deployment into a fresh home works in
  an empty network namespace. acme.sh creates nothing but the `.conf`: no
  `account.conf`, no `ca/` directory, no log file, nothing in `~/.acme.sh`.
- **The domain is the first name.** It is the argument of `-d`, the directory
  name, the file name stem and `$1` of the hook. An IPv4 address, an IPv6
  address and a wildcard (`*.wild.example.internal`) as first name all work
  with `localcopy`. Some hooks derive names on the device from it
  (`routeros`: `<domain>.cer_0`).
- **RSA or EC makes no difference.** With `--ecc` acme.sh looks in
  `<domain>_ecc`; without it, in `<domain>` (and in `<domain>_ecc` only when
  `<domain>` does not exist). SICK always uses the plain directory and never
  passes `--ecc`.

## `--home`, `--config-home`, `--cert-home`

| Option | Variable | Default | What lives there |
|---|---|---|---|
| `--home` | `LE_WORKING_DIR` | `~/.acme.sh` | hooks of your own (`<home>/deploy/<hook>.sh`) |
| `--config-home` | `LE_CONFIG_HOME` | `--home` | `account.conf`, `ca/`, log, `http.header` |
| `--cert-home` | `CERT_HOME` | `--config-home` | one directory per certificate |

SICK passes all three with the same directory, so nothing depends on what the
environment says. That matters: the official Docker image sets
`LE_CONFIG_HOME=/acme.sh` in its environment, and with `--home` alone the
certificates would be looked for there.

**Hooks are found next to the script first**: `$_SCRIPT_HOME/deploy/<hook>.sh`,
where `_SCRIPT_HOME` is the directory of the (symlink-resolved) `acme.sh`
file - true for an installation (`~/.acme.sh/acme.sh` + `~/.acme.sh/deploy/`),
for a git checkout and, going by its `Dockerfile`, for the official image
(installed, with `/usr/local/bin/acme.sh` as a symlink). Only then
`<home>/<domain>/`, `<home>/` and `<home>/deploy/`. So a private, empty
`--home` still finds every shipped hook; calling `acme.sh` through `PATH` and
through a symlink was tried and works. A package that separates the script
from its `deploy/` directory would break this; none was examined.

`--home` and `--config-home` must not contain whitespace (acme.sh refuses:
"path can not contain spaces"). SICK validates that for a configured `home`;
a `TMPDIR` with a space in it fails in acme.sh's own words.

## Environment

- **Hooks read their settings from the environment** (`_getdeployconf`:
  environment first, then `SAVED_<name>` from `<domain>.conf`). That is the
  whole interface; there are no command line options for hook settings. Good
  for SICK: secrets never need to be on a command line.
- **Hooks write their settings back** (`_savedeployconf`) into
  `<domain>.conf` as `SAVED_<name>='<value>'` - **secrets included, in plain
  text** (some values base64-wrapped, which is encoding, not protection). The
  file is created with mode 0600. In a private temporary home this disappears
  with the home; in a home that stays, it stays. The next deployment uses the
  saved values for every variable that is not set - tried: a second
  `localcopy` run without any environment copies to the remembered places.
- **acme.sh takes its paths from the environment when they are set.** With
  `DOMAIN_PATH` inherited from the caller, `--deploy` fails ("Cannot find
  path") although `--home` is correct. The same holds for `DOMAIN_CONF`,
  `CERT_KEY_PATH`, `CERT_PATH`, `CA_CERT_PATH`, `CERT_FULLCHAIN_PATH`,
  `CERT_PFX_PATH` and their relatives in `_initpath`, and for
  `ACCOUNT_CONF_PATH`. `DEBUG`, `LOG_FILE`, `LOG_LEVEL`, `SYS_LOG` and
  `OUTPUT_INSECURE` in the environment make acme.sh log more, and elsewhere.
  SICK removes all of these from the environment of the child and refuses
  them in `env`/`env_files`.
- `NO_TIMESTAMP=1` removes the `[Mon Oct  5 03:02:18 UTC 2026]` prefix of
  every line. SICK sets it. Colour is only used on a terminal.

## Output and exit code

- Success: exit 0, progress on standard output, ending in `Success`.
- Any failure: **exit 1**, whatever the hook's own code was (a reload command
  exiting with 3 is still 1). Messages on standard error, the hook's own first,
  then `Error deploying for domain: ...` / `Error encountered while deploying.`
- A hook that does not exist: `The deploy hook <name> was not found.`, exit 1.
- After a success acme.sh adds `Le_DeployHook='<hook>,'`,
  `Le_DeploySuccessTime` and `Le_DeploySuccessTimeStr` to the `.conf`.
- At normal verbosity `localcopy` prints no setting. Other hooks print what
  their authors chose to print, and more with `--debug`, which SICK never
  passes. SICK replaces
  every literal occurrence of an `env_files` value in the output before it
  logs or reports it. A value the hook transformed (encoded, cut) is not
  caught by that.

## The trap: never share the home with a cron-driven acme.sh

`acme.sh --cron` walks every directory in the certificate home that has a
`.conf` and tries to renew it. For a directory SICK made, there is no `Le_API`
and no `Le_NextRenewTime`, so it goes straight to the default CA - in 3.1.6
ZeroSSL - and asks it for a certificate for the internal name. Tried in an
empty network namespace: `Renewing using Le_API=` followed by
`Cannot init API for: https://acme.zerossl.com/v2/DV90` in a retry loop. With
network access that publishes the internal names to a public CA and fails
there every night. A far-future `Le_NextRenewTime` would not be a reliable
guard either: the ARI check of 3.1.6 contacts the CA before it looks at it.

Consequence for SICK: the default `home` is a private temporary directory per
deployment, and the documentation of the `home` option says in bold not to
point it at the home of an acme.sh installation that runs as a cron job.

## What SICK does, in one place

```
<home>/                              0700, SICK::Temp unless `home` is set
  <first name>/                      0700
    <first name>.key                 0600  removed again when acme.sh is done
    <first name>.cer                 0644
    ca.cer                           0644  empty when there is no intermediate
    fullchain.cer                    0644
    <first name>.conf                0600  Le_Domain, Le_Alt, Le_Keylength; only if missing

acme.sh --deploy -d <first name> --deploy-hook <hook> \
        --home <home> --config-home <home> --cert-home <home>
```

with `env` and `env_files` in the environment, the path variables above
removed from it, `NO_TIMESTAMP=1`, umask 077, no shell, and a time limit of
300 seconds.

## Open points

- **Only `localcopy` has been run.** The hooks SICK is meant for in practice
  (`routeros`, `proxmoxve`, `proxmoxbs`) talk to a device and were not tried.
  The mechanism in front of them is the same; what each of them does to its
  device is not covered by anything here.
- **The `routeros` hook has no password setting.** It logs in with `ssh` and
  `scp` and reads `ROUTER_OS_HOST`, `ROUTER_OS_USERNAME`, `ROUTER_OS_PORT`,
  `ROUTER_OS_SSH_CMD`, `ROUTER_OS_SCP_CMD` and `ROUTER_OS_ADDITIONAL_SERVICES`;
  authentication is an SSH key (set through `ROUTER_OS_SSH_CMD`/`_SCP_CMD`, or
  the default key of the user running SICK). The example in the design
  document (`env_files: { ROUTER_OS_PASSWORD: ... }`) sets a variable that no
  hook reads. It also needs `ssh` and `scp` wherever SICK runs, and a known
  host key.
- **An empty `ca.cer`** is what a hook gets when the CA signs with its root
  directly (the self-signed test issuer). step-ca always has an intermediate.
  A hook that insists on a non-empty CA file would fail; none was found that
  does.
- **A hook that fails half way** leaves the device however far it got. acme.sh
  has no rollback, and SICK adds none; the next `sick run` starts from what
  the device presents.
- Older releases of acme.sh were read (`deploy()` of 2.8.8, 3.0.7, 3.1.0),
  not run. The `.conf` SICK creates is there for them; nothing else in
  `deploy()` differs.

## How this was checked

On reuben (no acme.sh): `prove -l t/42-target-acmesh.t` runs the target
against `t/bin/fake-acme-sh`, which records its command line, environment
names, umask and the modes of what it finds; the part against the real
program is skipped.

In the lab (Debian 13, acme.sh 3.1.6 from a git checkout in the `PATH`), the
same file additionally deploys through the real `localcopy` hook: EC and RSA
keys, a certificate with an intermediate, first names that are an IPv4
address, an IPv6 address and a wildcard, a secret that reaches the hook only
through the environment and is hidden in the log, a failing reload command, a
missing hook, a home that stays (saved settings are reused, the key is
removed), hostile inherited `DOMAIN_PATH`/`LE_WORKING_DIR`/`CERT_HOME`, and
one device through `SICK::Runner` (first run `renewed`, second `unchanged`).

```
PATH=/path/to/acme.sh-checkout:$PATH prove -l t/42-target-acmesh.t
# or
SICK_TEST_ACME_SH=/path/to/acme.sh prove -l t/42-target-acmesh.t
```
