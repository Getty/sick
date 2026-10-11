# A Linux host over SSH: the acme.sh hook `ssh` through `acmesh`

Question (karr k52, part of P7/k17): can SICK put its certificate onto a
Linux host that runs a TLS service but no ACME client, through the deploy
hook `ssh` of acme.sh, with the host key checked, a key of its own and the
smallest access that works? What happens when the host key, the key or the
reload is wrong, or the host does not answer?

**Answer: yes.** With `DEPLOY_SSH_USE_SCP=yes`, a dedicated account that
owns the certificate directory and nothing else, and one sudo rule for
`nginx -s reload`. Even smaller: no shell at all, a forced command that
allows SFTP and the reload, if the hook's backup is switched off. Every
negative case fails the device, and nothing is written on the host when
SSH refuses. No change to `SICK::Target::Acmesh` was needed.

Run by `t/e2e/device-ssh.sh` (its header lists the steps); the recipe is
`contrib/devices/linux-ssh/`, and the script uses it as it stands: the
device of `sick.yml`, the `sudoers` file and `sick-deploy-gate` go into the
host image, the options of `authorized_keys` onto the deploy key.

## What was run

The CA of `docker/compose.yml` (step-ca, used as shipped, an override
written into the working directory: no published port, everything labelled
`sick=1`), the `sick` service in the image `sick:local`, and a host `www`
(network alias `www.example.internal`) built from Debian with sshd, nginx and
sudo, set up as `contrib/devices/linux-ssh/README.md` says. SICK talks to it
as a device of type `acmesh`, hook `ssh`; it checks the port 443, not the
files.

| | Version |
|---|---|
| Host base image | `debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f` |
| Host packages | nginx 1.26.3-3+deb13u9, openssh-server 1:10.0p1-7+deb13u4, sudo 1.9.16p2-3+deb13u2, OpenSSL 3.5.7 |
| CA | `smallstep/step-ca:0.30.2` = `smallstep/step-ca@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270` |
| sick image | `sick:local` built from this checkout (`docker/Dockerfile`, Debian trixie): SICK 0.001, acme.sh 3.1.6, OpenSSH client 10.0p2, OpenSSL 3.5.7 |
| Docker | Compose 2.26.1, on agent-lab |

The image IDs of `sick:local` and of the host image are printed by the
script at step 1; they are local builds, not pulled. In the last run:
`sick:local` `sha256:e91af9332990aab47bced15956035a6913cf33da1c8318d0e2412c7ca0e9a4c4`
(built 2026-10-10 22:16 UTC, after the last change under `lib/`), host image
`sick-dev-ssh-www:local` `sha256:c00beef718c1c2fdf9064846c1a2bbed0343609a5b5b09bdfb51a3d56e4df51d`.

Two full runs passed (`ALL PASSED`, 71 PASS lines each), and one run killed
with SIGKILL in the middle (no teardown) was cleaned up by the next run
before it started. After every run no container, volume or network of the
project `sick-dev-ssh` was left.

## Results

| Case | Expected | Observed |
|---|---|---|
| positive: `sick run` | `renewed`; port shows the issued certificate | `www renewed foreign-ca`; fingerprint on 443 = `last_issue.fingerprint_sha256` of SICK's record = first certificate of `/etc/nginx/tls/fullchain.pem`; the chain verifies against the root for the name |
| second `sick run` | `unchanged`, nothing touched | `www unchanged ok`; certificate directory identical (listing and checksum) |
| access as claimed | owns only the cert dir; one sudo command; no pty, no forwarding | `find / -xdev -user sick-deploy`: only `/etc/nginx/tls`; `sudo -l`: `(root) NOPASSWD: /usr/sbin/nginx -s reload`; `touch` in `/etc/nginx`, `/etc/nginx/conf.d`: permission denied; `sudo nginx -t`, `sudo sh`: a password is required; `-tt`: `PTY allocation request failed`; `-W`: `administratively prohibited` |
| (a) host key unknown (empty known_hosts) | failed, nothing written | `failed forced deploy failed: acme.sh failed (exit 1): No ED25519 host key is known for www.example.internal and you have requested strict checking.; Host key verification failed.; Error code 255 returned from ssh; ...`; host unchanged |
| (a) host key changed | failed, nothing written | `... REMOTE HOST IDENTIFICATION HAS CHANGED! ... Host key verification failed.`; host unchanged |
| (c) deploy key not authorized | failed, nothing written | `... sick-deploy@www.example.internal: Permission denied (publickey).; Error code 255 returned from ssh; ...`; host unchanged |
| (b) reload refused (syntax error in another `conf.d` file) | failed; old certificate on the port | `deploy failed: acme.sh failed (exit 1): ... [emerg] ... unexpected end of file ... in /etc/nginx/conf.d/broken.conf:2; Error code 1 returned from ssh; ...`; port: the previous certificate; disk: the new key and certificate; backup: the previous ones |
| (b) reload accepted, not taken (a `listen 22` where sshd listens) | failed by SICK's look at the port | hook: `Success`; SICK: `verification failed: the device does not present the new certificate (SHA-256 ...) but another one (...)`; nginx error log: `bind() to 0.0.0.0:22 failed (98: Address already in use)`, `still could not bind()` |
| (d) host does not answer (`docker compose pause`) | `unreachable`, nothing issued | `failed unreachable unreachable: www.example.internal:443 did not answer within 10s`; no `issuing`, no `deploying`, no acme.sh in the log; `last_issue` unchanged |
| smaller access: forced command, no backup | `renewed`, shell refused | `www renewed forced`; port = issued; no backup made; `ssh ... id` and `ssh ... sudo -n /usr/sbin/nginx -s reload`: `sick-deploy-gate: refused`; SFTP `put` into `/etc/nginx/conf.d`: permission denied |

"Nothing written" is checked as a listing (name, size, mtime, mode, owner) of
the certificate directory, backups included, plus one checksum over all
file contents, before and after.

## What the hook does on the host (acme.sh 3.1.6, `deploy/ssh.sh`)

Read in the source and seen in the runs:

- **Settings** come from `DEPLOY_SSH_*` in the environment (the `env` of
  the device): `USER` (required), `SERVER` (default: the first name;
  `host:port` allowed, several separated by spaces), `CMD` (default
  `ssh -T`), `SCP_CMD` (`scp -q`), `USE_SCP`, `KEYFILE`, `CERTFILE`,
  `CAFILE`, `FULLCHAIN`, `REMOTE_CMD`, `BACKUP` (default `yes`),
  `BACKUP_PATH` (default `.acme_ssh_deploy`, relative to the account's home),
  `MULTI_CALL`, `REMOTE_SHELL` (`sh -c`), `REMOTE_CMD_QUOTE` (`yes`). `CMD`
  and `SCP_CMD` are split at spaces, unquoted: no spaces in the paths in
  them.
- **Without `USE_SCP`** everything goes into one `sh -c '...'` on the host,
  joined with `;`, and the files are written as `echo "<content>" > file` -
  the private key included. The key is then part of the argument list of the
  shell on the host and of `ssh` where SICK runs: readable in `ps` by every
  user of either machine while it runs. Also, only the exit code of the last
  command counts: a file that cannot be written is not an error when the
  reload after it succeeds. *(Read, not run.)*
- **With `USE_SCP=yes`** (the recipe) the calls are separate: one `ssh` for
  the backup clean-up, one `ssh` per file for the backup copy, one `scp` per
  file, one `ssh` for `REMOTE_CMD`. Each failing call ends the hook with an
  error. `scp` of OpenSSH 10 uses the SFTP subsystem: proven by the forced
  command run, which lets nothing else through.
- **Order**: key first, then the full chain, then the reload. Between the two
  copies the directory holds a new key beside the old certificate; a reload
  by somebody else in that moment would fail (nginx checks that key and
  certificate match), not serve a mismatch.
- **Backup**: before overwriting a file it copies it to
  `<BACKUP_PATH>/<first name>-backup-<UTC time>/` (`mkdir -p`, `cp`) and,
  at every run, deletes such directories older than 180 days. That includes
  the old private keys (mode 0600 kept); the directories themselves were
  0775 (the account's umask 002 on Debian, user private groups).
- **Reload**: `REMOTE_CMD` as given, through `sh -c`. Its exit code is the
  hook's result; acme.sh then exits 1 whatever the code was.
- Error output reaches SICK: SICK's message is `deploy failed: acme.sh
  failed (exit 1): ` followed by acme.sh's standard error, lines joined
  with `; ` in the table.

## Recipe facts for the handbook

**Rights on the device, and how to keep them small.** A dedicated account
(`sick-deploy`), password locked, key only. It owns the certificate
directory (`/etc/nginx/tls`, 0700) and nothing else; its home, `.ssh` and
`authorized_keys` belong to root, so it cannot remove its own
restrictions. One sudo rule: `sick-deploy ALL=(root) NOPASSWD:
/usr/sbin/nginx -s reload`. In `authorized_keys`: `restrict` (no pty, no
forwarding) and `from=` the address of SICK. The hook needs:

- a shell, as long as its backup is on - the backup is shell code it sends;
- with `DEPLOY_SSH_BACKUP=no` and `USE_SCP=yes` no shell: exactly two SFTP
  sessions and `sh -c ' sudo -n /usr/sbin/nginx -s reload;'`. A forced
  command (`contrib/devices/linux-ssh/sick-deploy-gate`) that allows these
  two and refuses everything else works; the price is the hook's backup.
  SFTP still lets the account read what any user may read and write where
  it may write - the file permissions remain the boundary.

Root is not needed. The sudo rule names the arguments: a rule for `nginx`
with any arguments would let the account start nginx as root with a
configuration of its own (`-c`, `-g`).

**Where the secret lives.** The private key of the deploy account is a file
in SICK's secrets volume (`/etc/sick/secrets/www-deploy.key`, owned by the
user sick runs as, 0600), named in the device list only as a path inside
`DEPLOY_SSH_CMD`/`DEPLOY_SSH_SCP_CMD`. It is not in the device list or the
environment. In the test it was made inside the volume by a one-off
container and never existed on the Docker host's disk. The `known_hosts`
beside it is not secret but must be right: it holds the host key as read on
the host itself, not from `ssh-keyscan`. The TLS private key exists in
SICK's private temporary directory for the time of the deployment and on the
host in `/etc/nginx/tls/key.pem` - and in the hook's backups, up to 180
days.

**What restarts.** Nothing restarts: nginx reloads. `nginx -s reload` (also
as the signaller) parses the whole configuration and loads the
certificates first; on an error it exits 1 and the running nginx keeps what
it had. Existing connections stay on the old workers until they end.
Errors only the master meets (binding a port) do not reach the reload
command: it exits 0 and nginx keeps the old configuration.

**How `sick check` sees success.** On the port only: the fingerprint nginx
presents on 443 has to be the one issued. That is what caught the second
(b) case, where the hook reported success. A written file proves nothing.

**How to get back.**

- Reload refused: nginx serves the old certificate from memory; the disk has
  the new key and certificate, both valid and matching. Fix the cause and
  reload - the new certificate goes live - or copy
  `/etc/nginx/tls/backup/<name>-backup-<time>/{key,fullchain}.pem` back
  (shown in the test: port and disk agree on the old certificate again).
  The next `sick run` then finds the device `ok`.
- Without the hook's backup (the forced command variant): there is no copy
  on the host. SICK keeps no keys and cannot redeploy an old certificate; a
  fresh one is `sick run --force <device>`.
- SICK's own state records what was issued and when (`sick inventory`), not
  the key.

**What a refused deployment costs.** SICK issues before it deploys: in (a),
(b) and (c) a certificate was issued each time and thrown away (not
revoked, its key gone). Without `--force` the back-off of SICK's state (1, 2,
4 ... 24 hours) keeps a host with a wrong host key from collecting one per
run. An unreachable host costs nothing: nothing is issued.

## Not tried

- The hook without `USE_SCP` (key on the command line, see above), with
  `MULTI_CALL`, with several servers in `DEPLOY_SSH_SERVER`, or with a port
  in it.
- `from=` refusing another address: set and in force (the connections came
  from inside the allowed network), but no connection from outside it was
  made.
- `systemctl reload nginx` as the sudo rule (no systemd in the container);
  other services than nginx; other distributions than Debian 13; an SSH
  server other than OpenSSH; `Subsystem sftp internal-sftp` on the host
  (the gate execs `/usr/lib/openssh/sftp-server` either way).
- RSA host or deploy keys (ed25519 only); a passphrase on the deploy key
  (SICK runs unattended; acme.sh has no way to give one).
- A reload by somebody else between the two copies of the hook.
- A real host, a real network: everything ran on one Docker network.
