# A Linux host over SSH: acme.sh hook `ssh`

For a host that runs a TLS service (nginx here) but no ACME client, and is
reached by SSH. SICK issues the certificate, the `acmesh` target hands it to
the deploy hook `ssh` of acme.sh 3.1.6, which copies key and certificate to
the host and reloads nginx; then SICK compares the fingerprint nginx presents
on 443 with the one it issued. Proven by `t/e2e/device-ssh.sh` against an
sshd container; findings in `docs/findings/device-ssh.md`.

| File | What |
|---|---|
| `sick.yml` | the device for your device list |
| `sudoers` | `/etc/sudoers.d/sick-deploy`: `nginx -s reload`, nothing else |
| `authorized_keys` | the deploy key with `restrict,from=...`; a second line with the forced command |
| `sick-deploy-gate` | the forced command: SFTP and the reload, nothing else |

## On the host (as root)

```bash
useradd --no-create-home --home-dir /home/sick-deploy --shell /bin/sh sick-deploy
usermod -p '*' sick-deploy                       # no password, key only
install -d -o root -g root -m 0755 /home/sick-deploy /home/sick-deploy/.ssh
install -o root -g root -m 0644 authorized_keys /home/sick-deploy/.ssh/authorized_keys
install -d -o sick-deploy -g sick-deploy -m 0700 /etc/nginx/tls
install -o root -g root -m 0440 sudoers /etc/sudoers.d/sick-deploy && visudo -cf /etc/sudoers.d/sick-deploy
# only for the second line of authorized_keys:
install -o root -g root -m 0755 sick-deploy-gate /usr/local/sbin/sick-deploy-gate
```

The account owns `/etc/nginx/tls` and nothing else; its home, `.ssh` and
`authorized_keys` belong to root, so it cannot lift its own restrictions.
nginx points `ssl_certificate` at `/etc/nginx/tls/fullchain.pem` and
`ssl_certificate_key` at `/etc/nginx/tls/key.pem`; the master process runs
as root and reads them. `sshd` needs public-key authentication and the
`sftp` subsystem (Debian's default): `scp` speaks SFTP since OpenSSH 9.0.

## Where SICK runs

- A deploy key of its own, made for this: `ssh-keygen -t ed25519 -N '' -f
  /etc/sick/secrets/www-deploy.key`. It has no passphrase (SICK runs
  unattended); it is a file owned by the user sick runs as, mode `0600`,
  in the secrets volume or directory. Not in the device list, not in the
  environment.
- A `known_hosts` with the host key of the host, taken from the host itself
  (`cat /etc/ssh/ssh_host_ed25519_key.pub` on its console, or from your
  inventory) and written as `www.example.internal ssh-ed25519 AAAA...`.
  Not `ssh-keyscan` over the network: that trusts whoever answers.
  `StrictHostKeyChecking=yes` refuses an unknown and a changed key.

## Two ways to keep the access small

1. **With the hook's backup** (as `sick.yml` stands): the hook sends shell
   code of its own (the backup and its clean-up), so the key gets a shell.
   `restrict` takes away pty and forwarding, `from=` other addresses; the
   file permissions and the one sudo rule bound the rest. The hook copies
   what it overwrites to `/etc/nginx/tls/backup/<name>-backup-<UTC time>/`,
   old private keys included, and deletes those older than 180 days.
2. **No shell**: `DEPLOY_SSH_BACKUP: "no"` in the device, the second line of
   `authorized_keys`, `sick-deploy-gate` installed. The hook then sends two
   SFTP sessions and `sh -c ' sudo -n /usr/sbin/nginx -s reload;'`; the gate
   allows exactly these. There is no backup on the host; getting back means
   a new certificate (`sick run --force www`) or a copy of your own.

Keep `DEPLOY_SSH_USE_SCP: "yes"`. Without it the hook writes the private key
with `echo "<key>" > file` inside the command it sends, which puts the key
into the argument list of a shell on the host (and of `ssh` where SICK runs),
readable by every user there for as long as it runs.

## When something goes wrong

- Unknown or changed host key, key not authorized: `deploy failed: acme.sh
  failed (exit 1): ... Host key verification failed.` or `... Permission
  denied (publickey).` Nothing is written on the host.
- Reload refused (nginx finds an error in its configuration or the new
  certificate): `deploy failed: acme.sh failed (exit 1): ... [emerg] ...`.
  nginx goes on serving the old certificate; the new key and certificate are
  on disk, the old ones in the backup. Fix the configuration and reload - the
  new files are valid - or copy the backup back.
- Reload accepted but not taken (nginx's master could not apply the new
  configuration, a port taken for instance): the hook says `Success`, SICK
  says `verification failed: the device does not present the new
  certificate`. Same remedy.
- The host does not answer: `unreachable`, and nothing is issued.

`sick check` reads the certificate on the port, never the files: success is
the fingerprint nginx presents.
