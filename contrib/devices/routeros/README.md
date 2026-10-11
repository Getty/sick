# MikroTik RouterOS

A RouterOS router cannot fetch a certificate from step-ca by itself. SICK
issues it and hands it to the deploy hook `routeros` of acme.sh (device type
`acmesh`), which logs in with ssh, copies key and certificate with scp and
imports them with a short RouterOS script. Proven against RouterOS CHR
7.24.5 and acme.sh 3.1.6 by `t/e2e/device-routeros.sh`; the details are in
`docs/findings/device-routeros.md`.

| File | What |
|---|---|
| `sick.yml` | the device entry for SICK's device list |
| `sick-user.rsc` | RouterOS commands: group `sick`, user `sick`, its key, www-ssl on |

## Setting it up

1. On the SICK host, a deploy key of its own and nothing else on it:

   ```bash
   ssh-keygen -t ed25519 -N '' -C sick -f /etc/sick/router.key
   chmod 600 /etc/sick/router.key
   ```

   RouterOS 7 takes ed25519 (tried on 7.24.5); older releases want RSA
   (`-t rsa -b 3072`).
2. On the router, as an administrator: `sick-user.rsc` (copy
   `router.key.pub` there as `sick.pub` first).
3. The host key into `/etc/sick/known_hosts`, read on the router (the end
   of `sick-user.rsc` says how), as
   `router.example.internal ssh-rsa AAAA...` - with `[host]:port` when ssh
   is not on 22. SICK runs ssh with `StrictHostKeyChecking=yes`: an unknown
   or changed host key fails the device, nothing is sent.
4. The entry of `sick.yml` into the device list; `sick check router`, then
   `sick run router`.

## What to know

- **Rights:** `ssh,ftp,read,write`, nothing more; each smaller set fails.
  `write` is RouterOS configuration without user management - the user can
  change much more than certificates. Keep it small around that: a group of
  its own, `address=` on the user limited to the SICK host, the key only in
  SICK's file. The hook never needs `sensitive` or `policy`.
- **Secrets:** the deploy key lives in a file on the SICK host
  (`/etc/sick/router.key`, 0600), referenced from `ROUTER_OS_SSH_CMD`; it is
  not in the device list's values, not in the environment of anything. The
  certificate's private key is uploaded as `<name>.key` (0600 as it leaves)
  and removed by the hook's script after the import. **If the script does
  not run** (missing right, a failure on the router), the key file stays in
  `/file` until the next good run removes it - look there after a failed
  deployment.
- **Restart:** none. The new certificate is imported as `<name>.cer_0` and
  set on www-ssl (and whatever `ROUTER_OS_ADDITIONAL_SERVICES` names);
  www-ssl presents it at once. Between removing the old certificate and
  setting the new one the script waits about four seconds (its `delay`s);
  what www-ssl presents in that window was not measured.
- **Success:** `sick check` looks at `host`:`port` - the www-ssl service,
  443. RouterOS answers a command that fails at run time with exit code 0,
  so acme.sh may say `Success` when nothing was imported; SICK's comparison
  of the fingerprint on the port is what catches it.
- **The way back:** there is none on the router. The hook removes
  `<name>.cer_0` to `_3` before it imports, so the previous certificate is
  gone after every deployment. Getting back means setting www-ssl to another
  certificate (`/ip service set www-ssl certificate=...`) or running SICK
  again.
- **Chain:** the hook uploads the full chain as one file; the leaf becomes
  `cer_0`. With an intermediate, it becomes `cer_1` - not tried, the test CA
  signs with its root.
- **RouterOS 7.24 note:** the CHR has a `reverse-proxy` service on 443 as
  well; with www-ssl enabled, www-ssl answered on 443.
