# 7. Emergencies

What to do when something has gone wrong, ordered by how much of the CA it
affects. Each entry says what is at stake, the first step, and the rest.
The distinction that runs through all of them: after a **planned** change
you may roll back to the previous state; after a **compromise** you may not,
because the previous state is what the attacker holds.

This edition covers the CA side (chapter 2). Clients, devices and services
follow with their chapters.

## A device's key is exposed

At stake: someone can impersonate that device until its certificate
expires.

1. `sick run --force <device>` – a new key and certificate, deployed and
   checked on the port.
2. `step ca revoke <serial>` of the old certificate (serial from `sick
   check` before step 1, or from the old file). With passive revocation
   this only blocks renewal; the old certificate stays valid until it
   expires. If that is too long for this device, the device lifetime was
   too long (chapter 1).
3. Find out how the key got out; a device type that hands its key over the
   network needs a look.

## The provisioner password of `sick` is exposed

At stake: anyone with it can obtain a certificate for any name the
constraints and the policy allow – until the provisioner is rekeyed.

1. `docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner`
   (chapter 2). This replaces the key pair; a new password alone would not
   be enough, because the encrypted key is served publicly.
2. Look at what was issued in the meantime: the CA log lists every
   signature with its names (`docker compose logs ca`). Anything you did not
   ask for: note the serial, revoke it, and treat the named device as in
   the previous entry.
3. Narrow the policy (`SICK_CA_ALLOW_*`) if it was wider than needed.

Tested: rotation, and the refusal of the old password and key
(`t/e2e/ca-recovery.sh`).

## An ACME account or a DNS credential used for ACME is exposed

*Not tried (P6).* The client deactivates its own account (RFC 8555,
7.3.6). step-ca without remote administration cannot deactivate somebody
else's; replace the ACME provisioner (`step ca provisioner remove acme`,
then add it again) to cut every account, and rotate the DNS credential.

## The CA is down

At stake: nothing at once. Certificates stay valid; only renewals fail.
How long you have is the recovery budget of chapter 1: about 30 days for
devices through SICK (`renew_before`), for ACME services about a third of
their lifetime.

1. `docker compose ps`, `docker compose logs ca` – a full disk or a lost
   volume?
2. Volume lost or damaged: restore the last backup (chapter 2, "Backup and
   a restore drill"): `docker compose create ca`, `ca-backup.sh restore`
   into its volume, `docker compose up -d`. Certificates issued after that
   backup are missing from the database and stay valid.
3. Never run a second CA from a copy *beside* a live one.

Tested: the restore drill (`t/e2e/ca-recovery.sh`); observed 3–4 seconds
from restore to the first certificate in the lab.

## The CA's own TLS certificate expired

At stake: SICK and ACME clients cannot talk to the CA (`step` refuses the
connection), so nothing renews.

step-ca renews its own serving certificate while it runs; this happens when
it was stopped for longer than that certificate's lifetime, or its clock
was wrong. Do not turn off verification in SICK or the clients to get
around it. Restart the CA (`docker compose restart ca`): step-ca issues
itself a new serving certificate from its intermediate at start, as long as
the intermediate is valid. If the intermediate itself has expired, see
"The intermediate expired".

*Not tried* as a drill yet.

## The intermediate expired

At stake: every certificate under it fails at once in every client, and the
CA cannot issue.

Renew the intermediate with the offline root ([chapter 2, "Renewing the
intermediate"](02-the-ca.md#renewing-the-intermediate)), switch at once and
retire the old one, then `sick run --force` for every device and let ACME
clients renew. Prevention is cheaper: the intermediate's end date is in the
backup manifest and the ceremony record; P5 monitors it.

## The intermediate key is compromised

At stake: anyone with it can sign certificates for any name **inside the
name constraints** – and clients accept them. Outside the constraints they
refuse them (tested, chapter 2). No rollback: the old intermediate must go.

1. Stop the CA (`docker compose stop ca`).
2. With the offline root, make a new intermediate with a **new key**
   (`ceremony.sh --renew-intermediate`), switch to it
   (`init-ca.sh --switch-intermediate`) and retire the old one right away
   (`--retire-intermediate`) – no overlap ([chapter 2](02-the-ca.md#renewing-the-intermediate)).
3. `sick run --force` for every device; make every ACME client renew.
4. Take the old intermediate off the trust page and out of
   `ca.intermediates`, and out of every program's `ca_bundle.pem` and every
   NSS database where it was imported (chapter 3). Where clients hold the
   intermediate *without* trust, removing the root is not needed; where an
   old setup put it into a store of anchors, it has to go from there
   explicitly – that is why the trust page no longer tells anyone to do so.
5. Rotate the provisioner (it was in the same volume) and restore nothing
   from a backup taken after the compromise began.

## The root key is lost

At stake: nothing today – but no new intermediate can ever be signed. When
the intermediate nears its end (or is compromised), you need a new root,
and every client has to learn it ([root replacement](02-the-ca.md#replacing-the-root)). Start the
replacement early, while the current intermediate still works: that turns
an emergency into a planned change.

## The root key is compromised

At stake: everything. Anyone with it can make an intermediate without your
constraints and issue for any name to every client that trusts your root.

1. A new hierarchy: a new ceremony with a new root (chapter 2).
2. Remove the old root from **every** client – that is the step that
   protects them, and the slow one; use the removal procedures of chapter 3.
3. Distribute the new root by the authenticated way of chapter 3 (the
   fingerprint over a second channel), re-issue everything (`sick run
   --force` for all devices, ACME clients renew).
4. No overlap period with the old root as for a planned replacement: it is
   the attacker's root now.

*Not tried* as a drill; the planned root replacement (`t/e2e/ca-rollover.sh`)
exercises the mechanics.
