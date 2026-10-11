# Decisions that are the maintainer's

Everything in this handbook that only the person responsible for the CA can
decide, in one place. Each record says what is to be decided, the options,
**a proposal** (marked as such: it is ours, not a decision), why, and where
the decision is set. Decisions already made are listed at the end, with who
made them.

## 1. Where the root key lives

- **Options:** an encrypted key file on removable media; a YubiKey (PIV) or
  a PKCS#11 HSM; the CA volume (lab mode only).
- **Proposal:** an encrypted file on two removable media kept in different
  places, the password stored apart from both; a YubiKey or HSM when one is
  at hand – with a second token or an encrypted backup, or losing the token
  means a root replacement.
- **Why:** the root key is needed every few years (a new intermediate);
  losing it forces a root replacement, a thief can sign anything.
- **Set in:** `ceremony.sh --root-key`, `--root-password-file`
  (chapter 2). The token variant is *not tried* (HQ checklist).

## 2. Names and networks the CA may issue for

- **Options:** the internal domain(s) and private ranges in use, in the
  intermediate's name constraints and the CA policy; wider; none (lab mode).
- **Proposal:** one internal domain below a domain you own (or
  `home.arpa`), the private ranges in use, the same email domain for people's
  certificates – nothing wider. Exclude all IP addresses if no certificate
  carries one.
- **Why:** the constraints are enforced by step-ca when it issues and by
  every client stack we tested when it verifies (chapters 2, 3, 8); a DNS/IP
  constraint does not bound email or URI SANs, so those need their own.
- **Set in:** `ceremony.sh --dns --ip --email --uri --exclude-all-ip`;
  `SICK_CA_ALLOW_DNS`, `_IP`, `_EMAIL`, `_URI` (chapters 1, 2, 8).

## 3. Lifetimes

- **Proposal:** root 20 years, intermediate 5, devices through SICK 397 days
  (renewed 30 days before the end), ACME services 30 days (at most 90),
  Proxmox VE native ACME 60 days (`acme-long`), client certificates 30 days.
- **Why:** each lifetime must outlast the longest outage you are prepared
  for – of the CA, of the network to a device, of the person who fixes it.
  30-day ACME certificates leave about ten days for a CA outage; device
  certificates are renewed by SICK with a month to spare; Apple refuses TLS
  server certificates longer than 825 days.
- **Set in:** `ceremony.sh --root-lifetime --intermediate-lifetime`;
  `defaults:` in the device list; `SICK_CA_MAX_LIFETIME`,
  `SICK_CA_ACME_LIFETIME`, `SICK_CA_ACME_MAX_LIFETIME`; `provisioners.json`
  (chapters 1, 2, 4, 8).

## 4. Key types

- **Proposal:** EC P-256 for the CA, RSA 2048 for device certificates.
- **Why:** P-256 is accepted by every client covered; old switch firmware
  takes RSA only, and a leaf's key type is independent of its issuer's.
- **Set in:** `ceremony.sh --kty`; `key:` per device or in `defaults:`.

## 5. Who may use ACME – external account binding (card k51)

- **Options:** the ACME endpoint open to everyone who reaches port 9000
  (today); reachable only from the service networks; external account
  binding (`requireEAB`) so that only clients with a key can open accounts.
- **Proposal:** keep port 9000 reachable only from the networks where
  services run, keep internal DNS in admin hands, policy no wider than your
  domain; require EAB once the endpoint has to be reachable more widely.
- **Why:** without EAB, whoever reaches the endpoint and can answer a
  challenge for a name gets a certificate; constraints and policy bound the
  names, not the requester.
- **Set in:** a firewall in front of port 9000; EAB would be a new setting
  in `init-ca.sh` (not built, *not tried*).

## 6. A separate client CA

- **Options:** a provisioner `clients` with `clientAuth` only under the
  same intermediate (built); a second intermediate for clients.
- **Proposal:** the provisioner, as built (chapter 8, decision record).
  Revisit when client certificates gate administrative access for many
  people, or need another lifetime or revocation regime.
- **Why:** the purpose separates server and client certificates (tested);
  the real control is mapping an identity to an allowed principal; a second
  intermediate doubles ceremonies, rotations and trust sets.
- **Set in:** `provisioners.json`; a second intermediate would need a second
  ceremony and is not supported by `init-ca.sh`.

## 7. Signing the Apple profile

- **Options:** unsigned (today: iOS and macOS show "Not Verified"); signed
  with a certificate trusted by the devices.
- **Proposal:** leave it unsigned for now and have people compare the root
  fingerprint after installing (chapter 3); sign it when the profile goes to
  many people who should not be taught to accept "Not Verified".
- **Why:** signing needs a signing key and certificate of its own, kept and
  rotated; its only gain is the "Verified" label.
- **Set in:** not built; a signing step after `sick trust` would be new.

## 8. People's enrolment: admin-issued PKCS#12 or OIDC

- **Options:** an admin issues and hands over the PKCS#12, its password over
  a second channel (built); an OIDC provisioner where people log in and get
  their own certificate.
- **Proposal:** admin-issued while there are few people; OIDC when there
  are many or turnover is high.
- **Set in:** `contrib/mtls/enroll.sh`; OIDC would be a provisioner in
  `provisioners.json` (*not tried*).

## 9. Repositories, CPAN, image

| Decision | Proposal | Set in |
|---|---|---|
| Visibility of the GitHub repositories (`sick`, `sick-target-ciscosb`, `sick-target-proxmox`) | yours | GitHub |
| CPAN release of the three distributions | after the HQ checklist's first steps (CA, one client, one device) passed | `dzil release`, never by an agent |
| Image name and registry | yours; the image is built from three checkouts today | `SICK_IMAGE`, `docker/compose.yml` |
| `docker/` and `t/e2e/` in the CPAN tarball | ship `docker/` (it is a documented way to run SICK); leave `t/e2e/` out (it needs Docker, `run-lab.sh` changes a real switch) | `dist.ini` |

## 10. Card k10: the tests on the house stack

- **To decide:** whether "Path::Tiny, JSON::MaybeXS and Moo" applies to the
  test suite as well (its helpers `slurp`/`spew` and `JSON::PP` in the fakes),
  or only to `lib/`.
- **Proposal:** yes, after the release; no assertion gets weaker.
- **Why:** consistency; the risk is in the two fakes, which run as programs
  of their own.

## 11. Card k11: which hand-written plumbing gives way to CPAN

- **To decide**, per item: `SICK::Command` (fork, list-form exec, timeout),
  the command line (`Getopt::Long` vs `MooX::Cmd`), the plugin search of
  `class_for`, `SICK::Names`, `SICK::Duration`, and the rule "X.509 through
  the `openssl` CLI, never a Perl X.509 module".
- **Proposal:** none from us – the card lists the items with their size;
  the property to keep for `SICK::Command` is that no shell ever sees an
  argument.

## Decisions already made

| Decision | By | When | Where it shows |
|---|---|---|---|
| Internal CA, no Let's Encrypt; take as much as possible from others (step-ca, step, acme.sh, CPAN) | maintainer | 2026-10-05 | the whole design |
| House stack (Moo, Path::Tiny, JSON::MaybeXS), not "core Perl only" | maintainer | 2026-10-10 | `lib/` |
| Proxmox: a device type of its own instead of the acme.sh hooks or an upstream request (k56) | maintainer | 2026-10-11 | SICK-Target-Proxmox, chapter 5 |
| A device rolled back to an older valid certificate: alert only (k44) | orchestrator, agreed by the hub | 2026-10-11 | chapter 6 |
| Root replacement does not publish the other hierarchy's intermediate (k34) | orchestrator | 2026-10-10 | chapter 2 |
| Kubernetes Secrets: cert-manager, no SICK target | orchestrator | 2026-10-11 | chapter 5 |
| Back-off instead of a new certificate on every failing run; no revocation of discarded certificates (k27) | orchestrator | 2026-10-10 | chapter 6 |
