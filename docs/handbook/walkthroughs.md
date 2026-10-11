# How this handbook was tested: walkthroughs from zero

The author of a handbook reads its gaps without noticing them. So this one
was walked through by agents that knew nothing about SICK: each got a fresh
copy of the repository, the handbook, an empty Docker environment and the
instruction to do exactly what the text says – and none of the test scripts,
findings or history. Every place where the text was not enough, a command
was wrong, or the output differed was fixed **in the handbook** (or, where
the setup itself was wrong, in the setup), never in the instructions to the
next agent. Then a new agent walked the same section again.

All runs on 2026-10-11, in containers on one host; names and addresses are
neutral (`example.internal`, `192.0.2.0/24`). Adaptations to that shared host
– a Compose project of its own, ports on 127.0.0.1, no `sudo` (done through
a container instead) – were not counted as findings.

| Section | Round 1 | Round 2 | Round 3 | Round 4 | Round 5 |
|---|---|---|---|---|---|
| Planning and the CA (chapters 1–2) | 2 blockers (no network alias for the CA in import mode; no command for the restore drill), 5 wrong, 7 unclear | 1 blocker (renewal read the root password from the wrong medium), 13 unclear | 1 blocker (the second root's key directory not made first), 2 wrong (`install` into the root-owned secrets directory without `sudo`; the old-password check advised a world-readable copy), 7 unclear | no blocker; 1 guess (the old provisioner password had to be saved before rotating, the text said so after the command), 5 unclear (manifest put back before a restore, `.env` permanent after phase C, the full policy error, …) | **no blocker, no guess**; 4 unclear (a transfer medium so that the root-key media never reach the CA host; certificates on both key media; which scripts carry which roots; `COMPOSE_FILE` before removing the old volume) |
| Clients and the first device (chapters 2, 3, 5) | 2 blockers (the alias; no runnable first device), 3 wrong, 9 unclear | no blocker; 1 wrong (`root_ca.crt` is DER, curl needs `root_ca.pem`), 10 unclear | **no blocker, no guess**; 1 markup error (a code fence not closed), 3 unclear | – (done) | – (done in round 3) |
| Services and operations (chapters 2, 4, 6) | 3 blockers (the alias; image not built before the ceremony; ACME recipes without lab wiring), 4 wrong, 5 unclear | no blocker; 2 wrong (exit code of `sick check`; "scrape its metrics" without metrics), 10 unclear | no blocker; 1 wrong (the Docker cron line dropped the metrics file when a device was unreachable), 1 wrong (the Caddy option named), 6 unclear | **no blocker, no guess on the path**; 1 wrong (the Docker cron line without cron's `PATH` – `sick-notify` not found, the failure unreported), 4 unclear (start-up run renews the first device first, fingerprint form in the recipe READMEs, port in the example, cron mail on delivery) | **no blocker, no guess**; 4 unclear (the first ACME order takes seconds; cron and the service's own runs, the lock; writing the webhook URL file; `.env` appended, not replaced) |
| Drills: restore, compromised intermediate (chapters 2, 7) | restore passed with a workaround; **compromise failed**: stopping the CA blocked the switch, and the text claimed that replacing the intermediate protects clients – it does not | both passed; 4 places still needed a guess | both passed; 3 commands failed as written (manifest kept apart but not put back before a restore; the second root's directory; `install` without `sudo`), 5 unclear | both passed, no command failed; 2 guesses (reading the issuer inside "Try it"; two fingerprints for a script with two roots), 1 wrong reference (the rotation line is in step 3's output, not the backup's), 4 unclear | **both passed, no blocker, no guess**; 3 unclear (wording of the manifest step, the stop time of a backup, that step 5 does not publish) |

What the walkthroughs changed, beyond wording:

- **The setup:** the CA got a network alias for its name inside the
  constraints (`SICK_CA_ALIAS`); the shipped device list starts empty; a
  first device that runs beside the Docker setup (`contrib/devices/files-nginx`);
  lab overrides for the ACME recipes; switching, retiring and rotating on a
  stopped CA; the ceremony names the variable the user sets; an alert for
  devices SICK cannot check (`SickDeviceError`); `sick-notify --help`.
- **Chapter 7:** the compromise procedure was wrong in substance and is
  rewritten – the old intermediate stays valid and an attacker sends it
  along, so only a root replacement cuts a stolen intermediate key off for
  clients. The second drill showed it working: after the root replacement, a
  client with only the new root refused a certificate signed with the old
  intermediate key, with the old intermediate sent along.
- **Round 5** ran every section without a blocker and without a guess;
  its remaining unclear points are fixed in the text – the largest a
  separate transfer medium, so that the media with the root key never go
  into the CA host.
- **Round 4** found no blocker in any section. Its findings are fixed in
  the text: the order of the rotation check, two copies of the manifest and
  putting one back, `COMPOSE_FILE` in `.env` after a root replacement, the
  phase-A trust scripts kept for phase C, both fingerprints for a script
  with two roots, the cron line's `PATH`, the first device started before
  the `sick` service.
- **Commands with their output** where a step had none: the ceremony with
  image build and password medium, the public-key comparison, `.env`,
  "Try it", backup paths and the drill, renewing and switching, the root
  replacement phase by phase, the client check, the first device, the Docker
  cron line.

## Transcripts

The chapters show the commands with the output the walkthroughs got; the
fingerprints differ every time. Two short ones that show the whole path:

**The CA from zero (chapter 2):**

```text
$ docker compose build sick
$ docker run --rm --network none … sick:local /ceremony.sh --operator 'A. Operator' --out /work/for-the-ca \
    --root-key /work/root/root_ca_key --root-password-file /pw/root.pw \
    --root-name 'Example Root CA' --intermediate-name 'Example Intermediate CA' \
    --dns example.internal --ip 192.0.2.0/24
ceremony: making the root 'Example Root CA' (EC P-256, 175320h)
ceremony: making the intermediate 'Example Intermediate CA' (EC P-256, 43830h)
ceremony: root fingerprint (SHA-256): f8209eec…
ceremony: for the CA (SICK_CA_IMPORT): /work/for-the-ca - the record is /work/for-the-ca/ceremony.txt
$ docker compose -f compose.yml -f compose.import.yml up -d
$ docker compose logs ca | grep init-ca
init-ca: import mode: no CA in /home/step yet: building it on the hierarchy in /home/step/import (no root key)
init-ca: configuration updated: 'sick' grants up to 19800h, serverAuth only, names allowed: *.example.internal, 192.0.2.0/24; …
init-ca: root fingerprint (SHA-256): f8209eec…
```

**The first device and a client (chapters 3, 5):**

```text
$ docker compose -f compose.yml -f ../contrib/devices/files-nginx/compose.yml up -d web
$ docker compose run --rm sick sick check web
DEVICE  STATUS   RENEW  DETAIL
web     missing  yes    the device presents no certificate
$ docker compose run --rm sick sick run web
DEVICE  ACTION   REASON   ERROR
web     renewed  missing
$ docker compose run --rm sick sick check web
DEVICE  STATUS  RENEW  DETAIL
web     ok      no     valid until 2027-11-12 08:53:46 UTC, 396 days left
# a Debian client:
$ sh trust-linux.sh install --fingerprint f8209eec…
installed: /usr/local/share/ca-certificates/sick-root-f8209eec89cedea4.crt
$ curl --cacert root_ca.pem --resolve web.example.internal:8443:127.0.0.1 https://web.example.internal:8443/
hello from web
```
