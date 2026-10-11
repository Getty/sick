# To try at HQ

Everything in this handbook that could not be walked through in the
container lab, in one place: what to do, and what counts as passed. Each
entry names the chapter it belongs to. When an entry passes, mark it here
and remove the *not tried* in the chapter; when it fails, it becomes a card.

Before you start: a CA from the ceremony (chapter 2), its root fingerprint
on paper, the trust page and its scripts (chapter 3), and SICK running on a
host from which the devices are reachable.

## Chapter 2 – the CA

- [ ] **Root key on a YubiKey or HSM.** Make a root with `step certificate
      create --profile root-ca --kms … --key …` on the token, sign an
      intermediate with it. *Passed:* the intermediate verifies against the
      root; a second token or an encrypted backup restores the ability to
      sign.
- [ ] **Restore on another host.** `ca-backup.sh restore` of a real backup
      onto a second machine, started isolated. *Passed:* it issues under the
      same root, the database holds a certificate issued before the backup;
      the original stays the only CA serving.
- [ ] **Planned rollback of a root replacement.** Phase B, then start
      without `compose.ca-next.yml`. *Passed:* the old CA serves again,
      `sick run --force` re-issues under the old root, clients that still
      have both roots connect.

## Chapter 3 – clients

- [ ] **Windows 11**: `trust-windows.ps1 install --fingerprint …` and
      `remove`, in Windows PowerShell 5.1 and PowerShell 7. *Passed:* Edge
      and Chrome accept a SICK device after install and refuse it after
      remove; the intermediate is in *Intermediate Certification
      Authorities*, not in the root store.
- [ ] **Windows, Firefox** picks up the root from the Windows store
      (Firefox 120+). *Passed:* a SICK device opens without importing into
      Firefox.
- [ ] **macOS**: `trust-macos.sh install`/`remove`; the profile. *Passed:*
      Safari and Chrome accept and, after removal, refuse; running install
      twice does not fail (a root already in the keychain).
- [ ] **iPhone/iPad**: the profile, "Not Verified", full trust under
      *Certificate Trust Settings*. *Passed:* Safari opens a SICK device;
      a leaf-only switch opens through the profile's intermediate.
- [ ] **Android**: the root as a user CA. *Passed:* Chrome accepts a SICK
      device that sends its chain; an app without opt-in refuses it; a
      leaf-only switch is refused (expected).
- [ ] **Chrome on Linux** with `trust-nss.sh install … sql:$HOME/.pki/nssdb`.
      *Passed:* Chrome accepts after a restart, refuses after remove.
- [ ] **Decide: sign the Apple profile?** Needs a signing key and
      certificate. *Passed:* a decision, and if yes, iOS shows "Verified".
- [ ] **Docker daemon registry trust** through
      `/etc/docker/certs.d/<registry>/ca.crt`. *Passed:* `docker pull` from
      a registry with a SICK certificate works without restarting the
      daemon (or the need for a restart is recorded).

## Chapter 4 – services

- [ ] **Proxmox VE, native ACME**: the recipe in chapter 4 on one node.
      *Passed:* `pvenode acme cert order` gets a certificate from the CA,
      pveproxy presents it on 8006, and the daily `pveupdate` renews it
      (note how often, card k57).
- [ ] **Proxmox Backup Server, native ACME** likewise on 8007.
- [ ] **External account binding** (card k51), if the maintainer decides
      for it. *Passed:* an ACME client without an EAB key is refused, one
      with a key gets its certificate.

## Chapter 5 – devices

- [ ] **MikroTik RouterOS, a physical router** (RouterOS 7): the recipe in
      `contrib/devices/routeros/`. *Passed:* `sick run` renews, www-ssl on
      443 presents the issued certificate, a second run changes nothing;
      also with a chain (intermediate) and, if wanted, an EC key.
- [ ] **Proxmox VE and Proxmox Backup Server with `proxmox-ve` /
      `proxmox-bs`** on real nodes under systemd, a PVE cluster and a node
      over a real network: the checklist of SICK-Target-Proxmox,
      [`docs/hq-checklist.md`](https://github.com/Getty/sick-target-proxmox/blob/main/docs/hq-checklist.md)
      in that repository (`../sick-target-proxmox/docs/hq-checklist.md` in a
      checkout), with the pass criteria for each step – token and rights,
      first upload by cluster CA and by pin, restart time, second run, wrong
      anchor, cluster, the way back. **It replaces a real node's certificate
      and restarts its proxy.**
- [ ] **A Linux host outside Docker** with the `ssh` recipe (sudo rule or
      forced command). *Passed:* as in the container test.
- [ ] **Dell iDRAC 7 and 8**: settle the open questions of card k18 (which
      firmware imports certificates over Redfish, whether the CSR carries
      SANs, chain upload, reset time, minimum privilege) before
      SICK-Target-IDRAC is built.

## Chapter 6 – operations

- [ ] **systemd** really running `sick.timer` and `sick.service` on a host
      for a week. *Passed:* one run a day at a fixed time, the Prometheus
      file and trust page written after each, a forced failure (a device
      with a wrong reload) sends one notification.
- [ ] **A real mail server** behind `sick-notify` (`mail_to`). *Passed:*
      the mail arrives with the failed device in it.
- [ ] **Prometheus and Alertmanager** scraping the textfile with the rules
      of `contrib/prometheus/`. *Passed:* `SickCAUnreachable` fires when
      the CA is stopped for half an hour and resolves when it is back.

## Chapter 8 – client certificates

- [ ] **Firefox and Chrome** with a person's PKCS#12 imported (Firefox:
      *Your Certificates → Import*; Chrome: the OS store). *Passed:* the
      browser offers the certificate, the mTLS service answers 200 with the
      principal; without it 400; a not-allowed identity 403.
- [ ] **Windows and macOS stores**: import the PKCS#12 (double-click, or
      `security import`). *Passed:* Edge/Safari present it and get in.
- [ ] **iOS and Android**: install the PKCS#12. *Passed:* Safari / Chrome
      present it and get in.
- [ ] **Loss drill**: revoke a person's serial and block it in
      `revoked-serials.map`. *Passed:* 403 at once; `step ca renew` refused;
      the CA log names any later serial.
- [ ] **Decide: OIDC enrolment** for people instead of admin-issued
      PKCS#12 (not tried).

