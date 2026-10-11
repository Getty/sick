# A group and a user for SICK on a MikroTik router (RouterOS 7).
# Paste into the terminal of an administrator, or /import the file.
# The same group, user, key and service settings were made on RouterOS CHR
# 7.24.5 by t/e2e/device-routeros.sh (through the REST API); this file as
# such was not imported there.
#
# Before: copy the public half of SICK's deploy key to the router as
# sick.pub (Winbox Files, or: scp sick.pub admin@router.example.internal:).
# The private half stays with SICK, in a file.
#
# The four policies are the least the acme.sh hook "routeros" works with:
#   ssh    log in with the deploy key
#   ftp    put files on the router - also over scp/sftp, which the hook uses
#   read   without it RouterOS interrupts the hook's /system script add
#   write  add and run the script, import the certificate, set the services
# Each of ssh,ftp,write / ssh,write / ssh,ftp,read was tried and fails.
# Not needed: sensitive, policy, password, reboot, api, rest-api, winbox, web.
# The names with "!" spell out the rest, so that "set" cannot leave one on.

/user group add name=sick comment="SICK deploys certificates" \
    policy=ssh,ftp,read,write,!local,!telnet,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api

# The password is never used (keys only; RouterOS refuses password login
# for a user with a key by default, password-authentication=yes-if-no-key).
# Give it a long random one anyway.
/user add name=sick group=sick comment="SICK deploys certificates" \
    password=REPLACE-WITH-A-LONG-RANDOM-STRING

/user ssh-keys import user=sick public-key-file=sick.pub
# (or, without the file: /user ssh-keys add user=sick key="ssh-ed25519 AAAA..." -
#  that is how the e2e test did it; ed25519 keys work on 7.24.5)

# Optional, and recommended: only from the host SICK runs on.
# /user set sick address=192.0.2.10/32

# The service SICK checks. The hook sets its certificate but does not
# enable it.
/ip service set www-ssl disabled=no

# The host key, for SICK's known_hosts - read it here, not over the network:
#   /ip ssh export-host-key key-file-prefix=hostkey
# then fetch hostkey_rsa_pub.pem, remove both hostkey_* files from /file at
# once (the export writes the private half too), and on the SICK host:
#   ssh-keygen -i -m PKCS8 -f hostkey_rsa_pub.pem
# gives the "ssh-rsa AAAA..." part of the known_hosts line.
