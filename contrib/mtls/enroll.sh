#!/bin/bash
#
# Enrol one holder of a client certificate: a person or a machine. Run by
# the admin who holds the password of the provisioner "clients"; the output
# directory is handed to the holder and then removed here. See README.md.
#
#   enroll.sh person  person@example.internal            OUTDIR
#   enroll.sh machine backup1.machines.example.internal  OUTDIR
#
# Writes into OUTDIR (made with mode 0700; it must not exist yet):
#
#   <identity>.crt     certificate and intermediate (step's bundle)
#   <identity>.key     its private key, new for this holder, mode 0600
#   person only:
#   <identity>.p12     key, certificate and intermediate as PKCS#12, for a
#                      browser or the store of an operating system
#   <identity>.p12.pw  its password, unless P12_PASSWORD_FILE names one:
#                      hand it over on another channel than the .p12
#
# The certificate is checked before anything is written further: subject
# CN = the identity, the identity the only SAN, clientAuth the only
# extended key usage.
#
# From the environment:
#
#   CLIENTS_PASSWORD_FILE  password of the provisioner "clients" (required)
#   STEP_CA_URL            https://ca.example.internal:9000
#   STEP_ROOT              root certificate of the CA        (root_ca.crt)
#   LIFETIME               of the certificate, a Go duration        (720h)
#   P12_PASSWORD_FILE      password for the .p12 (person); generated when
#                          unset
#
# Requires step and openssl. No password and no key ever reaches a command
# line: step and openssl get paths.

set -euo pipefail

die() { printf 'enroll.sh: %s\n' "$*" >&2; exit 1; }

[ $# -eq 3 ] || die 'usage: enroll.sh person|machine IDENTITY OUTDIR'
kind=$1 id=$2 out=$3
ca_url=${STEP_CA_URL:-https://ca.example.internal:9000}
root=${STEP_ROOT:-root_ca.crt}
lifetime=${LIFETIME:-720h}
pwfile=${CLIENTS_PASSWORD_FILE:-}

case $kind in
  person)
    # a mailbox: the CN and the email SAN
    [[ $id =~ ^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$ ]] \
      || die "'$id' is not a lower-case email address"
    ;;
  machine)
    # a host name with at least three labels, inside the DNS names of the
    # CA: Java and the CA's policy judge the CN as a DNS name
    [[ $id =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){2,}$ ]] \
      || die "'$id' is not a lower-case host name with at least three labels"
    ;;
  *) die "'$kind' is neither person nor machine" ;;
esac
[ -n "$pwfile" ] || die 'CLIENTS_PASSWORD_FILE names the password file of the provisioner "clients"'
[ -r "$pwfile" ] || die "cannot read $pwfile"
[ -r "$root" ] || die "cannot read the root certificate $root (STEP_ROOT)"
[ ! -e "$out" ] || die "$out exists: an enrolment writes a new directory"
for program in step openssl; do
  command -v "$program" >/dev/null || die "$program is not installed"
done

umask 077
mkdir -p "$(dirname "$out")"
mkdir -m 700 "$out"
crt=$out/$id.crt key=$out/$id.key

# step keeps nothing of this in a home directory
STEPPATH=$(mktemp -d)
export STEPPATH
trap 'rm -rf "$STEPPATH"' EXIT

step ca certificate "$id" "$crt" "$key" --san "$id" \
  --provisioner clients --provisioner-password-file "$pwfile" \
  --not-after "$lifetime" --ca-url "$ca_url" --root "$root" >/dev/null 2>"$STEPPATH/err" \
  || { cat "$STEPPATH/err" >&2; rm -rf "$out"; die "the CA did not issue a certificate for $id"; }

subject=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253)
san=$(openssl x509 -in "$crt" -noout -ext subjectAltName | sed 1d | tr -d ' ')
eku=$(openssl x509 -in "$crt" -noout -ext extendedKeyUsage | sed 1d | tr -d ' ')
if [ "$kind" = person ]; then want_san=email:$id; else want_san=DNS:$id; fi
problem=
[ "$subject" = "subject=CN=$id" ] || problem="subject is '$subject'"
[ "$san" = "$want_san" ] || problem="${problem:+$problem, }SAN is '$san'"
[ "$eku" = TLSWebClientAuthentication ] || problem="${problem:+$problem, }extended key usage is '$eku'"
[ -z "$problem" ] || { rm -rf "$out"; die "the certificate for $id is not a client certificate of this recipe: $problem"; }

if [ "$kind" = person ]; then
  p12pw=${P12_PASSWORD_FILE:-$out/$id.p12.pw}
  if [ -z "${P12_PASSWORD_FILE:-}" ]; then
    openssl rand -base64 24 | tr -d '\n' >"$p12pw"
  fi
  # the intermediate comes along from the bundle in $crt
  step certificate p12 "$out/$id.p12" "$crt" "$key" \
    --password-file "$p12pw" --force >/dev/null 2>"$STEPPATH/err" \
    || { cat "$STEPPATH/err" >&2; rm -rf "$out"; die "step certificate p12 failed"; }
fi

printf '%s: %s, %s, until %s\n' "$id" "$subject" "$san" \
  "$(openssl x509 -in "$crt" -noout -enddate | sed 's/^notAfter=//')"
printf 'serial %s, SHA-256 %s\n' "$(openssl x509 -in "$crt" -noout -serial | sed 's/^serial=//')" \
  "$(openssl x509 -in "$crt" -noout -fingerprint -sha256 | sed 's/^.*=//')"
