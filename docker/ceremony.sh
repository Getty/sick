#!/bin/bash
#
# The ceremony: makes the root and the intermediate certificate of a CA
# outside step-ca, so that the root key never lies where the CA runs.
#
# Run it on an offline machine, or in a container without network
# ("docker run --network none ..."), with step and openssl installed - the
# sick image has both. Nothing but those two and bash is used.
#
# What it makes:
#
#   the root           step certificate create --profile root-ca
#                      (EC P-256 or RSA 4096, 20 years by default)
#   the intermediate   signed by the root from an X.509 template: name
#                      constraints (critical) with the DNS domains and IP
#                      ranges given, CA with pathlen 0, key usage
#                      certSign and crlSign (5 years by default)
#
# and where it goes:
#
#   ROOT_KEY           the root key, encrypted with the password from
#                      ROOT_PASSWORD_FILE, at the place the operator names.
#                      Refused inside OUT: OUT goes to the CA.
#   OUT/root_ca.crt, OUT/intermediate_ca.crt
#   OUT/intermediate_ca_key   encrypted with the password in OUT/password
#   OUT/password       that password (from INTERMEDIATE_PASSWORD_FILE, or
#                      generated); step-ca starts with it
#   OUT/ceremony.txt   the ceremony record: who, when, tool versions, both
#                      fingerprints, and constraints, validity and key usage
#                      as openssl reads them back from the certificates. No
#                      secret; where the root key went is a path.
#
# OUT is what init-ca.sh imports (SICK_CA_IMPORT_DIR, see docker/README.md).
#
# Every read-back value is compared with what was asked for; a difference
# ends the ceremony with exit 1 and a message saying what differs.
#
# Options, each also from the environment (in brackets, with the default):
#
#   --operator NAME            who runs the ceremony     (SICK_CEREMONY_OPERATOR, required)
#   --out DIR                  output for the CA, new or empty  (SICK_CEREMONY_OUT, required)
#   --root-key FILE            destination of the root key, must not exist
#                                                        (SICK_CEREMONY_ROOT_KEY, required)
#   --root-password-file FILE  password for the root key (SICK_CEREMONY_ROOT_PASSWORD_FILE, required)
#   --intermediate-password-file FILE
#                              password for the intermediate key
#                                                        (SICK_CEREMONY_INTERMEDIATE_PASSWORD_FILE, generated)
#   --root-name NAME           (SICK_CEREMONY_ROOT_NAME, "SICK Root CA")
#   --intermediate-name NAME   (SICK_CEREMONY_INTERMEDIATE_NAME, "SICK Intermediate CA")
#   --dns DOMAIN[,DOMAIN]      permitted DNS domains, repeatable  (SICK_CEREMONY_DNS)
#   --ip CIDR[,CIDR]           permitted IP ranges, repeatable    (SICK_CEREMONY_IP)
#   --email DOMAIN[,DOMAIN]    permitted email domains (rfc822Name), repeatable:
#                              example.internal (that host), .example.internal
#                              (hosts below it) or person@example.internal
#                                                        (SICK_CEREMONY_EMAIL)
#   --uri DOMAIN[,DOMAIN]      permitted URI hosts, repeatable: example.internal
#                              or .example.internal       (SICK_CEREMONY_URI)
#   --exclude-all-ip           no IP address at all: excludes 0.0.0.0/0 and ::/0
#                                                        (SICK_CEREMONY_EXCLUDE_ALL_IP=yes)
#   --kty EC|RSA               key type of both keys     (SICK_CEREMONY_KTY, EC)
#   --size BITS                RSA key size              (SICK_CEREMONY_SIZE, 4096)
#   --root-lifetime DURATION   Go duration               (SICK_CEREMONY_ROOT_LIFETIME, 175320h = 20 years)
#   --intermediate-lifetime DURATION                     (SICK_CEREMONY_INTERMEDIATE_LIFETIME, 43830h = 5 years)
#
# At least one --dns or --ip is required. Per RFC 5280 a name form without
# constraints is not constrained: DNS domains without --ip leave every IP
# address open, so the ceremony warns, unless --exclude-all-ip says that no
# certificate under this intermediate carries an address. The same holds for
# email addresses and URIs: without --email and --uri, client certificates
# under this intermediate may carry any of them (docs/findings/client-san.md).
# With --uri, a URI without a host (urn:...) is refused by every validator.
#
# Renewing the intermediate under the existing root (--renew-intermediate):
#
#   ceremony.sh --renew-intermediate --operator NAME --out DIR \
#     --root-cert root_ca.crt --root-key FILE --root-password-file FILE \
#     --intermediate intermediate_ca.crt
#
# makes a new intermediate with a NEW key under the root that is there
# already; no new root. The root key is read where it lies, never copied.
# What is not given is taken from the current intermediate (--intermediate),
# read back with openssl: the name constraints (permitted and excluded DNS
# domains, IP ranges, email domains and URI hosts; any other kind of
# constraint ends the ceremony - give the constraints as options then) and
# the key type. The name defaults
# to that of the current intermediate with today's date in place of a date
# at its end: two intermediates with one name and two keys leave the chain
# to key identifiers. The new intermediate has to end before the root.
# OUT gets the same set as above (root_ca.crt being a copy of --root-cert),
# and the record says it is a renewal and which intermediate it follows.
# OUT goes to the running CA with init-ca.sh --switch-intermediate.
#
#   --renew-intermediate       the renewal mode     (SICK_CEREMONY_RENEW_INTERMEDIATE=yes)
#   --root-cert FILE           the existing root certificate (SICK_CEREMONY_ROOT_CERT)
#   --root-key FILE            its key, which has to exist here
#   --intermediate FILE        the current intermediate     (SICK_CEREMONY_INTERMEDIATE)

set -euo pipefail
umask 077

log() { printf 'ceremony: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

operator=${SICK_CEREMONY_OPERATOR:-}
out=${SICK_CEREMONY_OUT:-}
root_key=${SICK_CEREMONY_ROOT_KEY:-}
root_pw=${SICK_CEREMONY_ROOT_PASSWORD_FILE:-}
int_pw=${SICK_CEREMONY_INTERMEDIATE_PASSWORD_FILE:-}
root_name=${SICK_CEREMONY_ROOT_NAME:-SICK Root CA}
int_name=${SICK_CEREMONY_INTERMEDIATE_NAME:-SICK Intermediate CA}
dns_list=${SICK_CEREMONY_DNS:-}
ip_list=${SICK_CEREMONY_IP:-}
email_list=${SICK_CEREMONY_EMAIL:-}
uri_list=${SICK_CEREMONY_URI:-}
exclude_all_ip=${SICK_CEREMONY_EXCLUDE_ALL_IP:-no}
kty=${SICK_CEREMONY_KTY:-EC}
size=${SICK_CEREMONY_SIZE:-4096}
root_lifetime=${SICK_CEREMONY_ROOT_LIFETIME:-175320h}
int_lifetime=${SICK_CEREMONY_INTERMEDIATE_LIFETIME:-43830h}
renew=${SICK_CEREMONY_RENEW_INTERMEDIATE:-no}
root_cert=${SICK_CEREMONY_ROOT_CERT:-}
current=${SICK_CEREMONY_INTERMEDIATE:-}
# what the renewal takes from the current intermediate unless it is given
int_name_given=${SICK_CEREMONY_INTERMEDIATE_NAME:+yes}
kty_given=${SICK_CEREMONY_KTY:+yes}
[ -z "${SICK_CEREMONY_SIZE:-}" ] || kty_given=yes

while [ $# -gt 0 ]; do
  case $1 in
    --exclude-all-ip) exclude_all_ip=yes; shift; continue ;;
    --renew-intermediate) renew=yes; shift; continue ;;
    -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    --operator|--out|--root-key|--root-password-file|--intermediate-password-file|--root-name|\
    --intermediate-name|--dns|--ip|--email|--uri|--kty|--size|--root-lifetime|--intermediate-lifetime|--root-cert|--intermediate)
      [ $# -ge 2 ] || die "$1 needs a value" ;;
    *) die "unknown argument '$1' (--help)" ;;
  esac
  case $1 in
    --operator) operator=$2 ;;
    --out) out=$2 ;;
    --root-key) root_key=$2 ;;
    --root-password-file) root_pw=$2 ;;
    --intermediate-password-file) int_pw=$2 ;;
    --root-name) root_name=$2 ;;
    --intermediate-name) int_name=$2; int_name_given=yes ;;
    --dns) dns_list=${dns_list:+$dns_list,}$2 ;;
    --ip) ip_list=${ip_list:+$ip_list,}$2 ;;
    --email) email_list=${email_list:+$email_list,}$2 ;;
    --uri) uri_list=${uri_list:+$uri_list,}$2 ;;
    --kty) kty=$2; kty_given=yes ;;
    --size) size=$2; kty_given=yes ;;
    --root-cert) root_cert=$2 ;;
    --intermediate) current=$2 ;;
    --root-lifetime) root_lifetime=$2 ;;
    --intermediate-lifetime) int_lifetime=$2 ;;
  esac
  shift 2
done

#### helpers: what openssl reads back

# 192.0.2.0/24 -> 192.0.2.0/255.255.255.0, 2001:db8::/32 -> openssl's
# 2001:DB8:0:0:0:0:0:0/FFFF:FFFF:0:0:0:0:0:0
openssl_ip() {
  local addr=${1%/*} bits=${1#*/}
  if [[ $addr == *:* ]]; then
    local head tail g groups=() missing i n mask=()
    if [[ $addr == *::* ]]; then head=${addr%%::*} tail=${addr#*::}; else head=$addr tail=; fi
    local -a h=() t=()
    [ -z "$head" ] || IFS=: read -ra h <<<"$head"
    [ -z "$tail" ] || IFS=: read -ra t <<<"$tail"
    missing=$((8 - ${#h[@]} - ${#t[@]}))
    [[ $addr == *::* ]] || missing=0
    groups=("${h[@]}")
    for ((i = 0; i < missing; i++)); do groups+=(0); done
    groups+=("${t[@]}")
    [ ${#groups[@]} -eq 8 ] || return 1
    for i in "${!groups[@]}"; do g=${groups[$i]}; groups[$i]=$(printf '%X' "$((16#${g:-0}))"); done
    for ((i = 0; i < 8; i++)); do
      n=$((bits - 16 * i)); [ $n -gt 16 ] && n=16; [ $n -lt 0 ] && n=0
      mask+=("$(printf '%X' $(( (0xFFFF << (16 - n)) & 0xFFFF )))")
    done
    (IFS=:; printf 'IP:%s/%s\n' "${groups[*]}" "${mask[*]}")
  else
    local m=() i n
    for ((i = 0; i < 4; i++)); do
      n=$((bits - 8 * i)); [ $n -gt 8 ] && n=8; [ $n -lt 0 ] && n=0
      m+=($(( (0xFF << (8 - n)) & 0xFF )))
    done
    (IFS=.; printf 'IP:%s/%s\n' "$addr" "${m[*]}")
  fi
}

# the other way: openssl's 192.0.2.0/255.255.255.0 -> 192.0.2.0/24,
# 2001:DB8:0:0:0:0:0:0/FFFF:FFFF:0:0:0:0:0:0 -> 2001:DB8:0:0:0:0:0:0/32
cidr_of() {
  local addr=${1%/*} mask=${1#*/} bits=0 part n base sep
  local -a parts
  if [[ $mask == *:* ]]; then base=16 sep=:; else base=10 sep=.; fi
  IFS=$sep read -ra parts <<<"$mask"
  for part in "${parts[@]}"; do
    n=$(( $base#$part ))
    while [ "$n" -gt 0 ]; do bits=$((bits + (n & 1))); n=$((n >> 1)); done
  done
  printf '%s/%s\n' "$addr" "$bits"
}

# the lines of one extension below its heading, and the heading itself
extension() { # <text> <name>
  awk -v name="$2" '
    index($0, name ":") && /^ {12}X509v3 / { on = 1; sub(/^ +/, ""); sub(/ +$/, ""); print; next }
    on && /^ {0,12}[^ ]/ { exit }
    on { sub(/^ +/, ""); print }
  ' <<<"$1"
}

subject_of() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'; }
epoch() { date -u -d "$1" +%s; }
dates() { openssl x509 -in "$1" -noout -startdate -enddate -dateopt iso_8601 | sed 's/^[a-zA-Z]*=//'; }
key_algorithm() { openssl x509 -in "$1" -noout -text | sed -n 's/^ *Public Key Algorithm: //p; s/^ *Public-Key: /  /p; s/^ *NIST CURVE: /  /p' | tr -d '\n' | tr -s ' '; }

#### checking what was asked for, before anything is made

for program in step openssl; do
  command -v "$program" >/dev/null || die "$program is not installed"
done

[ "$renew" = yes ] || [ "$renew" = no ] || die 'SICK_CEREMONY_RENEW_INTERMEDIATE is yes or no'
[ "$exclude_all_ip" = yes ] || [ "$exclude_all_ip" = no ] || die 'SICK_CEREMONY_EXCLUDE_ALL_IP is yes or no'
[ -n "$operator" ] || die '--operator is required: the record says who ran the ceremony'
[[ $operator != *$'\n'* ]] || die '--operator is one line'
[ -n "$out" ] || die '--out is required'
if [ "$renew" = yes ]; then
  [ -n "$root_key" ] || die '--root-key is required: the key of the root, to sign the new intermediate'
else
  [ -n "$root_key" ] || die '--root-key is required: where the root key goes'
fi
[ -n "$root_pw" ] || die '--root-password-file is required'
[ -s "$root_pw" ] || die "$root_pw: no password in it, or not readable"
[ -z "$int_pw" ] || [ -s "$int_pw" ] || die "$int_pw: no password in it, or not readable"

# a Go duration of hours, minutes and seconds, in seconds
seconds_of() {
  local rest=$1 total=0 n unit
  [[ $rest =~ ^([0-9]+[hms])+$ ]] || return 1
  while [[ $rest =~ ^([0-9]+)([hms])(.*)$ ]]; do
    n=$((10#${BASH_REMATCH[1]})) unit=${BASH_REMATCH[2]} rest=${BASH_REMATCH[3]}
    case $unit in h) total=$((total + n * 3600)) ;; m) total=$((total + n * 60)) ;; s) total=$((total + n)) ;; esac
  done
  printf '%s\n' "$total"
}
int_seconds=$(seconds_of "$int_lifetime") || die "--intermediate-lifetime $int_lifetime is not a duration like 43830h"

copied=no
current_nc=
dns=() ips=() x_dns=() x_ips=() emails=() uris=() x_emails=() x_uris=()

if [ "$renew" = no ]; then
  [ -z "$root_cert" ] && [ -z "$current" ] || die '--root-cert and --intermediate belong to --renew-intermediate'
  root_seconds=$(seconds_of "$root_lifetime") || die "--root-lifetime $root_lifetime is not a duration like 175320h"
  [ "$int_seconds" -lt "$root_seconds" ] || die 'the intermediate has to expire before the root'
  root_dn="CN=$root_name"
else
  [ -n "$root_cert" ] || die '--root-cert is required with --renew-intermediate: the root the new intermediate goes under'
  [ -n "$current" ] || die '--intermediate is required with --renew-intermediate: the intermediate that is renewed'
  for file in "$root_cert" "$current"; do
    openssl x509 -in "$file" -noout 2>/dev/null || die "$file: not a readable certificate"
  done
  [ -s "$root_key" ] || die "$root_key: no root key there, or not readable"
  openssl verify -no-CApath -no-CAstore -CAfile "$root_cert" "$root_cert" >/dev/null 2>&1 \
    || die "$root_cert is no self-signed root certificate"
  openssl verify -no-CApath -no-CAstore -CAfile "$root_cert" "$current" >/dev/null 2>&1 \
    || die "$current does not verify against $root_cert: renew an intermediate under the root it belongs to"
  key_pub=$(openssl pkey -in "$root_key" -passin "file:$root_pw" -pubout 2>/dev/null) \
    || die "cannot open $root_key with the password in $root_pw"
  [ "$key_pub" = "$(openssl x509 -in "$root_cert" -noout -pubkey)" ] || die "$root_key is not the key of $root_cert"
  unset key_pub
  root_dn=$(subject_of "$root_cert")
  current_text=$(openssl x509 -in "$current" -noout -text)

  if [ "$kty_given" != yes ]; then
    case $(key_algorithm "$current") in
      *id-ecPublicKey*P-256*) kty=EC ;;
      *rsaEncryption*) kty=RSA; size=$(sed -n 's/^ *Public-Key: (\([0-9]*\) bit).*/\1/p' <<<"$current_text" | head -n 1) ;;
      *) die "the key of $current is neither EC P-256 nor RSA: give --kty" ;;
    esac
  fi
  if [ "$int_name_given" != yes ]; then
    cn=$(openssl x509 -in "$current" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')
    [ -n "$cn" ] || die "$current has no common name: give --intermediate-name"
    int_name="$(sed -E 's/ [0-9]{4}-[0-9]{2}-[0-9]{2}$//' <<<"$cn") $(date -u +%F)"
  fi
  [ "$int_name" != "$(openssl x509 -in "$current" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')" ] \
    || log "WARNING: the new intermediate gets the name of the current one; clients tell the two apart by key identifiers only"

  if [ -z "$dns_list$ip_list$email_list$uri_list" ] && [ "$exclude_all_ip" = no ]; then
    copied=yes
    current_nc=$(extension "$current_text" 'Name Constraints')
    [ -n "$current_nc" ] || die "$current has no name constraints to copy: give --dns and/or --ip"
    section=
    while IFS= read -r line; do
      case $line in
        'X509v3 Name Constraints'*) ;;
        Permitted:) section=permitted ;;
        Excluded:) section=excluded ;;
        DNS:*) if [ "$section" = permitted ]; then dns+=("${line#DNS:}"); else x_dns+=("${line#DNS:}"); fi ;;
        IP:*) if [ "$section" = permitted ]; then ips+=("$(cidr_of "${line#IP:}")"); else x_ips+=("$(cidr_of "${line#IP:}")"); fi ;;
        email:*) if [ "$section" = permitted ]; then emails+=("${line#email:}"); else x_emails+=("${line#email:}"); fi ;;
        URI:*) if [ "$section" = permitted ]; then uris+=("${line#URI:}"); else x_uris+=("${line#URI:}"); fi ;;
        *) die "cannot copy the constraint '$line' of $current: give the constraints with --dns, --ip, --email, --uri, --exclude-all-ip" ;;
      esac
    done <<<"$current_nc"
    # what --exclude-all-ip made, read back
    [ "${x_ips[*]}" != '0.0.0.0/0 0:0:0:0:0:0:0:0/0' ] || [ ${#ips[@]} -ne 0 ] || exclude_all_ip=yes
  fi

  now_s=$(date -u +%s)
  root_end=$(epoch "$(dates "$root_cert" | tail -n 1)")
  [ $((now_s + int_seconds)) -le "$root_end" ] \
    || die "an intermediate of $int_lifetime would outlive the root (valid until $(dates "$root_cert" | tail -n 1)): give --intermediate-lifetime $(( (root_end - now_s) / 3600 - 1 ))h or less"
fi

case $kty in
  EC|ec) kty=EC; key_args=(--kty EC --curve P-256); key_desc='EC P-256' ;;
  RSA|rsa)
    kty=RSA
    [[ $size =~ ^[0-9]+$ ]] && [ "$size" -ge 3072 ] || die "--size $size: RSA keys of a CA have 3072 bits or more"
    key_args=(--kty RSA --size "$size"); key_desc="RSA $size" ;;
  *) die "--kty $kty: EC or RSA" ;;
esac

# "a, b,,c" as one item per line
items() { tr ',' '\n' <<<"$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d'; }

if [ "$copied" = no ]; then
  mapfile -t dns < <(items "$dns_list")
  mapfile -t ips < <(items "$ip_list")
  mapfile -t emails < <(items "$email_list")
  mapfile -t uris < <(items "$uri_list")
  if [ "$exclude_all_ip" = yes ]; then
    [ ${#ips[@]} -eq 0 ] || die '--exclude-all-ip and --ip contradict each other'
    x_ips=(0.0.0.0/0 ::/0)
  fi
fi
label='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
for d in "${dns[@]}" "${x_dns[@]}"; do
  [[ $d =~ ^($label\.)*$label$ ]] || die "--dns $d is not a domain like example.internal"
done
for e in "${emails[@]}" "${x_emails[@]}"; do
  [[ $e =~ ^([^@[:space:]]+@)?\.?($label\.)*$label$ ]] \
    || die "--email $e is not a domain like example.internal or .example.internal, nor an address like person@example.internal"
done
for u in "${uris[@]}" "${x_uris[@]}"; do
  [[ $u =~ ^\.?($label\.)*$label$ ]] || die "--uri $u is not a host like example.internal or .example.internal"
done
for i in "${ips[@]}" "${x_ips[@]}"; do
  [[ $i =~ ^[0-9.]+/[0-9]+$ || $i =~ ^[0-9A-Fa-f:]+/[0-9]+$ ]] || die "--ip $i is not a network like 192.0.2.0/24"
done
[ ${#dns[@]} -gt 0 ] || [ ${#ips[@]} -gt 0 ] \
  || die 'no name constraints asked for: give --dns and/or --ip (an unconstrained intermediate is what this ceremony is there to avoid)'
if [ ${#dns[@]} -gt 0 ] && [ ${#ips[@]} -eq 0 ] && [ ${#x_ips[@]} -eq 0 ]; then
  log 'WARNING: DNS constraints without IP constraints - IP addresses stay unconstrained (RFC 5280).'
  log 'WARNING: give --ip for the networks, or --exclude-all-ip if no certificate may carry an address.'
fi
if [ ${#ips[@]} -gt 0 ] && [ ${#dns[@]} -eq 0 ] && [ ${#x_dns[@]} -eq 0 ]; then
  log 'WARNING: IP constraints without DNS constraints - DNS names stay unconstrained (RFC 5280).'
fi

# The places. The root key must not end up in what goes to the CA.
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
if [ "$renew" = no ]; then
  [ ! -e "$root_key" ] || die "$root_key exists: the ceremony does not overwrite a key"
fi
root_key_dir=$(dirname "$root_key")
[ -d "$root_key_dir" ] || die "$root_key_dir does not exist: make the place for the root key first"
root_key_dir=$(cd "$root_key_dir" && pwd -P)
case $root_key_dir/ in
  "$out"/*) die "$root_key lies inside $out, which goes to the CA: the root key goes somewhere else" ;;
esac
root_key=$root_key_dir/$(basename "$root_key")
[ -z "$(ls -A "$out")" ] || die "$out is not empty: the ceremony writes into a new or empty directory"

#### making the hierarchy

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# step looks for its defaults in $STEPPATH; none of them shall apply here
export STEPPATH=$work/step

if [ -n "$int_pw" ]; then
  cp "$int_pw" "$out/password"
else
  password=$(set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)
  [ "${#password}" -eq 40 ] || die 'cannot generate a password'
  printf '%s\n' "$password" >"$out/password"
  unset password
fi
chmod 600 "$out/password"

json_strings() { local s='' x; for x in "$@"; do s+="${s:+, }\"$x\""; done; printf '[%s]' "$s"; }
constraints='"critical": true'
[ ${#dns[@]} -eq 0 ] || constraints+=", \"permittedDNSDomains\": $(json_strings "${dns[@]}")"
[ ${#ips[@]} -eq 0 ] || constraints+=", \"permittedIPRanges\": $(json_strings "${ips[@]}")"
[ ${#x_dns[@]} -eq 0 ] || constraints+=", \"excludedDNSDomains\": $(json_strings "${x_dns[@]}")"
[ ${#x_ips[@]} -eq 0 ] || constraints+=", \"excludedIPRanges\": $(json_strings "${x_ips[@]}")"
[ ${#emails[@]} -eq 0 ] || constraints+=", \"permittedEmailAddresses\": $(json_strings "${emails[@]}")"
[ ${#uris[@]} -eq 0 ] || constraints+=", \"permittedURIDomains\": $(json_strings "${uris[@]}")"
[ ${#x_emails[@]} -eq 0 ] || constraints+=", \"excludedEmailAddresses\": $(json_strings "${x_emails[@]}")"
[ ${#x_uris[@]} -eq 0 ] || constraints+=", \"excludedURIDomains\": $(json_strings "${x_uris[@]}")"
cat >"$work/intermediate.tpl" <<EOF
{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["certSign", "crlSign"],
  "basicConstraints": { "isCA": true, "maxPathLen": 0 },
  "nameConstraints": { $constraints }
}
EOF

if [ "$renew" = no ]; then
  log "making the root '$root_name' ($key_desc, $root_lifetime)"
  step certificate create --profile root-ca "${key_args[@]}" --not-after "$root_lifetime" \
    --password-file "$root_pw" "$root_name" "$out/root_ca.crt" "$root_key" >/dev/null 2>"$work/step.log" \
    || { cat "$work/step.log" >&2; die 'making the root failed'; }
else
  cp "$root_cert" "$out/root_ca.crt"
  log "renewal under the existing root '$root_dn'; its key is read at $root_key and not copied"
  [ "$copied" = no ] || log "name constraints, as openssl reads them in $current: $(tr '\n' ' ' <<<"$current_nc")"
fi

log "making the intermediate '$int_name' ($key_desc, $int_lifetime)"
step certificate create --template "$work/intermediate.tpl" "${key_args[@]}" --not-after "$int_lifetime" \
  --ca "$out/root_ca.crt" --ca-key "$root_key" --ca-password-file "$root_pw" \
  --password-file "$out/password" "$int_name" "$out/intermediate_ca.crt" "$out/intermediate_ca_key" \
  >/dev/null 2>"$work/step.log" \
  || { cat "$work/step.log" >&2; die 'making the intermediate failed'; }

#### reading back with openssl, and comparing

mismatch=0
compare() { # <what> <expected> <read back>
  if [ "$2" = "$3" ]; then return 0; fi
  log "MISMATCH in $1"
  log "  asked for: $(tr '\n' '|' <<<"$2")"
  log "  read back: $(tr '\n' '|' <<<"$3")"
  mismatch=1
}

root_text=$(openssl x509 -in "$out/root_ca.crt" -noout -text)
int_text=$(openssl x509 -in "$out/intermediate_ca.crt" -noout -text)

if [ "$renew" = no ]; then
  compare 'root key usage' $'X509v3 Key Usage: critical\nCertificate Sign, CRL Sign' "$(extension "$root_text" 'Key Usage')"
  compare 'root basic constraints' $'X509v3 Basic Constraints: critical\nCA:TRUE, pathlen:1' "$(extension "$root_text" 'Basic Constraints')"
  compare 'root name constraints (none)' '' "$(extension "$root_text" 'Name Constraints')"
fi
compare 'intermediate key usage' $'X509v3 Key Usage: critical\nCertificate Sign, CRL Sign' "$(extension "$int_text" 'Key Usage')"
compare 'intermediate basic constraints' $'X509v3 Basic Constraints: critical\nCA:TRUE, pathlen:0' "$(extension "$int_text" 'Basic Constraints')"

want_nc='X509v3 Name Constraints: critical'
# in the order step (Go's crypto/x509) writes them: DNS, IP, email, URI
if [ ${#dns[@]} -gt 0 ] || [ ${#ips[@]} -gt 0 ] || [ ${#emails[@]} -gt 0 ] || [ ${#uris[@]} -gt 0 ]; then
  want_nc+=$'\nPermitted:'
  for d in "${dns[@]}"; do want_nc+=$'\n'"DNS:$d"; done
  for i in "${ips[@]}"; do want_nc+=$'\n'"$(openssl_ip "$i" || die "--ip $i is not a network")"; done
  for e in "${emails[@]}"; do want_nc+=$'\n'"email:$e"; done
  for u in "${uris[@]}"; do want_nc+=$'\n'"URI:$u"; done
fi
if [ ${#x_dns[@]} -gt 0 ] || [ ${#x_ips[@]} -gt 0 ] || [ ${#x_emails[@]} -gt 0 ] || [ ${#x_uris[@]} -gt 0 ]; then
  want_nc+=$'\nExcluded:'
  for d in "${x_dns[@]}"; do want_nc+=$'\n'"DNS:$d"; done
  for i in "${x_ips[@]}"; do want_nc+=$'\n'"$(openssl_ip "$i" || die "excluded $i is not a network")"; done
  for e in "${x_emails[@]}"; do want_nc+=$'\n'"email:$e"; done
  for u in "${x_uris[@]}"; do want_nc+=$'\n'"URI:$u"; done
fi
read_nc=$(extension "$int_text" 'Name Constraints')
compare 'intermediate name constraints' "$want_nc" "$read_nc"
[ "$copied" = no ] || compare 'intermediate name constraints, against the current intermediate' "$current_nc" "$read_nc"

if [ "$renew" = no ]; then
  compare 'root subject' "CN=$root_name" "$(subject_of "$out/root_ca.crt")"
fi
compare 'intermediate subject' "CN=$int_name" "$(subject_of "$out/intermediate_ca.crt")"
compare 'intermediate issuer' "$root_dn" "$(openssl x509 -in "$out/intermediate_ca.crt" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"

check_lifetime() { # <what> <file> <seconds> <duration>
  local start end got
  { read -r start; read -r end; } < <(dates "$2")
  got=$(( $(epoch "$end") - $(epoch "$start") ))
  # step backdates notBefore by up to a minute
  if [ $((got - $3)) -gt 120 ] || [ $(($3 - got)) -gt 120 ]; then
    compare "$1 lifetime" "$4 ($3 s)" "$start .. $end ($got s)"
  fi
}
[ "$renew" = yes ] || check_lifetime 'root' "$out/root_ca.crt" "$root_seconds" "$root_lifetime"
check_lifetime 'intermediate' "$out/intermediate_ca.crt" "$int_seconds" "$int_lifetime"

openssl verify -no-CApath -no-CAstore -CAfile "$out/root_ca.crt" "$out/intermediate_ca.crt" >"$work/verify.log" 2>&1 \
  || { cat "$work/verify.log" >&2; log 'MISMATCH: openssl does not verify the intermediate against the root'; mismatch=1; }

if [ "$renew" = yes ] \
  && [ "$(openssl x509 -in "$out/intermediate_ca.crt" -noout -pubkey)" = "$(openssl x509 -in "$current" -noout -pubkey)" ]; then
  log 'MISMATCH: the new intermediate has the key of the current one'
  mismatch=1
fi

if [ "$mismatch" -ne 0 ]; then
  if [ "$renew" = yes ]; then
    die "the certificates are not what was asked for (see above). Nothing in $out may be used: destroy it. The root key at $root_key was only read."
  fi
  die "the certificates are not what was asked for (see above). Nothing in $out may be used; the root key at $root_key belongs to this failed ceremony - destroy both."
fi

#### the record

fp() { step certificate fingerprint "$1"; }
{
  printf '# Ceremony record. Holds no secret.\n\n'
  if [ "$renew" = yes ]; then
    printf 'mode:             renewal of the intermediate under the existing root\n'
  else
    printf 'mode:             new hierarchy: root and intermediate\n'
  fi
  printf 'date (UTC):       %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'operator:         %s\n' "$operator"
  printf 'host:             %s\n' "$(uname -n)"
  printf 'step:             %s\n' "$(step version 2>&1 | head -n 1)"
  printf 'openssl:          %s\n' "$(openssl version)"
  if [ "$renew" = yes ]; then
    printf 'root key:         read at %s (not copied, not changed)\n' "$root_key"
  else
    printf 'root key:         written to %s (encrypted)\n' "$root_key"
  fi
  printf 'intermediate key: %s (encrypted, for step-ca)\n' "$out/intermediate_ca_key"
  printf '\nasked for:\n'
  printf '  key type              %s\n' "$key_desc"
  if [ "$renew" = yes ]; then
    printf '  root                  %s (existing, not made here)\n' "$root_dn"
  else
    printf '  root                  %s, %s\n' "$root_name" "$root_lifetime"
  fi
  printf '  intermediate          %s, %s\n' "$int_name" "$int_lifetime"
  if [ "$copied" = yes ]; then
    printf '  constraints           copied from the current intermediate, as openssl reads them\n'
  fi
  printf '  permitted DNS         %s\n' "${dns[*]:-(none: DNS names unconstrained)}"
  if [ "$exclude_all_ip" = yes ]; then
    printf '  permitted IP          none: all IPv4 and IPv6 excluded\n'
  else
    printf '  permitted IP          %s\n' "${ips[*]:-(none: IP addresses unconstrained)}"
    [ ${#x_ips[@]} -eq 0 ] || printf '  excluded IP           %s\n' "${x_ips[*]}"
  fi
  [ ${#x_dns[@]} -eq 0 ] || printf '  excluded DNS          %s\n' "${x_dns[*]}"
  printf '  permitted email       %s\n' "${emails[*]:-(none: email addresses unconstrained)}"
  [ ${#x_emails[@]} -eq 0 ] || printf '  excluded email        %s\n' "${x_emails[*]}"
  printf '  permitted URI         %s\n' "${uris[*]:-(none: URIs unconstrained)}"
  [ ${#x_uris[@]} -eq 0 ] || printf '  excluded URI          %s\n' "${x_uris[*]}"
  if [ "$renew" = yes ]; then
    printf '\nprevious intermediate: %s\n' "$current"
    printf '  SHA-256 fingerprint   %s\n' "$(fp "$current")"
    printf '  subject               %s\n' "$(subject_of "$current")"
    { read -r start; read -r end; } < <(dates "$current")
    printf '  valid                 %s .. %s\n' "$start" "$end"
    printf '  the new intermediate follows it: both lead to the root until the previous one is retired\n'
  fi
  for which in root intermediate; do
    file=$out/${which}_ca.crt
    printf '\n%s: %s\n' "$which" "${file##*/}"
    printf '  SHA-256 fingerprint   %s\n' "$(fp "$file")"
    printf '  subject               %s\n' "$(subject_of "$file")"
    printf '  serial                %s\n' "$(openssl x509 -in "$file" -noout -serial | sed 's/^serial=//')"
    printf '  public key            %s\n' "$(key_algorithm "$file")"
    { read -r start; read -r end; } < <(dates "$file")
    printf '  valid                 %s .. %s\n' "$start" "$end"
    printf '  read back with openssl x509 -text:\n'
    if [ "$which" = root ]; then text=$root_text; else text=$int_text; fi
    for ext in 'Basic Constraints' 'Key Usage' 'Name Constraints'; do
      extension "$text" "$ext" | sed "1s/^/    /; 1!s/^/      /"
    done
  done
  if [ "$renew" = yes ]; then
    printf '\nresult: every value read back matches what was asked for; openssl verifies the intermediate against the root; its key is new.\n'
  else
    printf '\nresult: every value read back matches what was asked for; openssl verifies the intermediate against the root.\n'
  fi
} >"$out/ceremony.txt"
chmod 644 "$out/ceremony.txt" "$out/root_ca.crt" "$out/intermediate_ca.crt"

log "root fingerprint (SHA-256): $(fp "$out/root_ca.crt")"
if [ "$renew" = yes ]; then
  log "new intermediate fingerprint (SHA-256): $(fp "$out/intermediate_ca.crt")"
  log "root key: unchanged at $root_key - take it off this machine again"
  log "for the running CA (init-ca.sh --switch-intermediate): $out - the record is $out/ceremony.txt"
else
  log "root key: $root_key - take it off this machine and keep it with its password, apart from the CA"
  log "for the CA (SICK_CA_IMPORT_DIR): $out - the record is $out/ceremony.txt"
fi
