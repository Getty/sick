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
# certificate under this intermediate carries an address.

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
exclude_all_ip=${SICK_CEREMONY_EXCLUDE_ALL_IP:-no}
kty=${SICK_CEREMONY_KTY:-EC}
size=${SICK_CEREMONY_SIZE:-4096}
root_lifetime=${SICK_CEREMONY_ROOT_LIFETIME:-175320h}
int_lifetime=${SICK_CEREMONY_INTERMEDIATE_LIFETIME:-43830h}

while [ $# -gt 0 ]; do
  case $1 in
    --exclude-all-ip) exclude_all_ip=yes; shift; continue ;;
    -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    --operator|--out|--root-key|--root-password-file|--intermediate-password-file|--root-name|\
    --intermediate-name|--dns|--ip|--kty|--size|--root-lifetime|--intermediate-lifetime)
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
    --intermediate-name) int_name=$2 ;;
    --dns) dns_list=${dns_list:+$dns_list,}$2 ;;
    --ip) ip_list=${ip_list:+$ip_list,}$2 ;;
    --kty) kty=$2 ;;
    --size) size=$2 ;;
    --root-lifetime) root_lifetime=$2 ;;
    --intermediate-lifetime) int_lifetime=$2 ;;
  esac
  shift 2
done

#### checking what was asked for, before anything is made

for program in step openssl; do
  command -v "$program" >/dev/null || die "$program is not installed"
done

[ -n "$operator" ] || die '--operator is required: the record says who ran the ceremony'
[[ $operator != *$'\n'* ]] || die '--operator is one line'
[ -n "$out" ] || die '--out is required'
[ -n "$root_key" ] || die '--root-key is required: where the root key goes'
[ -n "$root_pw" ] || die '--root-password-file is required'
[ -s "$root_pw" ] || die "$root_pw: no password in it, or not readable"
[ -z "$int_pw" ] || [ -s "$int_pw" ] || die "$int_pw: no password in it, or not readable"

case $kty in
  EC|ec) kty=EC; key_args=(--kty EC --curve P-256); key_desc='EC P-256' ;;
  RSA|rsa)
    kty=RSA
    [[ $size =~ ^[0-9]+$ ]] && [ "$size" -ge 3072 ] || die "--size $size: RSA keys of a CA have 3072 bits or more"
    key_args=(--kty RSA --size "$size"); key_desc="RSA $size" ;;
  *) die "--kty $kty: EC or RSA" ;;
esac

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
root_seconds=$(seconds_of "$root_lifetime") || die "--root-lifetime $root_lifetime is not a duration like 175320h"
int_seconds=$(seconds_of "$int_lifetime") || die "--intermediate-lifetime $int_lifetime is not a duration like 43830h"
[ "$int_seconds" -lt "$root_seconds" ] || die 'the intermediate has to expire before the root'

# "a, b,,c" as one item per line
items() { tr ',' '\n' <<<"$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d'; }

mapfile -t dns < <(items "$dns_list")
mapfile -t ips < <(items "$ip_list")
label='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
for d in "${dns[@]}"; do
  [[ $d =~ ^($label\.)*$label$ ]] || die "--dns $d is not a domain like example.internal"
done
for i in "${ips[@]}"; do
  [[ $i =~ ^[0-9.]+/[0-9]+$ || $i =~ ^[0-9A-Fa-f:]+/[0-9]+$ ]] || die "--ip $i is not a network like 192.0.2.0/24"
done
[ "$exclude_all_ip" = yes ] || [ "$exclude_all_ip" = no ] || die "SICK_CEREMONY_EXCLUDE_ALL_IP is yes or no"
if [ "$exclude_all_ip" = yes ] && [ ${#ips[@]} -gt 0 ]; then
  die '--exclude-all-ip and --ip contradict each other'
fi
[ ${#dns[@]} -gt 0 ] || [ ${#ips[@]} -gt 0 ] \
  || die 'no name constraints asked for: give --dns and/or --ip (an unconstrained intermediate is what this ceremony is there to avoid)'
if [ ${#dns[@]} -gt 0 ] && [ ${#ips[@]} -eq 0 ] && [ "$exclude_all_ip" = no ]; then
  log 'WARNING: DNS constraints without IP constraints - IP addresses stay unconstrained (RFC 5280).'
  log 'WARNING: give --ip for the networks, or --exclude-all-ip if no certificate may carry an address.'
fi
if [ ${#ips[@]} -gt 0 ] && [ ${#dns[@]} -eq 0 ]; then
  log 'WARNING: IP constraints without DNS constraints - DNS names stay unconstrained (RFC 5280).'
fi

# The places. The root key must not end up in what goes to the CA.
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
[ ! -e "$root_key" ] || die "$root_key exists: the ceremony does not overwrite a key"
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
[ "$exclude_all_ip" = no ] || constraints+=', "excludedIPRanges": ["0.0.0.0/0", "::/0"]'
cat >"$work/intermediate.tpl" <<EOF
{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["certSign", "crlSign"],
  "basicConstraints": { "isCA": true, "maxPathLen": 0 },
  "nameConstraints": { $constraints }
}
EOF

log "making the root '$root_name' ($key_desc, $root_lifetime)"
step certificate create --profile root-ca "${key_args[@]}" --not-after "$root_lifetime" \
  --password-file "$root_pw" "$root_name" "$out/root_ca.crt" "$root_key" >/dev/null 2>"$work/step.log" \
  || { cat "$work/step.log" >&2; die 'making the root failed'; }

log "making the intermediate '$int_name' ($key_desc, $int_lifetime)"
step certificate create --template "$work/intermediate.tpl" "${key_args[@]}" --not-after "$int_lifetime" \
  --ca "$out/root_ca.crt" --ca-key "$root_key" --ca-password-file "$root_pw" \
  --password-file "$out/password" "$int_name" "$out/intermediate_ca.crt" "$out/intermediate_ca_key" \
  >/dev/null 2>"$work/step.log" \
  || { cat "$work/step.log" >&2; die 'making the intermediate failed'; }

#### reading back with openssl, and comparing

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

# the lines of one extension below its heading, and the heading itself
extension() { # <text> <name>
  awk -v name="$2" '
    index($0, name ":") && /^ {12}X509v3 / { on = 1; sub(/^ +/, ""); sub(/ +$/, ""); print; next }
    on && /^ {0,12}[^ ]/ { exit }
    on { sub(/^ +/, ""); print }
  ' <<<"$1"
}

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

compare 'root key usage' $'X509v3 Key Usage: critical\nCertificate Sign, CRL Sign' "$(extension "$root_text" 'Key Usage')"
compare 'root basic constraints' $'X509v3 Basic Constraints: critical\nCA:TRUE, pathlen:1' "$(extension "$root_text" 'Basic Constraints')"
compare 'root name constraints (none)' '' "$(extension "$root_text" 'Name Constraints')"
compare 'intermediate key usage' $'X509v3 Key Usage: critical\nCertificate Sign, CRL Sign' "$(extension "$int_text" 'Key Usage')"
compare 'intermediate basic constraints' $'X509v3 Basic Constraints: critical\nCA:TRUE, pathlen:0' "$(extension "$int_text" 'Basic Constraints')"

want_nc='X509v3 Name Constraints: critical'
if [ ${#dns[@]} -gt 0 ] || [ ${#ips[@]} -gt 0 ]; then
  want_nc+=$'\nPermitted:'
  for d in "${dns[@]}"; do want_nc+=$'\n'"DNS:$d"; done
  for i in "${ips[@]}"; do want_nc+=$'\n'"$(openssl_ip "$i" || die "--ip $i is not a network")"; done
fi
if [ "$exclude_all_ip" = yes ]; then
  want_nc+=$'\nExcluded:\nIP:0.0.0.0/0.0.0.0\nIP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0'
fi
read_nc=$(extension "$int_text" 'Name Constraints')
compare 'intermediate name constraints' "$want_nc" "$read_nc"

subject_of() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'; }
compare 'root subject' "CN=$root_name" "$(subject_of "$out/root_ca.crt")"
compare 'intermediate subject' "CN=$int_name" "$(subject_of "$out/intermediate_ca.crt")"
compare 'intermediate issuer' "CN=$root_name" "$(openssl x509 -in "$out/intermediate_ca.crt" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"

epoch() { date -u -d "$1" +%s; }
dates() { openssl x509 -in "$1" -noout -startdate -enddate -dateopt iso_8601 | sed 's/^[a-zA-Z]*=//'; }
check_lifetime() { # <what> <file> <seconds> <duration>
  local start end got
  { read -r start; read -r end; } < <(dates "$2")
  got=$(( $(epoch "$end") - $(epoch "$start") ))
  # step backdates notBefore by up to a minute
  if [ $((got - $3)) -gt 120 ] || [ $(($3 - got)) -gt 120 ]; then
    compare "$1 lifetime" "$4 ($3 s)" "$start .. $end ($got s)"
  fi
}
check_lifetime 'root' "$out/root_ca.crt" "$root_seconds" "$root_lifetime"
check_lifetime 'intermediate' "$out/intermediate_ca.crt" "$int_seconds" "$int_lifetime"

openssl verify -no-CApath -no-CAstore -CAfile "$out/root_ca.crt" "$out/intermediate_ca.crt" >"$work/verify.log" 2>&1 \
  || { cat "$work/verify.log" >&2; log 'MISMATCH: openssl does not verify the intermediate against the root'; mismatch=1; }

if [ "$mismatch" -ne 0 ]; then
  die "the certificates are not what was asked for (see above). Nothing in $out may be used; the root key at $root_key belongs to this failed ceremony - destroy both."
fi

#### the record

fp() { step certificate fingerprint "$1"; }
key_algorithm() { openssl x509 -in "$1" -noout -text | sed -n 's/^ *Public Key Algorithm: //p; s/^ *Public-Key: /  /p; s/^ *NIST CURVE: /  /p' | tr -d '\n' | tr -s ' '; }
{
  printf '# Ceremony record. Holds no secret.\n\n'
  printf 'date (UTC):       %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'operator:         %s\n' "$operator"
  printf 'host:             %s\n' "$(uname -n)"
  printf 'step:             %s\n' "$(step version 2>&1 | head -n 1)"
  printf 'openssl:          %s\n' "$(openssl version)"
  printf 'root key:         written to %s (encrypted)\n' "$root_key"
  printf 'intermediate key: %s (encrypted, for step-ca)\n' "$out/intermediate_ca_key"
  printf '\nasked for:\n'
  printf '  key type              %s\n' "$key_desc"
  printf '  root                  %s, %s\n' "$root_name" "$root_lifetime"
  printf '  intermediate          %s, %s\n' "$int_name" "$int_lifetime"
  printf '  permitted DNS         %s\n' "${dns[*]:-(none: DNS names unconstrained)}"
  if [ "$exclude_all_ip" = yes ]; then
    printf '  permitted IP          none: all IPv4 and IPv6 excluded\n'
  else
    printf '  permitted IP          %s\n' "${ips[*]:-(none: IP addresses unconstrained)}"
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
  printf '\nresult: every value read back matches what was asked for; openssl verifies the intermediate against the root.\n'
} >"$out/ceremony.txt"
chmod 644 "$out/ceremony.txt" "$out/root_ca.crt" "$out/intermediate_ca.crt"

log "root fingerprint (SHA-256): $(fp "$out/root_ca.crt")"
log "root key: $root_key - take it off this machine and keep it with its password, apart from the CA"
log "for the CA (SICK_CA_IMPORT_DIR): $out - the record is $out/ceremony.txt"
