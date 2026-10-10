#!/bin/bash
#
# Entrypoint of the "ca" service: the official smallstep/step-ca image with
# this script in front of it.
#
# First start, in one of two modes:
#
#   lab mode     (nothing to import) makes everything here: root and
#                intermediate certificate with their keys, a JWK provisioner
#                for SICK and an ACME provisioner. The root key lies in the
#                volume - good for a lab, not for anything else.
#   import mode  (SICK_CA_IMPORT_DIR holds the output of ceremony.sh) builds
#                the CA on that hierarchy: root certificate, intermediate
#                certificate and key, the password of that key. The root key
#                is not there and never enters the volume.
#
# Every start: brings four settings of the CA configuration in line with
# the environment, hands the root certificate, the intermediate certificate
# and the provisioner password over to the sick service, and starts step-ca.
# A start that finds everything as it should be changes nothing.
#
# Rotating the provisioner, on the running CA:
#
#   docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner
#
# replaces key pair and password of the JWK provisioner, hands the new
# password over and has step-ca reload (SIGHUP). Tokens signed with the old
# key are refused from then on.
#
#   SICK_CA_IMPORT_DIR    the directory to import at the first start
#                         (default $STEPPATH/import); it holds
#                           root_ca.crt          the root certificate
#                           intermediate_ca.crt  the intermediate certificate
#                           intermediate_ca_key  its key, encrypted
#                           password             the password of that key
#                         and no other private key. Missing or empty: lab
#                         mode. Ignored once the CA exists.
#   SICK_CA_NAME          name of the CA, used once at the first start
#                         (default "SICK Internal CA")
#   SICK_CA_DNS           comma separated host names and addresses of the CA,
#                         for its own TLS certificate. Used at the first
#                         start. Lab mode adds "ca" and "localhost". Import
#                         mode takes this list alone and requires it: under
#                         name constraints the CA's own names have to lie
#                         inside them, or no client accepts its certificate.
#   SICK_CA_PROVISIONER   name of the JWK provisioner (default "sick")
#   SICK_CA_MAX_LIFETIME  longest certificate lifetime that provisioner
#                         grants, a Go duration (default "19800h", 825 days;
#                         step-ca itself would grant 24h). The provisioner
#                         also gets a template: server certificates with
#                         extended key usage serverAuth alone (step-ca's
#                         default adds clientAuth).
#   SICK_CA_ALLOW_DNS     comma separated DNS names the CA may issue for,
#                         "*.example.internal" style
#   SICK_CA_ALLOW_IP      comma separated addresses and networks the CA may
#                         issue for, "192.0.2.0/24" style
#                         Both empty: the policy of the CA is left as it is
#                         (none, for a new CA). One of them set: step-ca
#                         refuses every name and address that is not listed.
#   SICK_HANDOVER_DIR     where the files for the sick service go
#                         (default /handover)
#
# Secrets are files in the data volume and never in the environment:
#
#   $STEPPATH/secrets/password              encrypts the CA keys (import
#                                           mode: the intermediate key)
#   $STEPPATH/secrets/provisioner_password  encrypts the provisioner key
#
# Both are generated at the first start unless they are already there - put
# your own in place beforehand if you want to choose them.

set -euo pipefail
umask 077

STEPPATH=${STEPPATH:-/home/step}
export STEPPATH

config=$STEPPATH/config/ca.json
ca_password=$STEPPATH/secrets/password
provisioner_password=$STEPPATH/secrets/provisioner_password
root_cert=$STEPPATH/certs/root_ca.crt
intermediate_cert=$STEPPATH/certs/intermediate_ca.crt

name=${SICK_CA_NAME:-SICK Internal CA}
provisioner=${SICK_CA_PROVISIONER:-sick}
max_lifetime=${SICK_CA_MAX_LIFETIME:-19800h}
handover=${SICK_HANDOVER_DIR:-/handover}
import_dir=${SICK_CA_IMPORT_DIR:-$STEPPATH/import}
staged=$STEPPATH/import
run_as=step

# The leaf template of the provisioner: step-ca's default, with serverAuth
# as the only extended key usage.
leaf_template='{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth"]
}'

log() { printf 'init-ca: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

# "a, b,,c" as a JSON array of the non-empty items
json_list() {
  jq -cn --arg list "${1:-}" '$list | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)) | unique'
}

random_password() {
  # 40 characters out of 62: about 238 bits
  local password
  password=$(set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)
  [ "${#password}" -eq 40 ] || die 'cannot generate a password'
  printf '%s\n' "$password"
}

#### making the CA, as the unprivileged user

initialise() {
  [[ $max_lifetime =~ ^([0-9]+(h|m|s))+$ ]] \
    || die "SICK_CA_MAX_LIFETIME '$max_lifetime' is not a duration like 19800h"

  if [ ! -f "$config" ]; then
    mkdir -p "$STEPPATH/secrets"
    [ -s "$provisioner_password" ] || random_password >"$provisioner_password"
    if wants_import "$import_dir"; then
      import_ca "$import_dir"
    else
      make_ca
    fi
  else
    log "the CA in $STEPPATH exists: nothing to make"
    if [ "$import_dir" != "$staged" ] && [ -d "$import_dir" ]; then
      log "$import_dir is ignored: it is imported at the first start only"
    fi
  fi

  [ -s "$provisioner_password" ] \
    || die "$provisioner_password is missing: the password of the provisioner '$provisioner' has to be in that file"
  jq -e --arg name "$provisioner" '.authority.provisioners[]? | select(.type == "JWK" and .name == $name)' "$config" >/dev/null \
    || die "the CA has no JWK provisioner '$provisioner' (step ca provisioner add $provisioner --type JWK --create)"

  apply_settings "$config"

  log "root fingerprint (SHA-256): $(step certificate fingerprint "$root_cert")"
}

# The settings this script owns: lifetime and template of the provisioner,
# the policy. step-ca reads them at start. <file> is changed in place, and
# only when something differs.
apply_settings() {
  local file=$1 allow_dns allow_ip wanted
  allow_dns=$(json_list "${SICK_CA_ALLOW_DNS:-}")
  allow_ip=$(json_list "${SICK_CA_ALLOW_IP:-}")
  wanted=$(jq --arg name "$provisioner" --arg max "$max_lifetime" --arg template "$leaf_template" \
      --argjson dns "$allow_dns" --argjson ip "$allow_ip" '
      ( .authority.provisioners[] | select(.type == "JWK" and .name == $name) | .claims.maxTLSCertDuration ) = $max
      | ( .authority.provisioners[] | select(.type == "JWK" and .name == $name) | .options.x509.template ) = $template
      | if ($dns | length) + ($ip | length) > 0
        then .authority.policy.x509.allow =
          ( ( if ($dns | length) > 0 then { dns: $dns } else {} end )
          + ( if ($ip  | length) > 0 then { ip:  $ip  } else {} end ) )
        else .
        end
    ' "$file")
  if [ "$wanted" = "$(jq . "$file")" ]; then
    log "configuration unchanged: '$provisioner' grants up to $max_lifetime, serverAuth only$(describe_policy "$file")"
  else
    printf '%s\n' "$wanted" >"$file.new"
    mv "$file.new" "$file"
    log "configuration updated: '$provisioner' grants up to $max_lifetime, serverAuth only$(describe_policy "$file")"
  fi
}

#### rotating the provisioner: new key pair, new password

# The provisioner key is a JWK the CA hands to anybody who asks
# (/provisioners/<kid>/encrypted-key), encrypted with the provisioner
# password. A new password on the same key would leave whoever decrypted it
# with the old password able to sign tokens, so the key is replaced, not
# re-encrypted: "step ca provisioner remove" and "add --create", on a copy
# of ca.json that replaces the original only when everything worked.
# ("step ca provisioner update --create" fails in step 0.30.2 against a
# local ca.json: "provisioner sick:<new kid> not found".)
rotate_provisioner() {
  [ -f "$config" ] || die "no CA in $STEPPATH: nothing to rotate"
  local old_kid new_kid
  old_kid=$(jq -r --arg name "$provisioner" '.authority.provisioners[] | select(.type == "JWK" and .name == $name) | .key.kid' "$config")
  [ -n "$old_kid" ] || die "the CA has no JWK provisioner '$provisioner'"
  random_password >"$provisioner_password.new"
  cp "$config" "$config.rotate"
  { step ca provisioner remove "$provisioner" --ca-config "$config.rotate" \
      && step ca provisioner add "$provisioner" --type JWK --create \
           --password-file "$provisioner_password.new" --ca-config "$config.rotate"
  } >/dev/null 2>"$STEPPATH/rotate.log" \
    || { cat "$STEPPATH/rotate.log" >&2; rm -f "$config.rotate" "$provisioner_password.new"; die "rotating '$provisioner' failed; nothing changed"; }
  rm -f "$STEPPATH/rotate.log"
  apply_settings "$config.rotate"
  new_kid=$(jq -r --arg name "$provisioner" '.authority.provisioners[] | select(.type == "JWK" and .name == $name) | .key.kid' "$config.rotate")
  # ca.json first: should the second step not happen, the new password is
  # still in provisioner_password.new
  mv "$config.rotate" "$config"
  mv "$provisioner_password.new" "$provisioner_password"
  log "rotated provisioner '$provisioner': key $new_kid with a new password replaces key $old_kid"
}

# SICK_CA_DNS through a jq filter, as arguments of step ca init
ca_dns_args() {
  local names item
  names=$(json_list "${SICK_CA_DNS:-}" | jq -r "$1")
  while IFS= read -r item; do
    [ -z "$item" ] || printf -- '--dns\n%s\n' "$item"
  done <<<"$names"
}

make_ca() {
  log "lab mode: no CA in $STEPPATH yet: making '$name' with root and intermediate key here"
  [ -s "$ca_password" ] || random_password >"$ca_password"
  # "ca" first: it becomes the URL the CA calls its own
  local -a dns
  mapfile -t dns < <(ca_dns_args '( ["ca", "localhost"] + ( . - ["ca", "localhost"] ) )[]')

  # step prints the paths of what it made and an invitation to give
  # feedback; the summary below says what matters
  step ca init \
    --deployment-type standalone \
    --name "$name" \
    "${dns[@]}" \
    --address :9000 \
    --provisioner "$provisioner" \
    --password-file "$ca_password" \
    --provisioner-password-file "$provisioner_password" \
    --acme >/dev/null 2>"$STEPPATH/init.log" \
    || { cat "$STEPPATH/init.log" >&2; die 'step ca init failed'; }
  rm -f "$STEPPATH/init.log"
  log "made the CA: root and intermediate certificate, JWK provisioner '$provisioner', ACME provisioner 'acme'"
}

import_files=(root_ca.crt intermediate_ca.crt intermediate_ca_key password)

# Is there something to import in <dir>? Dies when it is half there or
# holds a private key that is not the intermediate's.
wants_import() {
  local dir=$1 file missing=()
  [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ] || return 1
  for file in "${import_files[@]}"; do
    [ -s "$dir/$file" ] || missing+=("$file")
  done
  [ ${#missing[@]} -eq 0 ] || die "$dir is not empty but has no ${missing[*]}: put root_ca.crt, intermediate_ca.crt, intermediate_ca_key and password there (the output of ceremony.sh), or nothing"
  for file in "$dir"/*; do
    [ "${file##*/}" = intermediate_ca_key ] && continue
    if [ -f "$file" ] && grep -q 'PRIVATE KEY' "$file"; then
      die "$file holds a private key: nothing but the intermediate key may be imported - the root key stays out of the CA"
    fi
  done
  return 0
}

# Import mode, the way Smallstep describes it for an existing hierarchy:
# "step ca init" for the configuration, then root certificate, intermediate
# certificate and key replaced and the root fingerprint in defaults.json
# updated. The init runs in a scratch directory outside the volume, so the
# keys it makes for itself never land there; only its configuration is
# taken over.
import_ca() {
  local from=$1 scratch file
  log "import mode: no CA in $STEPPATH yet: building it on the hierarchy in $from (no root key)"
  [ -n "$(json_list "${SICK_CA_DNS:-}" | jq -r '.[]')" ] \
    || die 'import mode needs SICK_CA_DNS: the names of the CA, inside the name constraints of the intermediate'

  step certificate verify "$from/intermediate_ca.crt" --roots "$from/root_ca.crt" >/dev/null 2>"$STEPPATH/import.log" \
    || { cat "$STEPPATH/import.log" >&2; die "$from/intermediate_ca.crt is not signed by $from/root_ca.crt"; }
  local have want
  want=$(step certificate key "$from/intermediate_ca.crt" 2>/dev/null) || die "cannot read the key of $from/intermediate_ca.crt"
  have=$(step crypto key public "$from/intermediate_ca_key" --password-file "$from/password" 2>/dev/null) \
    || die "cannot open $from/intermediate_ca_key with the password in $from/password"
  [ "$have" = "$want" ] || die "$from/intermediate_ca_key is not the key of $from/intermediate_ca.crt"
  rm -f "$STEPPATH/import.log"

  local -a dns
  mapfile -t dns < <(ca_dns_args '.[]')
  scratch=$(mktemp -d)
  STEPPATH=$scratch step ca init \
    --deployment-type standalone \
    --name "$name" \
    "${dns[@]}" \
    --address :9000 \
    --provisioner "$provisioner" \
    --password-file "$from/password" \
    --provisioner-password-file "$provisioner_password" \
    --acme >/dev/null 2>"$scratch/init.log" \
    || { cat "$scratch/init.log" >&2; rm -rf "$scratch"; die 'step ca init failed'; }

  mkdir -p "$STEPPATH/config" "$STEPPATH/certs"
  install -m 0644 "$from/root_ca.crt" "$root_cert"
  install -m 0644 "$from/intermediate_ca.crt" "$intermediate_cert"
  install -m 0600 "$from/intermediate_ca_key" "$STEPPATH/secrets/intermediate_ca_key"
  install -m 0600 "$from/password" "$ca_password"
  for file in ca.json defaults.json; do
    jq --arg from "$scratch" --arg to "$STEPPATH" \
      'walk(if type == "string" and startswith($from + "/") then $to + ltrimstr($from) else . end)' \
      "$scratch/config/$file" >"$STEPPATH/config/$file.new"
  done
  rm -rf "$scratch"
  jq --arg fp "$(step certificate fingerprint "$root_cert")" '.fingerprint = $fp' \
    "$STEPPATH/config/defaults.json.new" >"$STEPPATH/config/defaults.json"
  rm -f "$STEPPATH/config/defaults.json.new"
  # ca.json last: its existence says the CA is made
  mv "$STEPPATH/config/ca.json.new" "$config"
  [ "$from" != "$staged" ] || rm -rf "$staged"
  log "made the CA on the imported hierarchy: JWK provisioner '$provisioner', ACME provisioner 'acme'; no root key in $STEPPATH"
}

# As root: copy what is to be imported into the volume for the user of the
# image, who may not be able to read the original.
stage_import() {
  [ ! -f "$config" ] || return 0
  wants_import "$import_dir" || return 0
  [ "$import_dir" != "$staged" ] || { chown -R "$run_as" "$staged"; return 0; }
  rm -rf "$staged"
  mkdir -m 0700 "$staged"
  local file
  for file in "${import_files[@]}"; do
    install -o "$run_as" -m 0600 "$import_dir/$file" "$staged/$file"
  done
  chown "$run_as" "$staged"
  log "staged ${import_files[*]} from $import_dir for the import"
}

describe_policy() {
  local policy
  policy=$(jq -r '.authority.policy.x509.allow // empty | [ (.dns // [])[], (.ip // [])[] ] | join(", ")' "${1:-$config}")
  if [ -n "$policy" ]; then printf ', names allowed: %s' "$policy"; else printf ', names not restricted'; fi
}

#### what the sick service needs: two certificates and one password

hand_over() {
  [ -d "$handover" ] || { log "no $handover: nothing is handed over"; return 0; }
  put "$root_cert"            "$handover/root_ca.crt"         0644
  put "$intermediate_cert"    "$handover/intermediate_ca.crt" 0644
  put "$provisioner_password" "$handover/provisioner.pw"      0600
}

# Copy a file unless the copy is already the same, never leaving half a file.
put() {
  local from=$1 to=$2 mode=$3
  if [ -f "$to" ] && cmp -s "$from" "$to"; then
    return 0
  fi
  install -m "$mode" "$from" "$to.new"
  mv "$to.new" "$to"
  log "handed over ${to##*/}"
}

#### main

# step-ca reads ca.json again on SIGHUP
reload() {
  if pkill -HUP -x step-ca; then
    log 'step-ca reloads its configuration (SIGHUP)'
  else
    log 'no step-ca running here: the next start reads the new configuration'
  fi
}

case ${1:-} in
  --initialise)
    initialise
    exit 0
    ;;
  --rotate-provisioner-only)
    rotate_provisioner
    exit 0
    ;;
  --rotate-provisioner)
    # docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --rotate-provisioner
    if [ "$(id -u)" = 0 ]; then
      su "$run_as" -s /bin/bash -c 'exec /bin/bash "$0" --rotate-provisioner-only' -- "$0"
    else
      rotate_provisioner
    fi
    hand_over
    reload
    exit 0
    ;;
  '') ;;
  *) die "unknown argument '$1'" ;;
esac

if [ "$(id -u)" = 0 ]; then
  # Started as root, as the compose file does it, for one reason: a fresh
  # volume belongs to root, and what is handed over shall be readable by
  # root alone. Everything else, the CA included, runs as the user of the
  # image.
  chown "$run_as" "$STEPPATH"
  stage_import
  if [ -d "$staged" ]; then export SICK_CA_IMPORT_DIR=$staged; fi
  su "$run_as" -s /bin/bash -c 'exec /bin/bash "$0" --initialise' -- "$0"
  hand_over
  exec su "$run_as" -s /bin/bash -c 'exec step-ca --password-file "$0" "$1"' -- "$ca_password" "$config"
fi

initialise
hand_over
exec step-ca --password-file "$ca_password" "$config"
