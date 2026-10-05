#!/bin/bash
#
# Entrypoint of the "ca" service: the official smallstep/step-ca image with
# this script in front of it.
#
# First start: makes a CA (root and intermediate certificate), a JWK
# provisioner for SICK and an ACME provisioner.
# Every start: brings three settings of the CA configuration in line with
# the environment, hands the root certificate, the intermediate certificate
# and the provisioner password over to the sick service, and starts step-ca.
# A start that finds everything as it should be changes nothing.
#
#   SICK_CA_NAME          name of the CA, used once at the first start
#                         (default "SICK Internal CA")
#   SICK_CA_DNS           comma separated host names and addresses of the CA,
#                         for its own TLS certificate; "ca" and "localhost"
#                         are always part of it. Used at the first start.
#   SICK_CA_PROVISIONER   name of the JWK provisioner (default "sick")
#   SICK_CA_MAX_LIFETIME  longest certificate lifetime that provisioner
#                         grants, a Go duration (default "19800h", 825 days;
#                         step-ca itself would grant 24h)
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
#   $STEPPATH/secrets/password              encrypts the CA keys
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
run_as=step

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
    log "no CA in $STEPPATH yet: making '$name'"
    mkdir -p "$STEPPATH/secrets"
    [ -s "$ca_password" ] || random_password >"$ca_password"
    [ -s "$provisioner_password" ] || random_password >"$provisioner_password"

    # "ca" first: it becomes the URL the CA calls its own
    local -a dns=()
    local names item
    names=$(json_list "${SICK_CA_DNS:-}" | jq -r '( ["ca", "localhost"] + ( . - ["ca", "localhost"] ) )[]')
    while IFS= read -r item; do
      dns+=(--dns "$item")
    done <<<"$names"

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
  else
    log "the CA in $STEPPATH exists: nothing to make"
  fi

  [ -s "$provisioner_password" ] \
    || die "$provisioner_password is missing: the password of the provisioner '$provisioner' has to be in that file"
  jq -e --arg name "$provisioner" '.authority.provisioners[]? | select(.type == "JWK" and .name == $name)' "$config" >/dev/null \
    || die "the CA has no JWK provisioner '$provisioner' (step ca provisioner add $provisioner --type JWK --create)"

  # The three settings this script owns. step-ca reads them at start.
  local allow_dns allow_ip wanted
  allow_dns=$(json_list "${SICK_CA_ALLOW_DNS:-}")
  allow_ip=$(json_list "${SICK_CA_ALLOW_IP:-}")
  wanted=$(jq --arg name "$provisioner" --arg max "$max_lifetime" --argjson dns "$allow_dns" --argjson ip "$allow_ip" '
      ( .authority.provisioners[] | select(.type == "JWK" and .name == $name) | .claims.maxTLSCertDuration ) = $max
      | if ($dns | length) + ($ip | length) > 0
        then .authority.policy.x509.allow =
          ( ( if ($dns | length) > 0 then { dns: $dns } else {} end )
          + ( if ($ip  | length) > 0 then { ip:  $ip  } else {} end ) )
        else .
        end
    ' "$config")
  if [ "$wanted" = "$(jq . "$config")" ]; then
    log "configuration unchanged: '$provisioner' grants up to $max_lifetime$(describe_policy)"
  else
    printf '%s\n' "$wanted" >"$config.new"
    mv "$config.new" "$config"
    log "configuration updated: '$provisioner' grants up to $max_lifetime$(describe_policy)"
  fi

  log "root fingerprint (SHA-256): $(step certificate fingerprint "$root_cert")"
}

describe_policy() {
  local policy
  policy=$(jq -r '.authority.policy.x509.allow // empty | [ (.dns // [])[], (.ip // [])[] ] | join(", ")' "$config")
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

case ${1:-} in
  --initialise)
    initialise
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
  su "$run_as" -s /bin/bash -c 'exec /bin/bash "$0" --initialise' -- "$0"
  hand_over
  exec su "$run_as" -s /bin/bash -c 'exec step-ca --password-file "$0" "$1"' -- "$ca_password" "$config"
fi

initialise
hand_over
exec step-ca --password-file "$ca_password" "$config"
