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
# Every start: brings the settings of the CA configuration in line with
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
# Renewing the intermediate, on the running CA, with the output of
# "ceremony.sh --renew-intermediate" copied into the volume:
#
#   docker compose cp /media/offline/new-intermediate/. ca:/home/step/switch
#   docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate
#
# checks that the new intermediate leads to the root of this CA, that the
# key is its own and opens with the password beside it, and that the key is
# not the current one; re-encrypts the key with the password of the CA
# (step-ca keeps the password it started with across a reload), keeps the
# current intermediate as the previous one, installs the new one and has
# step-ca reload (SIGHUP): it signs with the new one from then on. The
# directory is removed from the volume afterwards, also when the switch is
# refused; another one is given as --switch-intermediate DIR (a path in the
# container) and is left alone. The handover then holds both
# intermediates, the new one first, so that devices with a certificate under
# the previous one stay "ok" and the trust page shows both.
# After the overlap:
#
#   docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate
#
# drops the previous intermediate from the handover and deletes its key.
# Devices still under it are "foreign-ca" from then on and renewed by the
# next run (a device that sends the previous one along stays "ok" while it
# is valid).
#
# On the stopped CA - after a compromise of the intermediate the CA must
# not serve while it is replaced - all three run in a container of their
# own on the CA's volumes, with the same -f files as the CA:
#
#   docker compose stop ca
#   docker compose cp /media/offline/new-intermediate/. ca:/home/step/switch
#   docker compose run --rm --no-deps --entrypoint /bin/bash ca \
#     /usr/local/bin/init-ca.sh --switch-intermediate
#   (the same with --retire-intermediate and --rotate-provisioner)
#   docker compose start ca
#
# "docker compose cp" copies into the volume of the stopped container. The
# handover is updated as on the running CA; there is no step-ca to reload
# (the log says so), the CA reads the volume at its start. Never with the
# CA running: that step-ca would not learn of the change.
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
#   SICK_CA_ACME_LIFETIME the lifetime the ACME provisioner "acme" gives a
#                         certificate, a Go duration (default "720h", 30
#                         days). An ACME client renews at about two thirds of
#                         the lifetime: 30 days leave about 10 days in which
#                         the CA may be down before services expire.
#   SICK_CA_ACME_MAX_LIFETIME  the longest lifetime "acme" grants a client
#                         that asks for one (default "2160h", 90 days)
#   SICK_CA_ACME_MIN_LIFETIME  the shortest (default "5m", step-ca's own)
#                         The three have to be min <= lifetime <= max. "acme"
#                         gets the same template as the JWK provisioner:
#                         serverAuth alone. Without a provisioner "acme" (it
#                         was removed) there is nothing to set.
#   SICK_CA_ACME_CHALLENGES  the challenge types "acme" offers, comma
#                         separated, out of http-01, tls-alpn-01 and dns-01
#                         (e.g. "http-01"). Empty: step-ca's default, all
#                         three.
#   SICK_CA_PROVISIONERS_FILE  a JSON file declaring further provisioners
#                         (default $STEPPATH/provisioners.json; when the
#                         variable is set the file has to exist). Each one is
#                         made when missing and its template, lifetimes and
#                         challenge types brought in line at every start,
#                         like "sick" and "acme":
#
#                           { "provisioners": [
#                             { "name": "clients", "type": "JWK",
#                               "profile": "client",
#                               "lifetime": "720h", "max": "2160h",
#                               "min": "5m",
#                               "password_file": "secrets/provisioner_clients_password" },
#                             { "name": "acme-long", "type": "ACME",
#                               "profile": "server",
#                               "lifetime": "1440h", "max": "2160h",
#                               "challenges": ["http-01"] } ] }
#
#                         name     letters, digits, ".", "_", "-"; not the
#                                  name of "sick" or "acme"
#                         type     JWK or ACME
#                         profile  "server": serverAuth alone (the template
#                                  of "sick"); "client": clientAuth alone,
#                                  key usage digitalSignature
#                         lifetime, max, min  Go durations, min <= lifetime
#                                  <= max (default 720h, 2160h, 5m)
#                         challenges  ACME only: a subset of http-01,
#                                  tls-alpn-01, dns-01 (default all three)
#                         password_file  JWK only: the password the key is
#                                  encrypted with, a path in the volume,
#                                  relative to $STEPPATH (default
#                                  secrets/provisioner_<name>_password).
#                                  Generated when missing, without a newline
#                                  at the end (step-issuer takes a Secret
#                                  byte for byte); read only when the
#                                  provisioner is made. Never logged.
#                         comment  free text, ignored
#
#                         Anything else is an error, and an error in the file
#                         stops the start before anything is changed. A
#                         provisioner that is in ca.json but neither built in
#                         nor declared is left as it is and named in the log:
#                         removing one is done by hand.
#   SICK_CA_ALLOW_DNS     comma separated DNS names the CA may issue for,
#                         "*.example.internal" style
#   SICK_CA_ALLOW_IP      comma separated addresses and networks the CA may
#                         issue for, "192.0.2.0/24" style
#   SICK_CA_ALLOW_EMAIL   comma separated email addresses the CA may issue
#                         for: "@example.internal" (every mailbox of that
#                         domain, not of its subdomains) or
#                         "person@example.internal" (that one)
#   SICK_CA_ALLOW_URI     comma separated hosts of the URIs the CA may issue
#                         for: "example.internal" (that host),
#                         "*.example.internal" (one label below it); no
#                         scheme, no port. A URI without a host is refused.
#                         All four empty: the policy of the CA is left as it
#                         is (none, for a new CA). Any of them set: the
#                         allow list becomes exactly what is set, and
#                         step-ca refuses every name of a form that is not
#                         listed - also the subject CN, judged by its form.
#                         Taking one away never lifts the restriction: the
#                         form is refused, or, with all four gone, the
#                         policy stays as it is.
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
intermediate_key=$STEPPATH/secrets/intermediate_ca_key
# the intermediate a switch replaced, until it is retired
previous_cert=$STEPPATH/certs/intermediate_ca.previous.crt
previous_key=$STEPPATH/secrets/intermediate_ca_key.previous
switch_dir=$STEPPATH/switch

name=${SICK_CA_NAME:-SICK Internal CA}
provisioner=${SICK_CA_PROVISIONER:-sick}
max_lifetime=${SICK_CA_MAX_LIFETIME:-19800h}
acme=acme
acme_lifetime=${SICK_CA_ACME_LIFETIME:-720h}
acme_max=${SICK_CA_ACME_MAX_LIFETIME:-2160h}
acme_min=${SICK_CA_ACME_MIN_LIFETIME:-5m}
acme_challenges=${SICK_CA_ACME_CHALLENGES:-}
provisioners_file=${SICK_CA_PROVISIONERS_FILE:-$STEPPATH/provisioners.json}
provisioners_given=${SICK_CA_PROVISIONERS_FILE:+yes}
# the declared provisioners, checked and with their defaults (load_declared)
declared='[]'
acme_challenge_list='null'
handover=${SICK_HANDOVER_DIR:-/handover}
import_dir=${SICK_CA_IMPORT_DIR:-$STEPPATH/import}
staged=$STEPPATH/import
run_as=step

# The leaf template of the JWK and the ACME provisioner: step-ca's default,
# with serverAuth as the only extended key usage.
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

# The template of a declared provisioner with profile "client": subject and
# SANs as the token (JWK) or the order (ACME) gives them - the email and URI
# SANs of "step ca certificate --san" included -, clientAuth as the only
# extended key usage. A TLS client signs with its key and never has a key
# encrypted to it, so digitalSignature alone, for RSA as well.
client_template='{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["clientAuth"]
}'

log() { printf 'init-ca: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

# "a, b,,c" as a JSON array of the non-empty items
json_list() {
  jq -cn --arg list "${1:-}" '$list | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)) | unique'
}

# A Go duration ("720h", "1h30m", "1.5h", "90s") in seconds; nothing when
# <text> is not one or not positive. Go's units: ns, us (µs), ms, s, m, h.
duration_seconds() {
  jq -rn --arg d "$1" '
    ( "([0-9]+(\\.[0-9]*)?|\\.[0-9]+)(ns|us|µs|ms|s|m|h)" ) as $part
    | { ns: 1e-9, us: 1e-6, "µs": 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 } as $unit
    | if $d | test("^(" + $part + ")+$")
      then [ $d | scan($part) | (.[0] | if startswith(".") then "0" + . else . end | rtrimstr(".") | tonumber) * $unit[.[2]] ]
           | add | select(. > 0)
      else empty end'
}

# The lifetimes of "acme": Go durations, min <= default <= max - step-ca
# itself refuses to start otherwise, with less to go on.
check_acme_lifetimes() {
  check_lifetimes SICK_CA_ACME_MIN_LIFETIME "$acme_min" SICK_CA_ACME_LIFETIME "$acme_lifetime" \
    SICK_CA_ACME_MAX_LIFETIME "$acme_max"
}

# check_lifetimes <what> <min> <what> <default> <what> <max> [<prefix>]
check_lifetimes() {
  local min def max at=${7:+$7: }
  min=$(duration_seconds "$2")
  def=$(duration_seconds "$4")
  max=$(duration_seconds "$6")
  [ -n "$min" ] || die "$at$1 '$2' is not a positive Go duration like 5m, 90s or 1h30m"
  [ -n "$def" ] || die "$at$3 '$4' is not a positive Go duration like 720h, 90m or 1h30m"
  [ -n "$max" ] || die "$at$5 '$6' is not a positive Go duration like 2160h, 90m or 1h30m"
  jq -en --argjson a "$min" --argjson b "$def" '$a <= $b' >/dev/null \
    || die "$at$3 '$4' is shorter than $1 '$2'"
  jq -en --argjson a "$def" --argjson b "$max" '$a <= $b' >/dev/null \
    || die "$at$3 '$4' is longer than $5 '$6'"
}

challenge_types='["http-01", "tls-alpn-01", "dns-01"]'

# SICK_CA_ACME_CHALLENGES as a JSON list, or null for step-ca's default
check_acme_challenges() {
  local list unknown
  list=$(json_list "$acme_challenges")
  unknown=$(jq -r --argjson known "$challenge_types" '. - $known | join(", ")' <<<"$list")
  [ -z "$unknown" ] || die "SICK_CA_ACME_CHALLENGES: unknown challenge type $unknown (http-01, tls-alpn-01, dns-01)"
  if [ "$list" = '[]' ]; then acme_challenge_list=null; else acme_challenge_list=$list; fi
}

#### declared provisioners

# Reads and checks the provisioners file into $declared: a JSON list of
# { name, type, profile, lifetime, max, min, challenges (or null),
# password_file (JWK: absolute path) }. Dies on the first error, before
# anything is changed.
load_declared() {
  local file=$provisioners_file errors entry name
  declared='[]'
  if [ ! -e "$file" ]; then
    [ "$provisioners_given" != yes ] || die "SICK_CA_PROVISIONERS_FILE: $file does not exist"
    return 0
  fi
  [ -f "$file" ] && [ -r "$file" ] \
    || die "$file is not a readable file (the user $(id -un) reads it; it holds no secret, mode 0644 will do)"
  jq -e . "$file" >/dev/null 2>&1 || die "$file is not JSON"
  errors=$(jq -r --argjson challenges "$challenge_types" --arg sick "$provisioner" --arg acme "$acme" '
    def where($i; $p): "provisioners[\($i)]" + (if ($p | type) == "object" and ($p.name | type) == "string" then " (\($p.name))" else "" end);
    def keys_of: if type == "object" then keys else [] end;
    if type != "object" then ["the file holds no JSON object: { \"provisioners\": [ ... ] }"]
    elif (keys - ["provisioners", "comment"]) != [] then ["unknown key \(keys - ["provisioners", "comment"] | join(", ")) at the top (provisioners, comment)"]
    elif (.provisioners | type) != "array" then ["\"provisioners\" is not a list"]
    else
      ( .provisioners | to_entries | map(.key as $i | .value as $p | where($i; $p) as $w |
        if ($p | type) != "object" then ["\($w): not an object"]
        else
          [ ( ($p | keys_of) - ["name", "type", "profile", "lifetime", "max", "min", "challenges", "password_file", "comment"]
              | select(length > 0) | "\($w): unknown key \(join(", "))" ),
            ( $p.name | select(type != "string" or test("^[A-Za-z0-9][A-Za-z0-9._-]*$") | not)
              | "\($w): name is missing or not letters, digits, \".\", \"_\", \"-\"" ),
            ( $p.name | select(. == $sick or . == $acme)
              | "\($w): \"\(.)\" is built in; its settings come from the environment" ),
            ( $p.type | select(. != "JWK" and . != "ACME") | "\($w): type is JWK or ACME" ),
            ( $p.profile | select(. != "server" and . != "client") | "\($w): profile is \"server\" or \"client\"" ),
            ( ["lifetime", "max", "min"][] as $k | $p[$k] | select(. != null and type != "string")
              | "\($w): \($k) is a Go duration in a string, like \"720h\"" ),
            ( $p.challenges | select(. != null) |
              if $p.type != "ACME" then "\($w): challenges belong to an ACME provisioner"
              elif type != "array" or length == 0 or (map(type == "string") | all | not) then "\($w): challenges is a non-empty list"
              elif (. - $challenges) != [] then "\($w): unknown challenge type \(. - $challenges | join(", ")) (http-01, tls-alpn-01, dns-01)"
              elif (unique | length) != length then "\($w): a challenge type is listed twice"
              else empty end ),
            ( $p.password_file | select(. != null) |
              if $p.type != "JWK" then "\($w): password_file belongs to a JWK provisioner"
              elif type != "string" or length == 0 then "\($w): password_file is a path"
              else empty end )
          ]
        end) | add // [] )
      + ( [ .provisioners[] | objects | .name | strings ] | group_by(.) | map(select(length > 1) | "\"\(.[0])\" is declared twice") )
    end | .[]' "$file")
  [ -z "$errors" ] || { while IFS= read -r entry; do log "$file: $entry"; done <<<"$errors"; die "$file: no provisioner changed"; }

  declared=$(jq -c --arg steppath "$STEPPATH" '[ .provisioners[] | {
      name, type, profile,
      lifetime: (.lifetime // "720h"), max: (.max // "2160h"), min: (.min // "5m"),
      challenges: (if .type == "ACME" then .challenges else null end),
      password_file: (if .type == "JWK" then (.password_file // "secrets/provisioner_\(.name)_password")
                        | (if startswith("/") then . else $steppath + "/" + . end) else null end)
    } ]' "$file")
  while IFS=$'\t' read -r name min def max entry; do
    check_lifetimes min "$min" lifetime "$def" max "$max" "$file: '$name'"
    [ -n "$entry" ] || continue
    case /$entry/ in
      */../* | */./* ) die "$file: '$name' password_file $entry: no \".\" or \"..\" in it" ;;
    esac
    case $entry in
      "$STEPPATH"/*) ;;
      *) die "$file: '$name' password_file $entry lies outside $STEPPATH: it belongs in the volume of the CA" ;;
    esac
    case $entry in
      "$ca_password" | "$provisioner_password" | "$intermediate_key" | "$previous_key" | "$config" | "$STEPPATH"/secrets/root_ca_key)
        die "$file: '$name' password_file $entry is a file of the CA itself" ;;
    esac
  done < <(jq -r '.[] | [.name, .min, .lifetime, .max, (.password_file // "")] | @tsv' <<<"$declared")
  [ "$(jq -r '[.[] | .password_file | strings] | (length == (unique | length))' <<<"$declared")" = true ] \
    || die "$file: two provisioners share a password_file"
}

# Makes the declared provisioners that <ca.json> does not have yet, on a
# copy that replaces it when every one was made. Template and lifetimes are
# apply_settings' business.
add_declared() {
  local file=$1 name type pw have made=()
  [ "$declared" != '[]' ] || return 0
  rm -f "$file.declare"
  while IFS=$'\t' read -r name type pw; do
    have=$(jq -r --arg name "$name" '[.authority.provisioners[]? | select(.name == $name) | .type] | join(", ")' "$file")
    if [ -n "$have" ]; then
      [ "$have" = "$type" ] \
        || die "$provisioners_file declares '$name' as $type, but the CA has a provisioner '$name' of type $have: remove it by hand (step ca provisioner remove) or choose another name"
      [ "$type" = JWK ] && check_password "$file" "$name" "$pw"
      continue
    fi
    [ -f "$file.declare" ] || cp "$file" "$file.declare"
    if [ "$type" = JWK ]; then
      local said="password from $pw"
      if [ ! -s "$pw" ]; then
        mkdir -p "${pw%/*}"
        # no newline at the end: step strips one, step-issuer would not
        random_password | tr -d '\n' >"$pw"
        said="password generated in $pw"
      fi
      step ca provisioner add "$name" --type JWK --create --password-file "$pw" --ca-config "$file.declare" \
        >/dev/null 2>"$STEPPATH/declare.log" \
        || { cat "$STEPPATH/declare.log" >&2; rm -f "$STEPPATH/declare.log" "$file.declare"; die "making the JWK provisioner '$name' failed; nothing changed"; }
      made+=("JWK provisioner '$name' ($said)")
    else
      step ca provisioner add "$name" --type ACME --ca-config "$file.declare" \
        >/dev/null 2>"$STEPPATH/declare.log" \
        || { cat "$STEPPATH/declare.log" >&2; rm -f "$STEPPATH/declare.log" "$file.declare"; die "making the ACME provisioner '$name' failed; nothing changed"; }
      made+=("ACME provisioner '$name'")
    fi
    rm -f "$STEPPATH/declare.log"
  done < <(jq -r '.[] | [.name, .type, (.password_file // "")] | @tsv' <<<"$declared")
  [ -f "$file.declare" ] || return 0
  mv "$file.declare" "$file"
  local one
  for one in "${made[@]}"; do log "made the declared $one"; done
}

# An existing JWK provisioner: does the password file still open its key?
# Only said, never fatal - the CA does not need the password.
check_password() {
  local file=$1 name=$2 pw=$3
  if [ ! -s "$pw" ]; then
    log "WARNING: no password for the provisioner '$name' in $pw: its key stays as it is; whoever uses '$name' needs the password it was made with"
    return 0
  fi
  jq -r --arg name "$name" '.authority.provisioners[] | select(.type == "JWK" and .name == $name) | .encryptedKey' "$file" \
    | step crypto jwe decrypt --password-file "$pw" >/dev/null 2>&1 \
    || log "WARNING: the password in $pw does not open the key of the provisioner '$name'"
}

describe_declared() {
  local file=$1 line
  while IFS= read -r line; do
    [ -z "$line" ] || log "$line"
  done < <(jq -r --argjson declared "$declared" --arg sick "$provisioner" --arg acme "$acme" --arg from "$provisioners_file" '
    ( $declared[] as $d | .authority.provisioners[]? | select(.type == $d.type and .name == $d.name)
      | "declared provisioner '\''\(.name)'\'' (\(.type)) issues for \(.claims.defaultTLSCertDuration) (\(.claims.minTLSCertDuration) to \(.claims.maxTLSCertDuration)), "
        + (if $d.profile == "client" then "clientAuth only" else "serverAuth only" end)
        + (if .type == "ACME" then ", challenges " + ((.challenges // ["http-01", "dns-01", "tls-alpn-01"]) | join(", ")) else "" end) ),
    ( .authority.provisioners[]? | . as $p
      | select(($p.type == "JWK" and $p.name == $sick) or ($p.type == "ACME" and $p.name == $acme) | not)
      | select([ $declared[] | select(.type == $p.type and .name == $p.name) ] | length == 0)
      | "provisioner '\''\(.name)'\'' (\(.type)) is neither built in nor declared in \($from): left as it is, not removed" )
  ' "$file")
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
  check_acme_lifetimes
  check_acme_challenges
  load_declared

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

  add_declared "$config"
  apply_settings "$config"

  log "root fingerprint (SHA-256): $(step certificate fingerprint "$root_cert")"
}

# The settings this script owns: lifetime and template of the JWK
# provisioner, lifetimes and template of the ACME provisioner, the policy.
# step-ca reads them at start. <file> is changed in place, and only when
# something differs.
apply_settings() {
  local file=$1 allow_dns allow_ip allow_email allow_uri wanted
  allow_dns=$(json_list "${SICK_CA_ALLOW_DNS:-}")
  allow_ip=$(json_list "${SICK_CA_ALLOW_IP:-}")
  allow_email=$(json_list "${SICK_CA_ALLOW_EMAIL:-}")
  allow_uri=$(json_list "${SICK_CA_ALLOW_URI:-}")
  wanted=$(jq --arg name "$provisioner" --arg max "$max_lifetime" --arg template "$leaf_template" \
      --arg acme "$acme" --arg amin "$acme_min" --arg adef "$acme_lifetime" --arg amax "$acme_max" \
      --argjson achallenges "$acme_challenge_list" \
      --argjson declared "$declared" --arg client "$client_template" \
      --argjson dns "$allow_dns" --argjson ip "$allow_ip" --argjson email "$allow_email" --argjson uri "$allow_uri" '
      def challenges($list): if $list == null then del(.challenges) else .challenges = $list end;
      ( .authority.provisioners[] | select(.type == "JWK" and .name == $name) | .claims.maxTLSCertDuration ) = $max
      | ( .authority.provisioners[] | select(.type == "JWK" and .name == $name) | .options.x509.template ) = $template
      | ( .authority.provisioners[] | select(.type == "ACME" and .name == $acme) ) |=
          ( .claims.minTLSCertDuration = $amin
          | .claims.defaultTLSCertDuration = $adef
          | .claims.maxTLSCertDuration = $amax
          | .options.x509.template = $template
          | challenges($achallenges) )
      | reduce $declared[] as $d (.;
          ( .authority.provisioners[] | select(.type == $d.type and .name == $d.name) ) |=
            ( .claims.minTLSCertDuration = $d.min
            | .claims.defaultTLSCertDuration = $d.lifetime
            | .claims.enableSSHCA = false
            | .claims.maxTLSCertDuration = $d.max
            | .options.x509.template = (if $d.profile == "client" then $client else $template end)
            | if $d.type == "ACME" then challenges($d.challenges) else . end ) )
      | ( { dns: $dns, ip: $ip, email: $email, uri: $uri } | with_entries(select(.value | length > 0)) ) as $allow
      | if ($allow | length) > 0 then .authority.policy.x509.allow = $allow else . end
    ' "$file")
  if [ "$wanted" = "$(jq . "$file")" ]; then
    log "configuration unchanged: '$provisioner' grants up to $max_lifetime, serverAuth only$(describe_policy "$file")$(describe_acme "$file")"
  else
    printf '%s\n' "$wanted" >"$file.new"
    mv "$file.new" "$file"
    log "configuration updated: '$provisioner' grants up to $max_lifetime, serverAuth only$(describe_policy "$file")$(describe_acme "$file")"
  fi
  describe_declared "$file"
}

describe_acme() {
  if jq -e --arg acme "$acme" '.authority.provisioners[]? | select(.type == "ACME" and .name == $acme)' "$1" >/dev/null; then
    printf "; '%s' issues for %s (%s to %s), serverAuth only, challenges %s" "$acme" "$acme_lifetime" "$acme_min" "$acme_max" \
      "$(jq -r 'if . == null then "http-01, dns-01, tls-alpn-01 (all, step-ca'\''s default)" else join(", ") end' <<<"$acme_challenge_list")"
  else
    printf "; no ACME provisioner '%s', nothing set for it" "$acme"
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
  check_acme_lifetimes
  check_acme_challenges
  load_declared
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

#### switching to a new intermediate, retiring the previous one

describe_cert() { printf "'%s' (%s)" "$(step certificate inspect --format json "$1" | jq -r .subject_dn)" "$(step certificate fingerprint "$1")"; }

# <dir>: the output of ceremony.sh --renew-intermediate, readable by this user
switch_intermediate() {
  local from=$1 file have want
  [ -f "$config" ] || die "no CA in $STEPPATH: nothing to switch"
  [ ! -e "$previous_cert" ] \
    || die "the previous intermediate $(describe_cert "$previous_cert") is still in its overlap: retire it first (--retire-intermediate)"
  for file in intermediate_ca.crt intermediate_ca_key password; do
    [ -s "$from/$file" ] || die "$from has no $file: give it the output of ceremony.sh --renew-intermediate"
  done
  for file in "$from"/*; do
    [ "${file##*/}" = intermediate_ca_key ] && continue
    if [ -f "$file" ] && grep -q 'PRIVATE KEY' "$file"; then
      die "$file holds a private key: nothing but the intermediate key goes to the CA - the root key stays out"
    fi
  done
  if [ -s "$from/root_ca.crt" ] \
    && [ "$(step certificate fingerprint "$from/root_ca.crt")" != "$(step certificate fingerprint "$root_cert")" ]; then
    die "$from/root_ca.crt is not the root of this CA ($(step certificate fingerprint "$root_cert")): a new root is a new CA, not a switch"
  fi
  step certificate verify "$from/intermediate_ca.crt" --roots "$root_cert" >/dev/null 2>"$STEPPATH/switch.log" \
    || { cat "$STEPPATH/switch.log" >&2; rm -f "$STEPPATH/switch.log"; die "$from/intermediate_ca.crt does not lead to the root of this CA: refused, nothing changed"; }
  rm -f "$STEPPATH/switch.log"
  want=$(step certificate key "$from/intermediate_ca.crt" 2>/dev/null) || die "cannot read the key of $from/intermediate_ca.crt"
  have=$(step crypto key public "$from/intermediate_ca_key" --password-file "$from/password" 2>/dev/null) \
    || die "cannot open $from/intermediate_ca_key with the password in $from/password"
  [ "$have" = "$want" ] || die "$from/intermediate_ca_key is not the key of $from/intermediate_ca.crt: refused, nothing changed"
  [ "$want" != "$(step certificate key "$intermediate_cert")" ] \
    || die "$from/intermediate_ca.crt has the key of the current intermediate: a renewal makes a new key"

  # the CA's own password: step-ca keeps the one it started with on SIGHUP
  rm -f "$intermediate_key.new"
  step crypto change-pass "$from/intermediate_ca_key" --password-file "$from/password" \
    --new-password-file "$ca_password" --out "$intermediate_key.new" --force >/dev/null 2>"$STEPPATH/switch.log" \
    || { cat "$STEPPATH/switch.log" >&2; rm -f "$STEPPATH/switch.log" "$intermediate_key.new"; die 'cannot re-encrypt the new key with the password of the CA; nothing changed'; }
  rm -f "$STEPPATH/switch.log"
  [ "$(step crypto key public "$intermediate_key.new" --password-file "$ca_password" 2>/dev/null)" = "$want" ] \
    || { rm -f "$intermediate_key.new"; die 'the re-encrypted key does not open with the password of the CA; nothing changed'; }
  install -m 0644 "$from/intermediate_ca.crt" "$intermediate_cert.new"

  # the current one becomes the previous one, then the new one takes its place
  cp -p "$intermediate_cert" "$previous_cert"
  cp -p "$intermediate_key" "$previous_key"
  mv "$intermediate_key.new" "$intermediate_key"
  mv "$intermediate_cert.new" "$intermediate_cert"
  log "switched the intermediate: $(describe_cert "$intermediate_cert") signs from now on"
  log "the previous intermediate $(describe_cert "$previous_cert") stays in the handover until --retire-intermediate"
}

retire_intermediate() {
  [ -f "$config" ] || die "no CA in $STEPPATH: nothing to retire"
  [ -e "$previous_cert" ] || die 'there is no previous intermediate: nothing to retire'
  local what
  what=$(describe_cert "$previous_cert")
  rm -f "$previous_key" "$previous_cert"
  log "retired the previous intermediate $what: out of the handover, its key deleted from $STEPPATH"
}

# As root: what is to be switched to, copied for the user of the image into
# a private directory of the volume.
stage_switch() {
  local from=$1 to=$STEPPATH/switch.staged file
  [ -d "$from" ] || die "$from does not exist: copy the output of ceremony.sh --renew-intermediate there (docker compose cp DIR ca:$switch_dir)"
  rm -rf "$to"
  mkdir -m 0700 "$to"
  # every file: switch_intermediate judges what is there
  for file in "$from"/*; do
    [ ! -f "$file" ] || install -o "$run_as" -m 0600 "$file" "$to/${file##*/}"
  done
  chown "$run_as" "$to"
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
  policy=$(jq -r '.authority.policy.x509.allow // empty | [ (.dns // [])[], (.ip // [])[], (.email // [])[], (.uri // [])[] ] | join(", ")' "${1:-$config}")
  if [ -n "$policy" ]; then printf ', names allowed: %s' "$policy"; else printf ', names not restricted'; fi
}

#### what the sick service needs: two certificates and one password

# During the overlap after a switch, intermediate_ca.crt holds the new
# intermediate and the previous one, in that order.
hand_over() {
  [ -d "$handover" ] || { log "no $handover: nothing is handed over"; return 0; }
  put "$root_cert"            "$handover/root_ca.crt"         0644
  if [ -f "$previous_cert" ]; then
    local both
    both=$(mktemp)
    cat "$intermediate_cert" "$previous_cert" >"$both"
    put "$both" "$handover/intermediate_ca.crt" 0644 'the new and the previous intermediate'
    rm -f "$both"
  else
    put "$intermediate_cert"  "$handover/intermediate_ca.crt" 0644
  fi
  put "$provisioner_password" "$handover/provisioner.pw"      0600
}

# Copy a file unless the copy is already the same, never leaving half a file.
put() {
  local from=$1 to=$2 mode=$3 what=${4:-}
  if [ -f "$to" ] && cmp -s "$from" "$to"; then
    return 0
  fi
  install -m "$mode" "$from" "$to.new"
  mv "$to.new" "$to"
  log "handed over ${to##*/}${what:+: $what}"
}

#### main

# step-ca reads ca.json again on SIGHUP. In a container of its own on the
# stopped CA's volume ("docker compose run ... ca", see the header) there is
# no step-ca to tell; the CA reads the volume when it starts.
reload() {
  if pkill -HUP -x step-ca; then
    log 'step-ca reloads its configuration (SIGHUP)'
  else
    log 'step-ca is not running: the change takes effect at the next start'
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
  --switch-intermediate-only)
    switch_intermediate "$2"
    exit 0
    ;;
  --switch-intermediate)
    # docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --switch-intermediate [DIR]
    from=${2:-$switch_dir}
    status=0
    if [ "$(id -u)" = 0 ]; then
      ( stage_switch "$from" ) || status=$?
      [ "$status" -ne 0 ] \
        || su "$run_as" -s /bin/bash -c 'exec /bin/bash "$0" --switch-intermediate-only "$1"' -- "$0" "$STEPPATH/switch.staged" \
        || status=$?
      rm -rf "$STEPPATH/switch.staged"
    else
      ( switch_intermediate "$from" ) || status=$?
    fi
    # the key and its password do not stay in the volume, taken or refused:
    # the operator has the original
    if [ "$from" = "$switch_dir" ] && [ -e "$switch_dir" ]; then rm -rf "$switch_dir" && log "removed $switch_dir"; fi
    [ "$status" -eq 0 ] || exit "$status"
    hand_over
    reload
    exit 0
    ;;
  --retire-intermediate-only)
    retire_intermediate
    exit 0
    ;;
  --retire-intermediate)
    # docker compose exec ca /bin/bash /usr/local/bin/init-ca.sh --retire-intermediate
    if [ "$(id -u)" = 0 ]; then
      su "$run_as" -s /bin/bash -c 'exec /bin/bash "$0" --retire-intermediate-only' -- "$0"
    else
      retire_intermediate
    fi
    hand_over
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
