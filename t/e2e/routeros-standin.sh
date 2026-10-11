#!/bin/sh
#
# A recording stand-in for a MikroTik router, for t/e2e/device-routeros.sh.
# It runs inside the stand-in container (Alpine, busybox sh) and is three
# things, by its first argument:
#
#   serve   the entrypoint (root): host keys, sshd, and a TLS server on 8443
#           that presents whatever "www-ssl" is set to - at the start a
#           throwaway self-signed certificate made here
#   login   the forced command of the deploy key (user sick): every upload
#           and every command the acme.sh hook "routeros" sends is recorded,
#           and the commands are answered as RouterOS 7 answered them in the
#           CHR run of docs/findings/device-routeros.md
#
# What is recorded, in /standin/record (readable by the script outside):
#
#   events          one line per event, in order:
#                     upload <protocol> <name> <size> <mode>
#                     exec <n>          (the command is in cmd-<n>)
#                     import <file> -> <certificate>
#                     service www-ssl <certificate>
#   cmd-<n>         the command line of exec <n>, byte for byte
#
# Never the content of an uploaded file: names, sizes and modes only.
#
# How RouterOS is imitated - only as far as the hook needs it, and the hook
# parses no output at all, it looks at exit codes:
#
#   :do {/system script remove ...}; /system script add name="X" ... source="..."
#        stores the command as script X
#   /system script run "X"
#        executes script X line by line: "/certificate remove [ find name=C ]",
#        "/certificate import file-name=\"F\"" (a certificate file becomes
#        F_0, a key file is attached to the certificate imported last),
#        "/file remove F", "/ip service set www-ssl|api-ssl certificate=C".
#        Like RouterOS, a failing line prints its error and the exit code
#        stays 0.
#   /system script remove "X"
#        removes script X
#   anything else
#        "bad command name ..." and exit 1, as RouterOS does for a syntax error
#
# Two switches, files in /standin/state, set from outside with docker exec:
#
#   fail-run    "/system script run" prints an error and exits 1, importing
#               nothing
#   noop-run    "/system script run" does nothing and exits 0 - what RouterOS
#               does when a line of a script fails at run time: it prints the
#               error and the exit code of the ssh session stays 0 (CHR
#               7.24.5, an import of a file that is not there)

set -u

home=/home/sick
record=/standin/record
state=/standin/state
store=/standin/certs

event() { printf '%s\n' "$*" >>"$record/events"; }

listing() {
  # name size mode, for the regular files in the home
  for f in "$home"/*; do
    [ -f "$f" ] || continue
    stat -c '%n %s %a' "$f" | sed "s|^$home/||"
  done
}

serve() {
  ssh-keygen -A >/dev/null
  mkdir -p "$record" "$state" "$store"
  chown sick:sick "$record" "$state" "$store" "$home"
  chmod 0755 "$record"
  chmod 0700 "$store"
  : >"$record/events"
  chown sick:sick "$record/events"
  # the certificate the "router" presents before anything was deployed
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=bootstrap.routeros.invalid \
    -keyout "$store/bootstrap.key" -out "$store/bootstrap.crt" 2>/dev/null
  chown sick:sick "$store"/bootstrap.*
  printf 'bootstrap\n' >"$state/www-ssl"
  chown sick:sick "$state/www-ssl"
  /usr/sbin/sshd -e
  serving=
  pid=
  while :; do
    want=$(cat "$state/www-ssl" 2>/dev/null)
    stamp="$want $(stat -c %Y "$store/$want.crt" 2>/dev/null)"
    if [ "$stamp" != "$serving" ] && [ -f "$store/$want.crt" ] && [ -f "$store/$want.key" ]; then
      [ -z "$pid" ] || kill "$pid" 2>/dev/null
      [ -z "$pid" ] || wait "$pid" 2>/dev/null
      openssl s_server -quiet -www -accept 8443 \
        -cert "$store/$want.crt" -key "$store/$want.key" >/dev/null 2>&1 &
      pid=$!
      serving=$stamp
    fi
    sleep 1
  done
}

transfer() {
  # an upload: run the real server as a child, record what it left
  protocol=$1
  shift
  before=$(listing)
  "$@"
  rc=$?
  listing | while read -r name size mode; do
    printf '%s\n' "$before" | grep -qxF "$name $size $mode" || event "upload $protocol $name $size $mode"
  done
  exit "$rc"
}

script_file() { printf '%s/script-%s' "$state" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_')"; }

run_script() {
  file=$(script_file "$1")
  if [ ! -f "$file" ]; then
    echo 'no such item (/system/script/run; line 1)'
    return 0
  fi
  if [ -f "$state/fail-run" ]; then
    echo 'failure: stand-in told to fail (/system/script/run; line 1)' >&2
    return 1
  fi
  [ -f "$state/noop-run" ] && return 0
  last=
  # the source: after source=", RouterOS "\n" separates the lines
  sed -e 's/.* source="//' "$file" | sed -e 's/\\n/\n/g' | while IFS= read -r line; do
    line=$(printf '%s' "$line" | sed -e 's/\\"/"/g')
    case $line in
      */certificate\ remove\ \[\ find\ name=*)
        c=$(printf '%s' "$line" | sed -e 's/.*find name=\([^ ]*\) \].*/\1/')
        rm -f "$store/$c.crt" "$store/$c.key"
        ;;
      */certificate\ import\ file-name=*)
        f=$(printf '%s' "$line" | sed -e 's/.*file-name="\([^"]*\)".*/\1/')
        if [ ! -f "$home/$f" ]; then
          echo 'input does not match any value of file-name (/certificate/import (file-name); line 1)'
        elif grep -q 'PRIVATE KEY' "$home/$f"; then
          if [ -n "$(cat "$state/last-import" 2>/dev/null)" ]; then
            c=$(cat "$state/last-import")
            cp "$home/$f" "$store/$c.key" && chmod 0600 "$store/$c.key"
            event "import $f -> $c (private key)"
          fi
        else
          c=${f}_0
          cp "$home/$f" "$store/$c.crt"
          printf '%s\n' "$c" >"$state/last-import"
          event "import $f -> $c"
        fi
        ;;
      *:do\ \{/file\ remove\ *)
        f=$(printf '%s' "$line" | sed -e 's/.*file remove \([^;]*\);.*/\1/')
        rm -f "$home/$f"
        ;;
      */ip\ service\ set\ www-ssl\ certificate=* | */ip\ service\ set\ api-ssl\ certificate=*)
        s=$(printf '%s' "$line" | sed -e 's/.*service set \([a-z-]*\) .*/\1/')
        c=$(printf '%s' "$line" | sed -e 's/.*certificate=\([^; ]*\).*/\1/')
        if [ -f "$store/$c.crt" ]; then
          event "service $s $c"
          [ "$s" = www-ssl ] && printf '%s\n' "$c" >"$state/www-ssl"
        else
          echo 'input does not match any value of certificate (/ip/service/set; line 1)'
        fi
        ;;
    esac
  done
  rm -f "$state/last-import"
  return 0
}

login() {
  cmd=${SSH_ORIGINAL_COMMAND-}
  case $cmd in
    internal-sftp* | */sftp-server* | sftp)
      transfer sftp /usr/lib/ssh/sftp-server
      ;;
    'scp -t '* | 'scp -d -t '*)
      # the legacy protocol (scp -O); the path is the user's own home
      # shellcheck disable=SC2086
      transfer scp $cmd
      ;;
  esac
  n=$(($(grep -c '^exec ' "$record/events") + 1))
  printf '%s' "$cmd" >"$record/cmd-$n"
  event "exec $n"
  case $cmd in
    ':do {/system script remove "'*'" } on-error={ }; /system script add name="'*)
      name=$(printf '%s' "$cmd" | sed -n -e '1s/.*script add name="\([^"]*\)".*/\1/p')
      printf '%s' "$cmd" >"$(script_file "$name")"
      exit 0
      ;;
    '/system script run "'*'"')
      name=${cmd#/system script run \"}
      run_script "${name%\"}"
      exit $?
      ;;
    '/system script remove "'*'"')
      name=${cmd#/system script remove \"}
      file=$(script_file "${name%\"}")
      if [ -f "$file" ]; then rm -f "$file"; else echo 'no such item (/system/script/remove; line 1)'; fi
      exit 0
      ;;
  esac
  printf 'bad command name %s (line 1 column 2)\n' "$(printf '%s' "$cmd" | sed -e 's/^[^a-z]*//; s/[^a-z-].*//')"
  exit 1
}

case ${1-} in
  serve) serve ;;
  login) login ;;
  *) echo "usage: $0 serve|login" >&2; exit 2 ;;
esac
