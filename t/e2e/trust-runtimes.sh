#!/bin/bash
#
# Does the runtime trust the CA? Evidence for the trust page and the handbook (k36, part of P4/k14).
#
# The trust page tells people how to make a client trust the root of the CA. "Client" is
# a lot of different things: curl and git, a Python script, a JVM, a Node process, a Go
# binary, a container image, a pod. Each loads trust from somewhere else, at another time,
# with another TLS library. This script asks each of them, with the real client.
#
# A throwaway PKI is made at run time with openssl, in a private temporary directory:
#
#   root R -> intermediate I, name-constrained to DNS:example.internal (pathlen 0)
#   leaf "good"     service.example.internal, by I, served with I          port 4431
#   leaf "wrong"    wrong.example.internal, by I (connected to as service)  port 4432
#   leaf "outside"  outside.example.org, by I: out of the constraint        port 4433
#   leaf "other"    service.example.internal, by an unrelated root          port 4434
#   leaf "free"     outside.example.org, by I2, an UNCONSTRAINED second
#                   intermediate of R: the control for "outside"            port 4435
#
# One container (openssl s_server, five listeners) on a labelled Docker network answers
# to service.example.internal and outside.example.org. Nothing is published to the host.
#
# Per consumer ("variant"), each with the expected and the observed result:
#
#   1   before the install                              refused
#   2   after the install, the documented way           accepted (or refused, where the
#                                                       way is known not to reach the consumer)
#   3   leaf with the wrong name                        refused
#   4   leaf outside the name constraint                refused
#   4k  the same name through the unconstrained         accepted when step 2 was: shows that
#       intermediate (control for 4)                    4 was refused because of the constraint
#   5   the leaf of the unrelated CA                    refused
#   6   after the removal                               refused
#
# and, where the consumer is a process that lives on, how it loads trust:
#
#   wA  a process started BEFORE the install: does it see the root without a restart?
#   wB  a process started WHILE installed: does it still trust the root after the removal?
#
# The consumers (variants) and where they run:
#
#   python image   curl-system, curl-cacert, curl-sslcertfile, git-system, git-sslCAInfo, py-urllib-system,
#                  py-ssl-system, py-ssl-sslcertfile, py-requests-certifi,
#                  py-requests-bundle-env, py-requests-rootfile, py-requests-sslcertfile,
#                  py-requests-truststore
#   Temurin JDK    java-sysstore, java-cacerts (keytool), java-truststore (-D)
#   Node           node-default, node-system (--use-system-ca), node-extra (NODE_EXTRA_CA_CERTS)
#   Go             go-system, go-sslcertfile
#   a built image  image-baked (Dockerfile: COPY the root, update-ca-certificates)
#   a k3d cluster  pod-bundle-subpath, pod-dir-cm, pod-sslcertfile (a ConfigMap into a pod)
#
# A line is one of
#   CONTROL      must hold or the harness proves nothing: ends the run with exit 1
#   PASS/FAIL    a claim: "refused" for the negatives; "accepted" or "refused" for step 2 of
#                a way whose result is known beforehand. FAIL is a finding, not an error
#   RECORD       what happened, no verdict (loading behaviour, things not known beforehand)
#
# Exit code: 0 when the harness worked (also with FAIL lines), 1 when it did not (a control
# failed, a program is missing, something is left behind).
#
# Not tried is part of the output: the Docker daemon (/etc/docker/certs.d) and BuildKit
# registry trust need a daemon of their own; trust-manager needs cert-manager and charts
# from the internet. See docs/findings/trust-runtimes.md.
#
# Needs Docker, and k3d and kubectl for the pods (without them "pods" is skipped with a
# RECORD), and internet for images and packages (pip install of requests and truststore
# inside the Python container). Everything created carries --label sick=1 and --label
# sick-e2e=trust-runtimes and is removed by those labels at the end, also after a failure
# or Ctrl-C. The k3d cluster is named sick-p4-rt, has its own kubeconfig in the private
# temporary directory (never ~/.kube/config, never a context switch) and is deleted by
# that exact name. No volume is created (no anonymous ones either: --rm, docker rm -v).
# Nothing is pruned; the pulled images stay as a cache. Keys and certificates exist only
# in the private temporary directory (0700) and in the containers that mount it read-only.
#
# Parameters, all from the environment:
#
#   SICK_E2E_RT_PYTHON    python image   (python:3)
#   SICK_E2E_RT_JAVA      JDK image      (eclipse-temurin:25-jdk)
#   SICK_E2E_RT_NODE      node image     (node:lts)
#   SICK_E2E_RT_GO        golang image   (golang:1)
#   SICK_E2E_RT_CURL      client pod     (buildpack-deps:stable-curl)
#   SICK_E2E_RT_OPENSSL   server pod     (alpine/openssl)
#   SICK_E2E_RT_ONLY      comma list of: python java node go image pods  (all of them)

set -uo pipefail

LABEL=sick-e2e=trust-runtimes
NET=sick-e2e-trust-rt
SRV=sick-e2e-trust-rt-server
CLUSTER=sick-p4-rt
HOST_GOOD=service.example.internal
HOST_OUT=outside.example.org

IMG_python=${SICK_E2E_RT_PYTHON:-python:3}
IMG_java=${SICK_E2E_RT_JAVA:-eclipse-temurin:25-jdk}
IMG_node=${SICK_E2E_RT_NODE:-node:lts}
IMG_go=${SICK_E2E_RT_GO:-golang:1}
IMG_curlpod=${SICK_E2E_RT_CURL:-buildpack-deps:stable-curl}
IMG_srvpod=${SICK_E2E_RT_OPENSSL:-alpine/openssl}
ONLY=${SICK_E2E_RT_ONLY:-python,java,node,go,image,pods}

# variant  container  expected-at-step-2  class  watch-A  watch-B
VARIANTS='
curl-system             python accepted EXPECT 0 0
curl-cacert             python accepted EXPECT 0 0
curl-sslcertfile        python accepted RECORD 0 0
git-system              python accepted EXPECT 0 0
git-sslCAInfo           python accepted EXPECT 0 0
py-urllib-system        python accepted EXPECT 1 1
py-ssl-system           python accepted EXPECT 1 1
py-ssl-sslcertfile      python accepted EXPECT 0 0
py-requests-certifi     python refused  EXPECT 0 0
py-requests-bundle-env  python accepted EXPECT 0 0
py-requests-rootfile    python accepted EXPECT 0 0
py-requests-sslcertfile python refused  RECORD 0 0
py-requests-truststore  python accepted EXPECT 0 0
java-sysstore           java   accepted RECORD 1 1
java-cacerts            java   accepted EXPECT 1 1
java-truststore         java   accepted EXPECT 0 0
node-default            node   refused  RECORD 0 0
node-system             node   accepted EXPECT 1 1
node-extra              node   accepted EXPECT 0 1
go-system               go     accepted EXPECT 1 1
go-sslcertfile          go     accepted EXPECT 0 1
'

umask 077
here=$(cd "$(dirname "$0")" && pwd)
dlabels=(--label sick=1 --label "$LABEL")
want() { [[ ",$ONLY," == *",$1,"* ]]; }

#### output ###################################################################

npass=0; nfail=0; nrecord=0
declare -A TBL=() MARK=() LOADA=() LOADB=() CONT=()
ORDER=()
VERS=()
EXTRA=()
say()  { printf '%s\n' "$*"; }
note() { printf -- '--- %s\n' "$*"; }
die()  { printf 'ERROR %s\n' "$*" >&2; exit 1; }
record() { say "RECORD   $*"; nrecord=$((nrecord+1)); }

# report <class> <variant> <step> <expected> <observed line> <what>
report() {
  local class=$1 v=$2 s=$3 exp=$4 line=$5 what=$6 word reason='' mark='' out
  word=${line%%[: ]*}
  [[ $line == *': '* ]] && reason=${line#*: }
  case $word in
    accepted|refused) ;;
    *) die "[$v] step $s gave neither accepted nor refused: $line" ;;
  esac
  TBL[$v|$s]=$word
  [ "$word" = "$exp" ] || { mark='  <== NOT AS EXPECTED'; MARK[$v|$s]='!'; }
  reason=${reason:0:150}
  out=$(printf '[%s] %-3s expected %-8s observed %-8s %s%s%s' "$v" "$s" "$exp" "$word" "$what" "${reason:+  ($reason)}" "$mark")
  case $class in
    CONTROL) if [ "$word" = "$exp" ]; then say "CONTROL  $out"; else say "CONTROL-FAIL  $out" >&2; die "a control failed: $v $s"; fi ;;
    EXPECT)  if [ "$word" = "$exp" ]; then say "PASS     $out"; npass=$((npass+1)); else say "FAIL     $out"; nfail=$((nfail+1)); fi ;;
    RECORD)  say "RECORD   $out"; nrecord=$((nrecord+1)) ;;
  esac
}

#### teardown #################################################################

work=$(mktemp -d "${TMPDIR:-/tmp}/sick-e2e-trust-rt.XXXXXX")
chmod 700 "$work"
mkdir -p "$work/pki" "$work/pub" "$work/probes" "$work/img" "$work/podpki"
CLUSTER_MADE=''
KC=$work/kubeconfig

leftovers() {
  docker ps -a --format '{{.Names}}' | grep -E '^(sick-e2e-trust-rt|k3d-sick-p4-rt)' | sed 's/^/container /'
  docker ps -aq --filter label=sick-e2e=trust-runtimes | sed 's/^/labelled container /'
  docker network ls --format '{{.Name}}' | grep -E '^(sick-e2e-trust-rt|k3d-sick-p4-rt)' | sed 's/^/network /'
  docker network ls -q --filter label=sick-e2e=trust-runtimes | sed 's/^/labelled network /'
  docker volume ls --format '{{.Name}}' | grep -E '^(sick-e2e-trust-rt|k3d-sick-p4-rt)' | sed 's/^/volume /'
  docker volume ls -q --filter label=sick-e2e=trust-runtimes | sed 's/^/labelled volume /'
  docker image ls -q --filter label=sick-e2e=trust-runtimes | sed 's/^/labelled image /'
  docker image ls --format '{{.Repository}}' | grep -E '^sick-e2e-trust-rt' | sed 's/^/image /'
  k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -x "$CLUSTER" | sed 's/^/k3d cluster /'
  docker volume ls -q | sort >"$work/vol.after"
  comm -13 "$work/vol.before" "$work/vol.after" | sed 's/^/volume not there at the start: /'
  [ "$(stat -c %Y "$HOME/.kube/config" 2>/dev/null)" = "$KUBE_MTIME" ] || echo 'the default kubeconfig changed'
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  printf '\n=== teardown\n'
  # the cluster by its exact name; everything else by label only, never by name
  if [ -n "$CLUSTER_MADE" ]; then KUBECONFIG=$KC k3d cluster delete "$CLUSTER" >/dev/null 2>&1; fi
  docker ps -aq --filter label=sick=1 --filter "label=$LABEL" | xargs -r docker rm -f -v >/dev/null 2>&1
  docker network ls -q --filter label=sick=1 --filter "label=$LABEL" | xargs -r docker network rm >/dev/null 2>&1
  docker image ls -q --filter label=sick=1 --filter "label=$LABEL" | xargs -r docker rmi -f >/dev/null 2>&1
  local left
  left=$(leftovers)
  if [ -n "$left" ]; then
    printf '%s\n' "$left" | sed 's/^/      | /' >&2
    printf 'FAIL  left behind (listed above)\n' >&2
    rc=1
  else
    say 'PASS  no container, network, volume or image labelled sick-e2e=trust-runtimes or named sick-e2e-trust-rt*/k3d-sick-p4-rt* is left,'
    say '      no volume that was not there at the start, no k3d cluster sick-p4-rt, ~/.kube/config untouched'
  fi
  printf -- '--- the pulled images stay as a cache; nothing was pruned\n'
  rm -rf "${work:?}"
  if [ "$rc" -eq 0 ]; then printf '\nDONE\n'; else printf '\nFAILED (exit %s)\n' "$rc" >&2; fi
  exit "$rc"
}

command -v docker >/dev/null || die 'docker is not installed'
docker info >/dev/null 2>&1 || die 'the Docker daemon does not answer'
command -v openssl >/dev/null || die 'openssl is not installed'
docker volume ls -q | sort >"$work/vol.before"
KUBE_MTIME=$(stat -c %Y "$HOME/.kube/config" 2>/dev/null)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[ -z "$(docker ps -a --format '{{.Names}}' | grep -E '^sick-e2e-trust-rt')" ] || die 'a container sick-e2e-trust-rt* exists already; remove it by hand'

#### the PKI (on the host, in the private directory) ##########################

make_pki() {
  cd "$work/pki" || die cd
  ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null || die "key $1"; }
  local r
  for r in "root:Trust Runtimes Root R" "other:Trust Runtimes Unrelated Root"; do
    ec "${r%%:*}.key"
    openssl req -x509 -new -key "${r%%:*}.key" -sha256 -days 2 -subj "/CN=${r#*:}" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -addext subjectKeyIdentifier=hash -out "${r%%:*}.pem" 2>/dev/null || die "root ${r%%:*}"
  done
  inter() { # name cn extra-extension-line
    ec "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null || die "csr $1"
    { printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'
      printf 'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
      [ -n "$3" ] && printf '%s\n' "$3"; } >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA root.pem -CAkey root.key -CAcreateserial -days 2 -sha256 \
      -extfile "$1.ext" -out "$1.pem" 2>/dev/null || die "signing $1"
  }
  inter inter  'Trust Runtimes Intermediate (constrained)' 'nameConstraints=critical,permitted;DNS:example.internal'
  inter inter2 'Trust Runtimes Intermediate (unconstrained)' ''
  leaf() { # name dns signer
    ec "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null || die "csr $1"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\nauthorityKeyIdentifier=keyid\n' "$2" >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 2 -sha256 \
      -extfile "$1.ext" -out "$1.pem" 2>/dev/null || die "signing $1"
  }
  leaf good       "$HOST_GOOD"           inter
  leaf wrong      wrong.example.internal inter
  leaf outside    "$HOST_OUT"            inter
  leaf other-leaf "$HOST_GOOD"           other
  leaf free       "$HOST_OUT"            inter2
  cp root.pem "$work/pub/root.pem"
  # what the server pod gets: no root key, no intermediate key
  cp good.pem good.key wrong.pem wrong.key outside.pem outside.key other-leaf.pem other-leaf.key \
     free.pem free.key inter.pem inter2.pem "$work/podpki/"
  cd "$here" || true
}

#### the programs the consumers run ###########################################

write_probes() {
  local p=$work/probes

  cat >"$p/serve.sh" <<'EOF'
#!/bin/sh
cd /pki || exit 1
s() { port=$1; cert=$2; shift 2
  openssl s_server -accept "$port" -www -no-CAfile -no-CApath -no-CAstore \
    -cert "$cert.pem" -key "$cert.key" "$@" >"/tmp/srv-$port.log" 2>&1 & }
s 4431 good -cert_chain inter.pem
s 4432 wrong -cert_chain inter.pem
s 4433 outside -cert_chain inter.pem
s 4434 other-leaf
s 4435 free -cert_chain inter2.pem
wait
EOF

  cat >"$p/Probe.java" <<'EOF'
import javax.net.ssl.*;
import java.io.*;
import java.net.*;

public class Probe {
  static String deepest(Throwable t) {
    Throwable c = t;
    while (c.getCause() != null) c = c.getCause();
    return c.getClass().getSimpleName() + ": " + String.valueOf(c.getMessage()).replace('\n', ' ');
  }
  static String attempt(String host, String port) {
    try {
      HttpsURLConnection c = (HttpsURLConnection) new URL("https://" + host + ":" + port + "/").openConnection();
      c.setConnectTimeout(5000);
      c.setReadTimeout(5000);
      c.setUseCaches(false);
      c.setRequestProperty("Connection", "close");
      c.getResponseCode();
      c.disconnect();
      return "accepted";
    } catch (SSLException e) {
      return "refused: " + deepest(e);
    } catch (IOException e) {
      return "error: " + deepest(e);
    }
  }
  public static void main(String[] a) throws Exception {
    if (a.length > 2 && a[2].equals("watch")) {
      while (true) {
        System.out.println(System.currentTimeMillis() + " " + attempt(a[0], a[1]));
        System.out.flush();
        Thread.sleep(1000);
      }
    }
    System.out.println(attempt(a[0], a[1]));
  }
}
EOF

  cat >"$p/probe.py" <<'EOF'
import sys, ssl, socket, time, urllib.request

mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
watch = len(sys.argv) > 4 and sys.argv[4] == 'watch'

if mode == 'requests-truststore':
    import truststore
    truststore.inject_into_ssl()
    mode = 'requests'
if mode == 'requests':
    import requests


def related(e):
    seen, todo = [], [e]
    while todo:
        x = todo.pop()
        if x is None or any(x is s for s in seen):
            continue
        seen.append(x)
        todo += [y for y in (x.__cause__, x.__context__, getattr(x, 'reason', None)) if isinstance(y, BaseException)]
        todo += [a for a in getattr(x, 'args', ()) if isinstance(a, BaseException)]
    return seen


def classify(e):
    for x in related(e):
        if isinstance(x, ssl.SSLCertVerificationError):
            return 'refused: ' + str(x).replace('\n', ' ')
    if 'CERTIFICATE_VERIFY_FAILED' in str(e):
        return 'refused: ' + str(e).replace('\n', ' ')
    return 'error: ' + type(e).__name__ + ': ' + str(e).replace('\n', ' ')


ctx_once = ssl.create_default_context() if mode == 'ssl' else None


def attempt():
    try:
        if mode == 'ssl':
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx_once.wrap_socket(raw, server_hostname=host):
                    pass
        elif mode == 'urllib':
            urllib.request.urlopen('https://%s:%d/' % (host, port), timeout=5).read(1)
        elif mode == 'requests':
            requests.get('https://%s:%d/' % (host, port), timeout=5, headers={'Connection': 'close'})
        else:
            return 'error: unknown mode ' + mode
        return 'accepted'
    except Exception as e:
        return classify(e)


if watch:
    while True:
        print(int(time.time() * 1000), attempt(), flush=True)
        time.sleep(1)
print(attempt())
EOF

  cat >"$p/probe.js" <<'EOF'
const https = require('https');
const [host, port, watch] = process.argv.slice(2);
const NET = ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'EPIPE'];

function attempt(cb) {
  let done = false;
  const fin = (r) => { if (!done) { done = true; cb(r); } };
  const req = https.request({ host, port: +port, path: '/', agent: false, timeout: 5000,
                              headers: { Connection: 'close' } }, (res) => {
    res.on('data', () => {});
    res.on('end', () => fin('accepted'));
    res.on('close', () => fin('accepted'));
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', (e) => {
    if (NET.includes(e.code) || e.message === 'timeout') fin('error: ' + (e.code || e.message));
    else fin('refused: ' + (e.code || '') + ' ' + e.message.replace(/\n/g, ' '));
  });
  req.end();
}

if (watch === 'watch') {
  const loop = () => attempt((r) => { console.log(Date.now() + ' ' + r); setTimeout(loop, 1000); });
  loop();
} else {
  attempt((r) => console.log(r));
}
EOF

  cat >"$p/main.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func attempt(host, port string, c *http.Client) string {
	resp, err := c.Get("https://" + host + ":" + port + "/")
	if err == nil {
		resp.Body.Close()
		return "accepted"
	}
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if strings.Contains(s, "x509:") {
		return "refused: " + s
	}
	return "error: " + s
}

func main() {
	host, port := os.Args[1], os.Args[2]
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	if len(os.Args) > 3 && os.Args[3] == "watch" {
		for {
			fmt.Println(time.Now().UnixMilli(), attempt(host, port, c))
			time.Sleep(time.Second)
		}
	}
	fmt.Println(attempt(host, port, c))
}
EOF

  # runs INSIDE a consumer container: /pki/root.pem and /probes are mounted read-only
  cat >"$p/variants.sh" <<'EOF'
#!/bin/bash
# variants.sh <action> [variant host port]   -- inside a consumer container
set -u
action=$1; v=${2:-}; H=${3:-}; P=${4:-}
ROOT=/pki/root.pem
SYSCRT=/usr/local/share/ca-certificates/sick-root.crt
OWN=/tmp/sick-own; CA=$OWN/ca.pem; STORE=$OWN/trust.p12
WATCH=/tmp/sick-watch
mkdir -p "$OWN" "$WATCH"

sys_install() { cp "$ROOT" "$SYSCRT" && update-ca-certificates >/tmp/uca.log 2>&1 || { cat /tmp/uca.log >&2; exit 2; }; }
sys_remove()  { rm -f "$SYSCRT"; update-ca-certificates --fresh >/tmp/uca.log 2>&1 || { cat /tmp/uca.log >&2; exit 2; }; }
own_install() { cp "$ROOT" "$CA"; }
own_remove()  { rm -f "$CA"; }

# build <mode>: sets ENVV, CMD, CLASSIFY. The programs take "watch" as the last argument, any
# other word (here: once) means one attempt.
build() {
  local m=$1
  ENVV=(); CMD=(); CLASSIFY=native
  case $v in
    curl-system)  CLASSIFY=curl; CMD=(curl -sS -o /dev/null --max-time 10 "https://$H:$P/") ;;
    curl-cacert)  CLASSIFY=curl; CMD=(curl -sS -o /dev/null --max-time 10)
                  [ -f "$CA" ] && CMD+=(--cacert "$CA"); CMD+=("https://$H:$P/") ;;
    curl-sslcertfile) CLASSIFY=curl; CMD=(curl -sS -o /dev/null --max-time 10 "https://$H:$P/")
                  [ -f "$CA" ] && ENVV=("SSL_CERT_FILE=$CA") ;;
    git-system)   CLASSIFY=git; ENVV=(GIT_TERMINAL_PROMPT=0); CMD=(git ls-remote "https://$H:$P/repo.git") ;;
    git-sslCAInfo) CLASSIFY=git; ENVV=(GIT_TERMINAL_PROMPT=0); CMD=(git)
                  [ -f "$CA" ] && CMD+=(-c "http.sslCAInfo=$CA"); CMD+=(ls-remote "https://$H:$P/repo.git") ;;
    py-urllib-system) CMD=(python3 /probes/probe.py urllib "$H" "$P" "$m") ;;
    py-ssl-system)    CMD=(python3 /probes/probe.py ssl "$H" "$P" "$m") ;;
    py-ssl-sslcertfile) CMD=(python3 /probes/probe.py ssl "$H" "$P" "$m"); [ -f "$CA" ] && ENVV=("SSL_CERT_FILE=$CA") ;;
    py-requests-certifi) CMD=(python3 /probes/probe.py requests "$H" "$P" "$m") ;;
    py-requests-bundle-env) ENVV=(REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt)
                  CMD=(python3 /probes/probe.py requests "$H" "$P" "$m") ;;
    py-requests-rootfile) CMD=(python3 /probes/probe.py requests "$H" "$P" "$m"); [ -f "$CA" ] && ENVV=("REQUESTS_CA_BUNDLE=$CA") ;;
    py-requests-sslcertfile) CMD=(python3 /probes/probe.py requests "$H" "$P" "$m"); [ -f "$CA" ] && ENVV=("SSL_CERT_FILE=$CA") ;;
    py-requests-truststore) CMD=(python3 /probes/probe.py requests-truststore "$H" "$P" "$m") ;;
    java-sysstore|java-cacerts) CMD=(java -cp /tmp/jprobe Probe "$H" "$P" "$m") ;;
    java-truststore) CMD=(java)
                  [ -f "$STORE" ] && CMD+=("-Djavax.net.ssl.trustStore=$STORE" -Djavax.net.ssl.trustStorePassword=changeit)
                  CMD+=(-cp /tmp/jprobe Probe "$H" "$P" "$m") ;;
    node-default) CMD=(node /probes/probe.js "$H" "$P" "$m") ;;
    node-system)  CMD=(node --use-system-ca /probes/probe.js "$H" "$P" "$m") ;;
    node-extra)   ENVV=("NODE_EXTRA_CA_CERTS=$CA"); CMD=(node /probes/probe.js "$H" "$P" "$m") ;;
    go-system)    CMD=(/tmp/gprobe "$H" "$P" "$m") ;;
    go-sslcertfile) CMD=(/tmp/gprobe "$H" "$P" "$m"); [ -f "$CA" ] && ENVV=("SSL_CERT_FILE=$CA") ;;
    *) echo "unknown variant $v" >&2; exit 2 ;;
  esac
}

run_classified() {
  local out rc
  case $CLASSIFY in
    native)
      out=$(env "${ENVV[@]}" "${CMD[@]}" 2>/tmp/probe.err | tail -n 1)
      echo "${out:-error: no output: $(tail -c 500 /tmp/probe.err | tr '\n' ' ')}" ;;
    curl)
      out=$(env "${ENVV[@]}" "${CMD[@]}" 2>&1); rc=$?
      case $rc in
        0)  echo accepted ;;
        60) echo "refused: $(sed -n 's/^curl: ([0-9]*) //p' <<<"$out" | head -n 1)" ;;
        *)  echo "error: curl rc=$rc $(tr '\n' ' ' <<<"$out")" ;;
      esac ;;
    git)
      out=$(env "${ENVV[@]}" timeout 25 "${CMD[@]}" 2>&1); rc=$?
      if grep -qiE 'resolve host|connection refused|timed out|Failed to connect' <<<"$out" || [ $rc -eq 124 ]; then
        echo "error: git rc=$rc $(tr '\n' ' ' <<<"$out")"
      elif grep -qiE 'certificate|subject name' <<<"$out"; then
        echo "refused: $(grep -iE 'certificate|subject name' <<<"$out" | head -n 1 | sed 's/^fatal: //')"
      else
        echo accepted   # TLS went through; what git says now is about HTTP or the repository
      fi ;;
  esac
}

case $action in
  prep)
    case $v in
      python) pip install -q --disable-pip-version-check requests truststore >/tmp/pip.log 2>&1 || { tail -5 /tmp/pip.log >&2; exit 2; } ;;
      java)   javac -d /tmp/jprobe /probes/Probe.java || exit 2 ;;
      go)     (cd /tmp && go build -o /tmp/gprobe /probes/main.go) || exit 2 ;;
      node)   : ;;
    esac
    command -v update-ca-certificates >/dev/null || { echo 'no update-ca-certificates' >&2; exit 2; } ;;
  supported)
    case $v in
      node-system) node --help | grep -q -- '--use-system-ca' ;;
      *) true ;;
    esac ;;
  install)
    case $v in
      java-cacerts)   keytool -importcert -cacerts -storepass changeit -noprompt -alias sick-root -file "$ROOT" >/dev/null || exit 2 ;;
      java-truststore) keytool -importcert -keystore "$STORE" -storetype PKCS12 -storepass changeit -noprompt -alias sick-root -file "$ROOT" >/dev/null || exit 2 ;;
      curl-cacert|curl-sslcertfile|git-sslCAInfo|py-ssl-sslcertfile|py-requests-rootfile|py-requests-sslcertfile|node-extra|go-sslcertfile) own_install ;;
      *) sys_install ;;
    esac ;;
  remove)
    case $v in
      java-cacerts)   keytool -delete -cacerts -storepass changeit -alias sick-root >/dev/null 2>&1; true ;;
      java-truststore) rm -f "$STORE" ;;
      curl-cacert|curl-sslcertfile|git-sslCAInfo|py-ssl-sslcertfile|py-requests-rootfile|py-requests-sslcertfile|node-extra|go-sslcertfile) own_remove ;;
      *) sys_remove ;;
    esac ;;
  probe)
    build once; run_classified ;;
  watch)
    build watch; echo $$ >"$WATCH/$v.pid"; : >"$WATCH/$v.log"
    exec env "${ENVV[@]}" "${CMD[@]}" >"$WATCH/$v.log" 2>&1 ;;
  update-system-store)
    update-ca-certificates >/tmp/uca.log 2>&1; true ;;
  versions)
    . /etc/os-release; echo "os: $PRETTY_NAME"
    case $v in
      python)
        echo "python: $(python3 -V 2>&1)"
        python3 -c 'import ssl,requests,urllib3,certifi,truststore,importlib.metadata as m; print("python ssl: "+ssl.OPENSSL_VERSION); print("requests: "+requests.__version__+"  urllib3: "+urllib3.__version__); print("certifi: "+m.version("certifi")+" ("+certifi.where()+")"); print("truststore: "+m.version("truststore"))'
        echo "curl: $(curl -V | head -n 1)"
        echo "git: $(git --version)"
        echo "git-remote-https links: $(ldd "$(git --exec-path)/git-remote-https" | grep -oE 'libcurl[^ ]*|libssl[^ ]*|libgnutls[^ ]*' | sort -u | tr '\n' ' ')"
        echo "openssl: $(openssl version)" ;;
      java)
        jh=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")
        echo "java: $(java -version 2>&1 | tr '\n' '|')"
        echo "cacerts: $(ls -l "$jh/lib/security/cacerts" | awk '{print $1, $5, $9, $10, $11}')"
        echo "ca-certificates-java: $(dpkg -l ca-certificates-java 2>&1 | tail -n 1 | cut -c1-70)"
        echo "/etc/ssl/certs/java: $(ls -d /etc/ssl/certs/java 2>&1)"
        echo "/etc/ca-certificates/update.d: $(ls /etc/ca-certificates/update.d 2>&1 | tr '\n' ' ')" ;;
      node)
        echo "node: $(node -v)"
        echo "node openssl: $(node -p process.versions.openssl)"
        echo "--use-system-ca in --help: $(node --help | grep -c -- '--use-system-ca')" ;;
      go)
        echo "go: $(go version)" ;;
    esac ;;
  *) echo "unknown action $action" >&2; exit 2 ;;
esac
EOF
}

#### Docker plumbing ###########################################################

# vx <container-key> <action> [variant host port]
vx() { local key=$1; shift; docker exec "${CONT[$key]}" bash /probes/variants.sh "$@"; }

start_consumer() { # key image
  local key=$1 image=$2 name=sick-e2e-trust-rt-$1 line
  docker run -d --name "$name" "${dlabels[@]}" --network "$NET" -v "$work/pub:/pki:ro" \
    -v "$work/probes:/probes:ro" "$image" sleep infinity >/dev/null || die "starting $key ($image)"
  CONT[$key]=$name
  note "preparing $key ($image)"
  vx "$key" prep "$key" || die "preparing $key"
  while IFS= read -r line; do VERS+=("[$key] $line"); done < <(vx "$key" versions "$key")
  VERS+=("[$key] image: $image $(docker image inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null)")
}

start_server() {
  docker network create "${dlabels[@]}" "$NET" >/dev/null || die 'network'
  docker run -d --name "$SRV" "${dlabels[@]}" --network "$NET" \
    --network-alias "$HOST_GOOD" --network-alias "$HOST_OUT" \
    -v "$work/pki:/pki:ro" -v "$work/probes:/probes:ro" "$IMG_python" sh /probes/serve.sh >/dev/null || die 'server'
  # controls: the PKI and the server do what they are meant to, checked with openssl s_client
  ctl() { # port host expected what
    local out i word=''
    for i in $(seq 40); do
      out=$(docker exec "$SRV" openssl s_client -connect "127.0.0.1:$1" -servername "$2" -verify_hostname "$2" \
        -verify_return_error -no-CApath -no-CAstore -CAfile /pki/root.pem </dev/null 2>&1)
      if grep -q '^Verification: OK' <<<"$out"; then word=accepted; break; fi
      if grep -q '^Verification error' <<<"$out"; then word="refused: $(sed -n 's/^Verification error: //p' <<<"$out" | head -n 1)"; break; fi
      sleep 0.3
    done
    [ -n "$word" ] || die "server port $1 gave no verdict: $out"
    report CONTROL "server" "$1" "$3" "$word" "$4"
  }
  ctl 4431 "$HOST_GOOD" accepted 'openssl s_client with R: good leaf, chain sent'
  ctl 4432 "$HOST_GOOD" refused  'openssl s_client with R: wrong name'
  ctl 4433 "$HOST_OUT"  refused  'openssl s_client with R: out of the name constraint'
  ctl 4434 "$HOST_GOOD" refused  'openssl s_client with R: unrelated CA'
  ctl 4435 "$HOST_OUT"  accepted 'openssl s_client with R: same name, unconstrained intermediate'
  local n
  n=$(docker exec "$SRV" sh -c "openssl s_client -connect 127.0.0.1:4431 -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'")
  [ "$n" = 2 ] || die "the good server sends $n certificates, not 2"
  say 'CONTROL  [server] the good server sends leaf and intermediate (2 certificates), never the root'
  n=$(docker exec "$SRV" openssl x509 -in /pki/inter.pem -noout -text | grep -A2 'Name Constraints' | tr -d '\n ' )
  say "CONTROL  [server] intermediate: $n"
  case $n in *DNS:example.internal*) ;; *) die 'the intermediate has no name constraint' ;; esac
}

# watchers: a process of the consumer that tries the good server once a second
watch_start() { # key variant
  local i
  docker exec -d "${CONT[$1]}" bash /probes/variants.sh watch "$2" "$HOST_GOOD" 4431
  for i in $(seq 80); do [ -n "$(watch_last "$1" "$2")" ] && return 0; sleep 0.5; done
  die "the watcher of $2 wrote nothing"
}
watch_lines() { docker exec "${CONT[$1]}" bash -c "wc -l </tmp/sick-watch/$2.log"; }
watch_last()  { docker exec "${CONT[$1]}" bash -c "tail -n 1 /tmp/sick-watch/$2.log 2>/dev/null | cut -d' ' -f2-"; }
watch_stop()  { docker exec "${CONT[$1]}" bash -c "kill \$(cat /tmp/sick-watch/$2.pid) 2>/dev/null; true"; }
watch_fresh() { # key variant: wait for two lines written after now
  local n i; n=$(watch_lines "$1" "$2")
  for i in $(seq 60); do [ "$(watch_lines "$1" "$2")" -ge $((n+2)) ] && return 0; sleep 0.5; done
  die "the watcher of $2 stopped writing"
}

step() { # variant id probe-function host port expected class what
  local v=$1 id=$2 fn=$3 h=$4 p=$5 exp=$6 class=$7 what=$8 r
  r=$($fn "$h" "$p") || die "[$v] probe for step $id failed: $r"
  report "$class" "$v" "$id" "$exp" "$r" "$what"
}

# the steps 2..5 after the install; $1 variant, $2 probe function, $3 expected at step 2, $4 class
steps_main() {
  local v=$1 fn=$2 exp2=$3 class2=$4 hint=''
  step "$v" 2 "$fn" "$HOST_GOOD" 4431 "$exp2" "$class2" 'after the install, the documented way'
  [ "${TBL[$v|2]}" = accepted ] || hint=' (the root is not trusted here: this is not a test of the check)'
  step "$v" 3 "$fn" "$HOST_GOOD" 4432 refused EXPECT "wrong name$hint"
  step "$v" 4 "$fn" "$HOST_OUT"  4433 refused EXPECT "leaf outside the name constraint$hint"
  step "$v" 4k "$fn" "$HOST_OUT" 4435 "${TBL[$v|2]}" RECORD 'control: the same name through the unconstrained intermediate'
  step "$v" 5 "$fn" "$HOST_GOOD" 4434 refused EXPECT "the leaf of the unrelated CA$hint"
}

load_line() { # variant tag text word
  record "[$1] $2  $3: $4"
}

run_variant() { # variant key exp2 class wa wb
  local v=$1 key=$2 exp2=$3 class2=$4 wa=$5 wb=$6 r pre
  note "$v"
  ORDER+=("$v")
  if ! vx "$key" supported "$v"; then record "[$v] not supported by this runtime: skipped"; TBL[$v|2]=n/a; return 0; fi
  probe_fn() { vx "$key" probe "$v" "$1" "$2"; }
  vx "$key" remove "$v" || die "[$v] remove (start)"
  [ "$wa" = 1 ] && watch_start "$key" "$v"
  step "$v" 1 probe_fn "$HOST_GOOD" 4431 refused EXPECT 'before the install'
  vx "$key" install "$v" || die "[$v] install"
  if [ "$wa" = 1 ]; then
    pre=$(watch_last "$key" "$v")
    watch_fresh "$key" "$v"; r=$(watch_last "$key" "$v")
    LOADA[$v]=${r%%[: ]*}
    load_line "$v" wA "a process started before the install, no restart (before: ${pre%%[: ]*})" "${r:0:110}"
    watch_stop "$key" "$v"
  fi
  steps_main "$v" probe_fn "$exp2" "$class2"
  if [ "$wb" = 1 ]; then
    watch_start "$key" "$v"
    pre=$(watch_last "$key" "$v")
    vx "$key" remove "$v" || die "[$v] remove"
    watch_fresh "$key" "$v"; r=$(watch_last "$key" "$v")
    LOADB[$v]=${r%%[: ]*}
    load_line "$v" wB "a process started while installed, after the removal (before: ${pre%%[: ]*})" "${r:0:110}"
    watch_stop "$key" "$v"
  else
    vx "$key" remove "$v" || die "[$v] remove"
  fi
  step "$v" 6 probe_fn "$HOST_GOOD" 4431 refused EXPECT 'after the removal'
  if [ "$v" = java-cacerts ]; then
    vx "$key" install "$v"; vx "$key" update-system-store "$v"
    r=$(vx "$key" probe "$v" "$HOST_GOOD" 4431)
    record "[$v] x   keytool entry in cacerts, then update-ca-certificates, then a new JVM: ${r:0:110}"
    EXTRA+=("[$v] after update-ca-certificates the keytool entry: ${r%%[: ]*}")
    vx "$key" remove "$v"
  fi
}

run_container_variants() { # key
  local key=$1 v k exp2 class wa wb
  while read -r v k exp2 class wa wb; do
    [ -n "$v" ] && [ "$k" = "$key" ] || continue
    run_variant "$v" "$k" "$exp2" "$class" "$wa" "$wb"
  done <<<"$VARIANTS"
}

#### a built image ############################################################

img_probe() { # image host port
  local out rc
  out=$(docker run --rm "${dlabels[@]}" --network "$NET" "$IMG_IMAGE" curl -sS -o /dev/null --max-time 10 "https://$1:$2/" 2>&1); rc=$?
  case $rc in
    0)  echo accepted ;;
    60) echo "refused: $(sed -n 's/^curl: ([0-9]*) //p' <<<"$out" | head -n 1)" ;;
    *)  echo "error: rc=$rc $(tr '\n' ' ' <<<"$out")"; return 1 ;;
  esac
}

phase_image() {
  local v=image-baked d=$work/img r
  note "$v (a Dockerfile: COPY the root, RUN update-ca-certificates)"
  ORDER+=("$v")
  cp "$work/pub/root.pem" "$d/root.crt"
  printf 'FROM %s\nCOPY root.crt /usr/local/share/ca-certificates/sick-root.crt\nRUN update-ca-certificates\n' "$IMG_python" >"$d/Dockerfile.with"
  printf 'FROM %s\nRUN update-ca-certificates\n' "$IMG_python" >"$d/Dockerfile.without"
  docker build -q "${dlabels[@]}" -t sick-e2e-trust-rt-img:with -f "$d/Dockerfile.with" "$d" >/dev/null 2>"$d/build.log" \
    || { cat "$d/build.log" >&2; die 'docker build (with the root)'; }
  docker build -q "${dlabels[@]}" -t sick-e2e-trust-rt-img:without -f "$d/Dockerfile.without" "$d" >/dev/null 2>"$d/build.log" \
    || { cat "$d/build.log" >&2; die 'docker build (without the root)'; }
  VERS+=("[image] builder: $(docker version --format '{{.Server.Version}}') with $(docker buildx version 2>/dev/null | head -n 1 | cut -c1-60)")
  IMG_IMAGE=$IMG_python
  step "$v" 1 img_probe "$HOST_GOOD" 4431 refused EXPECT "before: the base image $IMG_python as it is"
  IMG_IMAGE=sick-e2e-trust-rt-img:with
  steps_main "$v" img_probe accepted EXPECT
  IMG_IMAGE=sick-e2e-trust-rt-img:without
  step "$v" 6 img_probe "$HOST_GOOD" 4431 refused EXPECT 'after the removal: rebuilt from a Dockerfile without the COPY'
  IMG_IMAGE=sick-e2e-trust-rt-img:with
  r=$(img_probe "$HOST_GOOD" 4431)
  record "[$v] wB  the old image, still deployed, after the removal from the Dockerfile: ${r:0:110}"
  LOADB[$v]=${r%%[: ]*}
  LOADA[$v]='baked'
}

#### pods #####################################################################

k() { kubectl --kubeconfig "$KC" "$@"; }

pod_probe() { # host port [curl args]; the pod is in POD
  local h=$1 p=$2 out rc; shift 2
  out=$(k exec "$POD" -- curl -sS -o /dev/null --max-time 10 "$@" "https://$h:$p/" 2>&1); rc=$?
  case $rc in
    0)  echo accepted ;;
    60) echo "refused: $(sed -n 's/^curl: ([0-9]*) //p' <<<"$out" | head -n 1)" ;;
    *)  echo "error: rc=$rc $(tr '\n' ' ' <<<"$out")"; return 1 ;;
  esac
}
pod_plain()  { pod_probe "$@"; }
pod_cacert() { pod_probe "$1" "$2" --cacert /etc/sick-ca/root.pem; }

mkpod() { # name env-json mounts-json volumes-json
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"hostAliases":[{"ip":"%s","hostnames":["%s","%s"]}],"terminationGracePeriodSeconds":0,"containers":[{"name":"c","image":"%s","command":["sleep","3600"],"env":%s,"volumeMounts":%s}],"volumes":%s}}' \
    "$1" "$SVC_IP" "$HOST_GOOD" "$HOST_OUT" "$IMG_curlpod" "$2" "$3" "$4" | k apply -f - >/dev/null || die "pod $1"
  k wait --for=condition=Ready "pod/$1" --timeout=180s >/dev/null || die "pod $1 not ready"
}

phase_pods() {
  local v api cmx
  if ! command -v k3d >/dev/null || ! command -v kubectl >/dev/null; then
    record '[pods] k3d or kubectl is not installed: not tried'; return 0
  fi
  k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -qx "$CLUSTER" \
    && die "a k3d cluster $CLUSTER exists already; delete it by that name by hand"
  note "k3d cluster $CLUSTER (own kubeconfig in the private directory)"
  api=$(perl -MIO::Socket::INET -e 'print IO::Socket::INET->new(Listen=>1,LocalAddr=>"127.0.0.1",LocalPort=>0)->sockport')
  # every k3d and kubectl call below sees only the private kubeconfig, also the delete (which
  # otherwise rewrites ~/.kube/config)
  export KUBECONFIG=$KC
  : >"$KC"
  CLUSTER_MADE=1
  # a host whose /dev/kmsg is no device (here a symlink to /dev/console) needs the node to get /dev/null there
  local kmsg=()
  { [ -L /dev/kmsg ] || [ ! -e /dev/kmsg ]; } && kmsg=(--volume /dev/null:/dev/kmsg@server:0)
  k3d cluster create "$CLUSTER" --servers 1 --agents 0 --no-lb "${kmsg[@]}" \
    --api-port "127.0.0.1:$api" --kubeconfig-update-default=false --kubeconfig-switch-context=false \
    --runtime-label "sick=1@all" --runtime-label "$LABEL@all" \
    --k3s-arg '--disable=traefik@server:0' --wait --timeout 240s >"$work/k3d.log" 2>&1 \
    || { tail -20 "$work/k3d.log" >&2; die 'k3d cluster create'; }
  k3d kubeconfig get "$CLUSTER" >"$KC" || die 'kubeconfig'
  chmod 600 "$KC"
  VERS+=("[pods] $(k3d version | tr '\n' ' ')")
  VERS+=("[pods] kubectl server: $(k get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}') $(k get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')")
  VERS+=("[pods] kubeconfig server: $(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')")

  local i
  for i in $(seq 60); do k get serviceaccount default >/dev/null 2>&1 && break; sleep 2; done
  k create secret generic pki --from-file="$work/podpki" >/dev/null || die 'secret'
  k create configmap serve --from-file=serve.sh="$work/probes/serve.sh" >/dev/null || die 'configmap serve'
  k create configmap sick-root --from-file=root.pem="$work/pub/root.pem" >/dev/null || die 'configmap root'
  k create configmap sick-bundle --from-file=ca-certificates.crt="$work/pub/root.pem" >/dev/null || die 'configmap bundle'
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"srv","labels":{"app":"srv"}},"spec":{"containers":[{"name":"s","image":"%s","command":["sh","/serve/serve.sh"],"volumeMounts":[{"name":"pki","mountPath":"/pki"},{"name":"serve","mountPath":"/serve"}]}],"volumes":[{"name":"pki","secret":{"secretName":"pki"}},{"name":"serve","configMap":{"name":"serve"}}]}}' "$IMG_srvpod" | k apply -f - >/dev/null || die 'server pod'
  printf '{"apiVersion":"v1","kind":"Service","metadata":{"name":"srv"},"spec":{"selector":{"app":"srv"},"ports":[{"name":"p4431","port":4431},{"name":"p4432","port":4432},{"name":"p4433","port":4433},{"name":"p4434","port":4434},{"name":"p4435","port":4435}]}}' | k apply -f - >/dev/null || die 'service'
  k wait --for=condition=Ready pod/srv --timeout=240s >/dev/null || die 'the server pod is not ready'
  SVC_IP=$(k get svc srv -o jsonpath='{.spec.clusterIP}')
  [ -n "$SVC_IP" ] || die 'no cluster IP'

  # the clients: Debian trixie + curl (OpenSSL), the names resolve to the Service by hostAliases
  local none='[]'
  mkpod c-none '[]' '[]' '[]'
  mkpod c-subpath '[]' '[{"name":"v","mountPath":"/etc/ssl/certs/ca-certificates.crt","subPath":"ca-certificates.crt"}]' '[{"name":"v","configMap":{"name":"sick-bundle"}}]'
  mkpod c-dir '[]' '[{"name":"v","mountPath":"/etc/sick-ca"}]' '[{"name":"v","configMap":{"name":"sick-root"}}]'
  mkpod c-env '[{"name":"SSL_CERT_FILE","value":"/etc/sick-ca/root.pem"}]' '[{"name":"v","mountPath":"/etc/sick-ca"}]' '[{"name":"v","configMap":{"name":"sick-root"}}]'
  VERS+=("[pods] client image: $IMG_curlpod, $(k exec c-none -- sh -c '. /etc/os-release; echo $PRETTY_NAME; curl -V | head -n 1' | tr '\n' ' ')")
  VERS+=("[pods] server image: $IMG_srvpod, $(k exec srv -- openssl version)")
  # control: the service answers in the cluster (this one connection skips verification on purpose)
  POD=c-none
  [ "$(k exec c-none -- curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$HOST_GOOD:4431/")" = 200 ] \
    || die 'the server pod does not answer in the cluster'
  say "CONTROL  [pods] the server pod answers through the Service ($SVC_IP) under both names (curl -k, only here)"

  local pv pod fn exp2 class
  for pv in "pod-bundle-subpath c-subpath pod_plain accepted EXPECT" \
            "pod-dir-cm c-dir pod_cacert accepted EXPECT" \
            "pod-sslcertfile c-env pod_plain accepted RECORD"; do
    read -r v pod fn exp2 class <<<"$pv"
    note "$v"
    ORDER+=("$v")
    POD=c-none; step "$v" 1 pod_plain "$HOST_GOOD" 4431 refused EXPECT 'before: a pod without the root (same image)'
    POD=$pod;   steps_main "$v" "$fn" "$exp2" "$class"
    POD=c-none; step "$v" 6 pod_plain "$HOST_GOOD" 4431 refused EXPECT 'after the removal: the pod re-created without the ConfigMap'
  done

  # the running pods after the ConfigMap changed (it now holds the unrelated root)
  note 'a ConfigMap changes under running pods'
  local sum_other waited=0 sum_dir sum_sub
  sum_other=$(sha256sum "$work/pki/other.pem" | cut -d' ' -f1)
  k create configmap sick-root --from-file=root.pem="$work/pki/other.pem" --dry-run=client -o yaml | k replace -f - >/dev/null || die 'cm update'
  k create configmap sick-bundle --from-file=ca-certificates.crt="$work/pki/other.pem" --dry-run=client -o yaml | k replace -f - >/dev/null || die 'cm update'
  while [ $waited -lt 240 ]; do
    sum_dir=$(k exec c-dir -- sha256sum /etc/sick-ca/root.pem | cut -d' ' -f1)
    [ "$sum_dir" = "$sum_other" ] && break
    sleep 5; waited=$((waited+5))
  done
  if [ "$sum_dir" = "$sum_other" ]; then
    record "[pod-dir-cm] wB  the ConfigMap directory mount shows the new content in the running pod after about ${waited}s, no restart"
    POD=c-dir; step pod-dir-cm 6p pod_cacert "$HOST_GOOD" 4431 refused RECORD 'running pod, ConfigMap now holds the unrelated root: curl reads the file on every start'
    LOADB[pod-dir-cm]="file follows in ~${waited}s"
  else
    record "[pod-dir-cm] wB  the ConfigMap directory mount did NOT change within ${waited}s"
    LOADB[pod-dir-cm]='file unchanged'
  fi
  sum_sub=$(k exec c-subpath -- sha256sum /etc/ssl/certs/ca-certificates.crt | cut -d' ' -f1)
  if [ "$sum_sub" = "$sum_other" ]; then
    record '[pod-bundle-subpath] wB  the subPath mount followed the ConfigMap'
    LOADB[pod-bundle-subpath]='file follows'
  else
    record "[pod-bundle-subpath] wB  the subPath mount did NOT follow the ConfigMap (same wait, ${waited}s): the pod keeps the old root until it is re-created"
    POD=c-subpath; step pod-bundle-subpath 6p pod_plain "$HOST_GOOD" 4431 accepted RECORD 'running pod after the ConfigMap lost the root: the subPath file is unchanged'
    LOADB[pod-bundle-subpath]='file unchanged'
  fi
  k delete pod c-none c-subpath c-dir c-env srv --wait=false >/dev/null 2>&1
  record '[pods] trust-manager: not tried (needs cert-manager and charts from the internet)'
  k3d cluster delete "$CLUSTER" >"$work/k3d-delete.log" 2>&1 || { cat "$work/k3d-delete.log" >&2; die 'k3d cluster delete'; }
  CLUSTER_MADE=''
  say "PASS  k3d cluster $CLUSTER deleted by name"
}

#### the table ################################################################

print_result() {
  local v s c cols='1 2 3 4 4k 5 6'
  say ''
  say '=== VERSIONS'
  printf '%s\n' "${VERS[@]}"
  say '=== END VERSIONS'
  say ''
  say '=== TABLE (observed; ! marks a result that is not what was expected)'
  printf '%-25s' consumer; for s in $cols; do printf ' %-10s' "$s"; done; printf ' %-22s %-22s\n' wA wB
  for v in "${ORDER[@]}"; do
    printf '%-25s' "$v"
    for s in $cols; do printf ' %-10s' "${TBL[$v|$s]:--}${MARK[$v|$s]:-}"; done
    printf ' %-22s %-22s\n' "${LOADA[$v]:--}" "${LOADB[$v]:--}"
  done
  say '=== END TABLE'
  say '1 before  2 install  3 wrong name  4 outside the constraint  4k control for 4 (unconstrained intermediate)'
  say '5 unrelated CA  6 after the removal  wA process started before the install sees it  wB process started while installed, after the removal'
  [ ${#EXTRA[@]} -eq 0 ] || printf '%s\n' "${EXTRA[@]}"
  say ''
  say "SUMMARY: $npass PASS, $nfail FAIL, $nrecord RECORD"
  if [ "$nfail" -gt 0 ]; then say 'findings (FAIL lines are results, not harness errors):'; fi
}

#### main ######################################################################

make_pki
write_probes
note 'the server and the controls'
start_server
want python && { start_consumer python "$IMG_python"; run_container_variants python; }
want java   && { start_consumer java   "$IMG_java";   run_container_variants java; }
want node   && { start_consumer node   "$IMG_node";   run_container_variants node; }
want go     && { start_consumer go     "$IMG_go";     run_container_variants go; }
want image  && phase_image
want pods   && phase_pods
print_result
exit 0
