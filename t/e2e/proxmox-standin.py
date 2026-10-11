# A recording stand-in for the certificate API of Proxmox VE (pveproxy, port
# 8006) and Proxmox Backup Server (proxmox-backup-proxy, port 8007), for
# t/e2e/device-proxmox.sh. Python standard library only.
#
#   python3 -I -u proxmox-standin.py pve|pbs
#
# It answers what the acme.sh 3.1.6 deploy hooks proxmoxve and proxmoxbs
# call, modelled on the API schemas of both products (apidoc.js, read
# 2026-10-11):
#
#   POST   /api2/json/nodes/<node>/certificates/custom   upload chain + key
#   DELETE /api2/json/nodes/<node>/certificates/custom   back to self-signed
#   GET    anything else                                 200, {"data":null}
#
# and serves the API and the certificate on the same TLS port, as the real
# proxies do: first the self-signed certificate of the "installation"
# (/etc/standin/self.pem, self.key), after an accepted upload the uploaded
# one - for pve after a short delay (pveproxy is restarted in the
# background, restart=1), for pbs at once (the proxy reloads its
# certificate within the call; "restart" is ignored by PBS).
#
# The API token is checked as the products expect it:
#   pve: Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>
#   pbs: Authorization: PBSAPIToken=<user>@<realm>!<tokenid>:<secret>
# user, realm and token id from STANDIN_USER, STANDIN_REALM, STANDIN_TOKEN_ID,
# the secret from /etc/standin/token. A wrong or missing token is 401 with an
# empty body.
#
# One line per request goes to standard output: method, path, content type,
# the token's form (never its secret: only "secret=ok" or "secret=wrong"),
# the field names with their JSON types, node/restart/force, the number of
# certificates and the SHA-256 of the first, and for the key only that a PEM
# private key was there, its type and whether it matches the certificate.
# No body, no key, no token is ever printed.
#
# /etc/standin/mode, read at every request, steers it: "ok" (or missing),
# "500" (answer every API call with 500), "slow" (wait 4 s before answering
# an upload).

import hashlib
import hmac
import http.server
import json
import os
import re
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse

KIND = sys.argv[1] if len(sys.argv) > 1 else ''
if KIND not in ('pve', 'pbs'):
    sys.exit('usage: proxmox-standin.py pve|pbs')

PORT = 8006 if KIND == 'pve' else 8007
NODE = os.environ.get('STANDIN_NODE', 'pve1' if KIND == 'pve' else 'localhost')
USER = os.environ.get('STANDIN_USER', 'sick')
REALM = os.environ.get('STANDIN_REALM', 'pve' if KIND == 'pve' else 'pbs')
TOKEN_ID = os.environ.get('STANDIN_TOKEN_ID', 'sick')
RESTART_DELAY = float(os.environ.get('STANDIN_RESTART_DELAY', '2' if KIND == 'pve' else '0'))
CONF = '/etc/standin'
RUN = '/run/standin'

if KIND == 'pve':
    TOKEN_RE = re.compile(r'\APVEAPIToken=([^@\s!=:]+)@([^@\s!=:]+)!([A-Za-z][A-Za-z0-9._-]*)=(\S+)\Z')
else:
    TOKEN_RE = re.compile(r'\APBSAPIToken=([^@\s!=:]+)@([^@\s!=:]+)!([A-Za-z][A-Za-z0-9._-]*):(\S+)\Z')
PATH_RE = re.compile(r'\A/api2/json/nodes/([A-Za-z0-9-]+)/certificates/custom/?\Z')

with open(CONF + '/token', encoding='ascii') as f:
    SECRET = f.readline().strip().encode()

os.umask(0o077)
lock = threading.Lock()
state = {'ctx': None, 'custom': False, 'uploads': 0}


def log(line):
    print('standin %s: %s' % (KIND, line), flush=True)


def context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def use(cert, key, why):
    ctx = context(cert, key)
    with lock:
        state['ctx'] = ctx
    log('serving %s on port %d (sha256 %s)' % (why, PORT, leaf_sha256(open(cert).read())))


def mode():
    try:
        with open(CONF + '/mode', encoding='ascii') as f:
            return f.read().strip() or 'ok'
    except OSError:
        return 'ok'


PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----', re.S)


def leaf_sha256(pem):
    blocks = PEM_CERT.findall(pem)
    if not blocks:
        return '-'
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(blocks[0])).hexdigest()


OIDS = (
    (bytes.fromhex('06092a864886f70d010101'), 'RSA'),
    (bytes.fromhex('06072a8648ce3d0201'), 'EC'),
    (bytes.fromhex('06032b6570'), 'Ed25519'),
)


def key_type(pem):
    """The type of a PEM private key, from its header or its algorithm OID."""
    m = re.search(r'-----BEGIN ((?:RSA |EC |ENCRYPTED |OPENSSH )?)PRIVATE KEY-----\r?\n(.*?)-----END', pem, re.S)
    if not m:
        return None
    label = m.group(1).strip()
    if label in ('RSA', 'EC'):
        return label + ' (traditional PEM)'
    if label:
        return label + ' (refused)'
    import base64
    try:
        der = base64.b64decode(''.join(m.group(2).split()))
    except ValueError:
        return 'unreadable PKCS#8'
    for oid, name in OIDS:
        if oid in der[:40]:
            return name + ' (PKCS#8)'
    return 'other (PKCS#8)'


def describe(value):
    if isinstance(value, bool):
        return '%s(bool)' % ('true' if value else 'false')
    if isinstance(value, str):
        return '"%s"(str)' % value if len(value) < 40 else '(str, %d chars)' % len(value)
    if value is None:
        return 'null'
    return '%s(%s)' % (value, type(value).__name__)


def truthy(value):
    return value is True or value in (1, '1', 'true', 'yes', 'on')


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        sock, addr = self.socket.accept()
        with lock:
            ctx = state['ctx']
        # the handshake happens in the handler's thread, with the certificate
        # that was current when the connection came in
        return ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        # a probe that only looks at the certificate hangs up early: not worth
        # a line; a handshake the client refused is
        error = sys.exc_info()[1]
        if isinstance(error, ssl.SSLError):
            log('TLS handshake with %s failed (%s)' % (client_address[0], error.reason or type(error).__name__))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'standin-' + KIND
    sys_version = ''

    def setup(self):
        self.request.settimeout(10)
        self.request.do_handshake()
        super().setup()

    def log_message(self, *args):
        pass

    def reply(self, code, reason=None, body=None):
        data = b'' if body is None else json.dumps(body).encode()
        self.send_response(code, reason)
        self.send_header('Content-Type', 'application/json;charset=UTF-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        return code

    def auth(self):
        header = self.headers.get('Authorization')
        if header is None:
            return False, 'auth=none'
        m = TOKEN_RE.match(header)
        if not m:
            scheme = header.split('=', 1)[0] if '=' in header else '?'
            return False, 'auth=malformed(scheme %s)' % scheme
        user, realm, token_id, secret = m.groups()
        who = (user, realm, token_id) == (USER, REALM, TOKEN_ID)
        right = hmac.compare_digest(secret.encode(), SECRET)
        text = 'auth=%s(%s@%s!%s, format ok, id %s, secret=%s)' % (
            header.split('=', 1)[0], user, realm, token_id, 'ok' if who else 'unknown',
            'ok' if right else 'wrong')
        return who and right, text

    def body(self):
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) if length else b''
        ctype = (self.headers.get('Content-Type') or '-').split(';')[0].strip()
        if ctype == 'application/json':
            try:
                return ctype, json.loads(raw.decode('utf-8'))
            except ValueError:
                return ctype, None
        if ctype == 'application/x-www-form-urlencoded':
            return ctype, {k: v[-1] for k, v in urllib.parse.parse_qs(raw.decode('utf-8')).items()}
        return ctype, None

    def do_GET(self):
        self.reply(200, None, {'data': None})

    def api(self, method):
        m = PATH_RE.match(urllib.parse.urlsplit(self.path).path)
        ctype, fields = self.body()
        ok, auth = self.auth()
        words = ['%s %s' % (method, self.path), 'ctype=%s' % ctype, auth]
        try:
            if not m:
                words.append('-> 501')
                return self.reply(501, 'Method not implemented')
            node = m.group(1)
            if not ok:
                words.append('-> 401')
                return self.reply(401, 'authentication failure')
            if mode() == '500':
                words.append('-> 500 (mode 500)')
                return self.reply(500, 'internal error', {'data': None, 'message': 'stand-in answers 500\n'})
            if node != NODE and not (KIND == 'pbs' and node == 'localhost'):
                words.append('-> 500 (no such node %s)' % node)
                return self.reply(500, 'no such node', {'data': None, 'message': "no such cluster node '%s'\n" % node})
            if method == 'DELETE':
                return self.delete(words)
            return self.upload(words, ctype, fields)
        finally:
            log(' '.join(words))

    def do_POST(self):
        self.api('POST')

    def do_DELETE(self):
        self.api('DELETE')

    def upload(self, words, ctype, fields):
        if not isinstance(fields, dict):
            words.append('fields=unreadable -> 400')
            return self.reply(400, 'Parameter verification failed')
        words.append('fields=' + ','.join('%s:%s' % (k, type(fields[k]).__name__) for k in sorted(fields)))
        for name in ('node', 'restart', 'force'):
            if name in fields:
                words.append('%s=%s' % (name, describe(fields[name])))
        certs = fields.get('certificates')
        key = fields.get('key')
        if not isinstance(certs, str) or not PEM_CERT.search(certs):
            words.append('certificates=none -> 400')
            return self.reply(400, 'Parameter verification failed', {'data': None, 'errors': {'certificates': 'no PEM certificate'}})
        words.append('certificates=%d PEM, first sha256 %s' % (len(PEM_CERT.findall(certs)), leaf_sha256(certs)))
        if not isinstance(key, str):
            words.append('key=none -> 400')
            return self.reply(400, 'Parameter verification failed', {'data': None, 'errors': {'key': 'missing'}})
        kt = key_type(key)
        if kt is None or 'refused' in kt:
            words.append('key=no usable PEM private key (%s) -> 400' % kt)
            return self.reply(400, 'Parameter verification failed', {'data': None, 'errors': {'key': 'not a PEM private key'}})
        with lock:
            custom = state['custom']
        if KIND == 'pve' and custom and not truthy(fields.get('force')):
            words.append('key=PEM private key, %s -> 500 (custom certificate exists, force not set)' % kt)
            return self.reply(500, 'internal error', {'data': None, 'message': "Custom certificate exists but 'force' is not set.\n"})
        staged_cert, staged_key = RUN + '/staged.pem', RUN + '/staged.key'
        for path in (staged_cert, staged_key):
            if os.path.exists(path):
                os.unlink(path)
        with open(os.open(staged_cert, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
            f.write(certs)
        with open(os.open(staged_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
            f.write(key)
        try:
            context(staged_cert, staged_key)
        except ssl.SSLError as e:
            words.append('key=PEM private key, %s, matches certificate: no -> 500' % kt)
            for path in (staged_cert, staged_key):
                os.unlink(path)
            return self.reply(500, 'internal error', {'data': None, 'message': 'key does not match certificate (%s)\n' % e.reason})
        words.append('key=PEM private key, %s, matches certificate: yes' % kt)
        if mode() == 'slow':
            time.sleep(4)
        os.rename(staged_cert, RUN + '/custom.pem')
        os.rename(staged_key, RUN + '/custom.key')
        with lock:
            state['custom'] = True
            state['uploads'] += 1
        fingerprint = leaf_sha256(certs)
        restart = KIND == 'pbs' or truthy(fields.get('restart'))
        if restart:
            delay = RESTART_DELAY
            words.append('-> 200 (%s)' % ('proxy reloads in %gs' % delay if delay else 'proxy reloaded'))
            if delay:
                threading.Timer(delay, use, (RUN + '/custom.pem', RUN + '/custom.key', 'the uploaded certificate')).start()
            else:
                use(RUN + '/custom.pem', RUN + '/custom.key', 'the uploaded certificate')
        else:
            words.append('-> 200 (stored; not served until pveproxy restarts: restart not set)')
        colons = ':'.join(fingerprint[i:i + 2] for i in range(0, 64, 2)).upper()
        info = {'filename': 'pveproxy-ssl.pem' if KIND == 'pve' else 'proxy.pem', 'fingerprint': colons}
        return self.reply(200, None, {'data': info if KIND == 'pve' else [info]})

    def delete(self, words):
        with lock:
            custom = state['custom']
        if not custom:
            words.append('-> 500 (no custom certificate)')
            return self.reply(500, 'internal error', {'data': None, 'message': 'no custom certificate\n'})
        for name in ('custom.pem', 'custom.key'):
            os.unlink(RUN + '/' + name)
        with lock:
            state['custom'] = False
        words.append('-> 200 (custom certificate removed, back to self-signed)')
        use(CONF + '/self.pem', CONF + '/self.key', 'the self-signed certificate')
        return self.reply(200, None, {'data': None})


use(CONF + '/self.pem', CONF + '/self.key', 'the self-signed certificate')
log('node %s, token %s@%s!%s, API on port %d' % (NODE, USER, REALM, TOKEN_ID, PORT))
Server(('0.0.0.0', PORT), Handler).serve_forever()
