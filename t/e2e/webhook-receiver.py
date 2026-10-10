# The webhook of t/e2e/ops.sh: accepts a POST on one path - the secret part
# of the URL, read from /etc/hook/path - and prints each body it accepted on
# one line. The path itself is never printed: http.server's own request log,
# which would show it, is switched off.
import http.server
import json

with open('/etc/hook/path', encoding='ascii') as f:
    SECRET_PATH = f.read().strip()


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        if self.path != SECRET_PATH:
            print('hook: POST to another path, answered 404', flush=True)
            self.send_response(404)
            self.end_headers()
            return
        try:
            json.loads(body)
            kind = 'json'
        except ValueError:
            kind = 'not-json'
        print('hook: POST %s %s %s' % (kind, self.headers.get('Content-Type', '-'),
                                       body.decode('utf-8', 'replace')), flush=True)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(('0.0.0.0', 8080), Hook).serve_forever()
