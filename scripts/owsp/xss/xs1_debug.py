#!/usr/bin/env python3
"""XS-1 unit-test discrepancy diagnosis: the live minispec (openapi import)
is GREEN 6/6 but the unit test (HTML form discovery) stays RED. Dump what the
discovery produced (params/locations/values) and what the xss battery actually
sent, to isolate the layer that dies in the HTML-form path."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.orchestrator import SentinelScanner, ScanConfig

TCID = "BenchmarkTest00036"
SAFE = "BenchmarkTest00544"

REQUESTS = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _reply(self, code, b):
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _record(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode() if n else ""
        REQUESTS.append({"path": self.path, "body": body,
                         "ct": self.headers.get("Content-Type", "")})
        return body

    def do_GET(self):
        self._record()
        if urlsplit(self.path).path == "/":
            self._reply(200, (
                '<form method="POST" action="/xss-00/' + TCID + '">'
                '<input type="text" name="whatever" value="' + TCID + '">'
                '<input type="text" name="answer" value="">'
                '<input type="submit" name="go" value="go"></form>'
                '<form method="POST" action="/xss-01/' + SAFE + '">'
                '<input type="text" name="whatever" value="' + SAFE + '">'
                '<input type="text" name="answer" value="">'
                '<input type="submit" name="go" value="go"></form>').encode())
            return
        self._reply(200, b"<html><body></body></html>")

    def do_POST(self):
        body = self._record()
        q = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        sentinel = SAFE if SAFE in self.path else TCID
        name = ""
        for k, v in q.items():
            if v == sentinel:
                name = k; break
        if "xss-01" in self.path:
            self._reply(200, b"<html><body>moresafe</body></html>")
        elif name:
            self._reply(200, ("<html><body>" + name + "</body></html>").encode())
        else:
            self._reply(200, b"<html><body></body></html>")


port = 8909
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="xs1",
                 browser=False, oast=None)
rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()

print("=== findings ===")
for f in rep["findings"]:
    print(" ", f["type"], f.get("status"), f.get("url", "").rsplit("/", 1)[-1],
          "param:", repr(f.get("parameter"))[:60])
print("\n=== POST requests to the xss endpoints (name-channel hunt) ===")
for r in REQUESTS:
    if "/xss-00/" in r["path"] or "/xss-01/" in r["path"]:
        print(" ", r["path"], "|", r["body"][:120])
srv.shutdown(); srv.server_close()
