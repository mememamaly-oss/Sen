#!/usr/bin/env python3
"""TB-1c debug 2: call TrustBoundDetector.run directly with full traceback."""
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.core import Endpoint, EventBus, ParamKind, ParamLocation
from sentinel.http_engine import RequestEngine, RequestMutation, ScopeRule
from sentinel.detect import TrustBoundDetector


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _reply(self, code, b):
        self.send_response(code); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            self._reply(200, b'<a href="/tbmg?password=foo123&email=bar@x.y">v</a>')
            return
        if u.path == "/tbmg":
            v = q.get("tbmg", "")
            bar = v[:-1] if len(v) > 1 else v
            b = (f"<html><body>Item: '{bar}' with value: '10340' "
                 f"saved in session.</body></html>").encode()
            self._reply(200, b)
            return
        self._reply(404, b"no")


port = 8935
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

eng = RequestEngine(ScopeRule(f"http://127.0.0.1:{port}/", allow_private=True),
                    EventBus("tb1cdbg2"), timeout=5)
ep = Endpoint(url=f"http://127.0.0.1:{port}/tbmg", method="GET")
ep.parameters = []
from sentinel.core import Parameter
ep.parameters = [
    Parameter(name="password", value="foo123", kind=ParamKind.GENERIC,
              location=ParamLocation.QUERY),
    Parameter(name="email", value="bar@x.y", kind=ParamKind.GENERIC,
              location=ParamLocation.QUERY),
]
det = TrustBoundDetector(eng, EventBus("tb1cdbg2"))
try:
    f = det.run(ep)
    print("FINDING:", bool(f))
    if f:
        print("param:", f.parameter)
        for e in f.evidence:
            print(" ev:", e.kind, "|", str(e.detail)[:120])
except Exception:
    traceback.print_exc()
finally:
    srv.shutdown(); srv.server_close()
