#!/usr/bin/env python3
"""Debug gtp01/07/10 failures."""
import sys, threading
sys.path.insert(0, '/home/z/my-project/build-v430')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

# ---------- gtp07 shape ----------
class H7(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if urlsplit(self.path).path == "/":
            b = b'<a href="/app">a</a>'
            self.send_response(200)
            self.send_header("Set-Cookie", "JSESSIONID=abc123; Path=/")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        else:
            b = b"app page"
            self.send_response(200)
            self.send_header("Set-Cookie", "SomeCookie=tokenvalue123; Path=/")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
srv7 = ThreadingHTTPServer(("127.0.0.1", 8857), H7)
threading.Thread(target=srv7.serve_forever, daemon=True).start()

from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="dbg7",
                 browser=False, oast=None)
rep = SentinelScanner("http://127.0.0.1:8857", cfg).run()
print("gtp07 findings:", [(f["type"], f.get("parameter")) for f in rep["findings"]])

# direct detector probe
from sentinel.core import Endpoint, EventBus
from sentinel.http_engine import RequestEngine, ScopeRule, RequestMutation
from sentinel.detect import SecureCookieDetector
bus = EventBus("d7")
eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True), bus)
r = eng.send(RequestMutation(endpoint=Endpoint(url="http://127.0.0.1:8857/app", method="GET")))
print("direct headers:", dict(r.headers))
d = SecureCookieDetector(eng, bus)
f = d.run(Endpoint(url="http://127.0.0.1:8857/app", method="GET"))
print("direct detector:", f.type if f else None, f.parameter if f else "")
srv7.shutdown(); srv7.server_close()
