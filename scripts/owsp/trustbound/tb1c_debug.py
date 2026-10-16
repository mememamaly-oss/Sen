#!/usr/bin/env python3
"""TB-1c debug: trace TrustBoundDetector channel decisions on the mangle
fixture shape (the 01617-faithful unit fixture) with the real scanner."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.orchestrator import SentinelScanner, ScanConfig
import sentinel.detect as D

_orig = D.TrustBoundDetector._pair_hit
_orig_run = D.TrustBoundDetector.run
LOG = []


def traced_pair(self, r1, r2):
    hit = _orig(self, r1, r2)
    LOG.append(("pair", r1 is not None and (r1.body or "")[:60] if r1 else None,
                "hit" if hit else "miss"))
    return hit


def traced_run(self, ep):
    LOG.append(("run", ep.url, len(ep.parameters)))
    r = _orig_run(self, ep)
    LOG.append(("done", ep.url, bool(r)))
    return r


D.TrustBoundDetector._pair_hit = traced_pair
D.TrustBoundDetector.run = traced_run


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _reply(self, code, b):
        self.send_response(code); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            b = b'<a href="/tbmg?password=foo123&email=bar@x.y">v</a>'
            self._reply(200, b)
            return
        if u.path == "/tbmg":
            v = q.get("tbmg", "")
            bar = v[:-1] if len(v) > 1 else v
            b = (f"<html><body>Item: '{bar}' with value: '10340' "
                 f"saved in session.</body></html>").encode()
            self._reply(200, b)
            return
        self._reply(404, b"no")


port = 8934
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
cfg = ScanConfig(allow_private=True, max_pages=4, timeout=5, seed="tb1cdbg",
                 browser=False, oast=None, crawl=True)
rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
for entry in LOG:
    print(entry)
print("--- trust_bound findings ---")
for f in rep["findings"]:
    if f["type"] == "trust_bound":
        print(f["url"], f["status"])
