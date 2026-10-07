#!/usr/bin/env python3
"""Run unit_max03's exact fixture with deep instrumentation."""
import sys, threading, json
sys.path.insert(0, '/home/z/my-project/build-v430')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

REQS = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body: self.wfile.write(body)
    def do_GET(self):
        REQS.append(self.path[:110])
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            self._send(200, b'<html><body><a href="/search?q=hello">s</a></body></html>')
        elif u.path == "/search":
            v = q.get("q", "")
            if v == "hello" or v == "1":
                self._send(200, b'{"status":"success","data":[{"id":1}]}')
            elif v == "1'":
                self._send(500, (b"<html><head><title>Error: SQLITE_ERROR: "
                                 b'near &quot;&#39;%&quot;: syntax error</title></head>'
                                 b"<body>500</body></html>"))
            else:
                self._send(200, b'{"status":"success","data":[]}')
        else:
            self._send(404)

port = 8809
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"

from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5,
                 seed="max03-sqlite", browser=False, oast=None)
sc = SentinelScanner(base, cfg)
_orig = sc.bus.emit
def _emit(kind, **data):
    if kind in ("ScannerFailed", "CandidateCreated", "ScanPlanReady"):
        print(f"[{kind}]", {k: str(v)[:90] for k, v in data.items() if k != 'finding'})
    return _orig(kind, **data)
sc.bus.emit = _emit
rep = sc.run()
print("\n=== FINDINGS ===")
for f in rep["findings"]:
    print(" ", f["type"], f.get("status"))
print("=== REJECTED ===")
for c in rep.get("rejected_candidates", [])[:10]:
    print(" ", c.get("type"), str(c.get("reason"))[:120])
print("=== UNVERIFIED ===")
for c in rep.get("unverified_candidates", [])[:10]:
    print(" ", c.get("type"))
print("=== SEARCH REQUESTS (first 30) ===")
for r in [r for r in REQS if "/search" in r][:30]:
    print("  ", r)
print("total reqs:", len(REQS), " search reqs:", len([r for r in REQS if "/search" in r]))
srv.shutdown(); srv.server_close()
