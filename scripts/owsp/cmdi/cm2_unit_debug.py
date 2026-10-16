#!/usr/bin/env python3
"""CM-2 unit-debug driver: replicate the unit mini-app, scan it, dump the
journal's nc-probe requests, the OAST interaction log, and per-surface
findings — locate where the chain breaks (emission / render / callback /
poll / verify)."""
import os, subprocess as _sp, threading, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import sys
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.oast import OastServer

_SAFE_NAME = __import__("re").compile(r"^[a-z0-9.-]+$")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _reply(self, code, b):
        self.send_response(code); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            b = (b'<a href="/nc-env?host=localhost">e</a>'
                 b'<a href="/nc-direct?host=localhost">d</a>'
                 b'<a href="/nc-shell?host=localhost">s</a>'
                 b'<a href="/nc-safe?host=localhost">f</a>'
                 b'<a href="/shell?host=localhost">v</a>')
            self._reply(200, b); return
        bar = ""
        for k, v in q.items():
            if v == "localhost":
                bar = k; break
        if u.path == "/nc-env":
            _env = dict(os.environ); _env.pop("FOO", None)
            if "=" in bar:
                _k, _, _val = bar.partition("="); _env[_k] = _val
            _sp.run(["/bin/sh", "-c", "eval $FOO >/dev/null 2>&1; true"],
                    env=_env, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            self._reply(200, b"<html><body>processed.</body></html>")
        elif u.path == "/nc-direct":
            try: _sp.run(bar.split(), stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            except Exception: pass
            self._reply(200, b"<html><body>done.</body></html>")
        elif u.path == "/nc-shell":
            _sp.run(["/bin/sh", "-c", f"ls {bar}"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            self._reply(200, b"<html><body>ok</body></html>")
        elif u.path == "/nc-safe":
            if _SAFE_NAME.match(bar or ""):
                _sp.run(["/bin/sh", "-c", "true"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                self._reply(200, b"<html><body>ok</body></html>")
            else:
                self._reply(200, b"<html><body>rejected</body></html>")
        elif u.path == "/shell":
            _sp.run(["/bin/sh", "-c", f"true {q.get('host', '')}"],
                    stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            self._reply(200, b"<html><body>ok</body></html>")
        else:
            self._reply(404, b"no")

port = 8932
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
oast = OastServer()
cfg = ScanConfig(allow_private=True, max_pages=6, timeout=5, seed="cm2",
                 browser=False, oast=oast)
rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()

print("=== OAST interactions ===")
for it in (getattr(oast, "interactions", None) or []):
    print(" ", {k: it.get(k) for k in ("iid", "path", "ip")})
print("=== journal: nc / curl probes sent ===")
jour = rep.get("journal", []) or rep.get("request_journal", [])
cnt = 0
for e in jour:
    line = json.dumps(e)[:400]
    if "curl" in line or "oob-" in line:
        cnt += 1
        print(" ", line[:260])
        if cnt > 14: break
print(f"(nc-ish journal lines: {cnt})")
print("=== endpoints discovered ===")
for e in (rep.get("stats", {}).get("crawl", {}) or {}).get("endpoints", [])[:10]:
    print(" ", e)
print("=== findings (cmdi + all) ===")
for f in rep.get("findings", []):
    print(" ", f["type"], f.get("status"), f.get("url"), "|", (f.get("parameter") or "")[:60])
print("=== rejected candidates ===")
for f in rep.get("rejected_candidates", []) or []:
    print(" ", f.get("type"), f.get("url"), (f.get("reason") or "")[:80])
srv.shutdown(); oast.stop()
