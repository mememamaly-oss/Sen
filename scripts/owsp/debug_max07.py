#!/usr/bin/env python3
"""Debug the MAX-07 failure: run the fixture + scan + impact CLI manually,
dump the probe journal (URLs, statuses, sizes) to see WHY separation fails."""
import threading, subprocess, tempfile, os, sys, json, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

ROOT = "/home/z/my-project/build-v425"
sys.path.insert(0, ROOT)
os.chdir(ROOT)

TRUE_CONDS = {"1=1", "'1'='1'", "sqlite_version() LIKE '%'",
              "SUBSTR(sqlite_version(),1,1)='3'"}
HITS = []

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body: self.wfile.write(body)
    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        HITS.append((u.path, q.get("q", ""), len(u.path) + len(self.path)))
        if u.path == "/":
            self._send(200, b'<html><body><a href="/search?q=hello">s</a></body></html>')
        elif u.path == "/search":
            v = q.get("q", "")
            if v == "hello" or v == "1":
                self._send(200, b'{"data":[{"id":1}]}')
            elif v == "1'":
                self._send(500, b"Error: SQLITE_ERROR: near '%': syntax error")
            else:
                m = re.match(r"^\d+'?\s+OR\s+(.+?)\s*--?\s*$", v)
                cond = (m.group(1).strip() if m else v).rstrip("-").strip()
                if cond in TRUE_CONDS:
                    self._send(200, b"T" * 2000)
                else:
                    self._send(200, b"F" * 40)
        else:
            self._send(404)

port = 8812
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"

from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="max07dbg",
                 browser=False, oast=None)
rep = SentinelScanner(base, cfg).run()
sqls = [f for f in rep["findings"] if f["type"] == "sql_injection" and f["status"] == "verified"]
print("scan SQLi verified:", len(sqls), "| findings:", len(rep["findings"]))
assert sqls
sqls[0]["evidence"] = [{"kind": "db_error", "detail": "SQLITE_ERROR matched"}]

td = tempfile.mkdtemp()
rpath = os.path.join(td, "res.json")
json.dump(rep, open(rpath, "w"))
out2 = os.path.join(td, "assess.json")
outj = os.path.join(td, "journal.json")
print("\n--- fixture hits during scan (q values seen) ---")
for p, q, _ in HITS[-8:]:
    print(f"  {p} q={q!r}")
HITS.clear()

r2 = subprocess.run([sys.executable, "sentinel/cli.py", "impact", "--result", rpath,
                     "--execute", "--allow-private", "--assessment", out2,
                     "--probe-journal", outj],
                    cwd=ROOT, capture_output=True, text=True, timeout=200)
print("\nimpact rc:", r2.returncode)
if r2.stdout: print("stdout tail:", r2.stdout[-500:])
if r2.stderr: print("stderr tail:", r2.stderr[-800:])
a = json.load(open(out2))
print("\nsummary:", a["summary"])
for p in a.get("plans", a.get("impacts", []))[:3]:
    print(" plan:", p.get("kind"), "->", p.get("verdict") or p.get("status"))
print("\n--- fixture hits during impact (q values seen) ---")
for p, q, _ in HITS:
    print(f"  {p} q={q!r}")
try:
    j = json.load(open(outj))
    print("\n--- probe journal ---")
    for k, e in list(j.items())[:6]:
        r = e.get("response", {})
        print(f"  {k[:60]}: status={r.get('status')} len={r.get('length') or r.get('body_length')} url={str(e.get('url',''))[:100]}")
except Exception as ex:
    print("journal:", ex)
srv.shutdown(); srv.server_close()
