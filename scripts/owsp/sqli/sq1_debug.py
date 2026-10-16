#!/usr/bin/env python3
"""Debug harness for the SQ-1 fixture scan (why does it hang?)."""
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, "/home/z/my-project/build-v430")

TCID = "BenchmarkTest00037"
EMPTY = b"<html><body><p>Your results are:<br></p></body></html>"
HITS = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _reply(self, code, b):
        self.send_response(code); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        HITS.append(("GET", self.path))
        if urlsplit(self.path).path == "/":
            self._reply(200, (
                '<form method="POST" action="/sqli-00/' + TCID + '">'
                '<input type="text" name="whatever" value="' + TCID + '">'
                '<input type="text" name="answer" value="">'
                '<input type="submit" name="go" value="go"></form>').encode())
            return
        self._reply(200, EMPTY)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode() if n else ""
        HITS.append(("POST", self.path, body[:120]))
        q = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        name = ""
        for k, v in q.items():
            if v == TCID:
                name = k; break
        if name == "1'":
            self._reply(500, b"java.sql.SQLSyntaxErrorException: malformed string: ' "
                             b"in statement [ SELECT * from USERS ]")
        else:
            self._reply(200, EMPTY)


if __name__ == "__main__":
    port = 8906
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    from sentinel.orchestrator import SentinelScanner, ScanConfig
    cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="sq1",
                     browser=False, oast=None)
    t0 = time.time()
    print("scan starting...", flush=True)

    def watch():
        while time.time() - t0 < 60:
            time.sleep(10)
            print(f"  t={time.time()-t0:.0f}s hits={len(HITS)} last={HITS[-3:]}", flush=True)
    threading.Thread(target=watch, daemon=True).start()

    rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
    print(f"scan done in {time.time()-t0:.1f}s, total hits={len(HITS)}")
    for f in rep["findings"]:
        print("  finding:", f["type"], f.get("status"), f.get("url"))
    print("last 12 hits:")
    for h in HITS[-12:]:
        print("   ", h)
