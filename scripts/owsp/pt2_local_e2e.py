#!/usr/bin/env python3
"""Local end-to-end: CLI scan against a local header-name sink fixture.
If the finding appears -> wiring OK (benchmark-specific issue). If not -> wiring bug."""
import json, subprocess, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COMMON = {"host", "user-agent", "accept", "accept-encoding", "connection",
          "content-length", "content-type", "origin", "referer", "cookie",
          "accept-language", "cache-control", "pragma"}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/openapi.json":
            spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                    "servers": [{"url": f"http://127.0.0.1:{PORT}"}],
                    "paths": {"/hn-sink": {"get": {"operationId": "hn",
                        "parameters": [], "responses": {"default": {"description": "x",
                        "content": {"text/html": {}}}}}}}}
            b = json.dumps(spec).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            return
        name = next((n for n in self.headers.keys() if n.lower() not in COMMON), "")
        target = "/base/" + name
        exists = os.path.exists(os.path.normpath("/home/z")) if name == ".." else False
        body = (f"Access to file: '{target}' created.\n" +
                (" And file already exists." if exists else " But file doesn't exist yet.")).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_POST = do_GET

PORT = 8893
srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# write spec file for --no-crawl mode
spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{PORT}"}],
        "paths": {"/hn-sink": {"get": {"operationId": "hn", "parameters": [],
             "responses": {"default": {"description": "x", "content": {"text/html": {}}}}}}}}
open("/tmp/hn_spec.json", "w").write(json.dumps(spec))

r = subprocess.run([sys.executable, "sentinel/cli.py", "scan", f"http://127.0.0.1:{PORT}",
                    "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
                    "--openapi-spec", "/tmp/hn_spec.json", "--seed", "7f3c91aa",
                    "--max-pages", "10", "--out", "/tmp/hn_scan.json", "--db", "/tmp/hn_scan.db"],
                   cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=240)
print("rc:", r.returncode)
print(r.stdout[-1500:])
print(r.stderr[-500:])
try:
    d = json.load(open("/tmp/hn_scan.json"))
    act = [f for f in d["findings"] if f["type"] not in
           ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
    print("ACTIVE FINDINGS:", [(f["type"], f["status"], f.get("parameter")) for f in act])
    print("requests:", d["stats"]["requests"])
    print("unverified:", [(u["type"], u.get("parameter")) for u in d.get("unverified_candidates", [])])
except Exception as e:
    print("no scan json:", e)
srv.shutdown(); srv.server_close()
