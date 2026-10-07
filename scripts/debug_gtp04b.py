#!/usr/bin/env python3
"""Debug unit_gtp04b: why the FOO= battery never fires on the fixture."""
import sys, threading
sys.path.insert(0, '/home/z/my-project/build-v430')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.detect import CmdiEchoDetector, command_shaped_endpoint


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            b = b'<a href="/envp?q=x">e</a>'
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
            return
        c = q.get("q", "")
        if c.startswith("FOO="):
            cmd = c[4:]
            out = ""
            if cmd.startswith("echo "):
                arg = cmd[5:]
                if arg.startswith("$((") and arg.endswith("))"):
                    try:
                        out = str(eval(arg[3:-2]))
                    except Exception:
                        out = ""
                else:
                    out = arg
            b = (f"stdout:<br>Your original string:<br>{out}<br>"
                 f"reversed:<br>{cmd[::-1]}<br>").encode()
        else:
            b = b"static page no commands here"
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)


port = 8855
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="dbg4b", browser=False, oast=None)
rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
print("findings:", [(f["type"], f.get("status")) for f in rep["findings"]])

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("dbg4b"), timeout=5)
ep = Endpoint(url=f"http://127.0.0.1:{port}/envp", method="GET")
ep.parameters = [Parameter("q", ParamLocation.QUERY, "x")]
print("command_shaped:", command_shaped_endpoint(ep))
det = CmdiEchoDetector(eng, EventBus("dbg4b"))
f = det.run(ep)
print("direct run ->", (f.type, [(e.kind, e.detail[:80]) for e in f.evidence]) if f else None)
for v in ["FOO=echo x", "FOO=echo $((6*7))"]:
    r = eng.send(RequestMutation(endpoint=ep, param_name="q", param_value=v, note="dbg"))
    print(repr(v), "->", (r.body or "")[:110] if r else None)
srv.shutdown(); srv.server_close()
