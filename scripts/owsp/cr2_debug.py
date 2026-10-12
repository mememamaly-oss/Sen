#!/usr/bin/env python3
"""CR-2 unit-test debug: why does the fixed engine miss CH1 on the fixture?"""
import sys, threading, base64, os as _os
sys.path.insert(0, "/home/z/my-project/build-v430")
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from sentinel.chainphase import HashCryptoChainPhase
from sentinel.core import (Endpoint, EventBus, Evidence, Finding, FindingStatus,
                           Severity, Parameter, ParamLocation)
from sentinel.http_engine import RequestEngine, ScopeRule

ART = {"body": ""}
COMMON = {"host", "user-agent", "accept", "accept-encoding", "connection",
          "content-length", "content-type", "origin", "referer", "cookie"}

def _des_ct(pt):
    pad = 8 - (len(pt) % 8)
    return _os.urandom(len(pt) + pad)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _ok(self, b):
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def _route(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        n = int(self.headers.get("Content-Length", 0) or 0)
        form = {}
        if n:
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}
        if u.path == "/read":
            b = ART["body"].encode() if q.get("file") == "passwordFile.txt" else b"no such file"
            self._ok(b); return
        if u.path == "/write":
            ART["body"] = ""; self._ok(b"Now ready to write"); return
        last = u.path.rstrip("/").split("/")[-1]
        pt = ""
        if last == "BenchmarkTestCH1":
            pt = self.headers.get(last, "")
            print(f"    [fixture] CH1 hit: header {last!r} present={last in self.headers} pt={pt[:20]!r} all-headers={list(self.headers.keys())}", file=sys.stderr)
        elif last == "BenchmarkTestCH2":
            pt = next((h for h in self.headers.keys() if h.lower() not in COMMON), "")
        else:
            pt = ""
        ART["body"] = "secret_value=" + base64.b64encode(_des_ct(pt)).decode() + "\n"
        self._ok(b"encrypted and stored")
    def do_GET(self): self._route()
    def do_POST(self): self._route()

port = 8903
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

bus = EventBus("cr2dbg")
eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=bus, timeout=5)

# spy on _probe
orig_probe = HashCryptoChainPhase._probe
def spy_probe(self, ep, value, read_ep, read_param, artifact_name,
              write_ep=None, write_param=None, channel="declared"):
    ct = orig_probe(self, ep, value, read_ep, read_param, artifact_name,
                    write_ep, write_param, channel)
    print(f"  probe {ep.url.rsplit('/',1)[-1]:22s} ch={channel:9s} v={len(value):2d} -> ct={None if ct is None else len(ct)}",
          file=sys.stderr)
    return ct
HashCryptoChainPhase._probe = spy_probe

def _ep(last):
    e = Endpoint(url=f"http://127.0.0.1:{port}/cr2/{last}", method="POST")
    e.parameters = [Parameter("decoy", ParamLocation.QUERY, "x")]
    return e
read_ep = Endpoint(url=f"http://127.0.0.1:{port}/read", method="GET")
read_ep.parameters = [Parameter("file", ParamLocation.QUERY, "x")]
write_ep = Endpoint(url=f"http://127.0.0.1:{port}/write", method="POST")
write_ep.parameters = [Parameter("f", ParamLocation.QUERY, "x")]
rprim = Finding(type="path_traversal", severity=Severity.HIGH, endpoint_url=read_ep.url,
                parameter="file", method="GET",
                evidence=[Evidence("file_marker", "content leak", "r", "root:x:0:0:")],
                status=FindingStatus.VERIFIED)
wprim = Finding(type="path_traversal", severity=Severity.HIGH, endpoint_url=write_ep.url,
                parameter="f", method="POST",
                evidence=[Evidence("writability_oracle", "write sink", "w", "")],
                status=FindingStatus.VERIFIED)
ph = HashCryptoChainPhase(eng, bus)
eps = [read_ep, write_ep, _ep("BenchmarkTestCH1")]
out = ph.run(eps, [rprim, wprim])
print("findings:", [(f.type, f.status, f.endpoint_url.rsplit('/',1)[-1]) for f in out], file=sys.stderr)
srv.shutdown(); srv.server_close()
