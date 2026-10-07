#!/usr/bin/env python3
"""Minimal repro: SQLi flow on a tiny fixture, exposing the exact failure."""
import sys, threading, json
sys.path.insert(0, '/home/z/my-project/build-v430')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b"<html><body>home</body></html>")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        q = urlsplit(self.path).query
        params = {}
        for kv in (q + "&" + body).split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v
        val = params.get("q", "")
        from urllib.parse import unquote_plus
        val = unquote_plus(val)
        if "'" in val and "''" not in val:
            self.send_response(500); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"<html><body>SQLITE_ERROR: near \"'\": syntax error</body></html>")
            return
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(("<html><body>results for " + val + " (12 rows)</body></html>").encode())

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

from sentinel.core import Endpoint, EventBus, ParamKind, ParamLocation
from sentinel.core import Parameter, Target, ScopeRule
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.detect import SQLiDetector

ep = Endpoint(url=f"http://127.0.0.1:{port}/search", method="POST")
ep.parameters = [Parameter(name="q", value="test", kind=ParamKind.SEARCH,
                           location=ParamLocation.BODY).classify()]
bus = EventBus("dbg")
eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True), bus)
det = SQLiDetector(eng, bus)
cands = det.candidates(ep)
print("candidates:", len(cands))
print("tags:", [t for t, _ in cands][:30])

# group exactly like the orchestrator
from itertools import groupby
def key(t):
    n = getattr(t[1], "note", "") or ""
    return n[8:] if n.startswith("ncgroup:") else t[1].param_name
for gkey, grp in groupby(cands, key=key):
    grp = list(grp)
    resp_map = {}
    err = None
    for strat, m in grp:
        try:
            r = eng.send(m)
            resp_map[strat] = r
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            break
    print(f"GROUP {gkey[:40]!r}: {len(grp)} probes, strategies={list(resp_map.keys())[:25]} err={err}")
    for s in ("base", "pair_quote", "quote_error", "boolean_true", "boolean_false"):
        r = resp_map.get(s)
        if r is not None:
            print(f"   {s}: status={r.status} len={len(r.body or '')} body[:60]={(r.body or '')[:60]!r}")
    if resp_map and not err:
        try:
            from sentinel.detect import _pseudo_param
            param_obj = next((p for p in ep.parameters if p.name == gkey), None)
            if param_obj is None:
                _m0 = next((mm for tt, mm in grp if tt.endswith("_base")), grp[0][1])
                param_obj = _pseudo_param(gkey.split("|")[0], _m0.param_value or "1", ParamKind.GENERIC)
            cand = det.analyze((ep, param_obj), resp_map)
            print("  -> analyze:", cand.type if cand else None,
                  [(e.kind) for e in cand.evidence] if cand else "")
            if cand:
                from sentinel.intel import VerificationEngine
                ve = VerificationEngine(eng, bus)
                out = ve.verify(cand, ep)
                print("  -> verify:", out.status, out.verification.method if out.verification else None)
        except Exception as e:
            import traceback; traceback.print_exc()

# ---- full orchestrator scan through the same engine path ----
print("\n=== FULL SCAN ===")
bus2 = EventBus("dbg2")
_orig_emit = bus2.emit
def _emit(kind, **data):
    if kind == "ScannerFailed":
        print("  !! ScannerFailed:", data.get("scanner"), str(data.get("error"))[:150])
    return _orig_emit(kind, **data)
bus2.emit = _emit
from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=True, active=True, passive=True, oast=None, secrets=False,
                 auth=None, browser=False, logic_active=False, openapi=False,
                 openapi_spec=None, max_pages=50, seed="deadbeef", timeout=5.0)
orch = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
try:
    result = orch.run()
    print("findings:", [(f.type, str(f.status)) for f in orch.findings])
except Exception as e:
    import traceback; traceback.print_exc()
print("scanner-failure events:", len(bus2.by_kind("ScannerFailed")))
srv.shutdown(); srv.server_close()
