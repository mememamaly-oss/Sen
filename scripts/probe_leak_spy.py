#!/usr/bin/env python3
"""Instrument the fixture: log every response body containing AKIA/ghp_ shapes,
with the exact request path+query that produced it."""
import sys, threading, importlib.util, re
sys.path.insert(0, "/home/z/my-project/verify-live")
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location(
    "vulnapp_probe4", "/home/z/my-project/verify-live/fixtures/vulnapp.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

# instrument _send
orig_send = mod.Handler._send
def spy_send(self, code, body, headers=None):
    try:
        b = body.decode() if isinstance(body, bytes) else str(body)
        if "AKIA" in b or "ghp_" in b:
            print(f"[SPY] code={code} self.path={self.path!r} body_has_AKIA={'AKIA' in b} "
                  f"ghp={'ghp_' in b} cookie={bool(self.headers.get('Cookie'))}", flush=True)
            m = re.search(r'.{0,40}(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}).{0,10}', b)
            if m: print(f"[SPY]   context: {m.group(0)!r}", flush=True)
    except Exception as e:
        print("[SPY] err", e, flush=True)
    return orig_send(self, code, body, headers)
mod.Handler._send = spy_send

port = 8896
srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.oast import OastServer
from sentinel.auth import AuthProfile
base = f"http://127.0.0.1:{port}"
auth = AuthProfile(login_url=base + "/login", username="demo", password="demo123",
                   user_field="uid", pass_field="passw", success_marker="Sign Off")
oast = OastServer()
try:
    cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6, seed="v8-e2e-regression",
                     oast=oast, auth=auth)
    sc = SentinelScanner(base, cfg)
    rep = sc.run()
    print("credential findings:", [f["parameter"] for f in rep["findings"]
                                   if f["type"] == "credential_exposure"])
finally:
    oast.stop(); srv.shutdown(); srv.server_close()
