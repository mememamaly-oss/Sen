#!/usr/bin/env python3
"""Find WHERE aws_access_key / github_token / db_connection_uri findings arise
in a fixture v8 scan (E2E test expects all three classes)."""
import json, sys, threading, importlib.util, os
sys.path.insert(0, "/home/z/my-project/verify-live")
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location(
    "vulnapp_probe", "/home/z/my-project/verify-live/fixtures/vulnapp.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
port = 8899
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
    cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6,
                     seed="v8-e2e-regression", oast=oast, auth=auth)
    sc = SentinelScanner(base, cfg)
    rep = sc.run()
    cred = [f for f in rep["findings"] if f["type"] == "credential_exposure"]
    print("credential_exposure findings:", len(cred))
    for f in cred:
        print(" -", f["parameter"], f["url"])
    # also: dump the raw body the fixture actually serves on leak-config
    import urllib.request
    for p in ("/vuln/leak-config", "/safe/leak-config"):
        try:
            body = urllib.request.urlopen(base + p, timeout=5).read().decode()
            print(p, "serves:", body[:220])
        except Exception as e:
            print(p, "ERR", e)
    st = rep["stats"].get("secrets")
    print("stats.secrets:", json.dumps(st))
finally:
    oast.stop(); srv.shutdown(); srv.server_close()
