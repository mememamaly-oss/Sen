#!/usr/bin/env python3
"""Diagnostic: replicate regression_phase56_intelligence_end_to_end scan setup
and dump the coverage / intelligence stats so we can see which gate number is off.

Same fixture, same seed, same config as the test (different port to avoid clashes).
Prints the full coverage block + related stats. READ-ONLY (no source edits).
"""
import importlib.util
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, "/home/z/my-project/verify-live")

spec = importlib.util.spec_from_file_location(
    "vulnapp_v8_diag", "/home/z/my-project/verify-live/fixtures/vulnapp.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PORT = 8812
srv = ThreadingHTTPServer(("127.0.0.1", PORT), mod.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.oast import OastServer
from sentinel.auth import AuthProfile

oast = OastServer()
try:
    base = f"http://127.0.0.1:{PORT}"
    auth = AuthProfile(login_url=base + "/login", username="demo", password="demo123",
                       user_field="uid", pass_field="passw", success_marker="Sign Off")
    authz_cfg = {"login_url": "/login", "user_field": "uid", "pass_field": "passw",
                 "success_marker": "Sign Off",
                 "accounts": [
                     {"name": "demo-admin", "role": "admin", "username": "demo",
                      "password": "demo123", "marker": "root-admin@sentinel-fixture.local",
                      "object_id": "1001"},
                     {"name": "bob-user", "role": "user", "username": "bob",
                      "password": "bob123", "marker": "bob-user@sentinel-fixture.local",
                      "object_id": "2002"},
                     {"name": "carol-user", "role": "user", "username": "carol",
                      "password": "carol123", "marker": "carol-user@sentinel-fixture.local",
                      "object_id": "3003"}]}
    cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6,
                     seed="v8-e2e-regression", oast=oast, auth=auth, authz=authz_cfg)
    sc = SentinelScanner(base, cfg)
    rep = sc.run()
    st = rep["stats"]
    print("=== COVERAGE ===")
    print(json.dumps(st.get("coverage", {}), indent=1))
    print("=== crawl/endpoints ===")
    print(json.dumps({k: st.get(k) for k in
                      ("requests", "endpoints", "crawl", "browser_pages")}, indent=1)[:1500])
    print("=== authz summary ===")
    az = st.get("authz", {})
    print(json.dumps({k: az.get(k) for k in ("ran", "accounts_logged_in", "roles",
                                             "requests", "matrix")} , indent=1)[:800])
    print("=== param_intel (kinds/data_objects keys) ===")
    pi = st.get("param_intel", {})
    print(json.dumps({"by_kind": pi.get("by_kind"),
                      "data_object_keys": sorted(pi.get("data_objects", {}).keys())},
                     indent=1))
    print("=== findings by type ===")
    from collections import Counter
    print(json.dumps(Counter(f["type"] for f in rep["findings"]), indent=1))
    print("=== untested endpoint urls (if any) ===")
    cov = st.get("coverage", {})
    for e in cov.get("endpoints", []):
        if e.get("status") not in ("tested", None) and not e.get("tested"):
            print(" UNTESTED:", e.get("url"), "skips:", e.get("skips"), "reason:", e.get("reason"))
finally:
    oast.stop()
    srv.shutdown()
    srv.server_close()
