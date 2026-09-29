#!/usr/bin/env python3
"""Phase 57 dev probe: where do the fixture's credential findings actually come
from, and does an armed vault capture every raw value end-to-end?"""
import importlib.util, json, os, sys, threading, tempfile

sys.path.insert(0, "/home/z/my-project/verify-live")
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location(
    "vulnapp_probe", "/home/z/my-project/verify-live/fixtures/vulnapp.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
port = 8877
srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.oast import OastServer
from sentinel.auth import AuthProfile
from sentinel.vault import Vault, keygen

td = tempfile.mkdtemp(prefix="vault-probe-")
kf, vp = os.path.join(td, "k.json"), os.path.join(td, "v.vault")
keygen(kf, label="probe")
Vault.init(vp, kf, "probe-org")

oast = OastServer()
try:
    base = f"http://127.0.0.1:{port}"
    auth = AuthProfile(login_url=base + "/login", username="demo", password="demo123",
                       user_field="uid", pass_field="passw", success_marker="Sign Off")
    cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6, seed="p57-probe",
                     oast=oast, auth=auth, vault=vp, vault_key_file=kf)
    rep = SentinelScanner(base, cfg).run()
    print("=== credential findings ===")
    for f in rep["findings"]:
        if f["type"] == "credential_exposure":
            print(" ", f["parameter"], f["url"])
            print("    evidence:", f["evidence"][0]["detail"][:160])
    print("=== stats.secrets ===")
    print(json.dumps(rep["stats"].get("secrets", {}), indent=1))
    print("=== stats.vault ===")
    print(json.dumps(rep["stats"].get("vault", {}), indent=1))
    # byte-level: raw secrets must NOT be in the report dump
    blob = json.dumps(rep)
    for raw in ("s3nt1nelDbPw",):
        print(f"report contains raw {raw!r}:", raw in blob)
    # vault contents
    v = Vault.open(vp, kf)
    print("=== vault records (masked list) ===")
    for r in v.list():
        print(" ", r["id"], r["cls"], r["masked"], "hits=", r["hits"])
    print("=== vault raws (authorized reveal) ===")
    for r in v.report()["records"]:
        print(" ", r["cls"], "raw=", r["raw"][:40])
    vault_bytes = open(vp, "rb").read()
    for raw in ("s3nt1nelDbPw",):
        print(f"vault FILE contains raw {raw!r}:", raw.encode() in vault_bytes)
    print("=== audit tail ===")
    for e in v.audit()[-6:]:
        print(" ", e["action"], e["target"], e["detail"][:80])
finally:
    oast.stop(); srv.shutdown(); srv.server_close()
