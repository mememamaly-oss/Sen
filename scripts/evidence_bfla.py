"""Evidence generator for PART 1 — 3E BFLA.

RED/BLUE in one scan (the broken admin function and its hardened twin
are both in flight) + the full-repo regression scan (standard fixture,
zero BFLA surfaces). Dumps the battery record, the finding, and the
VR-36 re-verification outcome for each.
"""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.orchestrator import BurhanScanner, ScanConfig         # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(bfla: bool):
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    if bfla:
        env["BFLA"] = "1"
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return port, proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("fixture never became reachable")


def _scan(base):
    cfg = ScanConfig(
        allow_private=True, max_pages=8, timeout=8.0, browser=False,
        modern_v2=True, max_requests=8000,
        authz={"login_url": f"{base}/login",
               "accounts": [
                   {"name": "admin", "role": "admin",
                    "username": "demo", "password": "demo123",
                    "marker": "root-admin@burhan-fixture.local"},
                   {"name": "bob", "role": "user",
                    "username": "bob", "password": "bob123",
                    "marker": "bob-user@burhan-fixture.local"}],
               "user_field": "uid", "pass_field": "passw",
               "success_marker": "Sign Off"})
    return BurhanScanner(base, cfg).run()


def _record(data, label, target):
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    m2 = data["stats"].get("modern_v2") or {}
    return {
        "layer": "bfla",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "label": label,
        "authz": data["stats"].get("authz"),
        "battery_probe_counts": m2.get("probe_counts", {}).get("bfla"),
        "battery_boundaries": [b for b in m2.get("boundaries", [])
                               if b["family"] == "bfla"],
        "findings": [{"url": f["url"], "status": str(f["status"]),
                      "verification": (f.get("verification") or {}).get("notes")
                      if isinstance(f.get("verification"), dict)
                      else str(f.get("verification"))[:160],
                      "evidence": [{"kind": e.get("kind"), "detail": e.get("detail")}
                                   for e in (f.get("evidence") or [])]}
                     for f in bfla],
    }


out = os.path.join(ROOT, "evidence", "layers", "bfla")
os.makedirs(out, exist_ok=True)

port, proc = _spawn(bfla=True)
try:
    data = _scan(f"http://127.0.0.1:{port}")
finally:
    proc.terminate()
redblue = _record(data, "RED+BLUE — broken admin function vs hardened twin, one scan",
                  "fixtures/vulnapp.py (env BFLA=1)")
broken = [f for f in redblue["findings"] if "/api/admin/rotate-keys" in f["url"]]
secure = [f for f in redblue["findings"] if "secure" in f["url"]]
assert broken, redblue["findings"]
assert str(broken[0]["status"]).lower() == "verified", broken[0]["status"]
assert not secure, redblue["findings"]
with open(os.path.join(out, "RED_BLUE.json"), "w", encoding="utf-8") as fh:
    json.dump(redblue, fh, indent=2, ensure_ascii=False)

port, proc = _spawn(bfla=False)
try:
    data = _scan(f"http://127.0.0.1:{port}")
finally:
    proc.terminate()
reg = _record(data, "FULL-REPO REGRESSION — standard fixture, zero BFLA surfaces",
              "fixtures/vulnapp.py (stock)")
assert not reg["findings"], reg["findings"]
assert reg["battery_probe_counts"]["sent"] == 0, reg["battery_probe_counts"]
assert any(b["kind"] == "NOT_DISCOVERED" for b in reg["battery_boundaries"]), \
    reg["battery_boundaries"]
with open(os.path.join(out, "REGRESSION.json"), "w", encoding="utf-8") as fh:
    json.dump(reg, fh, indent=2, ensure_ascii=False)

print("RED+BLUE: broken fires (verified), hardened twin silent —",
      broken[0]["verification"])
print("REGRESSION: zero findings, probes sent =",
      reg["battery_probe_counts"]["sent"])
print("ALL EVIDENCE ASSERTIONS PASS")
