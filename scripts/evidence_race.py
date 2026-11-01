"""Evidence generator for PART 2 — 3F: the invariant-based race prober.

Runs the REAL distribution the order demands (>=10 real concurrent
bursts per twin, a fresh single-use code each) against both fixture
twins, plus the full-scan wiring record (VR-37 on the operator-declared
second sample) and the never-blind boundary.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.core import EventBus, ScopeRule                # noqa: E402
from burhan.http_engine import RequestEngine              # noqa: E402
from burhan.modernsec2 import run_modern_battery_v2       # noqa: E402
from burhan.orchestrator import BurhanScanner, ScanConfig  # noqa: E402

N_RUNS = 10
BURST = 6


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(mode):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**os.environ, "PORT": str(port), "RACE_MODE": mode},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return port, proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("fixture never became reachable")


def _burst(engine, base, code):
    mres = run_modern_battery_v2(
        engine, [], seed="race-evidence",
        race_candidates=[{"url": f"{base}/api/coupon/redeem",
                          "method": "POST", "params": {"code": code},
                          "quota": 1, "concurrent": BURST}])
    fam = [f for f in mres.findings if f.type == "race_condition"]
    if fam:
        m = re.search(r"winners (\d+)", fam[0].evidence[0].detail)
        return {"fired": True, "winners": int(m.group(1)),
                "detail": fam[0].evidence[0].detail}
    neg = [b for b in mres.boundaries
           if b["family"] == "race_condition" and b["kind"] == "TESTED_NEGATIVE"]
    m = re.search(r"(\d+) winner", neg[0]["detail"])
    return {"fired": False, "winners": int(m.group(1)),
            "detail": neg[0]["detail"]}


def _distribution(mode, label):
    port, proc = _spawn(mode)
    try:
        base = f"http://127.0.0.1:{port}"
        engine = RequestEngine(ScopeRule(allow_private=True,
                                         allowed_hosts=["127.0.0.1"]),
                               EventBus(f"race-{mode}"), timeout=10.0)
        runs = [_burst(engine, base, f"{mode.upper()}-{i}")
                for i in range(N_RUNS)]
    finally:
        proc.terminate()
    return {
        "layer": "race-prober",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": f"fixtures/vulnapp.py (env RACE_MODE={mode})",
        "label": label,
        "burst_width": BURST,
        "quota": 1,
        "runs": N_RUNS,
        "winners_distribution": [r["winners"] for r in runs],
        "violations": sum(1 for r in runs if r["winners"] > 1),
        "sample_evidence": runs[0]["detail"],
    }


out = os.path.join(ROOT, "evidence", "layers", "race-prober")
os.makedirs(out, exist_ok=True)

red = _distribution("broken", "RED — non-atomic check-then-set (40ms window)")
blue = _distribution("locked", "BLUE — the same handler under a mutex")

assert red["violations"] == N_RUNS, red
assert all(w == BURST for w in red["winners_distribution"]), red
assert blue["violations"] == 0, blue
assert all(w == 1 for w in blue["winners_distribution"]), blue

# full-scan wiring + VR-37 (fresh burst on the operator-declared 2nd sample)
port, proc = _spawn("broken")
base = f"http://127.0.0.1:{port}"
try:
    cfg = ScanConfig(
        allow_private=True, max_pages=3, timeout=8.0, browser=False,
        modern_v2=True, max_requests=6000,
        race_candidates=[{"url": f"{base}/api/coupon/redeem", "method": "POST",
                          "params": {"code": "SCAN-1"},
                          "verify_params": {"code": "SCAN-2"},
                          "quota": 1, "concurrent": BURST}])
    data = BurhanScanner(base, cfg).run()
finally:
    proc.terminate()
fam = [f for f in data["findings"] if f["type"] == "race_condition"]
assert fam and str(fam[0]["status"]).lower() == "verified", fam
wiring = {
    "layer": "race-prober",
    "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "target": "fixtures/vulnapp.py (env RACE_MODE=broken) — full BurhanScanner scan",
    "label": "WIRING + VR-37 — cfg.race_candidates reaches the battery; the "
             "finding survives a fresh burst on verify_params (the 2nd "
             "single-use sample — the first burst consumed the first code)",
    "finding": {"url": fam[0]["url"], "status": str(fam[0]["status"])},
    "vr37_notes": (fam[0].get("verification") or {}).get("notes")
    if isinstance(fam[0].get("verification"), dict) else str(fam[0].get("verification"))[:200],
    "battery_probe_counts": ((data["stats"].get("modern_v2") or {})
                             .get("probe_counts", {}).get("race_condition")),
}

for name, doc in (("RED_DISTRIBUTION.json", red),
                  ("BLUE_DISTRIBUTION.json", blue),
                  ("WIRING_VR37.json", wiring)):
    with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)

print(f"RED : violations {red['violations']}/{N_RUNS}, winners {red['winners_distribution']}")
print(f"BLUE: violations {blue['violations']}/{N_RUNS}, winners {blue['winners_distribution']}")
print(f"WIRING: {wiring['finding']} vr37={wiring['vr37_notes']}")
print("ALL EVIDENCE ASSERTIONS PASS")
