"""PART 3 PHASE 3 — full-config engine run with Store persistence, then
INDEPENDENT clean-engine re-execution (replay) of EVERY finding.

Mirrors the benchmark configuration exactly (same fixture code via its own
spawn, same seed, same auth/authz/workflow/logic/race batteries,
max_requests=0) so the finding set is the full-platform one, and persists
run + proofs to a Store DB so each finding can be replayed from a clean
engine via sentinel.evidence.replay_finding — the same primitive the CLI's
`reproduce --replay` uses.

Outputs (under evidence/full-reverify/fixtures-vulnapp/):
  store.db            — persisted run (findings + proofs)
  scan.json           — the raw engine report
  replay_results.json — per-finding clean-engine re-execution outcomes
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

EV = ROOT / "evidence" / "full-reverify" / "fixtures-vulnapp"
EV.mkdir(parents=True, exist_ok=True)

PORT = 8777
BASE = f"http://127.0.0.1:{PORT}"

# ---- 1. spawn our own fixture (same code the benchmark spawns) -------------
fixture = subprocess.Popen(
    [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
    env={"PORT": str(PORT), "PATH": "/usr/bin:/bin"},
    stdout=open(EV / "fixture.log", "w"), stderr=subprocess.STDOUT)
time.sleep(1.5)
import urllib.request
probe = urllib.request.urlopen(BASE + "/", timeout=5).status
assert probe == 200, probe
print(f"fixture up on {BASE} (pid {fixture.pid})")

# ---- 2. full-platform engine run (benchmark config) -------------------------
from sentinel.auth import AuthProfile
from sentinel.core import EventBus, ScopeRule
from sentinel.oast import OastServer
from sentinel.orchestrator import ScanConfig, SentinelScanner
from sentinel.store import Store

auth = AuthProfile(login_url=BASE + "/login", username="demo",
                   password="demo123", user_field="uid", pass_field="passw",
                   success_marker="Sign Off")
authz_cfg = json.load(open(ROOT / "benchmarks" / "authz_accounts.json"))
oast = OastServer()
t0 = time.time()
try:
    cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                     seed="bench430" * 8, oast=oast, auth=auth,
                     authz=authz_cfg, workflow=True, logic_active=True,
                     max_requests=0, race=True, race_parallel=10,
                     race_variance=0.005, symbolic=True)
    sc = SentinelScanner(BASE, cfg)
    rep = sc.run()
finally:
    oast.stop()
scan_s = time.time() - t0
(EV / "scan.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False),
                              encoding="utf-8")
n = Store(str(EV / "store.db")).save_run(rep)
findings = rep["findings"]
print(f"scan done in {scan_s:.1f}s: requests={rep['stats']['requests']} "
      f"findings={len(findings)} persisted={n}")

# ---- 3. independent clean-engine replay of EVERY finding --------------------
from sentinel.evidence import replay_finding
from urllib.parse import urlsplit

proofs = (rep.get("stats") or {}).get("proofs") or []
by_id = {p.get("finding_id"): p for p in proofs}
results = []
t1 = time.time()
for f in findings:
    proof = by_id.get(f["id"])
    if not proof:
        results.append({"finding_id": f["id"], "type": f["type"],
                        "url": f["url"], "parameter": f["parameter"],
                        "replay": "NO_PROOF_PERSISTED"})
        continue
    req = (proof.get("requests") or [{}])[0]
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(req.get("url", "")))
    scope = ScopeRule(allowed_domains=[urlsplit(req.get("url", "")).hostname],
                      allow_private=True)
    try:
        r = replay_finding(proof, scope, EventBus("reverify"), timeout=12.0)
    except Exception as exc:  # noqa: BLE001 — recorded, never hidden
        r = {"replay": "REPLAY_ERROR", "error": repr(exc)}
    r = dict(r)
    r.update({"finding_id": f["id"], "type": f["type"], "url": f["url"],
              "parameter": f["parameter"]})
    results.append(r)
replay_s = time.time() - t1

ok = sum(1 for r in results if r.get("replay") == "REPRODUCTION_VERIFIED")
notr = sum(1 for r in results if r.get("replay") == "NOT_REPLAYABLE")
fail = sum(1 for r in results if r.get("replay") == "REPRODUCTION_FAILED")
err = sum(1 for r in results if r.get("replay") in
          ("REPLAY_ERROR", "NO_PROOF_PERSISTED"))
summary = {"findings_total": len(results),
           "REPRODUCTION_VERIFIED": ok, "NOT_REPLAYABLE": notr,
           "REPRODUCTION_FAILED": fail, "errors": err,
           "scan_wall_seconds": round(scan_s, 1),
           "replay_wall_seconds": round(replay_s, 1)}
(EV / "replay_results.json").write_text(
    json.dumps({"summary": summary, "results": results}, indent=1,
               ensure_ascii=False), encoding="utf-8")
print("replay summary:", json.dumps(summary))

# ---- 4. teardown --------------------------------------------------------------
fixture.terminate()
try:
    fixture.wait(timeout=5)
except subprocess.TimeoutExpired:
    fixture.kill()
print("fixture stopped — STORE-RUN PHASE COMPLETE")
