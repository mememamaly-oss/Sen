"""INDEPENDENT VERIFICATION — Juice Shop 20.3.0 (official release bundle).

Phase-1 campaign (2026-10-31): scan the OFFICIAL Juice Shop release (GitHub
release artifact, md5-verified) with the engine and score against the
OFFICIAL published challenge list (data/static/challenges.yml @ v20.3.0) —
replacing circular self-made fixtures with an independent truth set.

Bounds, disclosed: loopback instance, max_pages=30, max_requests=4500,
timeout=10s, local OAST, authenticated with the account seeded by Juice
Shop's OWN documentation (admin@juice-sh.op / admin123 — documented in the
app's README); browser engine on (playwright available here). No race /
workflow / logic-active / symbolic batteries in this pass (the pure DAST
core) — disclosed in the report.

Outputs (evidence/independent-verification/juice-shop-20.3.0/):
  scan.json     — the raw engine report
  challenges.json — parsed official challenge list (name/category/difficulty)
  run_meta.json — versions, bounds, wall times
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/home/z/my-project")
EXT = ROOT / "external"
EV = ROOT / "evidence" / "independent-verification" / "juice-shop-20.3.0"
EV.mkdir(parents=True, exist_ok=True)

# ---- 1. parse the official challenge list -----------------------------------
raw = (EXT / "challenges-v20.3.0.yml").read_text(encoding="utf-8")
entries = re.split(r"\n-\n", "\n" + raw.strip())
entries = [e for e in entries if e.lstrip().startswith("name:")]
challenges = []
for e in entries:
    def f(pat, default=""):
        m = re.search(pat, e, re.M)
        return m.group(1).strip().strip("'\"") if m else default
    challenges.append({
        "name": f(r"^name:\s*'?(.*?)'?\s*$"),
        "category": f(r"category:\s*'?(.*?)'?\s*$"),
        "difficulty": f(r"difficulty:\s*(\d)"),
        "key": f(r"key:\s*(\S+)"),
    })
challenges = [c for c in challenges if c["name"]]
(EV / "challenges.json").write_text(
    json.dumps(challenges, indent=1, ensure_ascii=False), encoding="utf-8")
from collections import Counter
print(f"official challenges parsed: {len(challenges)}")
print("categories:", dict(Counter(c['category'] for c in challenges)))

# ---- 2. boot the official bundle --------------------------------------------
PORT = 31000
BASE = f"http://127.0.0.1:{PORT}"
up = False
try:
    import urllib.request
    urllib.request.urlopen(BASE + "/", timeout=3)
    up = True
    print("juice-shop already up")
except Exception:
    pass
proc = None
if not up:
    log = open("/tmp/js_scan_boot.log", "w")
    proc = subprocess.Popen(
        ["node", "build/app.js"],
        cwd=str(EXT / "juice-shop_20.3.0"),
        env={**os.environ, "PORT": str(PORT), "NODE_ENV": "production"},
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            import urllib.request
            urllib.request.urlopen(BASE + "/", timeout=3)
            up = True
            break
        except Exception:
            time.sleep(1)
    assert up, "juice-shop failed to boot (see /tmp/js_scan_boot.log)"
    print(f"juice-shop booted (pid {proc.pid})")

# ---- 3. engine scan (bounded, disclosed) ------------------------------------
sys.path.insert(0, str(ROOT))
from sentinel.core import EventBus, ScopeRule
from sentinel.oast import OastServer
from sentinel.orchestrator import ScanConfig, SentinelScanner

# authenticated with the account Juice Shop's own documentation seeds
from sentinel.auth import AuthProfile
auth = AuthProfile(login_url=BASE + "/rest/user/login",
                   username="admin@juice-sh.op", password="admin123",
                   user_field="email", pass_field="password",
                   success_marker="authentication")

oast = OastServer()
t0 = time.time()
cfg = ScanConfig(allow_private=True, max_pages=30, timeout=10.0,
                 seed="indep-juiceshop-20.3.0", oast=oast, auth=auth,
                 max_requests=4500, browser=True)
sc = SentinelScanner(BASE, cfg)
try:
    rep = sc.run()
finally:
    oast.stop()
wall = time.time() - t0

(EV / "scan.json").write_text(
    json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
meta = {
    "target": "OWASP Juice Shop 20.3.0 (official GitHub release bundle, "
              "md5-verified, node24_linux_x64)",
    "base_url": BASE,
    "challenge_list": "data/static/challenges.yml @ tag v20.3.0 (official)",
    "bounds": {"max_pages": 30, "max_requests": 4500, "timeout": 10.0,
               "oast": "local", "auth": "documented seed admin account",
               "batteries_off": ["race", "workflow", "logic_active",
                                 "symbolic", "authz"]},
    "scan_wall_seconds": round(wall, 1),
    "requests": rep["stats"]["requests"],
    "endpoints": rep["stats"]["endpoints"],
    "findings": len(rep["findings"]),
    "browser_pages": (rep["stats"].get("browser_pages") or {}).get("pages", 0)
                     if isinstance(rep["stats"].get("browser_pages"), dict)
                     else rep["stats"].get("browser_pages"),
    "run_id": rep.get("run_id"),
}
(EV / "run_meta.json").write_text(
    json.dumps(meta, indent=1, ensure_ascii=False), encoding="utf-8")
print(json.dumps(meta, indent=1, ensure_ascii=False))

if proc is not None:
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
print("SCAN PHASE COMPLETE")
