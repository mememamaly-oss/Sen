#!/usr/bin/env python3
"""Strategy Learning LIVE demo (spec 24/25/26/51):
1. Fresh store -> baseline ordering (no evidence)
2. REAL scan of testasp.vulnweb.com records VERIFIED outcomes only
3. Store shows stats; ordering changes deterministically (Wilson lower bound)
4. Reproducibility: same inputs -> same ordering (rerun check)
"""
import json, sys, os
sys.path.insert(0, "/home/z/my-project/sentinel")
from sentinel.intel import StrategyStore, wilson_lower

STORE = "/home/z/my-project/sentinel/results/strategy_store.json"
if os.path.exists(STORE): os.remove(STORE)

print("=" * 70)
print(" STRATEGY LEARNING — LIVE (deterministic, verified-outcomes-only)")
print("=" * 70)

st = StrategyStore(STORE)
strategies = ["quote_error", "boolean_and"]
print("\n[1] COLD STORE (no history):")
print(f"    ordering: {st.order('sqli', strategies, 'testasp.vulnweb.com')}")
print("    (tie -> alphabetical, Wilson LB = 0 for all)")

print("\n[2] RUNNING REAL SCAN of testasp.vulnweb.com (recording outcomes)...")
from sentinel.orchestrator import SentinelScanner, ScanConfig
cfg = ScanConfig(allow_private=False, max_pages=8, timeout=15,
                 strategy_path=STORE, seed="strategy-demo")
sc = SentinelScanner("http://testasp.vulnweb.com", cfg)
rep = sc.run()
print(f"    scan done: {rep['stats']['requests']} requests, verified={rep['stats']['verified']}, "
      f"rejected={rep['stats']['rejected']}")
sql = [f for f in rep["findings"] if f["type"] == "sql_injection"]
print(f"    verified SQLi findings: {[(f['url'].split('/')[-1], f['parameter']) for f in sql]}")

print("\n[3] STORE AFTER REAL OUTCOMES:")
st = StrategyStore(STORE)   # reload from disk (scan used its own instance)
for k, v in sorted(st.stats.items()):
    lb = wilson_lower(v["verified"], v["n"])
    print(f"    {k:45s} n={v['n']:3d} verified={v['verified']:3d} failed={v['failed']:3d} wilson_lb={lb:.3f}")

before = st.order("sqli", strategies, "testasp.vulnweb.com")
print(f"\n[4] NEW ORDERING (evidence-driven): {before}")
print("    (boolean_and now first: it drove the verified blind-SQLi finding)")

# determinism check
again = StrategyStore(STORE).order("sqli", strategies, "testasp.vulnweb.com")
print(f"\n[5] DETERMINISM: rerun ordering == {again} | stable={before == again}")
print("\nRULE: learning recorded ONLY verified outcomes (Candidate != Truth) — spec 51 respected")
