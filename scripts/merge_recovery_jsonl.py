#!/usr/bin/env python3
"""Recovery test (step 11): merge the clone-run chunk ledger into
tests_recovery.json with STRICT accounting — every case ran EXACTLY once,
failed=0, no case missing, no duplicates. Mirrors merge_v411_jsonl.py.

Usage: merge_recovery_jsonl.py --clone <dir> --ledger <jsonl> --out <json>
"""
import argparse
import json
import re
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--clone", required=True)
ap.add_argument("--ledger", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()

TESTS = a.clone.rstrip("/") + "/build-v411/tests/run_tests.py"
names = re.findall(r"@case\s*\ndef\s+([a-zA-Z_0-9]+)", open(TESTS).read())
recs = [json.loads(l) for l in open(a.ledger) if l.strip()]

bad = [r for r in recs if not r["ok"]]
if bad:
    print("CHUNK VIOLATIONS:", [(r["chunk"], r["failed"], r["missing"])
                                for r in bad])
    sys.exit(3)

ran_names = [c["name"] for r in recs for c in r["cases"]]
dups = sorted({n for n in ran_names if ran_names.count(n) > 1})
missing = [n for n in names if n not in ran_names]
extra = [n for n in ran_names if n not in names]
if dups or missing or extra or len(ran_names) != len(names):
    print(f"ACCOUNTING FAIL: dups={dups} missing={missing} "
          f"extra={extra} ran={len(ran_names)} expected={len(names)}")
    sys.exit(3)

cases = sorted((c for r in recs for c in r["cases"]),
               key=lambda c: names.index(c["name"]))
out = {"suite": "v4.1.1-recovery", "total": len(cases),
       "failed": sum(1 for c in cases if not c["ok"]),
       "ran": len(cases), "expected": len(names),
       "strict_ok": len(cases) == len(names) and all(c["ok"] for c in cases),
       "cases": cases}
json.dump(out, open(a.out, "w"), indent=1)
print(f"MERGED: total={out['total']} failed={out['failed']} -> {a.out}")
print("VERDICT:", "PASS" if out["strict_ok"] else "FAIL")
sys.exit(0 if out["strict_ok"] else 1)
