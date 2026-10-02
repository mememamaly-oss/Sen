#!/usr/bin/env python3
"""Merge the v4.1.1 chunk ledger into tests_v411_FULL.json with STRICT
accounting: every case in the runner ran EXACTLY once, failed=0, no case
missing, no duplicate execution."""
import json, re, sys

TESTS = "/home/z/my-project/build-v411/tests/run_tests.py"
LEDGER = "/home/z/my-project/gap-validation/results/tests_v411_chunks.jsonl"
OUT = "/home/z/my-project/gap-validation/results/tests_v411_FULL.json"

names = re.findall(r"@case\s*\ndef\s+([a-zA-Z_0-9]+)", open(TESTS).read())
recs = [json.loads(l) for l in open(LEDGER) if l.strip()]

bad = [r for r in recs if not r["ok"]]
if bad:
    print("CHUNK VIOLATIONS:", [(r["chunk"], r["failed"], r["missing"])
                                for r in bad])
    sys.exit(3)

ran_names = [c["name"] for r in recs for c in r["cases"]]
dups = {n for n in ran_names if ran_names.count(n) > 1}
missing = [n for n in names if n not in ran_names]
extra = [n for n in ran_names if n not in names]
if dups or missing or extra or len(ran_names) != len(names):
    print(f"ACCOUNTING FAIL: dups={sorted(dups)} missing={missing} "
          f"extra={extra} ran={len(ran_names)} expected={len(names)}")
    sys.exit(3)

cases = sorted((c for r in recs for c in r["cases"]),
               key=lambda c: names.index(c["name"]))
out = {"suite": "all", "total": len(cases),
       "failed": sum(1 for c in cases if not c["ok"]), "cases": cases}
json.dump(out, open(OUT, "w"), indent=1)
print(f"MERGED: total={out['total']} failed={out['failed']} "
      f"-> {OUT}")
print("VERDICT:", "PASS" if out["failed"] == 0 and out["total"] == len(names)
      else "FAIL")
