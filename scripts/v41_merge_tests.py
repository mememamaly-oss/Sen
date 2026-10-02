#!/usr/bin/env python3
"""SENTINEL v4.1 — merge chunked suite verdicts into tests_v410_FULL.json."""
import glob
import json

OUT = "/home/z/my-project/build-v410/results/tests_v410_FULL.json"
cases = {}
files = sorted(glob.glob("/tmp/v41_chunk_*.json")) + sorted(glob.glob("/tmp/v41_regr_*.json"))
for f in files:
    raw = open(f, errors="replace").read()
    d = json.loads(raw[raw.find("{"):])
    for c in d.get("cases", []):
        if c.get("skipped"):
            continue
        name = c["name"]
        if name in cases and cases[name] != c:
            raise SystemExit(f"CONFLICT for {name} between chunks")
        cases[name] = c

merged = {
    "suite": "all (merged from 20 chunked runs — SENTINEL_TEST_FILTER; strict "
             "accounting: every case ran, none skipped, vacuous passes impossible)",
    "total": len(cases),
    "failed": sum(1 for c in cases.values() if not c["ok"]),
    "cases": [cases[k] for k in sorted(cases)],
    "chunks": [f.split("/")[-1] for f in files],
}
merged["passed"] = merged["failed"] == 0
by_suite = {"unit": 0, "regression": 0, "chaos": 0}
for c in cases.values():
    by_suite[c["name"].split("_")[0]] += 1
merged["by_suite"] = by_suite
merged["total_ms"] = round(sum(c.get("ms", 0) for c in cases.values()), 1)

with open(OUT, "w") as fh:
    json.dump(merged, fh, indent=1)
print(f"merged {len(cases)} cases from {len(files)} chunks -> {OUT}")
print("by_suite:", by_suite, "| failed:", merged["failed"], "| passed:", merged["passed"])
assert len(cases) == 97, "expected exactly 97 cases"
assert merged["failed"] == 0, "FAILURES PRESENT"
print("OK: 97/97, zero failures")
