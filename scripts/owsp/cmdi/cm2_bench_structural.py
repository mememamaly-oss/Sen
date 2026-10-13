#!/usr/bin/env python3
"""CM-2 gate: benchmark x3 STRUCTURAL determinism (the v411 method,
order-insensitive + volatile-ID-scrubbed) applied to the cm2 bench runs.
The RAW json differs only in canaries/journal/coverage order (documented in
the CM-1 diff analysis); the structural hash is the determinism verdict."""
import json
import re
import sys

FILES = sys.argv[1:] or [f"/tmp/cm2_bench_{i}.json" for i in (1, 2, 3)]
runs = [json.load(open(f)) for f in FILES]


def scrub(s):
    s = re.sub(r'F-[0-9a-f]{10}', 'F-#', s)
    s = re.sub(r'req-[0-9a-zA-Z]+', 'req-#', s)
    s = re.sub(r'oob-[0-9a-f]+', 'oob-#', s)
    s = re.sub(r'sentinel-hh-[0-9a-f]{10}', 'hh-#', s)
    s = re.sub(r'sentinel-missing-\d+', 'missing-#', s)
    s = re.sub(r"[a-z0-9]*-?vr\d+-[0-9a-f]{6,12}", 'FT', s)
    s = re.sub(r"dom[0-9a-f]{8}", 'dom#', s)
    s = re.sub(r'at t\+\d+', 't+', s)
    s = re.sub(r'127\.0\.0\.1:\d+', 'IP:P', s)
    s = re.sub(r'localhost:\d+', 'LH:P', s)
    s = re.sub(r'"duration": [0-9.]+', '"duration": 0', s)
    s = re.sub(r'"(port|started|finished|timestamp)": ?[0-9]+', r'"\1": 0', s)
    return s


def structural(r):
    r = json.loads(scrub(json.dumps(r)))
    out = {}
    out["run_id"] = r.get("run_id")
    m = r.get("metrics", r)
    out["confusion"] = m.get("confusion")
    out["f1"] = m.get("f1", r.get("f1"))
    out["requests"] = (m.get("scan", {}) or m).get("stats", {}).get(
        "requests", (r.get("scan", {}) or {}).get("stats", {}).get(
            "requests", r.get("requests")))
    findings = m.get("findings", r.get("findings", []))
    out["findings"] = sorted(
        (f.get("type"), f.get("status"), f.get("endpoint_url"),
         f.get("parameter"), scrub(json.dumps(f.get("evidence", []))))
        for f in findings)
    jour = m.get("journal", r.get("journal", [])) or []
    out["journal"] = sorted(scrub(json.dumps(j)) for j in jour)
    cov = m.get("coverage", r.get("coverage", {})) or {}
    out["coverage_keys"] = sorted(cov.keys()) if isinstance(cov, dict) else []
    can = m.get("scan", r.get("scan", {})) or {}
    out["canary_scrubbed"] = scrub(json.dumps(can.get("stats", {})))
    return out


keys = ["run_id", "confusion", "f1", "requests", "findings", "journal",
        "coverage_keys", "canary_scrubbed"]
eq = True
base = None
for i, r in enumerate(runs, 1):
    s = structural(r)
    if base is None:
        base = s
    else:
        for k in keys:
            if s.get(k) != base.get(k):
                eq = False
                print(f"run {i} differs on {k}:")
                if k == "findings":
                    for a, b in zip(base[k], s[k]):
                        if a != b:
                            print("  base tuple:", json.dumps(a)[:360])
                            print("  cur  tuple:", json.dumps(b)[:360])
                            break
                    else:
                        print("  zip equal; set-only-base:",
                              len(set(base[k]) - set(s[k])),
                              "set-only-cur:", len(set(s[k]) - set(base[k])))
                else:
                    print("  base:", str(base.get(k))[:200])
                    print("  cur :", str(s.get(k))[:200])
print("STRUCTURAL EQUALITY x3:", eq)
print("=" * 64)
if eq:
    print("BENCHMARK x3: STRUCTURALLY IDENTICAL (order-insensitive)")
    print("  confusion:", base["confusion"], "| f1:", base["f1"],
          "| requests:", base["requests"],
          "| findings tuples:", len(base["findings"]))
sys.exit(0 if eq else 1)
