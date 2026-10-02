#!/usr/bin/env python3
"""L1-R: inspect benchmark recovery outputs vs frozen baseline (structural).

Reads recovery-validation/engine-outputs/bench_recovery_{1,2,3}.json and the
frozen gap-validation/results/bench_v411_{1,2,3}.json, printing the headline
metrics and a structural comparison of the security-relevant substance
(same comparison families as the L0 session / verify_recovery_v411.py).
"""
import json
import sys

OUT = "recovery-validation/engine-outputs"
BASE = "gap-validation/results"


def summary(d):
    c = d.get("confusion") or {}
    return {
        "f1": d.get("f1"),
        "precision": d.get("precision"),
        "recall": d.get("recall"),
        "tp": c.get("tp"), "fp": c.get("fp"), "fn": c.get("fn"), "tn": c.get("tn"),
        "findings": d.get("findings_count") or d.get("findings"),
        "requests": d.get("requests"),
    }


def main():
    ok = True
    rows = {}
    for i in (1, 2, 3):
        d = json.load(open(f"{OUT}/bench_recovery_{i}.json"))
        rows[f"recovery_{i}"] = summary(d)
    for i in (1, 2, 3):
        try:
            d = json.load(open(f"{BASE}/bench_v411_{i}.json"))
            rows[f"baseline_{i}"] = summary(d)
        except FileNotFoundError:
            print(f"baseline bench_v411_{i}.json missing"); ok = False
    for k, v in rows.items():
        print(k, json.dumps(v, sort_keys=True))
    # structural equality across the 3 recovery runs (headline metrics)
    recs = [rows[f"recovery_{i}"] for i in (1, 2, 3)]
    ident = all(r == recs[0] for r in recs)
    print("recovery x3 headline identical:", ident)
    base = [rows.get(f"baseline_{i}") for i in (1, 2, 3)]
    if all(base):
        print("recovery == baseline (headline):", all(r == base[0] for r in recs) and recs[0] == base[0])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
