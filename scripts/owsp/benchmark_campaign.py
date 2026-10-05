#!/usr/bin/env python3
"""OWASP Benchmark campaign driver — spec preparation + chunked scan runner.

Converts the target's own shipped data/openapi.yaml into JSON spec subsets
(servers rewritten to the live deployment base), so each scan call is bounded
within the 10-min tool window (the all-in-one single-call pattern: stack + scan
+ die). Baseline runs use the FROZEN engine (build-v423); no engine edits here.
"""
import json
import re
import sys
from pathlib import Path

import yaml

SRC = Path("/home/z/my-project/tools/benchmark-src")
OUT = SRC / "target" / "campaign"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://localhost:8080/benchmark"
EXPECTED = SRC / "expectedresults-1.2.csv"


def load_expected() -> list[dict]:
    rows = []
    for line in EXPECTED.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, cat, real, cwe = line.split(",")
        rows.append({"name": name, "category": cat, "vulnerable": real == "true", "cwe": cwe})
    return rows


def load_spec() -> dict:
    spec = yaml.safe_load((SRC / "data" / "openapi.yaml").read_text())
    spec["servers"] = [{"url": BASE}]
    return spec


def path_of_test(name: str, spec_paths: dict) -> str | None:
    for p in spec_paths:
        if p.endswith("/" + name):
            return p
    return None


def build_subset(spec: dict, names: list[str], out_file: Path) -> int:
    sub = {k: spec[k] for k in spec if k != "paths"}
    sub["paths"] = {}
    for n in names:
        p = path_of_test(n, spec["paths"])
        if p is None:
            continue
        sub["paths"][p] = spec["paths"][p]
    out_file.write_text(json.dumps(sub))
    return len(sub["paths"])


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "info"
    rows = load_expected()
    spec = load_spec()

    if mode == "info":
        from collections import Counter
        cats = Counter(r["category"] for r in rows)
        vec = Counter()
        for p, ops in spec["paths"].items():
            for op in ops.values():
                if not isinstance(op, dict):
                    continue
                for prm in op.get("parameters", []) or []:
                    vec[prm.get("in", "query")] += 1
        print("total tests:", len(rows))
        print("categories:", dict(cats))
        print("spec paths:", len(spec["paths"]))
        print("spec param locations:", dict(vec))
        return

    if mode == "subset":
        first, last = int(sys.argv[2]), int(sys.argv[3])
        names = [r["name"] for r in rows[first:last]]
        n = build_subset(spec, names, OUT / f"spec_{first:05d}_{last:05d}.json")
        print(f"subset {first}:{last} -> {n} paths")

    if mode == "one":
        name = sys.argv[2]
        n = build_subset(spec, [name], OUT / f"spec_one_{name}.json")
        print(f"single test {name} -> {n} paths")


if __name__ == "__main__":
    main()
