#!/usr/bin/env python3
"""GTP-13: build diagnostic/rescan specs from explicit test-name lists.

Modes:
  fnchunks        split ALL FN tests (from the definitive eval) into N chunks,
                  each SEEDED with the artifact-chain primitives
                  (BenchmarkTest00001 read + 00002 write) per GTP-12d, and emit
                  the file list for the runner.
  tests f1 f2...  build one spec from explicit names (also seeded).
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path("/home/z/my-project")
SRC = ROOT / "tools/benchmark-src"
OUT = SRC / "target" / "campaign"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://localhost:8080/benchmark"
EXPECTED = SRC / "expectedresults-1.2.csv"
SEEDS = ["BenchmarkTest00001", "BenchmarkTest00002"]


def load_expected():
    rows = []
    for line in EXPECTED.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, cat, real, cwe = line.split(",")
        rows.append({"name": name, "category": cat, "vulnerable": real == "true"})
    return rows


def main():
    spec = yaml.safe_load((SRC / "data" / "openapi.yaml").read_text())
    spec["servers"] = [{"url": BASE}]
    mode = sys.argv[1] if len(sys.argv) > 1 else "fnchunks"

    def build(names, out_name):
        sub = {k: spec[k] for k in spec if k != "paths"}
        sub["paths"] = {}
        for n in names:
            for p in spec["paths"]:
                if p.endswith("/" + n):
                    sub["paths"][p] = spec["paths"][p]
                    break
        (OUT / out_name).write_text(json.dumps(sub))
        return len(sub["paths"])

    if mode == "fnchunks":
        n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 2
        ev = json.load(open(ROOT / "build-v430/results/owsp/benchmark/"
                            "eval_v431_gtp12_definitive.json"))
        fns = []
        for cat, c in ev["per_category"].items():
            fns.extend(c["fn_tests"])
        fns = sorted(set(fns))
        print(f"total FN tests: {len(fns)}")
        per = (len(fns) + n_chunks - 1) // n_chunks
        plan = []
        for i in range(n_chunks):
            part = fns[i * per:(i + 1) * per]
            if not part:
                break
            name = f"gtp13_fn_{i:02d}"
            n = build(SEEDS + part, f"spec_{name}.json")
            plan.append(name)
            print(f"chunk {name}: {len(part)} fn + 2 seed -> {n} paths")
        (ROOT / "build-v430/results/owsp/benchmark/gtp13_fn_plan.json").write_text(
            json.dumps(plan))
    elif mode == "tests":
        names = sys.argv[2:]
        n = build(SEEDS + names, "spec_gtp13_explicit.json")
        print(f"explicit spec: {n} paths (seeds included)")


if __name__ == "__main__":
    main()
