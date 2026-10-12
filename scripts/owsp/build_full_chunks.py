#!/usr/bin/env python3
"""Build the 12 full-benchmark chunk specs (campaign pattern: expectedresults
order, ~230 tests/chunk, openapi.yaml paths, servers -> live base)."""
import json
import math
import yaml
from pathlib import Path

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/bm_full_chunks")
OUT.mkdir(parents=True, exist_ok=True)

rows = []
for line in open('/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv'):
    if line.startswith('#') or not line.strip():
        continue
    name, cat, real, cwe = line.strip().split(',')
    rows.append(name)

spec = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
by_test = {}
for p in spec["paths"]:
    by_test[p.rsplit("/", 1)[-1]] = p

n = len(rows)
k = 12
size = math.ceil(n / k)
made = 0
for i in range(k):
    chunk_tests = rows[i*size:(i+1)*size]
    sub = {kk: spec[kk] for kk in spec if kk != "paths"}
    sub["paths"] = {}
    for t in chunk_tests:
        if t in by_test:
            sub["paths"][by_test[t]] = spec["paths"][by_test[t]]
    label = f"{i*size:05d}_{min((i+1)*size, n)-1:05d}"
    (OUT / f"spec_{label}.json").write_text(json.dumps(sub))
    made += 1
    print(f"spec_{label}.json: {len(sub['paths'])} paths")
print("total specs:", made, "| tests:", n)
