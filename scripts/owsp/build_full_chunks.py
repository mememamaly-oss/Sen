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

# CR-1 (crypto/hash recall round, 2026-10-12): the hash/crypto chain phase dies
# entirely when a chunk's own scan has no VERIFIED file_marker read primitive
# (chainphase.run returns [] on prim None). Chunks 5-6 (tests 00917-01374) hold
# ZERO content-leaking traversal endpoints, so 23 crypto + 19 hash vulnerable
# tests were FN purely because of the artificial 12-chunk split. Seeding the two
# PROVEN chain primitives into EVERY chunk spec restores the single-scan
# semantics (a real one-shot scan of the app has all endpoints in scope; the
# findings still have to be earned on each test's own endpoint).
# Live-proven this round: chunk-5/6 minispec WITHOUT primitives = 0 catches;
# WITH the seeds the chain runs and the same tests verify.
SEED_PRIMITIVES = ["BenchmarkTest00001",   # read primitive (file_marker /etc/passwd leak)
                   "BenchmarkTest00002"]   # write/truncate primitive (writability_oracle sink)

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
    seeded = [t for t in SEED_PRIMITIVES if t not in chunk_tests]
    sub = {kk: spec[kk] for kk in spec if kk != "paths"}
    sub["paths"] = {}
    for t in chunk_tests + seeded:
        if t in by_test:
            sub["paths"][by_test[t]] = spec["paths"][by_test[t]]
    label = f"{i*size:05d}_{min((i+1)*size, n)-1:05d}"
    (OUT / f"spec_{label}.json").write_text(json.dumps(sub))
    made += 1
    print(f"spec_{label}.json: {len(sub['paths'])} paths ({len(chunk_tests)} tests + {len(seeded)} primitive seeds)")
print("total specs:", made, "| tests:", n)
