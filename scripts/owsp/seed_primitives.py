#!/usr/bin/env python3
"""GTP-12d: inject the artifact-chain primitives (the content-read servlet
BenchmarkTest00001 + the write-capable FileOutputStream servlet
BenchmarkTest00002) into EVERY no-crawl chunk spec.

Why: the hash/crypto chain phase needs a VERIFIED file-read primitive AND a
VERIFIED write sink in the SAME scan — the read window (artifact first 1000
bytes) and the truncation leg both live on Benchmark servlets that the
CSV-order chunks otherwise contain only by luck (chunk 0 has them, chunks
1-11 have neither -> 223 of 259 hash/crypto tests had no possible chain).
Cost per chunk: 2 extra endpoints (~100 requests).
Idempotent: skips specs that already carry the primitives.
"""
import json
import glob
from pathlib import Path

SRC = Path("/home/z/my-project/tools/benchmark-src")
SPEC_DIR = SRC / "target" / "campaign"
BASE = "http://localhost:8080/benchmark"

import yaml
spec_full = yaml.safe_load((SRC / "data" / "openapi.yaml").read_text())
spec_full["servers"] = [{"url": BASE}]
PRIMS = [p for p in spec_full["paths"]
         if p.endswith("/BenchmarkTest00001") or p.endswith("/BenchmarkTest00002")]

n_injected = 0
for f in sorted(glob.glob(str(SPEC_DIR / "spec_[0-9]*_[0-9]*.json"))):
    d = json.loads(Path(f).read_text())
    added = 0
    for p in PRIMS:
        if p not in d["paths"]:
            d["paths"][p] = spec_full["paths"][p]
            added += 1
    if added:
        Path(f).write_text(json.dumps(d))
        n_injected += 1
        print(f"{Path(f).name}: +{added} primitives")
    else:
        print(f"{Path(f).name}: already carries primitives")
print(f"done: {n_injected} specs updated")
