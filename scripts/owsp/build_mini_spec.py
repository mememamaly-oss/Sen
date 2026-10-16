#!/usr/bin/env python3
"""Build a mini validation spec: representative endpoints for every GTP-12..16
fix family, extracted from the campaign chunk specs."""
import json, glob, sys

TARGETS = [
    # GTP-12: writability on real write sinks + the FP source that must die
    "BenchmarkTest00001",  # read primitive (control, stays TP)
    "BenchmarkTest00002",  # FileOutputStream write sink (was FN)
    "BenchmarkTest00028",  # FileOutputStream write sink (was FN)
    "BenchmarkTest00064",  # NOT-vulnerable write sink (constant path, must stay silent)
    "BenchmarkTest00255",  # crypto echo page — writability FP must DIE
    # GTP-13: weakrand families
    "BenchmarkTest00085",  # nextLong
    "BenchmarkTest00160",  # nextBytes
    "BenchmarkTest00161",  # nextDouble
    "BenchmarkTest00461",  # Math.random router rescue
    "BenchmarkTest00078",  # nextFloat (honest FN — must stay silent)
    # GTP-14: trustbound channels
    "BenchmarkTest00031",  # param-map (test-named param)
    "BenchmarkTest00251",  # header-NAME channel
    "BenchmarkTest01875",  # cookie channel
    "BenchmarkTest01455",  # magic-value resolver (name channel)
    "BenchmarkTest00587",  # magic-value resolver
    # GTP-15: xpath channels
    "BenchmarkTest00207",  # header channel
    "BenchmarkTest00442",  # xpath FN
    # GTP-16: hash/crypto chain
    "BenchmarkTest00003",  # hash cookie channel
    "BenchmarkTest00005",  # crypto header channel DES
    "BenchmarkTest00019",  # crypto header channel DES (was FN)
    "BenchmarkTest00029",  # hash FN
    "BenchmarkTest00462",  # hash FN
    "BenchmarkTest00208",  # crypto FN
    "BenchmarkTest00009",  # hash (gate check)
]

out = {"openapi": "3.0.0", "info": {"title": "mini-gtp-validation", "version": "1"},
       "paths": {}}
found = 0
for f in sorted(glob.glob("/home/z/my-project/tools/benchmark-src/target/campaign/spec_*.json")):
    d = json.load(open(f))
    for p, ops in d.get("paths", {}).items():
        tcid = p.rsplit("/", 1)[-1]
        if tcid in TARGETS and tcid not in json.dumps(out):
            out["paths"][p] = ops
            found += 1
# dedupe check
seen = set()
for p in list(out["paths"]):
    tcid = p.rsplit("/", 1)[-1]
    if tcid in seen:
        del out["paths"][p]
    seen.add(tcid)
dest = "/home/z/my-project/tools/benchmark-src/target/campaign/spec_mini_gtp.json"
json.dump(out, open(dest, "w"), indent=1)
print(f"mini spec: {found} paths -> {dest}")
missing = set(TARGETS) - seen
if missing:
    print("MISSING:", sorted(missing))
