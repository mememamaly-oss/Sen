#!/usr/bin/env python3
"""Merge the 3 no-crawl chunk scans into one virtual scan JSON and save it
where benchmark_eval.py expects a single scan file."""
import json, sys

CAMP = "/home/z/my-project/tools/benchmark-src/target/campaign"
OUT = f"{CAMP}/v430_full/v430_merged_r2.json"
chunks = ["chunk_00000_00228.json", "chunk_00228_00457.json", "chunk_00457_00685.json",
          "chunk_00685_00914.json", "chunk_00914_01142.json", "chunk_01142_01371.json",
          "chunk_01371_01599.json", "chunk_01599_01828.json", "chunk_01828_02056.json",
          "chunk_02056_02284.json", "chunk_02284_02512.json", "chunk_02512_02740.json"]

merged = {"findings": [], "rejected_candidates": [], "unverified_candidates": []}
stats = {"requests": 0, "endpoints": 0}
for c in chunks:
    d = json.load(open(f"{CAMP}/v430_full/{c}"))
    merged["findings"].extend(d.get("findings", []))
    merged["rejected_candidates"].extend(d.get("rejected_candidates", []))
    merged["unverified_candidates"].extend(d.get("unverified_candidates", []))
    s = d.get("stats", {})
    stats["requests"] += s.get("requests") or 0
    stats["endpoints"] += (s.get("endpoints") or 0)
merged["stats"] = stats
merged["scanner"] = "sentinel-core/4.3.0 (3 no-crawl chunks merged)"
json.dump(merged, open(OUT, "w"))
n_act = [f for f in merged["findings"] if f["type"] not in ("missing_security_headers",
             "server_banner_disclosure", "tech_banner")]
n_ver = [f for f in n_act if f.get("status") == "verified"]
print(f"merged: {stats['requests']} reqs, {len(merged['findings'])} findings, "
      f"{len(n_act)} active, {len(n_ver)} verified")
print("saved:", OUT)
