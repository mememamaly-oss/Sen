#!/usr/bin/env python3
"""GTP-13: merge the 12 full chunks into one virtual scan + run the eval."""
import json
import subprocess
import sys
from pathlib import Path

CAMP = Path("/home/z/my-project/tools/benchmark-src/target/campaign")
OUTD = CAMP / "gtp13_full"

merged = {"findings": [], "rejected_candidates": [], "unverified_candidates": []}
stats = {"requests": 0, "endpoints": 0}
for i in range(12):
    d = json.load(open(OUTD / f"chunk_{i}.json"))
    merged["findings"].extend(d.get("findings", []))
    merged["rejected_candidates"].extend(d.get("rejected_candidates", []))
    merged["unverified_candidates"].extend(d.get("unverified_candidates", []))
    s = d.get("stats", {})
    stats["requests"] += s.get("requests") or 0
    stats["endpoints"] += (s.get("endpoints") or 0)
merged["stats"] = stats
merged["scanner"] = "sentinel-core/4.3.4-GTP13 (12 no-crawl chunks merged)"
merged["run_id"] = "gtp13-full-r1"
OUT = str(OUTD / "gtp13_merged.json")
json.dump(merged, open(OUT, "w"))

n_act = [f for f in merged["findings"] if f["type"] not in
         ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
n_ver = [f for f in n_act if f.get("status") == "verified"]
print(f"merged: {stats['requests']} reqs, {len(merged['findings'])} findings, "
      f"{len(n_act)} active, {len(n_ver)} verified")
print("saved:", OUT)
