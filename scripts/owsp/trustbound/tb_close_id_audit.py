#!/usr/bin/env python3
"""EVIDENCE 2 (order 2026-10-15) — full test-ID aggregation across the 12
benchmark chunk specs + duplicate/gap audit against the complete ground-truth
domain.

The 12 specs are regenerated with the EXACT campaign generator
(scripts/owsp/build_full_chunks.py) from the SAME preserved ground truth
(expectedresults-1.2.csv, 2740 tests) and the SAME pinned source
(BenchmarkJava @ 8b67a88, CSV byte-identical, openapi.yaml from the clone).
Fidelity markers reproduced: the two documented boundary placements
(BenchmarkTest01374 -> chunk 6's spec, BenchmarkTest02519 -> chunk 11's spec).
"""
import json
import re
from collections import Counter
from pathlib import Path

OUTD = Path("/home/z/my-project/tool-results/bm_full_chunks")
RESD = Path("/home/z/my-project/build-v430/results/owsp/benchmark")
EV = RESD / "tb_close_evidence"
EV.mkdir(exist_ok=True)

CHUNKS = ["00000_00228", "00229_00457", "00458_00686", "00687_00915",
          "00916_01144", "01145_01373", "01374_01602", "01603_01831",
          "01832_02060", "02061_02289", "02290_02518", "02519_02739"]
SEEDS = {"BenchmarkTest00001", "BenchmarkTest00002"}  # CR-1 chain primitives

# ---- ground truth: the complete domain ----
rows = [l.split(",")[0] for l in open(RESD / "expectedresults-1.2.csv")
        if not l.startswith("#") and l.strip()]
domain = set(rows)
nums = sorted(int(r.replace("BenchmarkTest", "")) for r in rows)
print(f"ground-truth domain: {len(rows)} tests, "
      f"BenchmarkTest{nums[0]:05d}..BenchmarkTest{nums[-1]:05d}, "
      f"contiguous={nums == list(range(nums[0], nums[-1] + 1))}")
print("  (0-based INDEX range of the same 2740 tests = 00000..02739 — "
      "the chunk labels are index-based)")

# ---- per-spec TCID sets ----
per_spec = {}
for label in CHUNKS:
    d = json.loads((OUTD / f"spec_{label}.json").read_text())
    tc = [p.rsplit("/", 1)[-1] for p in d["paths"]]
    assert all(re.fullmatch(r"BenchmarkTest\d{5}", t) for t in tc)
    per_spec[label] = tc

# ---- the PRIMARY partition (what the generator sliced from the CSV;
#      the seeds are deliberate CR-1 re-inclusions, accounted separately) ----
print("\n=== per-part primary partition (CSV slice) + seed re-inclusions ===")
assign = {}          # tcid -> primary chunk label
seed_hits = Counter()
for i, label in enumerate(CHUNKS):
    primary = per_spec[label]
    seeds = [t for t in primary if t in SEEDS and t in assign]
    fresh = [t for t in primary if t not in SEEDS]
    for t in primary:
        if t in SEEDS and t in assign:
            seed_hits[t] += 1
        else:
            assign[t] = label
    print(f"{label}: {len(primary)} paths | primary-new={len(fresh) + sum(1 for t in primary if t in SEEDS and t not in assign)}"
          f" | seed re-included={len(seeds)}")

# ---- aggregate: single sorted list over the PRIMARY partition ----
all_primary = sorted(assign, key=lambda t: int(t.replace("BenchmarkTest", "")))
dup_primary = [t for t, c in Counter(
    t for label in CHUNKS for t in per_spec[label]
    if not (t in SEEDS and any(t in per_spec[l2] for l2 in CHUNKS[:CHUNKS.index(label)]))
).items() if c > 1]

union_all = set().union(*[set(per_spec[l]) for l in CHUNKS])
gaps = sorted(domain - union_all, key=lambda t: int(t.replace("BenchmarkTest", "")))
foreign = sorted(union_all - domain, key=lambda t: int(t.replace("BenchmarkTest", "")))

print("\n=== AGGREGATE AUDIT ===")
print(f"distinct test IDs across ALL 12 parts (union): {len(union_all)}")
print(f"primary-partition assignments: {len(all_primary)}")
print(f"primary-partition duplicates (a test PRIMARY in >1 part): {len(dup_primary)} {dup_primary}")
print(f"seed re-inclusions (CR-1 chain primitives, by design): "
      f"{dict(seed_hits)} = {sum(seed_hits.values())} re-inclusions "
      f"(findings attribution unaffected: the eval keys each TCID exactly once)")
print(f"gaps vs full domain (in ground truth, NOT covered by any part): {len(gaps)} {gaps}")
print(f"foreign (covered by a part, NOT in ground truth): {len(foreign)} {foreign}")
print(f"VERDICT: union==domain: {union_all == domain} | "
      f"primary dups=0: {len(dup_primary) == 0} | gaps=0: {len(gaps) == 0} | "
      f"foreign=0: {len(foreign) == 0}")

# ---- cross-check vs the PRESERVED close-run scan + eval ----
scan = json.loads((RESD / "benchmark_scan_tb_close.json").read_text())
scan_tcids = set()
for f in scan["findings"]:
    m = re.search(r"(BenchmarkTest\d{5})(?:[?/].*)?$", f.get("url", ""))
    if m:
        scan_tcids.add(m.group(1))
print(f"\ncross-check vs preserved merged scan: "
      f"{len(scan_tcids)} distinct TCIDs with findings, "
      f"all inside covered set: {scan_tcids <= union_all}")
ev = json.loads((RESD / "eval_tb_close_full.json").read_text())
tot = sum(m["tp"] + m["fp"] + m["fn"] + m["tn"] for m in ev["per_category"].values())
print(f"cross-check vs preserved eval: per-category TP+FP+FN+TN total = {tot} "
      f"(every ground-truth test counted EXACTLY once: {tot == len(domain)})")

# ---- the single sorted list (full, unabridged) ----
out = EV / "03_id_aggregation.txt"
with out.open("w") as fh:
    fh.write("sorted test-ID list covered by the 12 parts (primary partition, "
             "all 2740, comma-separated):\n")
    fh.write(",".join(all_primary) + "\n")
    fh.write(f"\ntotal={len(all_primary)} distinct={len(union_all)} "
             f"primary-dups={len(dup_primary)} gaps={len(gaps)} foreign={len(foreign)}\n")
    fh.write(f"seed re-inclusions (by design, CR-1): {dict(seed_hits)}\n")
print(f"\nsorted list saved: {out}")
print("SORTED LIST (first 8):", ",".join(all_primary[:8]))
print("SORTED LIST (last 8):", ",".join(all_primary[-8:]))
print("\nFULL SORTED LIST:")
print(",".join(all_primary))
