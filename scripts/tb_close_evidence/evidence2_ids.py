#!/usr/bin/env python3
"""Evidence 2 — the 12-part test-ID coverage audit for the trustbound close.

Sources (all scan-side, machine-checked):
  - per chunk: the chunk scan DB (findings.url — every scanned endpoint carries
    at least a passive finding row, so the distinct-URL set == the scanned set)
  - the chunk's openapi spec (the input path list) as a cross-check
  - the chunk result JSON stats (endpoints/requests) as a second cross-check
  - the authoritative full range: expectedresults-1.2.csv (2,740 tests)

Prints: per-chunk table, the ONE sorted list (saved alongside), total count,
duplicate count (must be 0), and any gap vs the full 00000-02739 range.
"""
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

OUTD = Path("/home/z/my-project/tool-results/bm_full_chunks")
CSV = Path("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv")
CHUNKS = ["00000_00228", "00229_00457", "00458_00686", "00687_00915",
          "00916_01144", "01145_01373", "01374_01602", "01603_01831",
          "01832_02060", "02061_02289", "02290_02518", "02519_02739"]
ID_RE = re.compile(r"BenchmarkTest(\d{5})")

# the authoritative full range from the ground-truth CSV
csv_ids = set()
for line in CSV.read_text().splitlines():
    if line.startswith("#") or not line.strip():
        continue
    name = line.split(",")[0]
    m = ID_RE.fullmatch(name)
    assert m, f"unparseable CSV test name: {name!r}"
    csv_ids.add(m.group(1))
print(f"ground-truth CSV: {len(csv_ids)} tests, range {min(csv_ids)}..{max(csv_ids)}")
assert len(csv_ids) == 2740 and min(csv_ids) == "00000" and max(csv_ids) == "02739"

all_ids = []          # the one list: every covered ID, in chunk order
per_chunk = {}
print(f"\n{'chunk':<14}{'db_ids':>7}{'spec':>6}{'in-range':>9}{'endpoints':>11}{'requests':>10}  ok")
for label in CHUNKS:
    start, end = label.split("_")
    db = sqlite3.connect(f"file:{OUTD / ('chunk_' + label + '.db')}?mode=ro", uri=True)
    urls = [r[0] for r in db.execute("SELECT DISTINCT url FROM findings")]
    ids = sorted({ID_RE.search(u).group(1) for u in urls if ID_RE.search(u)})
    spec = json.loads((OUTD / f"spec_{label}.json").read_text())
    spec_ids = sorted({ID_RE.search(p).group(1) for p in spec["paths"] if ID_RE.search(p)})
    res = json.loads((OUTD / f"chunk_{label}.json").read_text())
    st = res["stats"]
    in_range = all(start <= i <= end for i in ids)
    ok = (ids == spec_ids                     # DB coverage == spec input list
          and in_range                        # nothing outside the declared range
          and st["endpoints"] >= len(spec_ids))
    per_chunk[label] = ids
    all_ids.extend(ids)
    print(f"{label:<14}{len(ids):>7}{len(spec_ids):>6}{str(in_range):>9}"
          f"{st['endpoints']:>11}{st['requests']:>10}  {'OK' if ok else 'MISMATCH'}")
    assert ok, f"chunk {label}: db/spec mismatch"
    db.close()

# ---- the one sorted list ----
sorted_list = sorted(all_ids)
Path("/home/z/my-project/tool-results/tb_close_ids_sorted.txt").write_text(
    "\n".join(sorted_list))

# ---- the audit numbers ----
counts = Counter(all_ids)
dups = sorted(i for i, n in counts.items() if n > 1)
unique = set(all_ids)
gaps = sorted(csv_ids - unique)
extras = sorted(unique - csv_ids)

print(f"\n=== THE ONE LIST (all covered test IDs across the 12 parts, sorted) ===")
print(f"saved: tool-results/tb_close_ids_sorted.txt  ({len(sorted_list)} IDs)")
print("first 5:", sorted_list[:5], " ... last 5:", sorted_list[-5:])
print(f"\ntotal collected   : {len(all_ids)}")
print(f"unique             : {len(unique)}")
print(f"duplicates         : {len(dups)}  {dups if dups else '(must be 0 — IS 0)'}")
print(f"gaps vs 00000-02739: {len(gaps)}  {gaps if gaps else '(full 2740 covered — NO GAP)'}")
print(f"extras beyond range: {len(extras)}  {extras if extras else '(none)'}")
print(f"\nsum of per-chunk counts: {sum(len(v) for v in per_chunk.values())}"
      f"  == 12 chunks x declared ranges: 11x229 + 1x221 = 2740")
ok = (len(all_ids) == 2740 and not dups and not gaps and not extras)
print("VERDICT:", "COMPLETE — 2740/2740, 0 duplicates, 0 gaps" if ok else "FAIL")
raise SystemExit(0 if ok else 3)
