#!/usr/bin/env python3
"""phase0_suite_aggregate.py — machine aggregate over the 19 per-chunk suite
result JSONs produced by scripts/hardening_gate_range.sh.

Built for the PHASE-0 debt-settlement gate (supervisor reset order 2026-10-17)
per the standing tools clause (rebuild -> commit -> push immediately; never
bare on disk). Output format reproduces the accepted axis-4 closure gate log
verbatim:

  machine aggregate over the 19 per-chunk result JSONs:
  chunks: 19 | per-chunk: 227/227 failed=0 (all)
  SUITE TOTAL: 4313/4313

Contract (from the accepted record, results/gate_axis4_7448f95e.log):
  - exactly 19 chunk result files (/tmp/tb_gates/result_c*.chunk.json)
  - every chunk: total == 227, failed == 0
  - SUITE TOTAL: 4313/4313 (19 x 227)
Any deviation is printed honestly and exits 1.
"""
import glob
import json
import os
import sys

OUT = "/tmp/tb_gates"
EXPECT_CHUNKS = 19
EXPECT_PER_CHUNK = 227


def main() -> int:
    files = sorted(glob.glob(os.path.join(OUT, "result_c*.chunk.json")))
    print("machine aggregate over the %d per-chunk result JSONs:" % len(files))
    chunks = []
    bad = []
    for f in files:
        try:
            with open(f) as fh:
                d = json.load(fh)
        except Exception as e:  # honest degradation: unreadable = failure
            bad.append((f, "unreadable: %s" % e))
            continue
        total = int(d.get("total", -1))
        failed = int(d.get("failed", -1))
        chunks.append((os.path.basename(f), total, failed))
        if total != EXPECT_PER_CHUNK or failed != 0:
            bad.append((os.path.basename(f), "total=%d failed=%d" % (total, failed)))
    ok_chunks = [c for c in chunks if c[1] == EXPECT_PER_CHUNK and c[2] == 0]
    if chunks and len(ok_chunks) == len(chunks) and not bad:
        per = "%d/%d failed=0 (all)" % (EXPECT_PER_CHUNK, EXPECT_PER_CHUNK)
    else:
        per = " ".join("%s=%d/%d" % (n, t - fl, t) for n, t, fl in chunks) or "no chunks"
    print("chunks: %d | per-chunk: %s" % (len(chunks), per))
    passed = sum(t - fl for _, t, fl in chunks)
    total = sum(t for _, t, _ in chunks)
    print("SUITE TOTAL: %d/%d" % (passed, total))
    if bad:
        print("DEVIATIONS (honest):")
        for name, why in bad:
            print("  %s: %s" % (name, why))
    if len(chunks) != EXPECT_CHUNKS:
        print("DEVIATION: expected %d chunks, got %d" % (EXPECT_CHUNKS, len(chunks)))
        return 1
    if total != EXPECT_CHUNKS * EXPECT_PER_CHUNK or failed_total(chunks) != 0:
        return 1
    return 0


def failed_total(chunks):
    return sum(fl for _, _, fl in chunks)


if __name__ == "__main__":
    sys.exit(main())
