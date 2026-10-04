#!/usr/bin/env python3
"""L2 projection over the v4.2.3 live scan reports (testaspnet + ginjuice).

WHY THIS EXISTS (honest context, 2026-10-04 round 6):
  The current environment kills any background process between tool calls and
  caps each foreground call at 600s. The testaspnet scan takes 936s and
  ginandjuice 620s (measured in the v4.2.3 re-gate), so a fresh v4.3.0 live
  re-scan of those two targets cannot complete inside one call in THIS
  environment generation (gruyere2 430s and testasp 505s did complete —
  their fresh v4.3.0 scans with pipeline-integrated attack_paths live in
  live_v430/ already).

  L2 (sentinel/apath.py) is a PURE PROJECTION over the serialized scan
  report: build_attack_paths() consumes findings + request_journal + twin +
  action_matrix and sends ZERO requests. The v4.2.3 live reports carry the
  full raw journals of REAL requests that were REALLY sent to the authorized
  targets. Projecting L2 over those journals yields attack paths whose every
  link cites real live evidence — the same paths the integrated pipeline
  produces for the same findings (proven by the testasp equivalence check:
  same 5 paths, same classifications, same link slots+statuses; the 6th live
  path is a target-drift +1 the fresh window produced).

WHAT THIS SCRIPT DOES:
  for each target in [testaspnet, ginjuice]:
    - load build-v423/results/live_v423/<t>.json (the REAL live scan report)
    - run sentinel.apath.build_attack_paths(report)
    - inject the result as .attack_paths into a copy of the report
    - stamp .l2_source = "projection over v4.2.3 live journal (run-...)"
      so every consumer can distinguish projected files from fresh
      v4.3.0 pipeline-integrated scans (which carry no such stamp)
    - write build-v423/results/live_v430/<t>.json

  The engine code is NOT touched; the journals are replayed, never re-sent.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "build-v423"))

from sentinel.apath import build_attack_paths  # noqa: E402

SRC = os.path.join(ROOT, "build-v423", "results", "live_v423")
DST = os.path.join(ROOT, "build-v423", "results", "live_v430")
TARGETS = ["testaspnet", "ginjuice"]


def main():
    out = {}
    for t in TARGETS:
        src = os.path.join(SRC, f"{t}.json")
        rep = json.load(open(src, encoding="utf-8"))
        paths = build_attack_paths(rep)
        rep["attack_paths"] = paths
        rep["l2_source"] = (f"v4.3.0 L2 projection over the v4.2.3 live journal "
                            f"({rep.get('run_id')}, seed {rep.get('seed')}) — "
                            "the engine is verdict-identical (gate verdict-diff vs "
                            "frozen v4.2.2 = NONE) and L2 is a zero-request pure "
                            "projection; this environment cannot host a >600s "
                            "fresh re-scan of this target")
        dst = os.path.join(DST, f"{t}.json")
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(rep, fh)
        s = paths.get("summary", {})
        out[t] = {"run_id": rep.get("run_id"), "paths": s.get("paths_total"),
                  "verified": s.get("paths_verified"),
                  "inferred": s.get("paths_inferred"),
                  "weak": s.get("weak_link_histogram")}
        print(f"{t}: {out[t]}")
    print(json.dumps({"projected": out, "written": TARGETS}))


if __name__ == "__main__":
    main()
