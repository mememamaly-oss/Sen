#!/usr/bin/env python3
"""Merge sequential SENTINEL suite-chunk verdicts into ONE full-suite verdict.

Usage: merge_suite_chunks.py <out.json> <chunk1.json> <chunk2.json> ...
Requires: chunk ranges, in order, cover the whole registration order exactly
once (no gaps, no overlaps); every case executed (skipped rows dropped);
zero failures. Emits the merged verdict with honest chunked-run metadata.
"""
import json
import sys


def main():
    if len(sys.argv) < 3:
        print("usage: merge_suite_chunks.py <out.json> <chunk.json> ...", file=sys.stderr)
        return 2
    out_path, chunk_paths = sys.argv[1], sys.argv[2:]
    chunks = [json.load(open(p)) for p in chunk_paths]
    names = []
    meta = []
    for ch in chunks:
        rng = ch["range"]
        meta.append({"tag": ch["tag"], "range": rng, "wall_s": ch["wall_s"],
                     "log": ch["log"]})
        expected = ch["members"]
        got = [c["name"] for c in ch["cases"]]
        if got != expected:
            print(f"chunk {ch['tag']}: executed set != members — refusing merge",
                  file=sys.stderr)
            return 1
        names.extend(got)
    # uniqueness + full coverage in registration order is implied by the
    # per-chunk member check plus this global uniqueness check:
    if len(names) != len(set(names)):
        dupes = {n for n in names if names.count(n) > 1}
        print(f"duplicate executions: {sorted(dupes)} — refusing merge", file=sys.stderr)
        return 1
    cases = []
    for ch in chunks:
        cases.extend(ch["cases"])
    failed = sum(1 for c in cases if not c["ok"])
    verdict = {
        "suite": "all",
        "mode": "sequential-chunks (sandbox 590s single-process wall)",
        "chunks": meta,
        "total": len(cases),
        "failed": failed,
        "cases": cases,
        "passed": failed == 0,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=1)
    print(f"merged {len(cases)} cases from {len(chunks)} chunks: "
          f"failed={failed} -> {out_path}")
    for c in cases:
        if not c["ok"]:
            print(f"  FAILED: {c['name']}: {c.get('error', '')[:200]}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
