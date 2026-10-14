#!/usr/bin/env python3
"""TB live minispec builder — extract the given BenchmarkTest paths from the
12-chunk specs into one small spec, so the patched engine can be proven LIVE
against the running stack per fix family (same discipline as the CM rounds)."""
import json
import sys
from pathlib import Path

SPEC_DIR = Path("/home/z/my-project/tool-results/bm_full_chunks")
OUT = Path("/home/z/my-project/tool-results/tb_minispec")


def build(label: str, tcids: list[str]):
    base = None
    paths = {}
    for spec in sorted(SPEC_DIR.glob("spec_*.json")):
        d = json.loads(spec.read_text())
        if base is None:
            base = {k: v for k, v in d.items() if k != "paths"}
        for p, methods in (d.get("paths") or {}).items():
            for t in tcids:
                if t in p:
                    paths[p] = methods
    assert len(paths) == len(tcids), f"missing: {set(tcids) - {p.split('/')[-1] for p in paths}}"
    out = dict(base)
    out["paths"] = paths
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / f"spec_{label}.json"
    dest.write_text(json.dumps(out, indent=1))
    print(f"{label}: {len(paths)} paths -> {dest}")
    for p in sorted(paths):
        print("  ", p)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "tb1a"
    if which == "tb1a":
        # self-named VALUE family representatives: map-read (00031), raw-qs
        # (02622), tcid-value no-mangle (00424), tcid-value+drop-last mangle
        # (00427 — expected STILL FN until TB-1c), plus a trustbound TN
        # control (00250, the safe twin next to the header-name 00251)
        build("tb1a", ["BenchmarkTest00031", "BenchmarkTest02622",
                       "BenchmarkTest00424", "BenchmarkTest00427",
                       "BenchmarkTest00250"])
    elif which == "tb1b":
        # header-NAME family: 00251 (the live-proven rep), 01143, 01206,
        # 02015, 02016 (02015 carries a last-char mangle on the NAME —
        # expected STILL FN until TB-1c's tail variant), TN 00250
        build("tb1b", ["BenchmarkTest00251", "BenchmarkTest01143",
                       "BenchmarkTest01206", "BenchmarkTest02015",
                       "BenchmarkTest02016", "BenchmarkTest00250"])
    elif which == "list":
        build(sys.argv[2], sys.argv[3].split(","))
