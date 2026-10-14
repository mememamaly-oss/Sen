#!/usr/bin/env python3
"""CM-2 chunk-3 stall bisector: split the chunk spec into halves and scan
each with a hard timeout; the hanging half narrows to the culprit tests.
Usage: cm2_bisect.py <spec.json> <timeout-per-half>"""
import json
import subprocess
import sys
from pathlib import Path

import yaml

SPEC = Path(sys.argv[1])
TMO = int(sys.argv[2]) if len(sys.argv) > 2 else 240
BM = Path("/home/z/tools/benchmark")
ENG = Path("/home/z/my-project/build-v430")
OUT = Path("/tmp/cm2_bisect")
OUT.mkdir(exist_ok=True)


def run_subset(paths, tag, timeout):
    spec = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
    spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
    spec["paths"] = {p: spec_paths[p] for p in paths}
    sp = OUT / f"spec_{tag}.json"
    sp.write_text(json.dumps(spec))
    out = OUT / f"res_{tag}.json"
    try:
        r = subprocess.run(
            [sys.executable, "sentinel/cli.py", "scan",
             "http://localhost:8080/benchmark",
             "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
             "--openapi-spec", str(sp), "--seed", "7f3c91aa", "--max-pages", "6000",
             "--out", str(out), "--db", str(OUT / f"db_{tag}.db")],
            cwd=str(ENG), capture_output=True, text=True, timeout=timeout)
        reqs = None
        if out.exists():
            d = json.loads(out.read_text())
            reqs = d.get("stats", {}).get("requests")
        print(f"{tag}: rc={r.returncode} reqs={reqs} "
              f"{'COMPLETED' if out.exists() else 'NO-RESULT(stall/timeout)'}")
        return out.exists(), reqs
    except subprocess.TimeoutExpired:
        print(f"{tag}: TIMEOUT after {timeout}s (HANGING SUBSET)")
        return False, None


spec_paths = json.loads(SPEC.read_text())["paths"]
keys = list(spec_paths.keys())
print(f"bisecting {len(keys)} paths from {SPEC.name}, {TMO}s per subset")
lo, hi = 0, len(keys)
# round 1: halves
mid = (lo + hi) // 2
okA, _ = run_subset(keys[lo:mid], f"h1_{lo}_{mid}", TMO)
okB, _ = run_subset(keys[mid:hi], f"h2_{mid}_{hi}", TMO)
print("half1:", "OK" if okA else "HANG", "| half2:", "OK" if okB else "HANG")
