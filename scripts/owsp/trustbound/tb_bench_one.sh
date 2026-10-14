#!/bin/bash
# tb_bench_one.sh — run ONE bench pass of the tb_gate.sh bench contract.
# Why this wrapper exists: tb_gate.sh bench runs all three passes + the
# structural compare in ONE invocation (~15 min), which cannot complete inside
# a single foreground call (the supervisor's foreground-only order — long
# background jobs get killed between calls). This wrapper runs pass <i> with
# the EXACT same inline python as tb_gate.sh bench, writing the same
# /tmp/tb_bench_<i>.json; run it for i=1,2,3, then run
# cmdi/cm2_bench_structural.py on the three files (same compare tb_gate.sh
# uses). Usage: tb_bench_one.sh 1|2|3
set -u
ENG=/home/z/my-project/build-v430
cd "$ENG" || exit 1
i="${1:?bench index required: 1|2|3}"
case "$i" in 1|2|3) ;; *) echo "index must be 1, 2 or 3"; exit 2;; esac
timeout 500 python3 - "$i" <<'PY'
import json, sys
i = sys.argv[1]
from sentinel.cli import run_benchmark
rep = run_benchmark(out=f"/tmp/tb_bench_{i}.json", label=f"tb-bench-{i}")
c = rep["confusion"]
print("bench-%s:" % i, {k: c[k] for k in ("TP","FP","FN","TN")},
      "F1=%.4f" % rep["f1"],
      "reqs=", rep.get("scan", {}).get("stats", {}).get("requests", rep.get("requests")))
PY
