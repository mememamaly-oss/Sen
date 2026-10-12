#!/bin/bash
# Task 40 CR-1 gate part 1 — doctor + bench x3 (engine untouched by CR-1:
# results must be IDENTICAL to the shipped baseline; 38/0/0/37).
set -u
ENG=/home/z/my-project/build-v430
cd "$ENG" || exit 1
echo "=== DOCTOR ==="
timeout 300 python3 sentinel/cli.py doctor 2>&1 | tail -6
echo "=== BENCH x3 ==="
for i in 1 2 3; do
  timeout 400 python3 - <<PY
import json
from sentinel.cli import run_benchmark
rep = run_benchmark(out="/tmp/cr1_bench_$i.json", label="cr1-bench-$i")
c = rep["confusion"]
print("bench-$i:", {k: c[k] for k in ("TP","FP","FN","TN")}, "F1=%.4f" % rep["f1"],
      "reqs=", rep.get("scan", {}).get("stats", {}).get("requests", rep.get("requests")))
PY
done
echo "=== GATE PART 1 DONE ==="
