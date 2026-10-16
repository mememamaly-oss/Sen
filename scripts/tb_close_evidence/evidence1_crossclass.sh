#!/bin/bash
# Evidence 1 — the cross-class (tuple/list) comparison fix in tb_close_eval.py:
#   (a) the TRUE pre-fix -> post-fix diff (recovered from the reflog: c13c4b5
#       was an amend of 554cb03 — the pre-fix bytes live in 554cb03)
#   (b) RAW output of the PRE-FIX script run now on the same 12 chunks (RED:
#       the spurious DIFFERS on identical data)
#   (c) RAW output of the FIXED script run now (GREEN: IDENTICAL + PASS)
#   (d) proof the fixed re-run left the committed scan/eval artifacts
#       byte-identical (determinism)
set -u
cd /home/z/my-project

echo "################ (a) THE TRUE DIFF (554cb03 pre-fix -> c13c4b5 post-fix) ################"
git diff 554cb03 c13c4b5 -- scripts/owsp/trustbound/tb_close_eval.py

echo
echo "################ (b) PRE-FIX SCRIPT RAW OUTPUT (run NOW on the same 12 chunks) ################"
mkdir -p /tmp/tb_prefix_out
git show 554cb03:scripts/owsp/trustbound/tb_close_eval.py > /tmp/tb_close_eval_prefix.py
# redirect only the two OUTPUT paths to /tmp (the committed artifacts stay untouched)
sed -i 's|SCAN_OUT = RESD / "benchmark_scan_tb_close.json"|SCAN_OUT = Path("/tmp/tb_prefix_out/scan.json")|' /tmp/tb_close_eval_prefix.py
sed -i 's|EVAL_OUT = RESD / "eval_tb_close_full.json"|EVAL_OUT = Path("/tmp/tb_prefix_out/eval.json")|' /tmp/tb_close_eval_prefix.py
(timeout 400 python3 -u /tmp/tb_close_eval_prefix.py; echo "prefix-exit-rc=$?")
echo "(pre-fix outputs written to /tmp/tb_prefix_out/ — the committed artifacts untouched)"

echo
echo "################ (c) FIXED SCRIPT RAW OUTPUT (the committed c13c4b5 file, run NOW) ################"
(timeout 400 python3 -u scripts/owsp/trustbound/tb_close_eval.py; echo "fixed-exit-rc=$?")

echo
echo "################ (d) DETERMINISM: the fixed re-run vs the committed artifacts ################"
ST=$(git status --short -- build-v430/results/owsp/benchmark/benchmark_scan_tb_close.json build-v430/results/owsp/benchmark/eval_tb_close_full.json)
if [ -z "$ST" ]; then
  echo "CLEAN — the re-run reproduced both committed artifacts byte-identically"
else
  echo "DIRTY — the re-run changed the artifacts (unexpected): $ST"
fi
