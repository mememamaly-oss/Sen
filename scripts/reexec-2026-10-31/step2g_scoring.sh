#!/bin/bash
# STEP 2g (atomic): independent scoring vs the pre-registered predictions
# (three-way: confirmed TP / undetermined / miss+reason) + SHA-256 stamping
# of all raw evidence.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }
EV=evidence/full-reverify

echo "== [1] scoring vs pre-registered ground truth (never engine output) =="
python3 scripts/reverify/score_reverify.py 2>&1 | tail -60

echo "== [2] key scoring sections (from artifact) =="
python3 - <<'PYEOF'
import json
d = json.load(open("evidence/full-reverify/scoring.json"))
for run in ("benchmark_cli_run", "store_full_config_run"):
    s = d[run]
    print(f"[{run}] findings={s['engine_findings']} confusion={s['confusion']} "
          f"P/R/F1={s['precision']}/{s['recall']}/{s['f1']}")
    print(f"  undetermined outside list ({len(s['undetermined_findings_outside_list'])}):",
          s['undetermined_findings_outside_list'][:8])
    print(f"  scan-time verified: {s['scan_time_verification']['findings_status_verified']}"
          f"/{s['scan_time_verification']['findings_total']}")
c = d.get("cross_run_agreement", {})
print("[cross-run agreement] a:", c.get("run_a_findings"), "b:", c.get("run_b_findings"),
      "identical:", c.get("identical_finding_sets"))
if c.get("only_in_a"): print("  only_in_a:", c["only_in_a"][:5])
if c.get("only_in_b"): print("  only_in_b:", c["only_in_b"][:5])
print("[fixture replay]", d.get("replay_verification"))
g = d.get("ginandjuice-shop", {})
print("[ginandjuice] findings:", g.get("engine_findings"), "| scoring:",
      (g.get("scoring") or "")[:80])
print("  replay:", g.get("replay_verification"))
print("  passive reobservation:", g.get("passive_reobservation"))
print("[testphp]", d.get("testphp-vulnweb"))
print("[docker]", d.get("docker-targets"))
PYEOF

echo "== [3] SHA-256 stamping of all raw evidence =="
cd $EV
find . -type f \( -name "*.json" -o -name "*.log" -o -name "*.html" -o -name "*.db" -o -name "*.md" -o -name "*.jsonl" \) ! -name "SHA256SUMS*" ! -name "*.memory.json" -print0 \
  | xargs -0 sha256sum > SHA256SUMS 2>/dev/null || \
  (find . -type f ! -name "SHA256SUMS*" ! -name "*.memory.json" -print0 | xargs -0 sha256sum > SHA256SUMS)
wc -l SHA256SUMS
grep -E 'predictions.json|scoring.json|benchmark.json|ginandjuice-shop/scan.json' SHA256SUMS
cd /home/z/my-project

echo "== [4] tree status =="
git status --short | head -20
echo "STEP2G COMPLETE"
