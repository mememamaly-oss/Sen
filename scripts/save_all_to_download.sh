#!/bin/bash
# Save ALL SENTINEL artifacts to /home/z/my-project/download/
# Task 6: "يرجي حفظ كل شيء في ملفات التنزيل"
set -e

BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/5] Copy missing result artifacts to download/sentinel-results/ ==="

# --- Real-target scans (all versions, historical evolution) ---
for f in scan_testasp_real.json scan_testasp_LIVE.json \
         scan_testaspnet_real.json scan_testaspnet_LIVE.json \
         scan_altoro_LIVE.json scan_altoro_FIXED.json scan_altoro_v202.json \
         scan_testfire_LIVE.json scan_testfire_FINAL.json scan_testfire_PRODUCTION.json \
         scan_ginjuice_LIVE.json scan_ginjuice_probe.json scan_ginjuice_BASELINE.json \
         scan_ginjuice_PRODUCTION.json scan_ginjuice_FINAL.json scan_ginjuice_v210.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done

# --- Benchmark evolution (v1 -> v210) ---
for f in benchmark_v1.json benchmark_v2.json benchmark_v3.json benchmark_FINAL.json \
         benchmark_INITIAL_f0833.json benchmark_v203.json benchmark_v203b.json \
         benchmark_v203c.json benchmark_v203d.json benchmark_v203e.json \
         benchmark_v203_FINAL.json benchmark_v210.json benchmark_v210_repro.json \
         benchmark_baseline.json bench_baseline_v21.json bench_d01.json \
         bench_postdisc.json vr02_bench.json eng_bench.json \
         benchmark_broken.json benchmark_repair_candidate.json \
         benchmark_repair_candidateA.json benchmark_repair_candidateB.json \
         repro_a.json repro_b.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done

# --- Reports ---
cp -f "$LIVE/results/report_live_test.html" "$RES/report_live_test.html" 2>/dev/null || true

# --- Database + strategy state (latest) ---
cp -f "$LIVE/results/sentinel.db" "$RES/sentinel.db"
cp -f "$LIVE/results/strategy_store.json" "$RES/strategy_store.json"

echo "=== [2/5] Copy docs: WORKLOG + CHANGELOG + test scripts ==="
mkdir -p "$RES/test-scripts"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$LIVE/scripts_test_api.py" "$RES/test-scripts/scripts_test_api.py" 2>/dev/null || true
cp -f "$LIVE/scripts_test_store.py" "$RES/test-scripts/scripts_test_store.py" 2>/dev/null || true
cp -f "$LIVE/scripts_strategy_demo.py" "$RES/test-scripts/scripts_strategy_demo.py" 2>/dev/null || true
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"

echo "=== [3/5] Build complete bundle: sentinel-2.1.0-complete-bundle.zip ==="
STAGE=/tmp/sentinel-bundle
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.1.0-complete"
B="$STAGE/sentinel-2.1.0-complete"

# Source tree (same as verified 2.1.0 zip + test scripts)
mkdir -p "$B/source"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$B/source/"
rm -rf "$B/source/sentinel/__pycache__" "$B/source/fixtures/__pycache__" "$B/source/tests/__pycache__"
cp -f "$LIVE"/scripts_*.py "$B/source/"

# Results organized
mkdir -p "$B/results/scans" "$B/results/benchmarks" "$B/results/reports" "$B/database" "$B/docs"
cp -f "$RES"/scan_*.json "$B/results/scans/"
cp -f "$RES"/benchmark*.json "$RES"/bench_*.json "$RES"/vr02_*.json "$RES"/eng_*.json "$RES"/repro_*.json "$B/results/benchmarks/" 2>/dev/null || true
cp -f "$RES"/*.html "$B/results/reports/"
cp -f "$RES"/SENTINEL_Results_Report_AR.pdf "$B/results/reports/" 2>/dev/null || true
cp -f "$RES"/sentinel.db "$RES"/strategy_store.json "$B/database/"
cp -f "$RES"/ground_truth.json "$B/results/benchmarks/"
cp -f "$RES"/WORKLOG.md "$RES"/CHANGELOG.md "$B/docs/"

# Bundle README (index)
cat > "$B/README.md" <<'EOF'
# SENTINEL 2.1.0 — Complete Bundle

Deterministic self-healing DAST platform + full real-test campaign artifacts.

## Contents
- source/            Full platform source (13 modules, fixtures, 36-case test suite, ground truth)
- results/scans/     All real-target scans (testasp, testaspnet, testfire/Altoro, ginandjuice/PortSwigger)
- results/benchmarks/ Benchmark evolution v1 -> v2.1.0 (F1 0.833 -> 1.000) + repair candidates + repro
- results/reports/   HTML + PDF reports (Arabic + English)
- database/          sentinel.db (SQLite runs+findings store) + strategy_store.json
- docs/              WORKLOG.md (full build/fix history) + CHANGELOG.md

## Quick start
    cd source
    python3 sentinel/cli.py doctor
    python3 sentinel/cli.py benchmark          # F1=1.000 expected (auto-starts fixture)
    python3 sentinel/cli.py scan <authorized-target> --max-pages 25 --out results/scan.json
    python3 sentinel/cli.py serve              # REST API + dashboard at http://127.0.0.1:8787

Only scan targets you are explicitly authorized to test.
EOF

cd "$STAGE" && rm -f "$DL/sentinel-2.1.0-complete-bundle.zip"
zip -rq "$DL/sentinel-2.1.0-complete-bundle.zip" sentinel-2.1.0-complete
echo "Bundle created."

echo "=== [4/5] Verify bundle integrity ==="
mkdir -p /tmp/bundle-verify && rm -rf /tmp/bundle-verify/* && cd /tmp/bundle-verify
unzip -q "$DL/sentinel-2.1.0-complete-bundle.zip"
FILES=$(find sentinel-2.1.0-complete -type f | wc -l)
echo "Bundle file count: $FILES"
# Smoke: run doctor from the extracted bundle itself
cd sentinel-2.1.0-complete/source && python3 sentinel/cli.py doctor 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); p=sum(1 for c in d['checks'] if c['status']=='PASS'); print(f'Bundle self-check: doctor {p}/{len(d[\"checks\"])} PASS')"

echo "=== [5/5] Final inventory ==="
echo "--- download/ ---"
ls -la "$DL"
echo "--- download/sentinel-results/ ---"
ls "$RES" | sort
echo "DONE"
