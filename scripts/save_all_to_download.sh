#!/bin/bash
# Save ALL SENTINEL artifacts to /home/z/my-project/download/ (v2.2.0 update)
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/4] Copy v2.2.0 + Phase-50 artifacts to download/sentinel-results/ ==="
for f in scan_ginjuice_v220_BROWSER.json scan_ginjuice_v220_FINAL.json \
         scan_ginjuice_v220_FINAL2.json scan_ginjuice_v220_PRODUCTION.json \
         benchmark_v4_live1.json benchmark_v4_live2.json benchmark_v4_repro1.json \
         benchmark_v4_repro2.json benchmark_v4_disc12.json benchmark_v4_BR02.json \
         benchmark_v4_FINAL.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
cp -f "$LIVE/results/sentinel.db" "$RES/sentinel.db"
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md"

echo "=== [2/4] Rebuild complete bundle (v2.2.0) ==="
STAGE=/tmp/sentinel-bundle-220
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.2.0-complete"
B="$STAGE/sentinel-2.2.0-complete"
mkdir -p "$B/source" "$B/results/scans" "$B/results/benchmarks" "$B/results/reports" "$B/database" "$B/docs"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$B/source/"
rm -rf "$B/source/sentinel/__pycache__" "$B/source/fixtures/__pycache__" "$B/source/tests/__pycache__"
cp -f "$LIVE"/scripts_*.py "$B/source/" 2>/dev/null || true
cp -f "$RES"/scan_*.json "$B/results/scans/"
cp -f "$RES"/benchmark*.json "$RES"/bench_*.json "$RES"/vr02_*.json "$RES"/eng_*.json "$RES"/repro_*.json "$B/results/benchmarks/" 2>/dev/null || true
cp -f "$RES"/*.html "$RES"/SENTINEL_Results_Report_AR.pdf "$B/results/reports/" 2>/dev/null || true
cp -f "$RES"/sentinel.db "$RES"/strategy_store.json "$B/database/"
cp -f "$RES"/ground_truth.json "$B/results/benchmarks/"
cp -f "$RES"/WORKLOG.md "$RES"/CHANGELOG.md "$B/docs/"

cat > "$B/README.md" <<'EOF'
# SENTINEL 2.2.0 — Complete Bundle

Deterministic self-healing DAST platform + full real-test campaign artifacts.
Phase 50 (v2.2.0): Browser/DOM engine — Playwright/Chromium rendering, DOM XSS
execution proofs, div-form + JSON-body discovery, session cookie jar, CSRF-token
preservation. Real-target proof: ginandjuice.shop /blog?search DOM XSS verified
via WAF-bypassing attribute-injection vector.

## Contents
- source/            Full platform source (14 modules incl. browser.py, fixtures v4,
                     41-case test suite, ground truth 17TP/12TN)
- results/scans/     All real-target scans (testasp, testaspnet, testfire/Altoro,
                     ginandjuice/PortSwigger incl. v2.2.0 browser-phase production runs)
- results/benchmarks/ Benchmark evolution v1 -> v2.2.0 (F1 0.833 -> 1.000) + repair + repro
- results/reports/   HTML + PDF reports
- database/          sentinel.db (SQLite runs+findings store) + strategy_store.json
- docs/              WORKLOG.md + CHANGELOG.md

## Quick start
    cd source
    python3 sentinel/cli.py doctor            # 10/10 (browser_engine included)
    python3 sentinel/cli.py benchmark         # F1=1.000 (TP=17 FP=0 FN=0 TN=12)
    python3 sentinel/cli.py scan <authorized-target> --max-pages 25 --out results/scan.json
    python3 sentinel/cli.py serve             # REST + dashboard at 127.0.0.1:8022

Requires: Python 3.10+ stdlib; optional Playwright+Chromium for the DOM phase
(graceful degradation without it). Only scan targets you are authorized to test.
EOF

cd "$STAGE" && rm -f "$DL/sentinel-2.2.0-complete-bundle.zip"
zip -rq "$DL/sentinel-2.2.0-complete-bundle.zip" sentinel-2.2.0-complete

echo "=== [3/4] Verify bundle ==="
mkdir -p /tmp/bundle-verify-220 && rm -rf /tmp/bundle-verify-220/* && cd /tmp/bundle-verify-220
unzip -q "$DL/sentinel-2.2.0-complete-bundle.zip"
FILES=$(find sentinel-2.2.0-complete -type f | wc -l)
echo "bundle files: $FILES"
cd sentinel-2.2.0-complete/source && python3 sentinel/cli.py doctor 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print('bundle self-check doctor:', d['passed'],'/',d['total'])"

echo "=== [4/4] Inventory ==="
ls "$DL" | sort
echo "sentinel-results count: $(ls "$RES" | wc -l)"
echo "DONE"
