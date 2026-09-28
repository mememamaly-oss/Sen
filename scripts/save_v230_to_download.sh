#!/bin/bash
# Save ALL SENTINEL v2.3.0 artifacts to /home/z/my-project/download/
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/5] Copy v2.3.0 / Phase-51 artifacts to download/sentinel-results/ ==="
mkdir -p "$RES"
for f in scan_testfire_AUTH_v230.json scan_testfire_AUTH_v230.log \
         benchmark_v5_first.json benchmark_v5_second.json \
         benchmark_v5_rep1.json benchmark_v5_rep2.json benchmark_v5_rep3.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
cp -f "$LIVE/results/sentinel.db" "$RES/sentinel.db"
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md"

echo "=== [2/5] Build sentinel-2.3.0-source.zip (self-sufficient source) ==="
STAGE=/tmp/sentinel-230-src
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.3.0"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$STAGE/sentinel-2.3.0/"
rm -rf "$STAGE/sentinel-2.3.0/sentinel/__pycache__" \
       "$STAGE/sentinel-2.3.0/fixtures/__pycache__" "$STAGE/sentinel-2.3.0/tests/__pycache__" \
       "$STAGE/sentinel-2.3.0/benchmarks/__pycache__"
cp -f "$LIVE"/scripts_*.py "$STAGE/sentinel-2.3.0/" 2>/dev/null || true
cd "$STAGE" && zip -qr "$DL/sentinel-2.3.0-source.zip" sentinel-2.3.0
echo "source zip: $(unzip -l "$DL/sentinel-2.3.0-source.zip" | tail -1)"

echo "=== [3/5] Self-check source zip: extract -> doctor + benchmark F1 ==="
CHK=/tmp/sentinel-230-chk
rm -rf "$CHK" && mkdir -p "$CHK" && cd "$CHK" && unzip -q "$DL/sentinel-2.3.0-source.zip"
cd "$CHK/sentinel-2.3.0"
python -m sentinel.cli doctor > /tmp/doctor_230.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_230.json'))
assert d['overall']=='PASS' and d['passed']==d['total'], d
print('  doctor from zip:', d['passed'], '/', d['total'], 'PASS')"
python -m sentinel.cli benchmark --out /tmp/bench_230.json >/dev/null 2>&1
python3 -c "
import json; d=json.load(open('/tmp/bench_230.json'))
c=d['confusion']
assert d['f1']==1.0 and c['TP']==19 and c['FP']==0 and c['FN']==0 and c['TN']==13, (d['f1'], c)
assert d['stats']['auth']['authenticated'] is True
print('  benchmark from zip: F1=1.000 TP=19 FP=0 FN=0 TN=13 (authenticated)')"

echo "=== [4/5] Rebuild complete bundle (v2.3.0) ==="
STAGE2=/tmp/sentinel-bundle-230
rm -rf "$STAGE2" && mkdir -p "$STAGE2/sentinel-2.3.0-complete"
B="$STAGE2/sentinel-2.3.0-complete"
mkdir -p "$B/source" "$B/results/scans" "$B/results/benchmarks" "$B/results/reports" "$B/database" "$B/docs"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$B/source/"
rm -rf "$B/source/sentinel/__pycache__" "$B/source/fixtures/__pycache__" \
       "$B/source/tests/__pycache__" "$B/source/benchmarks/__pycache__"
cp -f "$LIVE"/scripts_*.py "$B/source/" 2>/dev/null || true
cp -f "$RES"/scan_*.json "$B/results/scans/"
cp -f "$RES"/benchmark*.json "$RES"/bench_*.json "$RES"/vr02_*.json "$RES"/eng_*.json "$RES"/repro_*.json "$B/results/benchmarks/" 2>/dev/null || true
cp -f "$RES"/*.html "$RES"/SENTINEL_Results_Report_AR.pdf "$B/results/reports/" 2>/dev/null || true
cp -f "$RES"/sentinel.db "$RES"/strategy_store.json "$B/database/"
cp -f "$RES"/ground_truth.json "$B/results/benchmarks/"
cp -f "$RES"/WORKLOG.md "$RES"/CHANGELOG.md "$B/docs/"

cat > "$B/README.md" <<'EOF'
# SENTINEL 2.3.0 — Complete Bundle

Deterministic self-healing DAST platform + full real-test campaign artifacts.
Phase 51 (v2.3.0): authenticated scanning — form-intelligent login (session-bound
CSRF), session-loss watchdog with budget-capped re-auth + single replay, browser
session continuity, ENG-06/ENG-07 transport fixes. Real-target proof:
demo.testfire.net authenticated scan (jsmith demo account) reached 10 /bank/*
endpoints invisible anonymously and verified 4 NEW findings incl. CRITICAL SQLi
on /bank/ccApply — session expired 3x mid-scan, self-healed every time.

## Contents
- source/            Full platform source (15 modules incl. auth.py, fixtures v5,
                     46-case test suite, ground truth 19TP/13TN)
- results/scans/     All real-target scans (testasp, testaspnet, testfire/Altoro
                     incl. AUTHENTICATED v2.3.0 run, ginandjuice/PortSwigger)
- results/benchmarks/Full benchmark evolution v1 -> v5 (F1=1.000 at every step)
- results/reports/   HTML + PDF reports
- database/          sentinel.db (all persisted runs) + strategy store
- docs/              WORKLOG + CHANGELOG

## Verify (60s)
cd source && python -m sentinel.cli doctor     # 11/11
python -m sentinel.cli benchmark               # F1=1.000 TP=19 FP=0 FN=0 TN=13 (authenticated scan)
python tests/run_tests.py                      # 46/46

## Quality state
- 46/46 tests, 11/11 doctor, F1=1.000 deterministic x3 (run-3c0652b6be)
- Real targets: 4 platforms, 19 verified actives, 0 false positives
EOF
cd "$STAGE2" && zip -qr "$DL/sentinel-2.3.0-complete-bundle.zip" sentinel-2.3.0-complete
echo "bundle zip: $(unzip -l "$DL/sentinel-2.3.0-complete-bundle.zip" | tail -1)"

echo "=== [5/5] Bundle self-check (doctor from inside the bundle) ==="
CHK2=/tmp/sentinel-bundle-230-chk
rm -rf "$CHK2" && mkdir -p "$CHK2" && cd "$CHK2" && unzip -q "$DL/sentinel-2.3.0-complete-bundle.zip"
cd "$CHK2/sentinel-2.3.0-complete/source"
python -m sentinel.cli doctor > /tmp/doctor_bundle_230.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_bundle_230.json'))
assert d['overall']=='PASS' and d['passed']==d['total'], d
print('  bundle self-check doctor:', d['passed'], '/', d['total'], 'PASS')"

echo "=== DONE — inventory ==="
ls -la "$DL" | grep -E "2\.3\.0|README" || true
echo "sentinel-results files: $(ls "$RES" | wc -l)"
