#!/bin/bash
# Save ALL SENTINEL v2.5.0 artifacts to /home/z/my-project/download/
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/5] Copy v2.5.0 / Phase-53 artifacts to download/sentinel-results/ ==="
mkdir -p "$RES"
for f in scan_ginjuice_v250_PUBLIC_OAST.json live_validation_v250.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
for i in 1 2 3; do cp -f /tmp/bench_v25_det$i.json "$RES/benchmark_v250_det$i.json"; done
cp -f "$LIVE/results/sentinel.db" "$RES/sentinel.db"
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md" 2>/dev/null || true

echo "=== [2/5] Build sentinel-2.5.0-source.zip (self-sufficient source) ==="
STAGE=/tmp/sentinel-250-src
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.5.0"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$STAGE/sentinel-2.5.0/"
rm -rf "$STAGE/sentinel-2.5.0/sentinel/__pycache__" \
       "$STAGE/sentinel-2.5.0/fixtures/__pycache__" "$STAGE/sentinel-2.5.0/tests/__pycache__" \
       "$STAGE/sentinel-2.5.0/benchmarks/__pycache__"
cd "$STAGE" && zip -qr "$DL/sentinel-2.5.0-source.zip" sentinel-2.5.0
echo "source zip: $(unzip -l "$DL/sentinel-2.5.0-source.zip" | tail -1)"

echo "=== [3/5] Self-check source zip: extract -> doctor + benchmark F1 ==="
CHK=/tmp/sentinel-250-chk
rm -rf "$CHK" && mkdir -p "$CHK" && cd "$CHK" && unzip -q "$DL/sentinel-2.5.0-source.zip"
cd "$CHK/sentinel-2.5.0"
python -m sentinel.cli doctor > /tmp/doctor_250.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_250.json'))
assert d['overall']=='PASS' and d['passed']==d['total'], d
print('  doctor from zip:', d['passed'], '/', d['total'], 'PASS')"
python -m sentinel.cli benchmark --out /tmp/bench_250.json >/dev/null 2>&1
python3 -c "
import json; d=json.load(open('/tmp/bench_250.json'))
c=d['confusion']
assert d['f1']==1.0 and c['TP']==22 and c['FP']==0 and c['FN']==0 and c['TN']==16, (d['f1'], c)
assert d['stats']['auth']['authenticated'] is True
assert d['stats']['oast']['channel']=='local' and d['stats']['oast']['interactions']==7, d['stats']['oast']
print('  benchmark from zip: F1=1.000 TP=22 FP=0 FN=0 TN=16 (authenticated, oast local x7)')"
cd "$LIVE"

echo "=== [4/5] Rebuild complete bundle (v2.5.0) ==="
STAGE2=/tmp/sentinel-bundle-250
rm -rf "$STAGE2" && mkdir -p "$STAGE2/sentinel-2.5.0-bundle"
cp -r "$RES" "$STAGE2/sentinel-2.5.0-bundle/sentinel-results"
cp -f "$DL/sentinel-2.5.0-source.zip" "$STAGE2/sentinel-2.5.0-bundle/"
cp -f "$LIVE/CHANGELOG.md" "$STAGE2/sentinel-2.5.0-bundle/"
cp -f "$BASE/worklog.md" "$STAGE2/sentinel-2.5.0-bundle/WORKLOG.md" 2>/dev/null || true
cat > "$STAGE2/sentinel-2.5.0-bundle/README.txt" <<'TXT'
SENTINEL v2.5.0 — COMPLETE BUNDLE
=================================
sentinel-2.5.0-source.zip   self-sufficient source (16 modules: 9 detectors incl.
                            SSRF/command-injection/CORS, browser/DOM engine, auth
                            engine, OAST local+public providers, fixtures v6,
                            52-test suite, ground truth v6, CHANGELOG)
sentinel-results/           every real-target scan (v2.0.0 -> v2.5.0), full benchmark
                            evolution, repair campaigns, reports, sentinel.db,
                            strategy store, ground truth, WORKLOG
Quick start: unzip source -> python -m sentinel.cli doctor
             python -m sentinel.cli benchmark
             python -m sentinel.cli scan https://<authorized-target> --oast public
TXT
cd "$STAGE2" && zip -qr "$DL/sentinel-2.5.0-complete-bundle.zip" sentinel-2.5.0-bundle
echo "bundle: $(unzip -l "$DL/sentinel-2.5.0-complete-bundle.zip" | tail -1)"

echo "=== [5/5] Bundle self-check (doctor from inside the bundle) ==="
CHK2=/tmp/sentinel-bundle-250-chk
rm -rf "$CHK2" && mkdir -p "$CHK2" && cd "$CHK2" && unzip -q "$DL/sentinel-2.5.0-complete-bundle.zip"
mkdir -p /tmp/bundle-x250 && cd /tmp/bundle-x250 \
  && rm -rf sentinel-2.5.0 && unzip -q "$CHK2/sentinel-2.5.0-bundle/sentinel-2.5.0-source.zip" \
  && cd sentinel-2.5.0 && python -m sentinel.cli doctor 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['overall']=='PASS'
print('  bundle self-check doctor:', d['passed'], '/', d['total'], 'PASS')"

echo ""
echo "ALL v2.5.0 ARTIFACTS SAVED:"
ls -la "$DL" | grep -E "2.5.0|README" || true
