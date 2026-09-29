#!/bin/bash
# Save ALL SENTINEL v2.4.0 artifacts to /home/z/my-project/download/
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/5] Copy v2.4.0 / Phase-52 artifacts to download/sentinel-results/ ==="
mkdir -p "$RES"
for f in scan_ginjuice_v240_PUBLIC_OAST.json \
         bench_v24_det1.json bench_v24_det2.json bench_v24_det3.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
for i in 1 2 3; do cp -f /tmp/bench_v24_det$i.json "$RES/benchmark_v240_det$i.json"; done
cp -f "$LIVE/results/sentinel.db" "$RES/sentinel.db"
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md" 2>/dev/null || true

echo "=== [2/5] Build sentinel-2.4.0-source.zip (self-sufficient source) ==="
STAGE=/tmp/sentinel-240-src
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.4.0"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$STAGE/sentinel-2.4.0/"
rm -rf "$STAGE/sentinel-2.4.0/sentinel/__pycache__" \
       "$STAGE/sentinel-2.4.0/fixtures/__pycache__" "$STAGE/sentinel-2.4.0/tests/__pycache__" \
       "$STAGE/sentinel-2.4.0/benchmarks/__pycache__"
cd "$STAGE" && zip -qr "$DL/sentinel-2.4.0-source.zip" sentinel-2.4.0
echo "source zip: $(unzip -l "$DL/sentinel-2.4.0-source.zip" | tail -1)"

echo "=== [3/5] Self-check source zip: extract -> doctor + benchmark F1 ==="
CHK=/tmp/sentinel-240-chk
rm -rf "$CHK" && mkdir -p "$CHK" && cd "$CHK" && unzip -q "$DL/sentinel-2.4.0-source.zip"
cd "$CHK/sentinel-2.4.0"
python -m sentinel.cli doctor > /tmp/doctor_240.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_240.json'))
assert d['overall']=='PASS' and d['passed']==d['total'], d
print('  doctor from zip:', d['passed'], '/', d['total'], 'PASS')"
python -m sentinel.cli benchmark --out /tmp/bench_240.json >/dev/null 2>&1
python3 -c "
import json; d=json.load(open('/tmp/bench_240.json'))
c=d['confusion']
assert d['f1']==1.0 and c['TP']==19 and c['FP']==0 and c['FN']==0 and c['TN']==13, (d['f1'], c)
assert d['stats']['auth']['authenticated'] is True
assert d['stats']['oast']['channel']=='local' and d['stats']['oast']['interactions']==2, d['stats']['oast']
print('  benchmark from zip: F1=1.000 TP=19 FP=0 FN=0 TN=13 (authenticated, oast local x2)')"
cd "$LIVE"  # back to live tree for step 4 relative paths

echo "=== [4/5] Rebuild complete bundle (v2.4.0) ==="
STAGE2=/tmp/sentinel-bundle-240
rm -rf "$STAGE2" && mkdir -p "$STAGE2/sentinel-2.4.0-bundle"
cp -r "$RES" "$STAGE2/sentinel-2.4.0-bundle/sentinel-results"
cp -f "$DL/sentinel-2.4.0-source.zip" "$STAGE2/sentinel-2.4.0-bundle/"
cp -f "$LIVE/CHANGELOG.md" "$STAGE2/sentinel-2.4.0-bundle/"
cp -f "$BASE/worklog.md" "$STAGE2/sentinel-2.4.0-bundle/WORKLOG.md" 2>/dev/null || true
cat > "$STAGE2/sentinel-2.4.0-bundle/README.txt" <<'TXT'
SENTINEL v2.4.0 — COMPLETE BUNDLE
=================================
sentinel-2.4.0-source.zip   self-sufficient source (12 modules + browser/DOM engine,
                            auth engine, OAST local+public providers, fixtures v5,
                            49-test suite, ground truth v5, CHANGELOG)
sentinel-results/           every real-target scan (v2.0.0 -> v2.4.0), full benchmark
                            evolution, repair campaigns, reports, sentinel.db,
                            strategy store, ground truth, WORKLOG
Quick start: unzip source -> python -m sentinel.cli doctor
             python -m sentinel.cli benchmark
             python -m sentinel.cli scan https://<authorized-target> --oast public
TXT
cd "$STAGE2" && zip -qr "$DL/sentinel-2.4.0-complete-bundle.zip" sentinel-2.4.0-bundle
echo "bundle: $(unzip -l "$DL/sentinel-2.4.0-complete-bundle.zip" | tail -1)"

echo "=== [5/5] Bundle self-check (doctor from inside the bundle) ==="
CHK2=/tmp/sentinel-bundle-240-chk
rm -rf "$CHK2" && mkdir -p "$CHK2" && cd "$CHK2" && unzip -q "$DL/sentinel-2.4.0-complete-bundle.zip"
cd "$CHK2/sentinel-2.4.0-bundle" && mkdir -p /tmp/bundle-x && cd /tmp/bundle-x \
  && rm -rf sentinel-2.4.0 && unzip -q "$CHK2/sentinel-2.4.0-bundle/sentinel-2.4.0-source.zip" \
  && cd sentinel-2.4.0 && python -m sentinel.cli doctor 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['overall']=='PASS'
print('  bundle self-check doctor:', d['passed'], '/', d['total'], 'PASS')"

echo ""
echo "ALL v2.4.0 ARTIFACTS SAVED:"
ls -la "$DL" | grep -E "2.4.0|README" || true
