#!/bin/bash
# Save ALL SENTINEL v2.8.0 artifacts to /home/z/my-project/download/
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/5] Copy v2.8.0 artifacts to download/sentinel-results/ ==="
mkdir -p "$RES"
for f in scan_testfire_v280_LIVE.json scan_testfire_v280_AUTHZ.json \
         secrets_testfire_v280.json authz_testfire.json \
         tests_v280b_FULL.json benchmark_v280b_det1.json benchmark_v280b_det2.json \
         benchmark_v280b_det3.json probe_tf_second_account.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
cp -f "$LIVE/results/sentinel_v280.db" "$RES/sentinel_v280.db"
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md" 2>/dev/null || true
cp -f "$LIVE/run_live_authz_testfire.py" "$RES/run_live_authz_testfire.py"
ls "$RES" | wc -l | xargs echo "  sentinel-results files:"

echo "=== [2/5] Build sentinel-2.8.0-source.zip (self-sufficient source) ==="
STAGE=/tmp/sentinel-280-src
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.8.0"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md "$STAGE/sentinel-2.8.0/"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
cd "$STAGE" && zip -qr "$DL/sentinel-2.8.0-source.zip" sentinel-2.8.0
echo "  source zip: $(unzip -l "$DL/sentinel-2.8.0-source.zip" | tail -1)"

echo "=== [3/5] Self-check source zip: extract -> doctor + benchmark F1 ==="
CHK=/tmp/sentinel-280-chk
rm -rf "$CHK" && mkdir -p "$CHK" && cd "$CHK" && unzip -q "$DL/sentinel-2.8.0-source.zip"
cd "$CHK/sentinel-2.8.0"
python3 -m sentinel.cli doctor > /tmp/doctor_280.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_280.json'))
assert d['overall']=='PASS' and d['passed']==d['total']==13, d
print('  doctor from zip: 13 / 13 PASS')"
python3 -m sentinel.cli benchmark --out /tmp/bench_280.json >/dev/null 2>&1
python3 -c "
import json; d=json.load(open('/tmp/bench_280.json'))
c=d['confusion']
assert d['f1']==1.0 and c['TP']==30 and c['FP']==0 and c['FN']==0 and c['TN']==24, (d['f1'], c)
assert d['run_id']=='run-3c0652b6be', d['run_id']
assert d['stats']['authz']['ran'] is True, d['stats']['authz']
print('  benchmark from zip: F1=1.000 TP=30 FP=0 FN=0 TN=24 run-3c0652b6be (authz ran)')"
cd "$LIVE"

echo "=== [4/5] Build complete bundle (v2.8.0) ==="
STAGE2=/tmp/sentinel-bundle-280
rm -rf "$STAGE2" && mkdir -p "$STAGE2/sentinel-2.8.0-bundle"
cp -r "$RES" "$STAGE2/sentinel-2.8.0-bundle/sentinel-results"
cp -f "$DL/sentinel-2.8.0-source.zip" "$STAGE2/sentinel-2.8.0-bundle/"
cp -f "$LIVE/CHANGELOG.md" "$STAGE2/sentinel-2.8.0-bundle/"
cp -f "$BASE/worklog.md" "$STAGE2/sentinel-2.8.0-bundle/WORKLOG.md" 2>/dev/null || true
cat > "$STAGE2/sentinel-2.8.0-bundle/README.txt" <<'TXT'
SENTINEL v2.8.0 — COMPLETE BUNDLE ("Intelligence Layer" Release)
===============================================================
sentinel-2.8.0-source.zip   self-sufficient source: 26-module engine incl.
                           the six intelligence engines (authz / secrets /
                           paramintel / coverage / appmap / fingerprint+impact),
                           fixture v8, 67-test suite, ground truth v8 (30 TP / 24 TN).
                           Self-check: doctor 13/13 + benchmark F1=1.000
                           deterministic (run-3c0652b6be, authz armed).
sentinel-results/           every real-target artifact of the campaign,
                           incl. the v2.8.0 testfire live scan (672 req, 74
                           verified, 0 rejected) and the LIVE multi-user
                           authorization battery (48 req): vertical_privilege_
                           escalation VERIFIED on /admin/admin.jsp via the
                           chained SQLi -> admin-session -> role-differential
                           path, VR-18 reproduced, impact PROVEN.
CHANGELOG.md / WORKLOG.md   release notes + the full build history.
TXT
cd "$STAGE2" && zip -qr "$DL/sentinel-2.8.0-complete-bundle.zip" sentinel-2.8.0-bundle
echo "  bundle: $(unzip -l "$DL/sentinel-2.8.0-complete-bundle.zip" | tail -1)"

echo "=== [5/5] Verify zips ==="
unzip -t "$DL/sentinel-2.8.0-source.zip" > /dev/null && echo "  source zip OK"
unzip -t "$DL/sentinel-2.8.0-complete-bundle.zip" > /dev/null && echo "  bundle zip OK"
ls -la "$DL" | grep "2.8.0"
