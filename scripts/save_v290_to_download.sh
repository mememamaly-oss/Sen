#!/bin/bash
# Save ALL SENTINEL v2.9.0 artifacts to /home/z/my-project/download/
set -e
BASE=/home/z/my-project
LIVE=$BASE/verify-live
DL=$BASE/download
RES=$DL/sentinel-results

echo "=== [1/6] Copy v2.9.0 artifacts to download/sentinel-results/ ==="
mkdir -p "$RES"
for f in scan_testfire_v290_LIVE.json secrets_testfire_v290.json \
         testfire_vault.vault vault_audit_testfire_v290.json \
         live_validation_v290.json tests_v290_FULL.json \
         benchmark_v290_det1.json benchmark_v290_det2.json \
         benchmark_v290_det3.json doctor_v290.json; do
  [ -f "$RES/$f" ] && cp -f "$RES/$f" "$RES/$f" 2>/dev/null || true
done
# benchmark + doctor verdicts live in $LIVE/results
for f in benchmark_v290_det1.json benchmark_v290_det2.json benchmark_v290_det3.json doctor_v290.json; do
  [ -f "$LIVE/results/$f" ] && cp -f "$LIVE/results/$f" "$RES/$f"
done
# NOTE: the live scan/secrets/vault/audit/live-validation artifacts were
# written DIRECTLY to $RES by the production run (incl. sentinel_v290.db);
# benchmark/doctor verdicts live in $LIVE/results and are copied above.
cp -f "$LIVE/benchmarks/ground_truth.json" "$RES/ground_truth.json"
cp -f "$LIVE/CHANGELOG.md" "$RES/CHANGELOG.md"
cp -f "$BASE/worklog.md" "$RES/WORKLOG.md" 2>/dev/null || true
ls "$RES" | wc -l | xargs echo "  sentinel-results files:"

echo "=== [2/6] Build sentinel-2.9.0-source.zip (self-sufficient source) ==="
STAGE=/tmp/sentinel-290-src
rm -rf "$STAGE" && mkdir -p "$STAGE/sentinel-2.9.0"
cd "$LIVE" && cp -r sentinel fixtures tests benchmarks CHANGELOG.md .gitignore-vault "$STAGE/sentinel-2.9.0/"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
cd "$STAGE" && zip -qr "$DL/sentinel-2.9.0-source.zip" sentinel-2.9.0
echo "  source zip: $(unzip -l "$DL/sentinel-2.9.0-source.zip" | tail -1)"

echo "=== [3/6] Self-check source zip: doctor + benchmark F1 + vault gates ==="
CHK=/tmp/sentinel-290-chk
rm -rf "$CHK" && mkdir -p "$CHK" && cd "$CHK" && unzip -q "$DL/sentinel-2.9.0-source.zip"
cd "$CHK/sentinel-2.9.0"
python3 -m sentinel.cli doctor > /tmp/doctor_290.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/doctor_290.json'))
assert d['overall']=='PASS' and d['passed']==d['total']==14, d
print('  doctor from zip: 14 / 14 PASS')"
# ENG-11 guard: the vault command group must work in SCRIPT mode from the zip
python3 sentinel/cli.py vault --help > /dev/null 2>&1 && echo "  script-mode vault CLI: OK (ENG-11 guard)"
SENTINEL_TEST_FILTER="unit_phase57" python3 tests/run_tests.py all > /tmp/p57chk.json 2>/dev/null
python3 -c "
import json; d=json.load(open('/tmp/p57chk.json'))
executed=[c for c in d['cases'] if not c.get('skipped')]
assert d['failed']==0 and len(executed)==1, (d['failed'], len(executed))
print('  phase57 vault unit battery from zip: OK')"
python3 -m sentinel.cli benchmark --out /tmp/bench_290.json >/dev/null 2>&1
python3 -c "
import json; d=json.load(open('/tmp/bench_290.json'))
c=d['confusion']
assert d['f1']==1.0 and c['TP']==30 and c['FP']==0 and c['FN']==0 and c['TN']==24, (d['f1'], c)
assert d['run_id']=='run-3c0652b6be', d['run_id']
print('  benchmark from zip: F1=1.000 TP=30 FP=0 FN=0 TN=24 run-3c0652b6be')"
cd "$LIVE"

echo "=== [4/6] Build complete bundle (v2.9.0) ==="
STAGE2=/tmp/sentinel-bundle-290
rm -rf "$STAGE2" && mkdir -p "$STAGE2/sentinel-2.9.0-bundle"
cp -r "$RES" "$STAGE2/sentinel-2.9.0-bundle/sentinel-results"
cp -f "$DL/sentinel-2.9.0-source.zip" "$STAGE2/sentinel-2.9.0-bundle/"
cp -f "$LIVE/CHANGELOG.md" "$STAGE2/sentinel-2.9.0-bundle/"
cp -f "$LIVE/.gitignore-vault" "$STAGE2/sentinel-2.9.0-bundle/"
cp -f "$BASE/worklog.md" "$STAGE2/sentinel-2.9.0-bundle/WORKLOG.md" 2>/dev/null || true
cat > "$STAGE2/sentinel-2.9.0-bundle/README.txt" <<'TXT'
SENTINEL v2.9.0 — COMPLETE BUNDLE ("Credential Intelligence" Release)
====================================================================
sentinel-2.9.0-source.zip   self-sufficient source: 27-module engine incl.
                           the Credential Vault (ChaCha20+HMAC encrypt-then-
                           MAC, pure stdlib), the 10-command vault CLI group,
                           .gitignore-vault template, fixture v8, 69-test
                           suite, ground truth v8 (30 TP / 24 TN).
                           Self-check: doctor 14/14 + script-mode vault CLI
                           + phase57 vault unit battery + benchmark F1=1.000
                           deterministic (run-3c0652b6be).
sentinel-results/           every real-target artifact of the campaign,
                           incl. the v2.9.0 testfire live scan with an ARMED
                           vault (673 req, 74 verified, 0 rejected, credential
                           exposure = 0 — an honest negative), the encrypted
                           vault artifact + its audit trail, and the
                           multi-party authorization demonstration
                           (org-owner key authorized; key files NEVER ship
                           with deliverables).
.gitignore-vault            copy into your repo BEFORE creating any vault.
CHANGELOG.md / WORKLOG.md   release notes + the full build history.
TXT
cd "$STAGE2" && zip -qr "$DL/sentinel-2.9.0-complete-bundle.zip" sentinel-2.9.0-bundle
echo "  bundle: $(unzip -l "$DL/sentinel-2.9.0-complete-bundle.zip" | tail -1)"

echo "=== [5/6] Verify zips ==="
unzip -t "$DL/sentinel-2.9.0-source.zip" > /dev/null && echo "  source zip OK"
unzip -t "$DL/sentinel-2.9.0-complete-bundle.zip" > /dev/null && echo "  bundle zip OK"

echo "=== [6/6] Cleanup old source-tree stage dirs ==="
rm -rf "$STAGE" "$STAGE2" "$CHK"
ls -la "$DL" | grep "2.9.0"
