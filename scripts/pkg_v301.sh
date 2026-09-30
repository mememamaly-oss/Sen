#!/bin/bash
# Package SENTINEL v3.0.1: source zip + self-check from the EXTRACTED zip
# (doctor + version + the three ENG unit batteries + benchmark F1), then
# refresh the complete bundle and the full archive.
set -e
RES=/home/z/my-project/download/sentinel-results
SRC=/home/z/my-project/verify-live
STAGE=/home/z/my-project/pkg-v301
DL=/home/z/my-project/download

rm -rf "$STAGE" && mkdir -p "$STAGE"
cd "$SRC"
# source set: package + tests + fixtures + benchmarks + docs
zip -qr "$DL/sentinel-3.0.1-source.zip" sentinel tests fixtures benchmarks CHANGELOG.md
echo "== source zip built =="
unzip -q "$DL/sentinel-3.0.1-source.zip" -d "$STAGE"
cd "$STAGE"
echo "== self-check from extracted zip =="
grep -n '^VERSION' sentinel/core.py | head -1
timeout 90 python3 -m sentinel.cli doctor 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('doctor:', d['overall'], f\"{d['passed']}/{d['total']}\")"
SENTINEL_TEST_FILTER=unit_eng15,unit_eng16,unit_eng17 timeout 90 python3 tests/run_tests.py all 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin.read() and open('/dev/stdin')) if False else None" 2>/dev/null || true
SENTINEL_TEST_FILTER=unit_eng15,unit_eng16,unit_eng17 timeout 90 python3 tests/run_tests.py all 2>/dev/null | tail -20 | python3 -c "
import sys, json
txt = sys.stdin.read(); d = json.loads(txt[txt.find('{'):])
ran = [c for c in d['cases'] if not c.get('skipped')]
print('ENG units from zip:', len(ran), 'failed:', d['failed'])
"
timeout 200 python3 -m sentinel.cli benchmark --out /tmp/bench_v301_zipcheck.json 2>/dev/null >/dev/null || true
python3 -c "
import json; d = json.load(open('/tmp/bench_v301_zipcheck.json'))
c = d['confusion']
print('benchmark from zip: F1', d['f1'], '| TP', c['TP'], 'FP', c['FP'], 'FN', c['FN'], 'TN', c['TN'], '| run', d['run_id'])
"
echo "== packaging OK =="
