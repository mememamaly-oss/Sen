#!/bin/bash
# Final GTP-12 gate: the gtp-family tests + doctor + bench x3, from the engine dir.
set -u
cd /home/z/my-project/build-v430 || exit 1
SENTINEL_TEST_FILTER=unit_gtp1 timeout 300 python3 tests/run_tests.py all > /tmp/g12_clean.json 2>/dev/null
python3 - << 'PY'
import json
d = json.load(open('/tmp/g12_clean.json'))
ran = [c for c in d['cases'] if not c.get('skipped')]
print(f'GTP family tests: {len(ran)} ran, {sum(1 for c in ran if not c["ok"])} failed, passed={d["passed"]}')
for c in ran:
    if not c['ok']:
        print('  FAIL:', c['name'], c.get('error', '')[:120])
PY
timeout 120 python3 sentinel/cli.py doctor 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
checks = d.get('checks', [])
print(f'doctor: {sum(1 for c in checks if c[\"status\"]==\"PASS\")}/{len(checks)} PASS')
"
for i in 1 2 3; do
  timeout 560 python3 sentinel/cli.py benchmark --out /tmp/bench_final_$i.json >/dev/null 2>&1
done
python3 -c "
import json
runs = []
for i in (1,2,3):
    d = json.load(open(f'/tmp/bench_final_{i}.json'))
    runs.append((d['confusion'], d['stats'].get('requests'), d.get('run_id')))
for i, r in enumerate(runs): print(f'bench run{i+1}:', r)
print('BENCH x3 IDENTICAL:', runs[0] == runs[1] == runs[2] and runs[0][0]['TP'] == 38 and runs[0][0]['FP'] == 0)
"
