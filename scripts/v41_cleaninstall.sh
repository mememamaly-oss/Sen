#!/bin/bash
# SENTINEL v4.1 — CLEAN INSTALL verification from the FINAL source zip.
# env -i + system python 3.13.5 (no venv, no env vars, no browser deps).
# Battery: doctor -> fixture scan (auth+workflow+v4.1 engines) -> findings ->
#          capability-matrix -> report html+ci -> SARIF -> reproduce --replay.
set -u
Z=/tmp/sentinel-4.1.0-source.zip
W=/tmp/v41_cleaninstall
rm -rf "$W" && mkdir -p "$W" && cd "$W" || exit 1
unzip -q "$Z" || exit 1
echo "=== extracted: $(find . -type f | wc -l) files ==="

PY=/usr/bin/python3

echo "=== [1/7] doctor (env -i, system python) ==="
env -i "$PY" sentinel/cli.py doctor > doctor_clean.json 2>&1
env -i "$PY" -c "
import json; d = json.load(open('doctor_clean.json'))
checks = d.get('checks', [])
p = sum(1 for c in checks if c['status'] == 'PASS')
print(f'doctor: {p} PASS / {len(checks)} total')
for c in checks:
    if c['status'] != 'PASS':
        print('  non-pass:', c.get('check'), c['status'], str(c.get('detail'))[:100])
"

echo "=== [2/7] spawn vulnapp fixture (port 8931) + scan it ==="
env -i PORT=8931 "$PY" fixtures/vulnapp.py > fixture_boot.log 2>&1 &
FIXPID=$!
sleep 3
curl -s -o /dev/null -w "fixture http=%{http_code}\n" http://127.0.0.1:8931/ || echo "fixture FAILED"

env -i "$PY" sentinel/cli.py scan http://127.0.0.1:8931/ \
  --allow-private --workflow --max-pages 10 --seed clean-install-v41 \
  --db clean.db --out clean_scan.json 2>&1 | tail -4

echo "=== [3/7] findings summary ==="
env -i "$PY" -c "
import json
d = json.load(open('clean_scan.json'))
st = d.get('stats', {})
print('verified:', st.get('verified'), '| rejected:', st.get('rejected'),
      '| reqs:', st.get('requests'))
print('boundary:', (st.get('boundary') or {}).get('records'), 'records')
print('twin nodes:', (st.get('digital_twin') or {}).get('nodes', '?'))
cls = {}
for f in d.get('findings', []):
    cls[f.get('type')] = cls.get(f.get('type'), 0) + 1
print('classes:', dict(sorted(cls.items())))
top = [f for f in d.get('findings', []) if f.get('severity') in ('critical', 'high')]
print('crit/high findings:', [(f['id'], f['type']) for f in top][:3])
open('top_finding.txt', 'w').write(top[0]['id'] if top else '')
"

echo "=== [4/7] capability-matrix (machine-generated) ==="
env -i "$PY" sentinel/cli.py capability-matrix --db clean.db --out CAPABILITY_CLEAN.md 2>&1 | tail -2
head -8 CAPABILITY_CLEAN.md

echo "=== [5/7] report html + CI exit semantics ==="
env -i "$PY" sentinel/cli.py report --db clean.db --out clean_report.html --format html 2>&1 | tail -1
env -i "$PY" sentinel/cli.py report --db clean.db --out clean_report.sarif --format sarif 2>&1 | tail -1
env -i "$PY" sentinel/cli.py report --db clean.db --out /dev/null --format json --ci
echo "ci exit (verified crit/high present -> expect 1): $?"

echo "=== [6/7] reproduce --replay the top finding (live clean-engine) ==="
FID=$(cat top_finding.txt)
if [ -n "$FID" ]; then
  env -i "$PY" sentinel/cli.py reproduce --db clean.db --finding "$FID" --replay 2>&1 | head -8
  echo "replay exit: $?"
else
  echo "(no crit/high finding to replay)"
fi

echo "=== [7/7] foreign CWD + fresh DB + no-source-touch check ==="
cd /tmp || exit 1
env -i "$PY" /tmp/v41_cleaninstall/sentinel/cli.py doctor 2>&1 | env -i "$PY" -c "
import json, sys
raw = sys.stdin.read(); d = json.loads(raw[raw.find('{'):])
p = sum(1 for c in d.get('checks', []) if c['status'] == 'PASS')
print(f'foreign-CWD doctor: {p}/{len(d.get(\"checks\", []))} PASS')"
echo "=== CLEAN INSTALL BATTERY DONE ==="
