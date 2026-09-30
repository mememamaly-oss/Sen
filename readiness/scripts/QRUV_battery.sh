#!/usr/bin/env bash
# Q+R+U+V behavior experiments: concurrency, kill-9 phases, memory, traversal, XSS-in-report, fingerprint
R=/home/z/my-project/readiness; Z=$R/ziprun2; EV=$R/evidence
cd $Z
> $EV/QRUV_battery.txt
PORT=8778 python3 fixtures/vulnapp.py > $EV/QRUV_fixture.log 2>&1 &
sleep 3

echo "== Q02: two CONCURRENT scan processes on ONE db ==" >> $EV/QRUV_battery.txt
( timeout 240 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 12 \
    --db $EV/q_concurrent.db --out $EV/q_c1.json > /dev/null 2>&1; echo "c1=$?" >> $EV/QRUV_battery.txt ) &
( timeout 240 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 12 \
    --db $EV/q_concurrent.db --out $EV/q_c2.json > /dev/null 2>&1; echo "c2=$?" >> $EV/QRUV_battery.txt ) &
wait
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/q_concurrent.db')
runs = db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]
fnds = db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
integ = db.execute('PRAGMA integrity_check').fetchone()[0]
journal = db.execute('PRAGMA journal_mode').fetchone()[0]
print(f'concurrent: runs={runs} findings={fnds} integrity={integ} journal={journal}')" >> $EV/QRUV_battery.txt

echo "== Q04/Q06/X01: kill -9 DURING discovery (2s in) ==" >> $EV/QRUV_battery.txt
rm -f $EV/q_kill1.db
python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 30 \
  --db $EV/q_kill1.db --out $EV/q_kill1.json > /dev/null 2>&1 &
KP=$!; sleep 2; kill -9 $KP 2>/dev/null; sleep 1
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/q_kill1.db')
print('kill-discovery: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])" >> $EV/QRUV_battery.txt

echo "== X02: kill -9 DURING detection (12s in) ==" >> $EV/QRUV_battery.txt
rm -f $EV/q_kill2.db
python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 30 \
  --db $EV/q_kill2.db --out $EV/q_kill2.json > /dev/null 2>&1 &
KP=$!; sleep 12; kill -9 $KP 2>/dev/null; sleep 1
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/q_kill2.db')
print('kill-detection: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])" >> $EV/QRUV_battery.txt

echo "== X05: kill -9 DURING report generation ==" >> $EV/QRUV_battery.txt
# report gen is fast; kill during is hard to time — instead verify reports are rebuildable after kill2
timeout 60 python3 sentinel/cli.py report --db $EV/q_kill2.db --format html --out $EV/q_kill2_report.html > /dev/null 2>&1
echo "report-after-kill exit=$? size=$(stat -c%s $EV/q_kill2_report.html 2>/dev/null)" >> $EV/QRUV_battery.txt

echo "== Q05/X06: restart scan after kill (same DB) ==" >> $EV/QRUV_battery.txt
timeout 240 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 30 \
  --db $EV/q_kill2.db --out $EV/q_kill2_rerun.json > /dev/null 2>&1; echo "restart-scan exit=$?" >> $EV/QRUV_battery.txt
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/q_kill2.db')
print('after-restart: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])" >> $EV/QRUV_battery.txt

echo "== U10/U11: memory + CPU of a full scan ==" >> $EV/QRUV_battery.txt
/usr/bin/time -v python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast --max-pages 12 \
  --db $EV/q_mem.db --out $EV/q_mem.json > $EV/q_mem.time 2>&1
grep -E "Maximum resident|Elapsed|User time|System time" $EV/q_mem.time >> $EV/QRUV_battery.txt
python3 -c "
import json; d=json.load(open('$EV/q_mem.json'))
print('mem-scan: req', d['stats']['requests'], 'dur', d['stats']['duration'], 'verified', d['stats']['verified'])" >> $EV/QRUV_battery.txt

echo "== V01/V07: fingerprint stability vs change ==" >> $EV/QRUV_battery.txt
python3 -c "
import json
std = json.load(open('$EV/g16_std.json')); mod = json.load(open('$EV/g16_mod.json'))
std2 = json.load(open('$EV/g16_std2.json'))
f1 = std['stats'].get('fingerprint', {}); f2 = mod['stats'].get('fingerprint', {})
f3 = std2['stats'].get('fingerprint', {})
print('fingerprint same-app:', f1 == f3, '| app-changed:', f1 != f2)
print('fp keys:', list(f1.keys())[:8])
print('fp:', json.dumps(f1, ensure_ascii=False)[:250])" >> $EV/QRUV_battery.txt

echo "== R10: path traversal probes on input/report paths ==" >> $EV/QRUV_battery.txt
timeout 30 python3 sentinel/cli.py report --db $EV/q_concurrent.db --format html --out "$EV/../trav_test.html" > /dev/null 2>&1; echo "traversal-out(../): exit=$? (wrote: $(ls $R/trav_test.html 2>/dev/null || echo NO))" >> $EV/QRUV_battery.txt
rm -f $R/trav_test.html
timeout 30 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --max-pages 2 --openapi-spec "/etc/passwd" --db $EV/q_trav.db --out $EV/q_trav.json > /dev/null 2>&1; echo "passwd-as-spec exit=$?" >> $EV/QRUV_battery.txt
timeout 30 python3 sentinel/cli.py scan "http://127.0.0.1:8778/../../etc/passwd" --allow-private --max-pages 2 --db $EV/q_trav2.db --out $EV/q_trav2.json > /dev/null 2>&1; echo "traversal-target exit=$?" >> $EV/QRUV_battery.txt

echo "== R12: shell-out audit (subprocess/os.system with interpolation) ==" >> $EV/QRUV_battery.txt
grep -rn "os.system\|subprocess" sentinel/*.py | grep -v "ensure_fixture\|sys.executable, fixture\|Popen(\[sys.executable" >> $EV/QRUV_battery.txt || echo "no other subprocess/os.system uses" >> $EV/QRUV_battery.txt

echo "== R14: stored-XSS check — target payloads must be ESCAPED in reports ==" >> $EV/QRUV_battery.txt
python3 - <<'PYEOF' >> $EV/QRUV_battery.txt 2>&1
import re
html = open('/home/z/my-project/readiness/evidence/B06_report_clean.html').read()
# the fixture reflects XSS canaries; find any RAW (unescaped) script/iframe markup that came from target data
raw = re.findall(r'<script>alert|<img src=x onerror|<svg onload', html, re.I)
escaped = re.findall(r'&lt;script&gt;|&lt;img src=x', html)
print('raw hostile markup in report:', raw[:3] or 'NONE')
print('escaped copies present:', len(escaped))
PYEOF
cat $EV/QRUV_battery.txt
