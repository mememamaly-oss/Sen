#!/usr/bin/env bash
# X03/X04: kill during workflow / OAST phases (full battery scan, late kills)
R=/home/z/my-project/readiness; Z=$R/ziprun2; EV=$R/evidence
cd $Z
> $EV/X_battery.txt
PORT=8778 python3 fixtures/vulnapp.py > $EV/X_fixture.log 2>&1 &
sleep 3

echo "== X03: kill -9 at T+45s (full battery: workflow window) ==" >> $EV/X_battery.txt
rm -f $EV/x_wf.db
python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --oast local \
  --workflow --logic-active \
  --auth-user demo --auth-pass demo123 --auth-url http://127.0.0.1:8777/login \
  --auth-user-field uid --auth-pass-field passw \
  --authz-accounts benchmarks/authz_accounts.json \
  --max-pages 30 --db $EV/x_wf.db --out $EV/x_wf.json > $EV/x_wf.stdout 2>&1 &
KP=$!; sleep 45; kill -9 $KP 2>/dev/null; sleep 1
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/x_wf.db')
print('kill-workflow-window: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])
# half-findings check: every stored finding must be complete (verified + evidence)
rows = db.execute('SELECT findings_json FROM findings LIMIT 400').fetchall()
import json as j
bad = 0
for (fj,) in rows:
    f = j.loads(fj)
    if not f.get('id') or not f.get('type') or (f.get('status') == 'verified' and not f.get('verification')):
        bad += 1
print('incomplete finding rows:', bad)" >> $EV/X_battery.txt

echo "== X04: kill -9 at T+70s (OAST window of the battery) ==" >> $EV/X_battery.txt
rm -f $EV/x_oast.db
python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --oast local \
  --workflow --logic-active \
  --auth-user demo --auth-pass demo123 --auth-url http://127.0.0.1:8777/login \
  --auth-user-field uid --auth-pass-field passw \
  --authz-accounts benchmarks/authz_accounts.json \
  --max-pages 30 --db $EV/x_oast.db --out $EV/x_oast.json > $EV/x_oast.stdout 2>&1 &
KP=$!; sleep 70; kill -9 $KP 2>/dev/null; sleep 1
python3 -c "
import sqlite3, json as j
db = sqlite3.connect('$EV/x_oast.db')
print('kill-oast-window: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])
rows = db.execute('SELECT findings_json FROM findings LIMIT 400').fetchall()
bad = sum(1 for (fj,) in rows if not j.loads(fj).get('id'))
print('incomplete finding rows:', bad)" >> $EV/X_battery.txt

echo "== X08: resume equivalent — rerun full battery into killed DB ==" >> $EV/X_battery.txt
timeout 300 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --oast local \
  --workflow --logic-active \
  --auth-user demo --auth-pass demo123 --auth-url http://127.0.0.1:8777/login \
  --auth-user-field uid --auth-pass-field passw \
  --authz-accounts benchmarks/authz_accounts.json \
  --max-pages 30 --db $EV/x_wf.db --out $EV/x_wf_rerun.json > /dev/null 2>&1
echo "rerun exit=$?" >> $EV/X_battery.txt
python3 -c "
import sqlite3
db = sqlite3.connect('$EV/x_wf.db')
print('after-rerun: integrity=', db.execute('PRAGMA integrity_check').fetchone()[0],
      '| runs=', db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
      '| findings=', db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])" >> $EV/X_battery.txt
cat $EV/X_battery.txt
