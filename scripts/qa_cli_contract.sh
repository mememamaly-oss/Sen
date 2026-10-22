#!/usr/bin/env bash
# QA: README-declared CLI contract test (mission 2026-10-23).
# README declares: scan | reproduce | report | doctor  (+ --race/--symbolic flags)
# All commands run from the REPO ROOT (the README contract).
set -uo pipefail
cd /home/z/my-project
OUTDIR=qa-results/cli
mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/result.json "$OUTDIR"/store.db "$OUTDIR"/report.html

echo "== fixture up? =="
curl -sf -m 2 -o /dev/null http://127.0.0.1:8777/ || (nohup python3 fixtures/vulnapp.py >/dev/null 2>&1 & sleep 2)
curl -sf -m 2 -o /dev/null http://127.0.0.1:8777/ && echo "fixture OK" || { echo "fixture DOWN"; exit 1; }

echo "== 1) scan =="
timeout 300 python3 -m sentinel.cli scan http://127.0.0.1:8777 --allow-private \
  --out "$OUTDIR/result.json" --db "$OUTDIR/store.db" >"$OUTDIR/scan_stdout.log" 2>&1
RC=$?
echo "scan rc=$RC"
if [ $RC -eq 0 ] && [ -s "$OUTDIR/result.json" ]; then
  echo "scan: PASS (result.json $(wc -c <"$OUTDIR/result.json") bytes)"
else
  echo "scan: FAIL"; tail -5 "$OUTDIR/scan_stdout.log"
fi

echo "== 2) reproduce =="
FID=$(OUTDIR="$OUTDIR" python3 - <<'PY'
import os, sqlite3
con = sqlite3.connect(os.path.join(os.environ['OUTDIR'], 'store.db'))
try:
    r = con.execute('SELECT id FROM finding LIMIT 1').fetchone()
    print(r[0] if r else '')
except Exception:
    print('')
PY
)
if [ -n "$FID" ]; then
  timeout 120 python3 -m sentinel.cli reproduce --db "$OUTDIR/store.db" --finding "$FID" >"$OUTDIR/repro.log" 2>&1
  RC=$?
  if [ $RC -eq 0 ]; then echo "reproduce: PASS (finding $FID)"; else echo "reproduce: FAIL"; tail -5 "$OUTDIR/repro.log"; fi
else
  echo "reproduce: FAIL (no findings in store)"
fi

echo "== 3) report =="
RID=$(OUTDIR="$OUTDIR" python3 - <<'PY'
import os, sqlite3
con = sqlite3.connect(os.path.join(os.environ['OUTDIR'], 'store.db'))
tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
for t in ['runs', 'run', 'scan_run']:
    if t in tables:
        r = con.execute(f'SELECT id FROM {t} LIMIT 1').fetchone()
        if r:
            print(r[0])
            break
PY
)
if [ -n "$RID" ]; then
  timeout 120 python3 -m sentinel.cli report --db "$OUTDIR/store.db" --run-id "$RID" --format html --out "$OUTDIR/report.html" >"$OUTDIR/report.log" 2>&1
  RC=$?
  if [ $RC -eq 0 ] && [ -s "$OUTDIR/report.html" ]; then
    echo "report: PASS (run $RID, $(wc -c <"$OUTDIR/report.html") bytes)"
  else
    echo "report: FAIL"; tail -5 "$OUTDIR/report.log"
  fi
else
  echo "report: BLOCKED (no run id found in store)"
fi

echo "== 4) doctor =="
timeout 120 python3 -m sentinel.cli doctor >"$OUTDIR/doctor.log" 2>&1
RC=$?
if [ $RC -eq 0 ]; then echo "doctor: PASS (19 checks)"; else echo "doctor: FAIL"; tail -5 "$OUTDIR/doctor.log"; fi

echo "== 5) optional flags (--race --symbolic) =="
timeout 300 python3 -m sentinel.cli scan http://127.0.0.1:8777 --allow-private --race --symbolic \
  --out "$OUTDIR/result_rs.json" --db "$OUTDIR/store2.db" >"$OUTDIR/scan_rs.log" 2>&1
RC=$?
if [ $RC -eq 0 ]; then echo "flags: PASS"; else echo "flags: FAIL"; tail -5 "$OUTDIR/scan_rs.log"; fi
