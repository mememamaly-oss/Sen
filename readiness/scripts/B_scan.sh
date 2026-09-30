#!/usr/bin/env bash
# Section B: clean-install full production scan (B04-B08)
set -x
R=/home/z/my-project/readiness
SRC=$R/cleanenv/src1
W=$R/cleanenv/workdir
CLEAN="env -i HOME=$R/cleanenv/home1 PATH=/usr/bin:/bin /usr/bin/python3"
cd $W

# spawn fixture under the CLEAN env (stdlib-only app)
PORT=8777 $CLEAN $SRC/fixtures/vulnapp.py > $R/evidence/B04_fixture.log 2>&1 &
FIXPID=$!
sleep 3
curl -s -o /dev/null -w "fixture:%{http_code}\n" http://127.0.0.1:8777/ || echo "FIXTURE DEAD"

# B04+B05: full scan, fresh DB, from the clean install tree
$CLEAN $SRC/sentinel/cli.py scan http://127.0.0.1:8777 \
  --allow-private --workflow --logic-active \
  --auth-user demo --auth-pass demo123 \
  --auth-url http://127.0.0.1:8777/login \
  --auth-user-field uid --auth-pass-field passw \
  --auth-success-marker "Sign Off" \
  --authz-accounts $SRC/benchmarks/authz_accounts.json \
  --oast local \
  --db $W/clean_scan1.db --out $R/evidence/B04_scan_clean.json > $R/evidence/B04_scan_clean.stdout 2>$R/evidence/B04_scan_clean.stderr
echo "scan exit=$?"

# B06: reports from scratch (HTML + executive + glass)
$CLEAN $SRC/sentinel/cli.py report --db $W/clean_scan1.db --format html --out $R/evidence/B06_report_clean.html > $R/evidence/B06_html.log 2>&1
echo "html exit=$?"
$CLEAN $SRC/sentinel/cli.py report --db $W/clean_scan1.db --format executive --out $R/evidence/B06_executive_clean.json > $R/evidence/B06_exec.log 2>&1
echo "exec exit=$?"
$CLEAN $SRC/sentinel/cli.py report --db $W/clean_scan1.db --format glass --out $R/evidence/B06_glass_clean.html > $R/evidence/B06_glass.log 2>&1
echo "glass exit=$?"

# B08: SARIF
$CLEAN $SRC/sentinel/cli.py report --db $W/clean_scan1.db --format sarif --out $R/evidence/B08_sarif_clean.sarif > $R/evidence/B08_sarif.log 2>&1
echo "sarif exit=$?"

# capture a finding id for B07 (business-logic preferred)
$CLEAN $SRC/sentinel/cli.py findings --db $W/clean_scan1.db > $R/evidence/B04_findings_list.json 2>&1
echo "findings exit=$?"
kill $FIXPID 2>/dev/null
ls -la $W/ $R/evidence/ | grep -E "clean|sarif" | head -12
