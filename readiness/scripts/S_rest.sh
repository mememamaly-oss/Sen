#!/usr/bin/env bash
# S+T battery v2: correct API routes + CI exit codes
R=/home/z/my-project/readiness; Z=$R/ziprun2; EV=$R/evidence
> $EV/S_rest_battery.txt
cd $Z
PORT=8778 python3 fixtures/vulnapp.py > $EV/S_fixture.log 2>&1 &
sleep 3
python3 sentinel/cli.py serve --host 127.0.0.1 --port 8899 --db $EV/live/live_final.db --token s3cret-token-xyz > $EV/S_serve.log 2>&1 &
SERVE_PID=$!
sleep 4
B="http://127.0.0.1:8899"
T="X-Auth-Token: s3cret-token-xyz"

echo "== S02 health ==" >> $EV/S_rest_battery.txt
curl -s -o /dev/null -w "health(no token):%{http_code}\n" $B/api/health >> $EV/S_rest_battery.txt
curl -s -H "$T" $B/api/health >> $EV/S_rest_battery.txt; echo >> $EV/S_rest_battery.txt
echo "== S08 unauthorized ==" >> $EV/S_rest_battery.txt
curl -s -o /dev/null -w "stats(no token):%{http_code}\n" $B/api/stats >> $EV/S_rest_battery.txt
curl -s -o /dev/null -w "stats(bad token):%{http_code}\n" -H "X-Auth-Token: WRONG" $B/api/stats >> $EV/S_rest_battery.txt
echo "== S03+S09 concurrent REST scans (async 202) ==" >> $EV/S_rest_battery.txt
curl -s -X POST -H "$T" -H "Content-Type: application/json" -d '{"target":"http://127.0.0.1:8778/","allow_private":true,"max_pages":5,"timeout":5}' $B/api/scans >> $EV/S_rest_battery.txt; echo >> $EV/S_rest_battery.txt
curl -s -X POST -H "$T" -H "Content-Type: application/json" -d '{"target":"http://127.0.0.1:8778/","allow_private":true,"max_pages":5,"timeout":5}' $B/api/scans >> $EV/S_rest_battery.txt; echo >> $EV/S_rest_battery.txt
# poll until both done (max 100s)
for i in $(seq 1 50); do
  RUN1=$(curl -s -H "$T" "$B/api/scans" | python3 -c "import json,sys; s=json.load(sys.stdin); print(s.get('state','?'))" 2>/dev/null)
  sleep 2
  N=$(curl -s -H "$T" "$B/api/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('scans_running',0))" 2>/dev/null)
  [ "$N" = "0" ] && break
done
echo "scans_running after poll: $N" >> $EV/S_rest_battery.txt
curl -s -H "$T" "$B/api/stats" | head -c 250 >> $EV/S_rest_battery.txt; echo >> $EV/S_rest_battery.txt
curl -s -H "$T" "$B/api/runs?limit=3" | head -c 200 >> $EV/S_rest_battery.txt; echo >> $EV/S_rest_battery.txt
kill $SERVE_PID 2>/dev/null

echo "== CI exit codes ==" >> $EV/S_rest_battery.txt
python3 sentinel/cli.py report --db $EV/live/live_final.db --format sarif --ci --out $EV/S_ci.sarif > /dev/null 2>&1; echo "ci_exit(db with critical findings):$?" >> $EV/S_rest_battery.txt
timeout 60 python3 sentinel/cli.py scan http://127.0.0.1:59999/ --allow-private --max-pages 1 --timeout 2 --db $EV/S_fail.db --out $EV/S_fail.json > /dev/null 2>&1; echo "failed_scan_exit:$?" >> $EV/S_rest_battery.txt
cat $EV/S_rest_battery.txt
