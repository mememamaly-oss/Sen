#!/usr/bin/bash
# maxtest — Phase 1b: WebGoat 8.2.2 + WebWolf 8.2.2 all-in-one campaign.
# One call: launch WG (HSQLDB 9001) -> register user via parsed form ->
# launch WW (9090) -> readiness -> deep authenticated scan (WG) -> L2 ->
# (time permitting) WW scan -> kill.
set -u
LT=/home/z/my-project/live-targets
B=/home/z/my-project/build-v423
OUT=$B/results/maxtest/webgoat
LOGD=$LT/logs
mkdir -p "$OUT" "$LOGD"
TS0=$(date +%s)

echo "=== [1/6] launch WebGoat $(date -u +%H:%M:%S) ==="
pkill -f "webgoat-server" 2>/dev/null; pkill -f "webwolf" 2>/dev/null; sleep 1
cd "$LT"
setsid nohup java -jar webgoat-server-8.2.2.jar > $LOGD/webgoat.log 2>&1 < /dev/null &
WG_UP=000
for i in $(seq 1 90); do
  WG_UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:8080/WebGoat/" 2>/dev/null)
  [ "$WG_UP" = "302" ] || [ "$WG_UP" = "200" ] && break; sleep 1
done
echo "webgoat http=$WG_UP after ~${i}s"
[ "$WG_UP" = "000" ] && { echo "WG FAILED"; tail -5 $LOGD/webgoat.log; exit 1; }

echo "=== [2/6] register user (form-parsed) $(date -u +%H:%M:%S) ==="
python3 - <<'PYEOF'
import json, re, sys
import urllib.request, urllib.parse

BASE = "http://localhost:8080/WebGoat"
USER, PASSW = "maxtest01", "test1234"

def get(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")

import http.cookiejar
CJ = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CJ))

def post(url, data):
    r = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(),
                               method="POST")
    try:
        with OPENER.open(r, timeout=15) as resp:
            return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.geturl(), e.read().decode("utf-8", "replace")

# fetch the registration page and parse the real form (multiline inputs: re.S)
for reg_url in (BASE + "/registration", BASE + "/register"):
    try:
        st, html = get(reg_url)
    except Exception as e:
        print(f"[reg] {reg_url} -> {e}")
        continue
    forms = re.findall(r"<form[^>]*>(.*?)</form>", html, re.S | re.I)
    print(f"[reg] {reg_url} -> HTTP {st}, {len(forms)} form(s)")
    for fi, fbody in enumerate(forms):
        fields = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*>", fbody, re.S)
        fields = sorted(set(fields))
        print(f"[reg]   form{fi} fields: {fields}")
        data = {}
        for name in fields:
            ln = name.lower()
            if "user" in ln:
                data[name] = USER
            elif "pass" in ln or "confirm" in ln or "matching" in ln:
                data[name] = PASSW
            elif ln in ("agree", "agreement", "terms"):
                data[name] = "agree"
        if "username" not in data or "password" not in data:
            continue
        if "matchingPassword" in fields:
            data["matchingPassword"] = PASSW
        # the form's own action wins; fall back to the page url
        m = re.search(r"<form[^>]*action=[\"']([^\"']+)[\"']", html, re.I)
        action = m.group(1) if m else reg_url
        action_url = urllib.parse.urljoin(reg_url, action)
        st2, final, body = post(action_url, data)
        print(f"[reg] POST {action_url} fields={sorted(data)} -> {st2} final={final}")
        # verify login works
        st3, final3, body3 = post(BASE + "/login",
                                  {"username": USER, "password": PASSW})
        print(f"[reg] login check -> {st3} final={final3}")
        if "welcome" in final3.lower() or "welcome" in (body3 or "").lower():
            print("[reg] REGISTERED+LOGIN OK")
            json.dump({"user": USER, "pass": PASSW}, open("/tmp/wg_account.json", "w"))
            sys.exit(0)
print("[reg] NO WORKING REGISTRATION")
print("[reg] NO FORM FOUND")
sys.exit(1)
PYEOF
REG=$?
[ "$REG" != "0" ] && echo "WARNING: registration flow failed — scan will be anonymous"

echo "=== [3/6] launch WebWolf $(date -u +%H:%M:%S) ==="
setsid nohup java -jar webwolf-8.2.2.jar > $LOGD/webwolf.log 2>&1 < /dev/null &
WW_UP=000
for i in $(seq 1 60); do
  WW_UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:9090/WebWolf/" 2>/dev/null)
  [ "$WW_UP" != "000" ] && [ "$WW_UP" != "404" ] && break; sleep 1
done
echo "webwolf http=$WW_UP after ~${i}s (404 root is by-design; structured response = up)"

echo "=== [4/6] deep authenticated scan WebGoat $(date -u +%H:%M:%S) ==="
cd "$B"
if [ "$REG" = "0" ]; then
  python3 sentinel/cli.py scan http://localhost:8080/WebGoat \
    --allow-private --max-pages 45 \
    --auth-user maxtest01 --auth-pass test1234 \
    --auth-url http://localhost:8080/WebGoat/login \
    --auth-user-field username --auth-pass-field password \
    --seed maxtest-wg-01 \
    --db "$OUT/webgoat.db" --out "$OUT/webgoat.json" 2>&1 | tail -20
else
  python3 sentinel/cli.py scan http://localhost:8080/WebGoat \
    --allow-private --max-pages 45 --seed maxtest-wg-01 \
    --db "$OUT/webgoat.db" --out "$OUT/webgoat.json" 2>&1 | tail -20
fi

echo "=== [5/6] L2 apaths $(date -u +%H:%M:%S) ==="
python3 sentinel/cli.py apaths --result "$OUT/webgoat.json" --out "$OUT/apaths.json" 2>&1 | tail -2

echo "=== [6/6] summary + WebWolf (time permitting) $(date -u +%H:%M:%S) ==="
python3 - "$OUT" <<'PYEOF'
import json, sys
out = sys.argv[1]
r = json.load(open(f"{out}/webgoat.json"))
s = r["stats"]
types = {}
for f in r.get("findings", []):
    types[f["type"]] = types.get(f["type"], 0) + 1
print(f"WEBGOAT: req={s.get('requests')} ep={s.get('endpoints')} "
      f"cand={s.get('candidates')} verif={s.get('verified')} rej={s.get('rejected')}")
print("  findings:", types)
try:
    ap = json.load(open(f"{out}/apaths.json"))
    from collections import Counter
    cl = Counter(p.get("classification", "?") for p in ap.get("paths", []))
    print(f"  apaths: {len(ap.get('paths', []))} {dict(cl)}")
except Exception as e:
    print("  apaths err:", e)
PYEOF
NOW=$(date +%s); ELAPSED=$((NOW - TS0))
echo "elapsed=${ELAPSED}s"
if [ $ELAPSED -lt 430 ]; then
  python3 sentinel/cli.py scan http://localhost:9090/WebWolf \
    --allow-private --max-pages 20 --seed maxtest-ww-01 \
    --db "$OUT/webwolf.db" --out "$OUT/webwolf.json" 2>&1 | tail -12
  python3 sentinel/cli.py apaths --result "$OUT/webwolf.json" --out "$OUT/apaths_ww.json" 2>&1 | tail -2
  python3 - "$OUT" <<'PYEOF'
import json, sys
from collections import Counter
out = sys.argv[1]
try:
    r = json.load(open(f"{out}/webwolf.json"))
    s = r["stats"]
    types = Counter(f["type"] for f in r.get("findings", []))
    print(f"WEBWOLF: req={s.get('requests')} ep={s.get('endpoints')} verif={s.get('verified')}")
    print("  findings:", dict(types))
except Exception as e:
    print("webwolf summary err:", e)
PYEOF
else
  echo "SKIP WebWolf scan this call (elapsed ${ELAPSED}s) — run phase1b_webwolf.sh next"
fi
pkill -f "webgoat-server" 2>/dev/null; pkill -f "webwolf" 2>/dev/null
echo "=== DONE $(date -u +%H:%M:%S) ==="
