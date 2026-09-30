#!/usr/bin/env bash
# Re-register WebGoat account + rerun C01/C02 with correct postures
R=/home/z/my-project/readiness; Z=$R/ziprun; EV=$R/evidence/live
> /tmp/reg.txt
# 1) register fresh account (known-good pattern: lowercase+digit password, agree=true)
curl -s -o /dev/null -w "register:%{http_code} -> %{redirect_url}\n" -c /tmp/wg2.jar \
  -X POST "http://127.0.0.1:8080/WebGoat/register.mvc" \
  --data-urlencode "username=sentinel10y" \
  --data-urlencode "password=test1234" \
  --data-urlencode "matchingPassword=test1234" \
  --data-urlencode "agree=true" >> /tmp/reg.txt 2>&1
# 2) verify login
curl -s -o /dev/null -w "login:%{http_code} -> %{redirect_url}\n" -b /tmp/wg2.jar -c /tmp/wg2.jar \
  -X POST "http://127.0.0.1:8080/WebGoat/login" \
  --data-urlencode "username=sentinel10y" --data-urlencode "password=test1234" >> /tmp/reg.txt 2>&1
curl -s -b /tmp/wg2.jar -o /dev/null -w "welcome-authed:%{http_code}\n" "http://127.0.0.1:8080/WebGoat/welcome.mvc" >> /tmp/reg.txt 2>&1
cat /tmp/reg.txt

echo "=== C01 rerun: WebGoat authenticated light (browser on) ==="
cd $Z
timeout 400 python3 sentinel/cli.py scan http://127.0.0.1:8080/WebGoat \
  --allow-private --max-pages 40 \
  --auth-user sentinel10y --auth-pass test1234 \
  --auth-url http://127.0.0.1:8080/WebGoat/login \
  --auth-user-field username --auth-pass-field password \
  --workflow \
  --db $EV/live_v400.db --out $EV/C01_webgoat_v400.json > $EV/C01_webgoat.stdout 2> $EV/C01_webgoat.stderr
echo "webgoat exit=$?"

echo "=== C02 rerun: WebWolf with operator-supplied OpenAPI surface (from prior authorized bytecode analysis) ==="
timeout 400 python3 sentinel/cli.py scan http://127.0.0.1:9090/WebWolf \
  --allow-private --max-pages 25 \
  --openapi-spec /home/z/my-project/live-targets/webwolf_surface_openapi.json \
  --db $EV/live_v400.db --out $EV/C02_webwolf_v400.json > $EV/C02_webwolf.stdout 2> $EV/C02_webwolf.stderr
echo "webwolf exit=$?"

python3 - <<'PYEOF'
import json
from collections import Counter
for name, f in [("webgoat", "C01_webgoat_v400.json"), ("webwolf", "C02_webwolf_v400.json")]:
    try:
        d = json.load(open(f"/home/z/my-project/readiness/evidence/live/{f}"))
        st = d.get("stats", {}); auth = st.get("auth", {}); wf = st.get("workflow", {})
        print(f"[{name}] run={d.get('run_id')} req={st.get('requests')} ep={st.get('endpoints')} "
              f"verified={st.get('verified')} rejected={st.get('rejected')} "
              f"auth={ {k: auth.get(k) for k in ('authenticated','logins','reauths','failed') if k in auth} } "
              f"browser={st.get('browser_pages')} openapi_paths={(st.get('openapi') or {}).get('paths')} "
              f"wf_flows={wf.get('flows_learned')} wf_skips={wf.get('skipped', [])[:2]}")
        print(f"[{name}] types:", dict(Counter(x.get("type") for x in d.get("findings", []))))
    except Exception as e:
        print(f"[{name}] ERROR: {e}")
PYEOF
