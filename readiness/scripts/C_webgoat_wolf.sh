#!/usr/bin/env bash
# Section C: live-target scans with the SHIPPED v4.0.0 artifact (ziprun tree)
R=/home/z/my-project/readiness
Z=$R/ziprun
EV=$R/evidence/live
mkdir -p $EV
PY=python3
cd $Z

echo "=== C01: WebGoat authenticated light scan (browser + workflow learn-only) ==="
timeout 400 $PY sentinel/cli.py scan http://127.0.0.1:8080/WebGoat \
  --allow-private --max-pages 40 \
  --auth-user sentinel9x --auth-pass test1234 \
  --auth-url http://127.0.0.1:8080/WebGoat/login \
  --auth-user-field username --auth-pass-field password \
  --workflow \
  --db $EV/live_v400.db --out $EV/C01_webgoat_v400.json > $EV/C01_webgoat.stdout 2> $EV/C01_webgoat.stderr
echo "webgoat scan exit=$?"

echo "=== C02: WebWolf scan (attacker landing app, unauthenticated by design) ==="
timeout 300 $PY sentinel/cli.py scan http://127.0.0.1:9090/WebWolf \
  --allow-private --max-pages 25 \
  --db $EV/live_v400.db --out $EV/C02_webwolf_v400.json > $EV/C02_webwolf.stdout 2> $EV/C02_webwolf.stderr
echo "webwolf scan exit=$?"

$PY - <<'PYEOF'
import json
for name, f in [("webgoat", "C01_webgoat_v400.json"), ("webwolf", "C02_webwolf_v400.json")]:
    try:
        d = json.load(open(f"/home/z/my-project/readiness/evidence/live/{f}"))
        st = d.get("stats", {})
        auth = st.get("auth", {})
        wf = st.get("workflow", {})
        print(f"[{name}] run={d.get('run_id')} req={st.get('requests')} ep={st.get('endpoints')} "
              f"verified={st.get('verified')} rejected={st.get('rejected')} "
              f"auth={ {k: auth.get(k) for k in ('authenticated','logins','reauths','failed') if k in auth} } "
              f"browser={st.get('browser_pages')} wf_flows={wf.get('flows_learned')} wf_verdicts={wf.get('skipped', [])[:3]}")
        from collections import Counter
        print(f"[{name}] types:", dict(Counter(x.get("type") for x in d.get("findings", []))))
    except Exception as e:
        print(f"[{name}] ERROR: {e}")
PYEOF
