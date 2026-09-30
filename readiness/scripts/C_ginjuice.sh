#!/usr/bin/env bash
# C03: ginandjuice.shop fresh v4.0.0 scan (authenticated, browser, public OAST, workflow learn-only)
R=/home/z/my-project/readiness; Z=$R/ziprun; EV=$R/evidence/live
cd $Z
timeout 520 python3 sentinel/cli.py scan https://ginandjuice.shop/ \
  --auth-user carlos --auth-pass hunter2 \
  --auth-url https://ginandjuice.shop/login \
  --auth-user-field username --auth-pass-field password \
  --oast public --workflow --max-pages 30 \
  --db $EV/live_v400.db --out $EV/C03_ginjuice_v400.json > $EV/C03_ginjuice.stdout 2> $EV/C03_ginjuice.stderr
echo "ginjuice exit=$?"
python3 - <<'PYEOF'
import json
from collections import Counter
try:
    d = json.load(open("/home/z/my-project/readiness/evidence/live/C03_ginjuice_v400.json"))
    st = d.get("stats", {}); auth = st.get("auth", {}); wf = st.get("workflow", {})
    oast = st.get("oast", {}); twin = st.get("digital_twin", {}); rea = st.get("reasoning", {})
    print(f"run={d.get('run_id')} req={st.get('requests')} ep={st.get('endpoints')} "
          f"verified={st.get('verified')} rejected={st.get('rejected')}")
    print("auth:", {k: auth.get(k) for k in ('authenticated','logins','reauths','failed') if k in auth})
    print("browser:", st.get("browser_pages"), "| oast:", oast)
    print("workflow:", {k: wf.get(k) for k in ('flows_learned','clusters_tried')}, "skips:", wf.get('skipped', [])[:2])
    print("twin:", twin if not isinstance(twin, dict) else {k: twin[k] for k in list(twin)[:5]})
    print("reasoning:", rea if not isinstance(rea, dict) else {k: rea[k] for k in list(rea)[:6]})
    print("types:", dict(Counter(x.get("type") for x in d.get("findings", []))))
    print("coverage:", st.get("coverage", {}) if not isinstance(st.get("coverage"), dict) else {k: st["coverage"][k] for k in list(st["coverage"])[:6]})
except Exception as e:
    print("ERROR:", e)
PYEOF
