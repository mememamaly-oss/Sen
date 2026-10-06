#!/bin/bash
# Surgical post-OWSP-25/26 verification: target the two previously-missed
# surfaces DIRECTLY (query-string targets, --no-crawl) — the crawl cannot be
# the bottleneck; the form's own endpoint + batteries are the proof.
#   A) index.php?page=user-info.php   -> SQLi on username (OWSP-25: the twin-
#      form collapse kept every battery off this surface)
#   B) index.php?page=dns-lookup.php  -> command_injection on target_host
#      (OWSP-26: the per-endpoint budget starved it)
# All-in-one single call (stack relaunch if dead + both scans + verdicts).
set -u
OUTD=/home/z/my-project/build-v425/results/owsp/mutillidae
ENG=/home/z/my-project/build-v425
LOG=/home/z/my-project/tools/logs/php-server.log

code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:4290/index.php" 2>/dev/null)
if [ "$code" != "200" ] && [ "$code" != "302" ]; then
  echo "(relaunching stack)"
  bash /home/z/my-project/scripts/owsp/mutillidae_stack.sh >/dev/null 2>&1 | tail -1
  for i in $(seq 1 40); do
    sleep 2
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:4290/index.php" 2>/dev/null)
    [ "$c" = "200" -o "$c" = "302" ] && break
  done
fi
echo "stack: $(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:4290/index.php)"

run_surgical() {
  local NAME="$1" PAGE="$2"
  cd "$ENG"
  timeout 400 python3 sentinel/cli.py scan \
    "http://127.0.0.1:4290/index.php?page=$PAGE" \
    --no-crawl --allow-private --oast local --no-browser \
    --auth-user admin --auth-pass adminpass \
    --auth-url "http://127.0.0.1:4290/index.php?page=login.php" \
    --auth-user-field username --auth-pass-field password \
    --seed "owsp-surg-$NAME" --max-pages 5 \
    --out "$OUTD/surg_$NAME.json" --db "$OUTD/surg_$NAME.db" > "$OUTD/surg_$NAME.log" 2>&1
  local RC=$?
  python3 - "$OUTD/surg_$NAME.json" "$NAME" <<'PYEOF'
import json, sys
p, name = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(p))
except Exception as e:
    print(f"[{name}] no result json: {e}"); sys.exit(0)
f = d.get("findings", [])
act = [x for x in f if x.get("type") not in
       ("missing_security_headers", "tech_banner_disclosure", "host_header_injection")]
print(f"[{name}] requests={d.get('stats',{}).get('requests')} endpoints={d.get('stats',{}).get('endpoints')} "
      f"findings={len(f)} active={len(act)}")
for x in act:
    print(f"   {x.get('type'):22} {x.get('status'):10} param={x.get('parameter')}")
key = {"userinfo": "sql_injection", "dnslookup": "command_injection"}[name]
hit = [x for x in act if x.get("type") == key and x.get("status") == "verified"]
print(f"[{name}] *** {key.upper()} VERIFIED: {len(hit)} ***" if hit
      else f"[{name}] {key} not verified (honest)")
rj = d.get("rejected_candidates", [])
for x in rj[:4]:
    print(f"   rejected: {x.get('type')} param={x.get('parameter')}")
PYEOF
}

run_surgical userinfo "user-info.php"
run_surgical dnslookup "dns-lookup.php"
echo "=== surgical verification done ==="
