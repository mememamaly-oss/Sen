#!/bin/bash
# ALL-IN-ONE (the proven pattern): fresh stack + BOTH surgical scans + results,
# entirely within one tool call — the environment reaper kills cross-call stacks.
set -u
OUTD=/home/z/my-project/build-v425/results/owsp/mutillidae
ENG=/home/z/my-project/build-v425

echo "=== 1) fresh stack (reset DB for deterministic state) ==="
bash /home/z/my-project/scripts/owsp/mutillidae_stack.sh reset 2>&1 | tail -1

surg() {
  local NAME="$1" PAGE="$2"
  echo "=== surgical: $NAME ($PAGE) ==="
  cd "$ENG"
  timeout 420 python3 sentinel/cli.py scan \
    "http://127.0.0.1:4290/index.php?page=$PAGE" \
    --allow-private --oast local --no-browser \
    --auth-user admin --auth-pass adminpass \
    --auth-url "http://127.0.0.1:4290/index.php?page=login.php" \
    --auth-user-field username --auth-pass-field password \
    --seed "owsp-surg5-$NAME" --max-pages 8 \
    --out "$OUTD/surg5_$NAME.json" --db "$OUTD/surg5_$NAME.db" > "$OUTD/surg5_$NAME.log" 2>&1
  local RC=$?
  python3 - "$OUTD/surg5_$NAME.json" "$NAME" "$RC" <<'PYEOF'
import json, sys
p, name, rc = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(p))
except Exception as e:
    print(f"[{name}] rc={rc} NO RESULT ({e})"); sys.exit(0)
s = d.get("stats", {})
act = [x for x in d.get("findings", []) if x.get("type") not in
       ("missing_security_headers", "tech_banner_disclosure", "host_header_injection")]
print(f"[{name}] rc={rc} requests={s.get('requests')} endpoints={s.get('endpoints')} "
      f"verified={s.get('verified')} rejected={s.get('rejected')} active={len(act)}")
for x in act:
    print(f"   {x.get('type'):22} {x.get('status'):10} param={x.get('parameter')}")
key = {"userinfo": "sql_injection", "dnslookup": "command_injection"}[name]
hit = [x for x in act if x.get("type") == key and x.get("status") == "verified"]
print(f"[{name}] >>> {key.upper()} VERIFIED: {len(hit)} <<<" if hit
      else f"[{name}] {key}: not verified")
for x in d.get("rejected_candidates", [])[:5]:
    print(f"   rejected: {x.get('type')} param={x.get('parameter')}")
PYEOF
}

surg userinfo "user-info.php"
surg dnslookup "dns-lookup.php"
echo "=== all-in-one surgical verification complete ==="
