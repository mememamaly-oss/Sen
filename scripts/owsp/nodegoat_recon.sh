#!/bin/bash
# ALL-IN-ONE (proven pattern): fresh NodeGoat stack + full recon scan + summary,
# entirely within one tool call. Usage: bash scripts/owsp/nodegoat_recon.sh <tag> [max-pages] [extra-flags...]
set -u
TAG="${1:-recon1}"
MP="${2:-80}"
[ $# -ge 2 ] && shift 2
# remaining "$@" = extra engine flags, passed UNQUOTED-as-array via "$@"
ENG=/home/z/my-project/build-v425
OUTD=$ENG/results/owsp/nodegoat
mkdir -p "$OUTD"

echo "=== 1) stack (reset = deterministic seed) ==="
bash /home/z/my-project/scripts/owsp/nodegoat_stack.sh reset 2>&1 | tail -3
grep -q STACK_READY /dev/null 2>/dev/null; # marker check below
STACK_RC=$?

echo "=== 2) scan $TAG (max-pages $MP) start $(date -u +%H:%M:%S) ==="
cd "$ENG"
timeout 500 python3 sentinel/cli.py scan \
    "http://127.0.0.1:4000/" \
    --allow-private --oast local \
    --auth-user admin --auth-pass Admin_123 \
    --auth-url "http://127.0.0.1:4000/login" \
    --auth-user-field userName --auth-pass-field password \
    --seed "owsp-nodegoat-$TAG" --max-pages "$MP" \
    --out "$OUTD/$TAG.json" --db "$OUTD/$TAG.db" "$@" > "$OUTD/$TAG.log" 2>&1
RC=$?
echo "=== scan rc=$RC $(date -u +%H:%M:%S) ==="

python3 - "$OUTD/$TAG.json" "$TAG" "$RC" <<'PYEOF'
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
      f"verified={s.get('verified')} rejected={s.get('rejected')} candidates={len(d.get('unverified_candidates', []))} active={len(act)}")
from collections import Counter
c = Counter(x.get("type") for x in act if x.get("status") == "verified")
print(f"[{name}] VERIFIED by class: {dict(c)}")
for x in act:
    print(f"   {x.get('type'):24} {str(x.get('status')):10} param={x.get('parameter')} url={str(x.get('url'))[:70]}")
for x in d.get("unverified_candidates", [])[:12]:
    print(f"   CAND: {x.get('type'):22} param={x.get('parameter')} url={str(x.get('url'))[:70]}")
for x in d.get("rejected_candidates", [])[:8]:
    print(f"   REJ : {x.get('type'):22} param={x.get('parameter')}")
PYEOF
echo "=== all-in-one $TAG complete ==="
