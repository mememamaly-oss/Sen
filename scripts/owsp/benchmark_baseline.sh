#!/bin/bash
# FULL BASELINE scan of the OWASP Benchmark (2740 tests) through the FROZEN
# engine (build-v423) — the honest as-shipped numbers. All-in-one single call.
set -u
ENG=/home/z/my-project/build-v423
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_full.json
OUTD=$CAMP/baseline
mkdir -p "$OUTD"

# build the full spec (single call, deterministic)
cd /home/z/my-project && python3 - <<'EOF'
import sys
sys.path.insert(0, "scripts/owsp")
from benchmark_campaign import load_spec, load_expected, build_subset, OUT
spec = load_spec()
names = [r["name"] for r in load_expected()]
n = build_subset(spec, names, OUT / "spec_full.json")
print("full spec:", n, "paths")
EOF
[ -f "$SPEC" ] || { echo "SPEC BUILD FAIL"; exit 1; }

/home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack.log" 2>&1
grep -q "STACK READY" "$OUTD/stack.log" || { echo "STACK FAIL"; tail -3 "$OUTD/stack.log"; exit 1; }
echo "stack up"

START=$(python3 -c "import time; print(time.time())")
cd "$ENG" || exit 1
python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --no-crawl --no-browser --no-oast \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa \
  --max-pages 6000 \
  --out "$OUTD/baseline.json" --db "$OUTD/baseline.db" > "$OUTD/scan.log" 2>&1
RC=$?
END=$(python3 -c "import time; print(time.time())")
python3 -c "print(f'scan rc=$RC wall={$END-$START:.1f}s')"
python3 - <<'EOF'
import json
from collections import Counter
d = json.load(open("/home/z/my-project/tools/benchmark-src/target/campaign/baseline/baseline.json"))
s = d["stats"]
print("requests:", s.get("requests"), "duration:", s.get("duration"),
      "endpoints:", s.get("endpoints"), "candidates:", s.get("candidates"))
print("findings:", len(d["findings"]), dict(Counter(f["type"] for f in d["findings"])))
act = [f for f in d["findings"] if f["type"] != "missing_security_headers"]
print("active findings:", len(act), "verified:", sum(1 for f in act if f.get("status")=="verified"))
print("rejected:", len(d.get("rejected_candidates", [])), "unverified:", len(d.get("unverified_candidates", [])))
EOF
