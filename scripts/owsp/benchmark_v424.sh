#!/bin/bash
# v4.2.4 RESCAN of the full OWASP Benchmark — same config as the baseline of
# record (crawl + browser + local OAST + the target's own shipped spec) so the
# before/after numbers are a clean A/B over the engine fixes alone.
set -u
ENG=/home/z/my-project/build-v424
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_full.json
OUTD=$CAMP/v424_full
mkdir -p "$OUTD"

[ -f "$SPEC" ] || { echo "spec missing"; exit 1; }
/home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack.log" 2>&1
grep -q "STACK READY" "$OUTD/stack.log" || { echo "STACK FAIL"; tail -3 "$OUTD/stack.log"; exit 1; }
echo "stack up"

START=$(python3 -c "import time; print(time.time())")
cd "$ENG" || exit 1
python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa \
  --max-pages 6000 \
  --out "$OUTD/v424_full.json" --db "$OUTD/v424_full.db" > "$OUTD/scan.log" 2>&1
RC=$?
END=$(python3 -c "import time; print(time.time())")
python3 -c "print(f'scan rc=$RC wall={$END-$START:.1f}s')"
python3 - <<'EOF'
import json
from collections import Counter
d = json.load(open("/home/z/my-project/tools/benchmark-src/target/campaign/v424_full/v424_full.json"))
s = d["stats"]
print("requests:", s.get("requests"), "duration:", s.get("duration"),
      "endpoints:", s.get("endpoints"), "candidates:", s.get("candidates"))
print("crawl:", json.dumps(s.get("crawl", {}))[:200])
print("findings:", len(d["findings"]), dict(Counter(f["type"] for f in d["findings"])))
act = [f for f in d["findings"] if f["type"] != "missing_security_headers"]
print("active:", len(act), "verified:", sum(1 for f in act if f.get("status")=="verified"))
print("rejected:", len(d.get("rejected_candidates", [])), "unverified:", len(d.get("unverified_candidates", [])))
EOF
