#!/bin/bash
# Pilot scan: stack + 100-test subset through the FROZEN engine (build-v423).
# Measures wall time / request count to extrapolate the full-campaign budget.
set -u
ENG=/home/z/my-project/build-v423
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_00000_00100.json
OUTD=$CAMP/pilot
mkdir -p "$OUTD"

/home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack.log" 2>&1
grep -q "STACK READY" "$OUTD/stack.log" || { echo "STACK FAIL"; tail -3 "$OUTD/stack.log"; exit 1; }
echo "stack up"

START=$(python3 -c "import time; print(time.time())")
cd "$ENG" || exit 1
python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --no-crawl --no-browser --no-oast \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa \
  --max-pages 2000 \
  --out "$OUTD/pilot.json" --db "$OUTD/pilot.db" > "$OUTD/scan.log" 2>&1
RC=$?
END=$(python3 -c "import time; print(time.time())")
python3 -c "print(f'scan rc=$RC wall={$END-$START:.1f}s')"
tail -25 "$OUTD/scan.log"
