#!/bin/bash
# v4.3.0 GTP round: full OWASP Benchmark scan with the ground-truth-push engine.
set -u
ENG=/home/z/my-project/build-v430
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_00000_02740.json
OUTD=$CAMP/v430_full
mkdir -p "$OUTD"
[ -f "$SPEC" ] || { echo "spec missing"; exit 1; }
/home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack.log" 2>&1
grep -q "STACK READY" "$OUTD/stack.log" || { echo "STACK FAIL"; tail -5 "$OUTD/stack.log"; exit 1; }
echo "stack up"
START=$(date +%s)
cd "$ENG" || exit 1
timeout 520 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUTD/v430_full.json" --db "$OUTD/v430_full.db" > "$OUTD/scan.log" 2>&1
RC=$?
END=$(date +%s)
echo "scan rc=$RC wall=$((END-START))s"
tail -3 "$OUTD/scan.log"
