#!/usr/bin/env bash
# GTP-13: identify env-stall tests (hang on THIS runner, pass standalone or
# on other environments). Each test gets a hard timeout; stalls are listed.
set -u
cd /home/z/my-project/build-v430
PLAN=/tmp/gtp13_chunk_plan.json
ALL=$(python3 - "$PLAN" << 'PY'
import json, sys
d = dict(json.load(open(sys.argv[1])))
seen = []
for k in sorted(d):
    for t in d[k].split(','):
        if t not in seen:
            seen.append(t)
print(','.join(seen))
PY
)
IFS=',' read -ra TESTS <<< "$ALL"
STALLS=""
for t in "${TESTS[@]}"; do
  SENTINEL_TEST_FILTER="$t" timeout 22 python3 tests/run_tests.py all > /tmp/gtp13_one.json 2>/dev/null < /dev/null
  RC=$?
  if [ "$RC" != "0" ]; then
    STALLS="$STALLS $t"
    echo "STALL($RC): $t" >&2
  fi
done
echo "ALL_STALLS:$STALLS"
