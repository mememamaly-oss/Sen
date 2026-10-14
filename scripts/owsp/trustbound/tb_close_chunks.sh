#!/bin/bash
# trustbound CATEGORY CLOSE — the full 12-chunk re-run on the final TB engine
# (cc142b3), one chunk per cr_full_chunk.sh call, chunk 12 FIRST (supervisor's
# explicit order), then 1..11. Resume-safe: a chunk with an existing PASS
# result JSON is skipped. Environmental faults (rc!=0 / NO RESULT JSON / empty
# findings) are re-run once before aborting honestly.
# Usage: tb_close_chunks.sh [start-after-label]   (resume support)
set -u
OWSP=/home/z/my-project/scripts/owsp
OUTD=/home/z/my-project/tool-results/bm_full_chunks
mkdir -p "$OUTD"

CHUNKS="02519_02739 00000_00228 00229_00457 00458_00686 00687_00915 00916_01144 01145_01373 01374_01602 01603_01831 01832_02060 02061_02289 02290_02518"
RESUME_AFTER="${1:-}"

active() {
  # print chunks after the resume point
  local started=0
  for c in $CHUNKS; do
    if [ "$RESUME_AFTER" = "" ]; then echo "$c"; continue; fi
    if [ "$started" = "1" ]; then echo "$c"; fi
    [ "$c" = "$RESUME_AFTER" ] && started=1
  done
}

run_chunk() {
  local LABEL="$1"
  local J="$OUTD/chunk_${LABEL}.json"
  if [ -s "$J" ]; then
    echo "[skip] chunk $LABEL already has a result JSON"
    return 0
  fi
  for ATTEMPT in 1 2; do
    echo "=== [$(date -u +%H:%M:%S)] chunk $LABEL attempt $ATTEMPT ==="
    bash "$OWSP/cr_full_chunk.sh" "$LABEL"
    if [ -s "$J" ]; then
      # environmental-fault sanity: stats + findings present
      python3 - "$J" <<'PY' && return 0
import json, sys
d = json.load(open(sys.argv[1]))
s = d.get("stats", {})
assert s.get("requests", 0) > 0, "requests==0"
assert isinstance(d.get("findings"), list) and d["findings"], "no findings list"
print("  [ok] chunk sane: reqs=%s findings=%d" % (s.get("requests"), len(d["findings"])))
PY
      echo "  [fault] chunk $LABEL produced a JSON but failed sanity — removing and retrying"
      rm -f "$J" "$OUTD/chunk_${LABEL}.db"
    else
      echo "  [fault] chunk $LABEL attempt $ATTEMPT produced NO result JSON"
    fi
    [ "$ATTEMPT" = "2" ] && { echo "  [ABORT] chunk $LABEL failed twice — environmental, stop honestly"; return 1; }
    sleep 5
  done
}

FAILED=0
for c in $(active); do
  run_chunk "$c" || { FAILED=1; break; }
done

echo "=== chunk run summary ==="
for c in $CHUNKS; do
  J="$OUTD/chunk_${c}.json"
  if [ -s "$J" ]; then
    python3 - "$J" "$c" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); s = d["stats"]
act = [f for f in d["findings"] if f["type"] not in ("missing_security_headers","server_banner_disclosure","tech_banner")]
print(f"{sys.argv[2]}: OK reqs={s.get('requests')} active={len(act)} verified={sum(1 for f in act if f.get('status')=='verified')}")
PY
  else
    echo "$c: MISSING"
  fi
done
[ "$FAILED" = "0" ] || exit 1
echo "ALL 12 CHUNKS COMPLETE"
