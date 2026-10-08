#!/bin/bash
# GTP-12 live gate: chain mini-scan (read+write primitives, 1 hash, 2 crypto, 1 secure control)
set -u
cd /home/z/my-project/build-v430 || exit 1
SPEC=/home/z/my-project/tools/benchmark-src/target/campaign/spec_chain_mini.json
OUT=${1:-/tmp/chain_mini2.json}
timeout 500 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser --no-crawl \
  --openapi-spec "$SPEC" --seed 7f3c91aa --max-pages 6000 \
  --out "$OUT" --db "${OUT%.json}.db" > "${OUT%.json}.log" 2>&1
echo "rc=$?"
python3 - "$OUT" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print('requests:', d['stats'].get('requests'))
for f in d['findings']:
    if f['type'] in ('weak_hash','weak_crypto','path_traversal','weak_random'):
        kinds = [e.get('kind') for e in f.get('evidence',[])]
        print(f"  {f['type']:14s} {f.get('status'):9s} {f.get('url','').split('/')[-1]:22s} {kinds}")
for r in d.get('rejected_candidates',[])[:10]:
    print('  REJECTED:', r.get('type'), r.get('url','').split('/')[-1],
          (r.get('reason') or r.get('notes') or '')[:90])
PY
