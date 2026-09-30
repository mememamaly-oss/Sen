#!/usr/bin/env python3
import json

v = json.load(open('/home/z/my-project/readiness/evidence/a03_verdict.json'))
a, b = v['runs'][0]['stats']['proofs'], v['runs'][1]['stats']['proofs']

diff_fields = {}
def walk(x, y, path):
    if isinstance(x, dict) and isinstance(y, dict):
        for k in set(x) | set(y):
            walk(x.get(k), y.get(k), f'{path}.{k}')
    elif isinstance(x, list) and isinstance(y, list):
        if len(x) != len(y):
            diff_fields.setdefault(f'{path} (len {len(x)} vs {len(y)})', []).append((x, y))
        else:
            for i, (xi, yi) in enumerate(zip(x, y)):
                walk(xi, yi, f'{path}[{i}]')
    elif x != y:
        diff_fields.setdefault(path, []).append((str(x)[:80], str(y)[:80]))

for pa, pb in zip(a, b):
    walk(pa, pb, 'proof')

summary = {k: {'count': len(vals), 'example': vals[0]} for k, vals in diff_fields.items()}
with open('/home/z/my-project/readiness/evidence/a03_proof_field_diffs.json', 'w') as f:
    json.dump(summary, f, indent=1)
print(json.dumps(summary, indent=1))
