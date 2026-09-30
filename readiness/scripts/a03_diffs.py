#!/usr/bin/env python3
import json
v = json.load(open('/home/z/my-project/readiness/evidence/a03_verdict.json'))
runs = v['runs']

def diff(a, b, path=''):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in set(a) | set(b):
            out += diff(a.get(k), b.get(k), f'{path}.{k}')
    elif a != b:
        out.append((path, a, b))
    return out

res = {
    "run1_vs_run2": diff(runs[0]['stats'], runs[1]['stats']),
    "run1_vs_run3": diff(runs[0]['stats'], runs[2]['stats']),
    "identical_confusion": v['identical_confusion_matrices'],
    "identical_listings": v['identical_per_row_tp_tn_listings'],
}
with open('/home/z/my-project/readiness/evidence/a03_stats_diff.json', 'w') as f:
    json.dump(res, f, indent=1)
print(json.dumps(res, indent=1))
