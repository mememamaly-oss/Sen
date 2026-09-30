#!/usr/bin/env python3
import json

v = json.load(open('/home/z/my-project/readiness/evidence/a03_verdict.json'))
runs = v['runs']
out = {}
for idx in (1, 2):
    a, b = runs[0]['stats']['proofs'], runs[idx]['stats']['proofs']
    ka = [(p.get('finding_id'), p.get('type'), p.get('requests', [{}])[0].get('url', '')) for p in a]
    kb = [(p.get('finding_id'), p.get('type'), p.get('requests', [{}])[0].get('url', '')) for p in b]
    out[f'run1_vs_run{idx+1}'] = {
        'n_proofs': (len(ka), len(kb)),
        'same_order_types': [t for _, t, _ in ka] == [t for _, t, _ in kb],
        'same_types_multiset': sorted(t for _, t, _ in ka) == sorted(t for _, t, _ in kb),
        'finding_ids_run1_sample': [k[0] for k in ka[:5]],
        'finding_ids_run%d_sample' % (idx + 1): [k[0] for k in kb[:5]],
        'ids_differ': [k[0] for k in ka] != [k[0] for k in kb],
        'full_content_identical_excluding_ids_and_ids_like_fields': None,  # computed below
    }
    # deep compare ignoring volatile id-ish fields
    def strip(p):
        q = json.loads(json.dumps(p))
        q.pop('finding_id', None)
        return q
    sa, sb = [strip(p) for p in a], [strip(p) for p in b]
    out[f'run1_vs_run{idx+1}']['full_content_identical_excluding_ids_and_ids_like_fields'] = (sa == sb)

with open('/home/z/my-project/readiness/evidence/a03_proofs_diff.json', 'w') as f:
    json.dump(out, f, indent=1)
print(json.dumps(out, indent=1))
