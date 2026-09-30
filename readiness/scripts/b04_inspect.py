#!/usr/bin/env python3
import json

d = json.load(open('/home/z/my-project/readiness/evidence/B04_scan_clean.json'))
findings = d.get('findings', [])
stats = d.get('stats', {})
print('run_id:', d.get('run_id'))
print('scanner:', d.get('scanner'))
print('findings:', len(findings))
print('rejected:', len(d.get('rejected_candidates', [])))
print('stats keys:', list(stats.keys()))
for k in ['requests', 'endpoints', 'verified', 'rejected', 'authenticated', 'browser_pages']:
    if k in stats:
        print(f'  {k}:', stats[k])
# workflow stats
wf = stats.get('workflow') or {}
print('workflow:', {k: wf[k] for k in list(wf)[:8]} if wf else 'n/a')
# finding types histogram
from collections import Counter
types = Counter(f.get('type') for f in findings)
print('finding types:', dict(types))
# pick a business-logic finding id for B07
bl = [f for f in findings if 'business_logic' in (f.get('type') or '')]
pick = bl[0] if bl else findings[0]
print('B07 finding pick:', pick.get('id'), pick.get('type'), pick.get('endpoint') or pick.get('url'))
with open('/home/z/my-project/readiness/evidence/B07_finding_pick.json', 'w') as f:
    json.dump({'id': pick.get('id'), 'type': pick.get('type'), 'endpoint': pick.get('endpoint') or pick.get('url'),
               'n_findings': len(findings), 'run_id': d.get('run_id'), 'types': dict(types)}, f, indent=1)
