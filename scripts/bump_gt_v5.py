#!/usr/bin/env python3
"""Ground truth v5: add the Phase-51 authenticated surface (fixture v5).
17 TP + 12 TN (v4)  ->  19 TP + 13 TN (v5).
New auth-gated entries are provably UNREACHABLE without login (302 -> /login):
  TP xss_reflected  /account          q      (raw reflection, auth-gated)
  TP sql_injection  /vault/transfer   acct   (boolean oracle 200/500, auth-gated)
  TN xss_reflected  /account          tab    (escaped twin, auth-gated)
"""
import json

gt = json.load(open('benchmarks/ground_truth.json'))
assert gt['benchmark'] == 'local-fixture-v4', 'expected v4 baseline'

gt['benchmark'] = 'local-fixture-v5'
gt['version'] = '2.3.0'
gt['environment'] = ('local http://127.0.0.1:8777 (requires --allow-private for scope); '
                     'authenticated scan (demo/demo123) — /account and /vault/transfer '
                     '302 to /login for anonymous clients')

new = [
    {"type": "xss_reflected", "endpoint": "/account", "parameter": "q", "present": True},
    {"type": "sql_injection", "endpoint": "/vault/transfer", "parameter": "acct", "present": True},
    {"type": "xss_reflected", "endpoint": "/account", "parameter": "tab", "present": False},
]
existing = {(c['type'], c['endpoint'], c['parameter']) for c in gt['ground_truth']}
for c in new:
    assert (c['type'], c['endpoint'], c['parameter']) not in existing, c
    gt['ground_truth'].append(c)

tp = sum(1 for c in gt['ground_truth'] if c['present'])
tn = len(gt['ground_truth']) - tp
assert (tp, tn) == (19, 13), (tp, tn)

json.dump(gt, open('benchmarks/ground_truth.json', 'w'), indent=1)
print(f"ground_truth.json -> {gt['benchmark']}: {len(gt['ground_truth'])} cases = {tp} TP + {tn} TN")
