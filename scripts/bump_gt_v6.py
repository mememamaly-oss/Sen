#!/usr/bin/env python3
"""Ground truth v6: add the Phase-53 hardening surfaces (fixture v6).
19 TP + 13 TN (v5)  ->  22 TP + 16 TN (v6).
New entries (all live-provable on the fixture):
  TP ssrf              /vuln/fetch  url     (blind server-side fetch, OOB-confirmed only)
  TP command_injection /vuln/ping   host    (shell=True interpolation, OOB-confirmed)
  TP cors_misconfig    /vuln/cors   Origin  (arbitrary Origin reflected + credentials)
  TN ssrf              /safe/fetch  url     (allowlist — attacker URLs never fetched)
  TN command_injection /safe/ping   host    (argv list, no shell — injection impossible)
  TN cors_misconfig    /safe/cors   Origin  (fixed allowlisted origin, no reflection)
"""
import json

gt = json.load(open('benchmarks/ground_truth.json'))
assert gt['benchmark'] == 'local-fixture-v5', 'expected v5 baseline'

gt['benchmark'] = 'local-fixture-v6'
gt['version'] = '2.5.0'
gt['environment'] = ('local http://127.0.0.1:8777 (requires --allow-private for scope); '
                     'authenticated scan (demo/demo123) — /account and /vault/transfer '
                     '302 to /login for anonymous clients; OAST armed — blind classes '
                     '(xxe / ssrf / command_injection) are OOB-confirmed only')

new = [
    {"type": "ssrf", "endpoint": "/vuln/fetch", "parameter": "url", "present": True},
    {"type": "command_injection", "endpoint": "/vuln/ping", "parameter": "host", "present": True},
    {"type": "cors_misconfig", "endpoint": "/vuln/cors", "parameter": "Origin", "present": True},
    {"type": "ssrf", "endpoint": "/safe/fetch", "parameter": "url", "present": False},
    {"type": "command_injection", "endpoint": "/safe/ping", "parameter": "host", "present": False},
    {"type": "cors_misconfig", "endpoint": "/safe/cors", "parameter": "Origin", "present": False},
]
existing = {(c['type'], c['endpoint'], c['parameter']) for c in gt['ground_truth']}
for c in new:
    key = (c['type'], c['endpoint'], c['parameter'])
    assert key not in existing, f'duplicate entry {key}'
    gt['ground_truth'].append(c)

tp = sum(1 for c in gt['ground_truth'] if c['present'])
tn = sum(1 for c in gt['ground_truth'] if not c['present'])
assert (tp, tn) == (22, 16), (tp, tn)

json.dump(gt, open('benchmarks/ground_truth.json', 'w'), indent=1)
print(f'ground truth v6: {tp} TP + {tn} TN = {len(gt["ground_truth"])} entries')
