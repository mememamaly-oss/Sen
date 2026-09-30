#!/usr/bin/env python3
"""D09/D10 password-leak scan + E16 matrix + H hypothesis details extractor."""
import json, re, glob, os

R = '/home/z/my-project/readiness'
out = {}

# ---- D09/D10: scan every artifact for real passwords ----
SECRETS = ['test1234', 'demo123', 'bob123', 'carol123', 'hunter2', 'admin123',
           'Test1234!', 'sentinel10y', 'sentinel11z']  # values used in this campaign
# note: usernames are not secrets; passwords are. hunter2/admin123/Test1234! are target-side demo creds.
PASSWORDS = ['test1234', 'demo123', 'bob123', 'carol123', 'hunter2', 'admin123', 'Test1234!']
artifacts = {
  'scan_stdout': f'{R}/evidence/B04_scan_clean.stdout',
  'scan_stderr': f'{R}/evidence/B04_scan_clean.stderr',
  'scan_json': f'{R}/evidence/B04_scan_clean.json',
  'html_report': f'{R}/evidence/B06_report_clean.html',
  'glass_report': f'{R}/evidence/B06_glass_clean.html',
  'executive': f'{R}/evidence/B06_executive_clean.json',
  'sarif': f'{R}/evidence/B08_sarif_clean.sarif',
  'webgoat_stdout': f'{R}/evidence/live/C01_webgoat.stdout',
  'webgoat_stderr': f'{R}/evidence/live/C01_webgoat.stderr',
  'ginjuice_stdout': f'{R}/evidence/live/C03_ginjuice.stdout',
  'ginjuice_json': f'{R}/evidence/live/C03_ginjuice_v400.json',
  'reproduce': f'{R}/evidence/B07_reproduce_reinstall.json',
}
leaks = {}
for name, path in artifacts.items():
    if not os.path.exists(path):
        leaks[name] = 'FILE MISSING'; continue
    body = open(path, 'rb').read().decode('utf-8', 'replace')
    found = [p for p in PASSWORDS if p in body]
    leaks[name] = found or 'CLEAN'
out['password_leak_scan'] = leaks
out['D09_verdict'] = 'PASS' if all(v in ('CLEAN',) for k, v in leaks.items()
                                   if 'stdout' in k or 'stderr' in k or k == 'scan_json') else 'FAIL'
out['D10_verdict'] = 'PASS' if all(v in ('CLEAN',) for k, v in leaks.items()
                                   if 'report' in k or k in ('executive', 'sarif', 'reproduce', 'ginjuice_json')) else 'FAIL'

# ---- E16: authorization matrix from the clean scan appmap ----
d = json.load(open(f'{R}/evidence/B04_scan_clean.json'))
am = d.get('stats', {}).get('appmap', {})
amx = am.get('access_matrix')
out['E16_matrix_shape'] = {
    'type': type(amx).__name__,
    'preview': json.dumps(amx, ensure_ascii=False)[:800] if amx else None,
}

# ---- H: hypothesis structure ----
rea = d.get('stats', {}).get('reasoning', {})
hyps = rea.get('hypotheses', [])
out['H_hypothesis_count'] = len(hyps)
if hyps:
    h = hyps[0]
    out['H_hypothesis_fields'] = sorted(h.keys())
    out['H_sample'] = json.dumps(h, ensure_ascii=False)[:900]

# ---- twin projections via CLI (authorization_matrix projection) — run separately
json.dump(out, open(f'{R}/evidence/D_E_H_extract.json', 'w'), indent=1, ensure_ascii=False)
print(json.dumps(out, indent=1, ensure_ascii=False)[:2500])
