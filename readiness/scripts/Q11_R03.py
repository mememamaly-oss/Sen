#!/usr/bin/env python3
"""Q11: store stress with thousands of findings + R03: credentials in exceptions check."""
import json, os, sys, time

sys.path.insert(0, '/home/z/my-project/readiness/ziprun2')
from sentinel.store import Store

EV = '/home/z/my-project/readiness/evidence'

# ---- Q11: 5000 findings + 20 runs into one store ----
st = Store(f'{EV}/q_stress.db')
t0 = time.time()
N_RUNS, N_FINDINGS = 20, 250
total = 0
for r in range(N_RUNS):
    findings = []
    for i in range(N_FINDINGS):
        findings.append({
            "id": f"F-stress{r:02d}{i:03d}", "type": "xss_reflected", "severity": "medium",
            "status": "verified", "url": f"http://stress.local/p{i}", "parameter": f"q{i}",
            "method": "GET", "confidence": 0.9, "risk": 50,
            "evidence": [{"kind": "reflection", "detail": "canary reflected"}],
            "verification": {"method": "oracle:replay-2round", "passed": True}})
    st.save_run({"run_id": f"run-stress{r:02d}", "seed": "s", "scanner": "t",
                 "target": "http://stress.local/", "stats": {"requests": 1000, "verified": N_FINDINGS},
                 "findings": findings, "rejected_candidates": []})
    total += N_FINDINGS
insert_s = time.time() - t0

t1 = time.time()
listed = st.list_findings(limit=10000)
recurring = st.recurring()
summary = st.stats_summary()
delta = st.delta()
query_s = time.time() - t1

import sqlite3
db = sqlite3.connect(f'{EV}/q_stress.db')
integ = db.execute('PRAGMA integrity_check').fetchone()[0]
size_mb = round(os.path.getsize(f'{EV}/q_stress.db') / 1e6, 1)

res = {
    'inserted_findings': total, 'runs': N_RUNS,
    'insert_seconds': round(insert_s, 2), 'query_seconds': round(query_s, 2),
    'listed': len(listed), 'recurring_rows': len(recurring),
    'integrity': integ, 'db_size_mb': size_mb,
    'summary_runs': summary.get('runs'),
}
json.dump(res, open(f'{EV}/Q_stress.json', 'w'), indent=1)
print(json.dumps(res, indent=1))

# ---- R03: wrong-credential scan must not leak the password in errors ----
import subprocess
r = subprocess.run(
    [sys.executable, '/home/z/my-project/readiness/ziprun2/sentinel/cli.py', 'scan',
     'http://127.0.0.1:8777', '--allow-private', '--no-browser', '--no-oast', '--max-pages', '3',
     '--auth-user', 'demo', '--auth-pass', 'WRONGPW_leakcheck_123',
     '--auth-url', 'http://127.0.0.1:8777/login', '--auth-user-field', 'uid', '--auth-pass-field', 'passw',
     '--db', f'{EV}/r03.db', '--out', f'{EV}/r03.json'],
    capture_output=True, text=True, timeout=120, cwd='/home/z/my-project/readiness/ziprun2')
leak = 'WRONGPW_leakcheck_123' in (r.stdout + r.stderr)
try:
    body = open(f'{EV}/r03.json').read()
    leak_json = 'WRONGPW_leakcheck_123' in body
except FileNotFoundError:
    body, leak_json = '', False
r03 = {'exit': r.returncode, 'leak_in_stdout_stderr': leak, 'leak_in_scan_json': leak_json,
       'auth_stats': json.loads(body).get('stats', {}).get('auth') if body else None}
json.dump(r03, open(f'{EV}/R03_check.json', 'w'), indent=1)
print(json.dumps(r03, indent=1))
