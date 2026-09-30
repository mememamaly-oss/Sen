#!/usr/bin/env python3
"""A03/A04/A05: compare the 3 fresh ZIP benchmark runs for full determinism."""
import json

dec = json.JSONDecoder()
stats, listings = [], []
for i in [1, 2, 3]:
    s = open(f'/home/z/my-project/readiness/evidence/A03_bench_zip_{i}.json').read()
    obj, consumed = dec.raw_decode(s)
    stats.append(obj)
    listings.append(s[consumed:])

for i, st in enumerate(stats, 1):
    print(f"run{i}: f1={st['f1']} confusion={st['confusion']} stats={st['stats']}")

ident_stats = stats[0]['stats'] == stats[1]['stats'] == stats[2]['stats']
ident_conf = stats[0]['confusion'] == stats[1]['confusion'] == stats[2]['confusion']
ident_rows = listings[0] == listings[1] == listings[2]
counts = [len([l for l in r.splitlines() if l.strip().startswith(('TP:', 'TN:', 'FP:', 'FN:'))]) for r in listings]
print('identical stats dicts:', ident_stats)
print('identical confusion matrices:', ident_conf)
print('identical per-row TP/TN listings:', ident_rows)
print('rows per listing:', counts)
print('--- last rows of run1 ---')
print('\n'.join(listings[0].splitlines()[-4:]))

ok = (ident_stats and ident_conf and ident_rows
      and all(st['f1'] == 1.0 and st['confusion'] == {'TP': 38, 'FP': 0, 'FN': 0, 'TN': 35} for st in stats))
print('A03/A04/A05 VERDICT:', 'PASS' if ok else 'FAIL')
