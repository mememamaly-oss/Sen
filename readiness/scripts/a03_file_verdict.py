#!/usr/bin/env python3
"""A03/A04/A05: determinism comparison of the 3 fresh ZIP benchmark runs.
Writes verdict to a03_verdict.json (transport-stall-proof)."""
import json

OUT = '/home/z/my-project/readiness/evidence/a03_verdict.json'
dec = json.JSONDecoder()
stats, listings = [], []
for i in [1, 2, 3]:
    s = open(f'/home/z/my-project/readiness/evidence/A03_bench_zip_{i}.json').read()
    obj, consumed = dec.raw_decode(s)
    stats.append(obj)
    listings.append(s[consumed:])

ident_stats = stats[0]['stats'] == stats[1]['stats'] == stats[2]['stats']
ident_conf = stats[0]['confusion'] == stats[1]['confusion'] == stats[2]['confusion']
ident_rows = listings[0] == listings[1] == listings[2]
all_f1 = all(st['f1'] == 1.0 for st in stats)
conf_ok = all(st['confusion'] == {'TP': 38, 'FP': 0, 'FN': 0, 'TN': 35} for st in stats)

verdict = {
    "runs": [
        {"f1": st['f1'], "precision": st['precision'], "recall": st['recall'],
         "confusion": st['confusion'], "stats": st['stats']} for st in stats
    ],
    "identical_stats_dicts": ident_stats,
    "identical_confusion_matrices": ident_conf,
    "identical_per_row_tp_tn_listings": ident_rows,
    "row_counts": [len([l for l in r.splitlines() if l.strip().startswith(('TP:', 'TN:'))]) for r in listings],
    "VERDICT_A03_A04_A05": "PASS" if (ident_stats and ident_conf and ident_rows and all_f1 and conf_ok) else "FAIL",
}
with open(OUT, 'w') as f:
    json.dump(verdict, f, indent=1)
print(json.dumps(verdict, indent=1))
