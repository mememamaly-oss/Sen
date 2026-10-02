#!/usr/bin/env python3
"""v4.2.0 gate summary — compact scalar output to FILE (never giant stdout)."""
import json

B = "/home/z/my-project/build-v420"
out = open("/home/z/my-project/tool-results/v420_gate.txt", "w")
w = out.write

w("== BENCHMARK x3 ==\n")
rows = []
for n in (1, 2, 3):
    d = json.load(open(f"{B}/results/bench_v420_{n}.json"))
    metrics = d.get("metrics") or {}
    row = {
        "run_id": d.get("run_id"),
        "precision": d.get("precision", metrics.get("precision")),
        "recall": d.get("recall", metrics.get("recall")),
        "f1": d.get("f1", metrics.get("f1")),
        "tp": d.get("tp", metrics.get("tp")),
        "fp": d.get("fp", metrics.get("fp")),
        "fn": d.get("fn", metrics.get("fn")),
        "tn": d.get("tn", metrics.get("tn")),
        "n_findings": len(d.get("findings", []) or []),
        "n_rejected": len(d.get("rejected_candidates", []) or []),
        "n_unverified": len(d.get("unverified_candidates", []) or []),
    }
    rows.append(row)
    w(f"BENCH {n}: {json.dumps(row, sort_keys=True)}\n")
    st = d.get("stats") or {}
    w(f"   stats.unverified_candidates={st.get('unverified_candidates')}\n")
    for f in d.get("findings", []):
        if f.get("type") == "missing_security_headers":
            w(f"   passive: conf={f.get('confidence')} method={(f.get('verification') or {}).get('method')}\n")
            break
    for f in d.get("findings", []):
        if f.get("type") in ("csrf", "nosql_injection"):
            v = f.get("verification") or {}
            w(f"   {f.get('type')}: conf={f.get('confidence')} method={v.get('method')} passed={v.get('passed')}\n")
    uv = d.get("unverified_candidates") or []
    from collections import Counter
    w(f"   unverified by type: {dict(Counter(f.get('type') for f in uv))}\n")

w("\n== DETERMINISM ==\n")
w(f"run_ids: {[r['run_id'] for r in rows]}\n")
w(f"identical metrics x3: {len({json.dumps(r, sort_keys=True) for r in rows}) == 1}\n")

w("\n== TESTS ==\n")
chunks, ran, failed, names = [], 0, 0, set()
for c in range(1, 10):
    try:
        d = json.load(open(f"{B}/results/tests_v420_c{c}.json"))
    except FileNotFoundError:
        continue
    chunks.append(f"c{c}")
    for case in d["cases"]:
        if case.get("skipped"):
            continue
        ran += 1
        names.add(case["name"])
        if not case["ok"]:
            failed += 1
            w(f" FAIL: {case['name']}: {str(case.get('error'))[:200]}\n")
merged = {"suite": "v4.2.0 full gate", "chunks": chunks, "ran": ran,
          "failed": failed, "cases": sorted(names)}
json.dump(merged, open(f"{B}/results/tests_v420_FULL.json", "w"), indent=1)
w(f"chunks={chunks} ran={ran} failed={failed} (expect 102/0)\n")
w(f"VERDICT: {'PASS' if failed == 0 and ran >= 102 else 'FAIL'}\n")
out.close()
print("written")
