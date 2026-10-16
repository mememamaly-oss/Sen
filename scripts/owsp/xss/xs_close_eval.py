#!/usr/bin/env python3
"""xss CATEGORY CLOSE — merge the 12 fresh full-benchmark chunk scans (XS-3
engine) + evaluate (campaign honesty rules — same logic as
scripts/owsp/merge_eval_full.py / benchmark_eval.py) + strict regression
check against the committed sqli-close eval (every category's TP set must be
byte-identical except xss, which must gain EXACTLY the 60 sqli-close FNs)."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

OUTD = Path("/home/z/my-project/tool-results/bm_full_chunks")
RESD = Path("/home/z/my-project/build-v430/results/owsp/benchmark")
EXPECTED = RESD / "expectedresults-1.2.csv"
SQLI_CLOSE_EVAL = RESD / "eval_sq_close_full.json"

# the 12 chunks of THIS re-run, explicit (a bare glob would also swallow the
# chunk_*.db.memory.json snapshots and corrupt the merge)
CHUNKS = ["00000_00228", "00229_00457", "00458_00686", "00687_00915",
          "00916_01144", "01145_01373", "01374_01602", "01603_01831",
          "01832_02060", "02061_02289", "02290_02518", "02519_02739"]

ENGINE_TYPE_TO_CATEGORY = {
    "sql_injection": "sqli", "xss_reflected": "xss", "xss_dom": "xss",
    "xss_stored": "xss", "path_traversal": "pathtraver", "open_redirect": "redirect",
    "command_injection": "cmdi", "ldap_injection": "ldapi",
    "xpath_injection": "xpathi", "secure_cookie": "securecookie",
    "trust_bound": "trustbound", "weak_crypto": "crypto", "weak_hash": "hash",
    "weak_random": "weakrand", "csrf": None, "nosql_injection": None,
}
COVERED_CATEGORIES = {"sqli", "xss", "cmdi", "ldapi", "xpathi", "securecookie",
                      "trustbound", "crypto", "hash", "weakrand"}

# ---- merge ----
merged = {"findings": [], "rejected_candidates": [], "unverified_candidates": []}
stats = {"requests": 0, "endpoints": 0}
for label in CHUNKS:
    d = json.loads((OUTD / f"chunk_{label}.json").read_text())
    merged["findings"].extend(d.get("findings", []))
    merged["rejected_candidates"].extend(d.get("rejected_candidates", []))
    merged["unverified_candidates"].extend(d.get("unverified_candidates", []))
    s = d.get("stats", {})
    stats["requests"] += s.get("requests") or 0
    stats["endpoints"] += (s.get("endpoints") or 0)
merged["stats"] = stats
merged["scanner"] = ("sentinel-core (12 no-crawl chunks merged, "
                     "xss recall-push round — category close, XS-3 engine)")
SCAN_OUT = RESD / "benchmark_scan_xs_close.json"
SCAN_OUT.write_text(json.dumps(merged))
n_act = [f for f in merged["findings"] if f["type"] not in
         ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
n_ver = [f for f in n_act if f.get("status") == "verified"]
print(f"merged: {stats['requests']} reqs, {len(merged['findings'])} findings, "
      f"{len(n_act)} active, {len(n_ver)} verified")
print("saved scan:", SCAN_OUT)

# ---- evaluate (campaign honesty rules, verbatim from merge_eval_full.py) ----
def load_expected():
    out = {}
    for line in EXPECTED.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, cat, real, cwe = line.split(",")
        out[name] = {"category": cat, "vulnerable": real == "true", "cwe": cwe}
    return out

def tcid_from_url(url):
    m = re.search(r"(BenchmarkTest\d{5})(?:[?/].*)?$", url)
    return m.group(1) if m else None

exp = load_expected()
hits = defaultdict(set)
for f in merged.get("findings", []):
    tcid = tcid_from_url(f.get("url", ""))
    if tcid:
        hits[tcid].add((f.get("type"), f.get("status")))
passive_only = {"missing_security_headers", "server_banner", "tech_banner"}
per_cat = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                               "fp_tests": [], "tp_tests": [], "fn_tests": []})
cross_class = []
for tcid, info in exp.items():
    cat, vuln = info["category"], info["vulnerable"]
    found = hits.get(tcid, set())
    active = [(t, s) for (t, s) in found if t not in passive_only]
    claimed = {ENGINE_TYPE_TO_CATEGORY.get(t) for t, _ in active}
    right = any(t for t, s in active if s == "verified"
                and ENGINE_TYPE_TO_CATEGORY.get(t) == cat)
    wrong = [t for t, s in active if s == "verified"
             and ENGINE_TYPE_TO_CATEGORY.get(t) not in (cat, None)]
    if wrong:
        cross_class.append((tcid, cat, wrong))
    m = per_cat[cat]
    if vuln:
        if right:
            m["tp"] += 1; m["tp_tests"].append(tcid)
        else:
            m["fn"] += 1; m["fn_tests"].append(tcid)
    else:
        if right or wrong:
            m["fp"] += 1; m["fp_tests"].append((tcid, wrong or "right-class"))
        else:
            m["tn"] += 1

print("\n=== PER-CATEGORY (fresh full benchmark, XS-3 engine — xss category close) ===")
print(f"{'category':<14} {'tp':>4} {'fp':>4} {'fn':>4} {'tn':>4} {'recall':>7} {'precision':>9}")
cov_tp = cov_fp = cov_fn = cov_tn = 0
for cat in sorted(per_cat):
    m = per_cat[cat]
    rec = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) else None
    prec = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) else None
    print(f"{cat:<14} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} {m['tn']:>4} "
          f"{(f'{rec:.4f}' if rec is not None else 'n/a'):>7} "
          f"{(f'{prec:.4f}' if prec is not None else 'n/a'):>9}")
    if cat in COVERED_CATEGORIES:
        cov_tp += m["tp"]; cov_fp += m["fp"]; cov_fn += m["fn"]; cov_tn += m["tn"]
prec_all = cov_tp / (cov_tp + cov_fp) if (cov_tp + cov_fp) else None
rec_all = cov_tp / (cov_tp + cov_fn) if (cov_tp + cov_fn) else None
f1 = (2 * prec_all * rec_all / (prec_all + rec_all)) if prec_all and rec_all else None
print(f"\nOVERALL (covered): TP={cov_tp} FP={cov_fp} FN={cov_fn} TN={cov_tn} "
      f"precision={prec_all:.4f} recall={rec_all:.4f} F1={f1:.4f}")
print("cross-class FPs:", len(cross_class), cross_class[:6])

report = {"label": "xss category close (XS-1 1a3a97a + XS-2 d8faa3e + XS-3 8b10ec6) — full 12-chunk re-run",
          "scan": str(SCAN_OUT), "total_tests": len(exp),
          "per_category": {c: {k: v for k, v in m.items()} for c, m in per_cat.items()},
          "overall_covered": {"tp": cov_tp, "fp": cov_fp, "fn": cov_fn, "tn": cov_tn,
                              "precision": prec_all, "recall": rec_all, "f1": f1},
          "cross_class_findings": cross_class}
EVAL_OUT = RESD / "eval_xs_close_full.json"
EVAL_OUT.write_text(json.dumps(report, indent=1))
print("\nsaved eval:", EVAL_OUT)

# ---- strict regression check vs the committed sqli-close eval ----
print("\n=== REGRESSION CHECK vs eval_sq_close_full.json (sqli close) ===")
base = json.loads(SQLI_CLOSE_EVAL.read_text())
ok = True
for cat in sorted(base["per_category"]):
    b, n = base["per_category"][cat], per_cat[cat]
    btp = set(b.get("tp_tests", []))
    ntp = set(n["tp_tests"])
    if cat == "xss":
        expected_tp = btp | set(b.get("fn_tests", []))   # all 246 vuln tests
        if ntp == expected_tp and n["fn"] == 0 and n["fp"] == 0:
            print(f"xss: 186->246 TP = EXACTLY the sqli-close TP+FN union; FN 0; FP 0  [CLOSED]")
        else:
            ok = False
            print(f"xss: MISMATCH tp={n['tp']} fn={n['fn']} fp={n['fp']} "
                  f"(expected tp=246 fn=0 fp=0); missing={sorted(expected_tp - ntp)}; extra={sorted(ntp - expected_tp)}; newFN={sorted(n['fn_tests'])}")
    else:
        same_counts = (b["tp"], b["fp"], b["fn"]) == (n["tp"], n["fp"], n["fn"])
        same_lists = btp == ntp and set(b.get("fp_tests", [])) == set(n.get("fp_tests", []))
        flag = "IDENTICAL" if (same_counts and same_lists) else "REGRESSION"
        if not (same_counts and same_lists):
            ok = False
        print(f"{cat:<14} tp {b['tp']}->{n['tp']} fp {b['fp']}->{n['fp']} fn {b['fn']}->{n['fn']}  [{flag}]")
        if not same_lists and same_counts:
            print(f"  (count-equal but test-list differs: "
                  f"lost={sorted(btp - ntp)[:5]} gained={sorted(ntp - btp)[:5]})")
print("\nREGRESSION CHECK:", "PASS — zero regressions, xss closed" if ok else "FAIL")
sys.exit(0 if ok else 3)
