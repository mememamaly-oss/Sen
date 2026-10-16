#!/usr/bin/env python3
"""Merge the 12 fresh full-benchmark chunk scans + evaluate (campaign honesty
rules — same logic as scripts/owsp/benchmark_eval.py, paths adapted)."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

OUTD = Path("/home/z/my-project/tool-results/bm_full_chunks")
EXPECTED = Path("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv")
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
for c in sorted(OUTD.glob("chunk_*.json")):
    d = json.loads(c.read_text())
    merged["findings"].extend(d.get("findings", []))
    merged["rejected_candidates"].extend(d.get("rejected_candidates", []))
    merged["unverified_candidates"].extend(d.get("unverified_candidates", []))
    s = d.get("stats", {})
    stats["requests"] += s.get("requests") or 0
    stats["endpoints"] += (s.get("endpoints") or 0)
merged["stats"] = stats
merged["scanner"] = "sentinel-core/4.3.9-cr3 (12 no-crawl chunks merged, crypto recall-push round)"
OUT = OUTD / "merged_full.json"
OUT.write_text(json.dumps(merged))
n_act = [f for f in merged["findings"] if f["type"] not in
         ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
n_ver = [f for f in n_act if f.get("status") == "verified"]
print(f"merged: {stats['requests']} reqs, {len(merged['findings'])} findings, "
      f"{len(n_act)} active, {len(n_ver)} verified")

# ---- evaluate ----
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

print("\n=== PER-CATEGORY (fresh full benchmark, engine v4.3.9-cr3) ===")
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

report = {"label": "v439_cr3_full", "scan": str(OUT), "total_tests": len(exp),
          "per_category": {c: {k: v for k, v in m.items()} for c, m in per_cat.items()},
          "overall_covered": {"tp": cov_tp, "fp": cov_fp, "fn": cov_fn, "tn": cov_tn,
                              "precision": prec_all, "recall": rec_all, "f1": f1},
          "cross_class_findings": cross_class}
(OUTD / "eval_v439_cr3_full.json").write_text(json.dumps(report, indent=1))
print("\nsaved:", OUTD / "eval_v439_cr3_full.json")
