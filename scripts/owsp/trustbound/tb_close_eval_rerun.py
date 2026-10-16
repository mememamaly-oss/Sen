#!/usr/bin/env python3
"""trustbound CATEGORY CLOSE — RE-RUN of the eval + regression check on the
PRESERVED merged scan (evidence order 2026-10-15).

Why a re-run variant exists: the 12 per-chunk JSONs under tool-results/
bm_full_chunks/ were destroyed by the 2026-10-15 environment wipe, so the
merge phase of tb_close_eval.py cannot re-execute. Its output, however, was
written on 2026-10-14 and is byte-preserved at
build-v430/results/owsp/benchmark/benchmark_scan_tb_close.json. This script
loads that preserved artifact and executes the IDENTICAL eval + regression
code (the post-cross-class-fix code path, verbatim from tb_close_eval.py)
on it. The re-derived eval JSON must be byte-identical to the preserved
eval_tb_close_full.json (sha256 checked and printed at the end)."""
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

RESD = Path("/home/z/my-project/build-v430/results/owsp/benchmark")
EV = RESD / "tb_close_evidence"
EV.mkdir(exist_ok=True)
EXPECTED = RESD / "expectedresults-1.2.csv"
CMDI_CLOSE_EVAL = RESD / "eval_cmdi_close_full.json"
PRESERVED_EVAL = RESD / "eval_tb_close_full.json"

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

# ---- input: the PRESERVED merge output of the 12-chunk close run ----
SCAN_OUT = RESD / "benchmark_scan_tb_close.json"
merged = json.loads(SCAN_OUT.read_text())
stats = merged["stats"]
n_act = [f for f in merged["findings"] if f["type"] not in
         ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
n_ver = [f for f in n_act if f.get("status") == "verified"]
n_rej = [f for f in n_act if f.get("status") == "rejected"]
print(f"merged: {stats['requests']} reqs, {len(merged['findings'])} findings, "
      f"{len(n_act)} active, {len(n_ver)} verified, {len(n_rej)} rejected")
print("scan (preserved artifact):", SCAN_OUT)


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

print("\n=== PER-CATEGORY (fresh full benchmark, TB engine cc142b3 — trustbound category close) ===")
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

report = {"label": "trustbound category close (TB-1a self-named value + TB-1b header-name + "
                   "TB-1c sacrificial-tail + TB-2 all-params + TB-3a resolver-name + "
                   "TB-3b header-tcid-value + TB-3c cookie-value engine cc142b3) — full 12-chunk re-run",
          "scan": str(SCAN_OUT), "total_tests": len(exp),
          "per_category": {c: {k: v for k, v in m.items()} for c, m in per_cat.items()},
          "overall_covered": {"tp": cov_tp, "fp": cov_fp, "fn": cov_fn, "tn": cov_tn,
                              "precision": prec_all, "recall": rec_all, "f1": f1},
          "cross_class_findings": cross_class}
EVAL_OUT = EV / "eval_tb_close_full.rerun.json"
EVAL_OUT.write_text(json.dumps(report, indent=1))
print("\nsaved eval (re-run):", EVAL_OUT)

print("\n=== REGRESSION CHECK vs eval_cmdi_close_full.json (cmdi close) ===")
base = json.loads(CMDI_CLOSE_EVAL.read_text())
ok = True
for cat in sorted(base["per_category"]):
    b, n = base["per_category"][cat], per_cat[cat]
    btp = set(b.get("tp_tests", []))
    ntp = set(n["tp_tests"])
    if cat == "trustbound":
        expected_tp = btp | set(b.get("fn_tests", []))   # all 83 vuln tests
        if ntp == expected_tp and n["fn"] == 0 and n["fp"] == 0:
            print(f"trustbound: 32->83 TP = EXACTLY the cmdi-close TP+FN union; FN 0; FP 0  [CLOSED]")
        else:
            ok = False
            print(f"trustbound: MISMATCH tp={n['tp']} fn={n['fn']} fp={n['fp']} "
                  f"(expected tp={len(expected_tp)} fn=0 fp=0); "
                  f"missing={sorted(expected_tp - ntp)}; extra={sorted(ntp - expected_tp)}; newFN={sorted(n['fn_tests'])}")
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
bx = base.get("cross_class_findings", [])
# normalize BOTH sides to sorted tuples before the string compare: the in-memory
# cross_class holds tuples while the JSON-loaded base holds lists, and
# str(('a','b')) != str(['a','b']) — a formatting difference that printed a
# spurious DIFFERS on identical data (live-caught on the 2026-10-14 close run:
# both sides 54, semantic + raw content identical after round-trip)
bxs = sorted((t, c, tuple(sorted(w))) for t, c, w in bx)
nxs = sorted((t, c, tuple(sorted(w))) for t, c, w in cross_class)
print(f"\ncross-class: {len(bx)} -> {len(cross_class)} "
      f"{'IDENTICAL' if bxs == nxs else 'DIFFERS'}")
if bxs != nxs:
    print("  only in base:", sorted(set(bxs) - set(nxs))[:10])
    print("  only in new:", sorted(set(nxs) - set(bxs))[:10])
print("\nREGRESSION CHECK:", "PASS — zero regressions, trustbound closed" if ok else "FAIL")

# ---- faithfulness proof: re-derived eval must be byte-identical to the preserved one
h_new = hashlib.sha256(EVAL_OUT.read_bytes()).hexdigest()
h_old = hashlib.sha256(PRESERVED_EVAL.read_bytes()).hexdigest()
print("\nsha256 re-derived eval :", h_new)
print("sha256 preserved eval  :", h_old)
print("BYTE-IDENTICAL to the 2026-10-14 close-run eval:", h_new == h_old)
if h_new != h_old:
    ok = False
sys.exit(0 if ok else 3)
