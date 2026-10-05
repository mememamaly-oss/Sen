#!/usr/bin/env python3
"""OWASP Benchmark evaluation — the numeric precision/recall measurement.

Maps SENTINEL scan findings to Benchmark test cases (TCIDs) and computes the
confusion matrix per category and overall, against expectedresults-1.2.csv.

Honesty rules baked in:
* A test counts as engine-POSITIVE only for a VERIFIED finding whose class maps
  to that test's category (a verified finding of the WRONG class on a test is a
  cross-class FP for that test and not a TP).
* Categories with NO active detector in the engine are listed as NOT-COVERED:
  they are excluded from the covered-precision/recall aggregate AND shown
  separately so nobody mistakes a missing detector for a true negative.
* Engine categories are counted with their benchmark names (sqli->sqli etc.).
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SRC = Path("/home/z/my-project/tools/benchmark-src")
EXPECTED = SRC / "expectedresults-1.2.csv"

# engine finding type -> benchmark category it claims evidence for
ENGINE_TYPE_TO_CATEGORY = {
    "sql_injection": "sqli",
    "xss_reflected": "xss",
    "xss_dom": "xss",
    "xss_stored": "xss",
    "path_traversal": "pathtraver",
    "command_injection": "cmdi",
    "cmdi": "cmdi",
    "ldap_injection": "ldapi",
    "xpath_injection": "xpathi",
    "open_redirect": "openredirect",
    "csrf": "csrf",
    "secure_cookie": "securecookie",
    "weak_random": "weakrand",
    "crypto": "crypto",
    "hash": "hash",
    "trust_bound": "trustbound",
}

# benchmark categories the engine has an ACTIVE detector for (v4.2.3):
# sqli->SQLiDetector, xss->XSSDetector, pathtraver->Traversal/PathTraversal,
# cmdi->CommandInjectionDetector (OOB). NO detector exists for ldapi, xpathi,
# crypto, hash, weakrand, securecookie, trustbound — honestly not covered.
COVERED_CATEGORIES = {"sqli", "xss", "pathtraver", "cmdi"}


def load_expected() -> dict:
    out = {}
    for line in EXPECTED.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, cat, real, cwe = line.split(",")
        out[name] = {"category": cat, "vulnerable": real == "true", "cwe": cwe}
    return out


def tcid_from_url(url: str) -> str | None:
    m = re.search(r"(BenchmarkTest\d{5})(?:[?/].*)?$", url)
    return m.group(1) if m else None


def evaluate(scan_json: str, label: str) -> dict:
    d = json.loads(Path(scan_json).read_text())
    exp = load_expected()

    # engine positives: TCID -> set of (type, status)
    hits = defaultdict(set)
    for f in d.get("findings", []):
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
        # does the engine have a verified finding OF THE RIGHT CATEGORY?
        claimed_cats = {ENGINE_TYPE_TO_CATEGORY.get(t) for t, _ in active}
        right = any(t for t, s in active if s == "verified"
                    and ENGINE_TYPE_TO_CATEGORY.get(t) == cat)
        wrong = [t for t, s in active if s == "verified"
                 and ENGINE_TYPE_TO_CATEGORY.get(t) != cat]
        if wrong:
            cross_class.append((tcid, cat, wrong))
        m = per_cat[cat]
        if vuln:
            if right:
                m["tp"] += 1; m["tp_tests"].append(tcid)
            else:
                m["fn"] += 1; m["fn_tests"].append(tcid)
        else:
            if right or wrong:  # any verified active claim on a not-vulnerable test = FP
                m["fp"] += 1
                m["fp_tests"].append((tcid, wrong or "right-class"))
            else:
                m["tn"] += 1

    report = {"label": label, "scan": scan_json,
              "total_tests": len(exp),
              "engine_active_findings": sum(len(v) for v in hits.values()),
              "per_category": {}, "cross_class_findings": cross_class}
    cov_tp = cov_fp = cov_fn = cov_tn = 0
    all_tp = all_fp = all_fn = all_tn = 0
    for cat in sorted(per_cat):
        m = per_cat[cat]
        prec = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) else None
        rec = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) else None
        covered = cat in COVERED_CATEGORIES
        report["per_category"][cat] = {
            "covered": covered, **{k: v for k, v in m.items() if not k.endswith("_tests")},
            "precision": round(prec, 4) if prec is not None else None,
            "recall": round(rec, 4) if rec is not None else None,
            "fn_tests": m["fn_tests"][:400], "fp_tests": m["fp_tests"][:50],
            "tp_tests": m["tp_tests"][:400],
        }
        all_tp += m["tp"]; all_fp += m["fp"]; all_fn += m["fn"]; all_tn += m["tn"]
        if covered:
            cov_tp += m["tp"]; cov_fp += m["fp"]; cov_fn += m["fn"]; cov_tn += m["tn"]

    def metrics(tp, fp, fn, tn):
        p = tp / (tp + fp) if (tp + fp) else None
        r = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * p * r / (p + r)) if (p and r) else None
        fpr = fp / (fp + tn) if (fp + tn) else None
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(p, 4) if p is not None else None,
                "recall": round(r, 4) if r is not None else None,
                "f1": round(f1, 4) if f1 is not None else None,
                "fpr": round(fpr, 4) if fpr is not None else None}

    report["overall_all_categories"] = metrics(all_tp, all_fp, all_fn, all_tn)
    report["overall_covered_only"] = metrics(cov_tp, cov_fp, cov_fn, cov_tn)
    return report


if __name__ == "__main__":
    scan_json = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else "baseline"
    rep = evaluate(scan_json, label)
    out = Path("/home/z/my-project/tools/benchmark-src/target/campaign") / f"eval_{label}.json"
    out.write_text(json.dumps(rep, indent=1))
    print(f"== {label} ==  (report: {out})")
    print("total tests:", rep["total_tests"], " engine active findings:", rep["engine_active_findings"])
    print(f"{'category':<14}{'cov':<5}{'tp':<5}{'fp':<5}{'fn':<5}{'tn':<5}{'prec':<8}{'rec':<8}")
    for cat, m in rep["per_category"].items():
        print(f"{cat:<14}{str(m['covered'])[0]:<5}{m['tp']:<5}{m['fp']:<5}{m['fn']:<5}{m['tn']:<5}"
              f"{str(m['precision']):<8}{str(m['recall']):<8}")
    print("OVERALL (covered categories only):", rep["overall_covered_only"])
    print("OVERALL (all categories):", rep["overall_all_categories"])
    if rep["cross_class_findings"]:
        print("cross-class findings:", rep["cross_class_findings"][:10])
