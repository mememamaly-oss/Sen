#!/usr/bin/env python3
"""Compare recovery-test outputs against the frozen v4.1.1 baseline evidence.

Usage:
  python3 verify_recovery_v411.py --recovery <dir> --baseline <dir>

  <recovery> must contain: tests_recovery.json, doctor_recovery.json, bench_recovery_1.json
  <baseline> is gap-validation/results (tests_v411_FULL.json, doctor_v411.json,
             bench_v411_{1,2,3}.json)
"""
import argparse
import json
import sys

OK = "\033[32mPASS\033[0m"
BAD = "\033[31mFAIL\033[0m"


def load(p):
    return json.load(open(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recovery", required=True)
    ap.add_argument("--baseline", required=True)
    a = ap.parse_args()
    R, B = a.recovery, a.baseline
    failures = []

    # ---------- TESTS ----------
    print("=" * 64)
    print("[TESTS] recovery vs baseline (102/102)")
    rt = load(f"{R}/tests_recovery.json")
    bt = load(f"{B}/tests_v411_FULL.json")
    r_map = {c["name"]: c.get("ok") for c in rt["cases"]}
    b_map = {c["name"]: c.get("ok") for c in bt["cases"]}
    t_ok = (rt["total"] == 102 and rt["failed"] == 0 and rt.get("strict_ok")
            and bt["total"] == 102 and bt["failed"] == 0)
    if not t_ok:
        failures.append("tests: totals differ from 102/0")
    if set(r_map) != set(b_map):
        only_r = set(r_map) - set(b_map)
        only_b = set(b_map) - set(r_map)
        failures.append(f"tests: case-name sets differ (only-recovery={only_r}, only-baseline={only_b})")
    else:
        diff = [n for n in b_map if r_map.get(n) != b_map.get(n)]
        if diff:
            failures.append(f"tests: ok-flags differ for {diff}")
    print(f"  recovery: total={rt['total']} failed={rt['failed']} strict_ok={rt.get('strict_ok')}")
    print(f"  baseline: total={bt['total']} failed={bt['failed']}")
    print(f"  case-name sets identical: {set(r_map) == set(b_map)} | ok-flags identical: "
          f"{not any(r_map.get(n) != b_map.get(n) for n in b_map)}")
    print(f"  => TESTS: {OK if not [f for f in failures if f.startswith('tests')] else BAD}")

    # ---------- DOCTOR ----------
    print("=" * 64)
    print("[DOCTOR] recovery vs baseline (15/15)")
    rd = load(f"{R}/doctor_recovery.json")
    bd = load(f"{B}/doctor_v411.json")
    r_checks = {c["check"]: c["status"] for c in rd["checks"]}
    b_checks = {c["check"]: c["status"] for c in bd["checks"]}
    d_ok = (rd.get("overall") == "PASS" and rd.get("passed") == 15 and rd.get("total") == 15
            and bd.get("overall") == "PASS" and bd.get("passed") == 15)
    if not d_ok:
        failures.append(f"doctor: overall/passed differ ({rd.get('overall')}, {rd.get('passed')})")
    if set(r_checks) != set(b_checks):
        failures.append("doctor: check-name sets differ")
    else:
        diff = [n for n in b_checks if r_checks.get(n) != b_checks.get(n)]
        if diff:
            failures.append(f"doctor: statuses differ for {diff}")
    print(f"  recovery: {rd.get('overall')} {rd.get('passed')}/{rd.get('total')}")
    print(f"  baseline: {bd.get('overall')} {bd.get('passed')}/{bd.get('total')}")
    print(f"  per-check statuses identical: {not any(r_checks.get(n) != b_checks.get(n) for n in b_checks)}")
    print(f"  => DOCTOR: {OK if not [f for f in failures if f.startswith('doctor')] else BAD}")

    # ---------- BENCHMARK ----------
    print("=" * 64)
    print("[BENCHMARK] recovery vs baseline x3 (F1=1.000, TP=38/FP=0/FN=0)")
    rb = load(f"{R}/bench_recovery_1.json")
    benches = [load(f"{B}/bench_v411_{i}.json") for i in (1, 2, 3)]
    rc, rbm = rb.get("confusion", {}), rb.get("metrics", rb)
    hard = [
        ("f1", rbm.get("f1", rb.get("f1")), [b.get("f1") for b in benches]),
        ("precision", rbm.get("precision", rb.get("precision")), [b.get("precision") for b in benches]),
        ("recall", rbm.get("recall", rb.get("recall")), [b.get("recall") for b in benches]),
        ("TP", rc.get("TP"), [b["confusion"].get("TP") for b in benches]),
        ("FP", rc.get("FP"), [b["confusion"].get("FP") for b in benches]),
        ("FN", rc.get("FN"), [b["confusion"].get("FN") for b in benches]),
        ("TN", rc.get("TN"), [b["confusion"].get("TN") for b in benches]),
        ("findings_count", len(rb.get("findings", [])), [len(b.get("findings", [])) for b in benches]),
    ]
    rs = rb.get("stats", {})
    for label, rv, bvs in [
        ("boundary.by_category", (rs.get("boundary") or {}).get("by_category"),
         [(b["stats"].get("boundary") or {}).get("by_category") for b in benches]),
        ("coverage.discovered", (rs.get("coverage") or {}).get("discovered"),
         [b["stats"]["coverage"].get("discovered") for b in benches]),
        ("coverage.tested", (rs.get("coverage") or {}).get("tested"),
         [b["stats"]["coverage"].get("tested") for b in benches]),
        ("coverage.untested", (rs.get("coverage") or {}).get("untested"),
         [b["stats"]["coverage"].get("untested") for b in benches]),
        ("coverage.coverage_pct", (rs.get("coverage") or {}).get("coverage_pct"),
         [b["stats"]["coverage"].get("coverage_pct") for b in benches]),
        ("api_inventory.total", (rs.get("api_inventory") or {}).get("total"),
         [b["stats"].get("api_inventory", {}).get("total") for b in benches]),
        ("digital_twin.surfaces_total", (rs.get("digital_twin") or {}).get("surfaces_total"),
         [b["stats"].get("digital_twin", {}).get("surfaces_total") for b in benches]),
        ("param_intel.params_total", (rs.get("param_intel") or {}).get("params_total"),
         [b["stats"].get("param_intel", {}).get("params_total") for b in benches]),
        ("requests", rs.get("requests"), [b["stats"].get("requests") for b in benches]),
    ]:
        hard.append((label, rv, bvs))
    for label, rv, bvs in hard:
        base = bvs[0]
        same = all(v == base for v in bvs) and rv == base
        print(f"  {label:28s} recovery={rv!r} baseline={base!r} {'OK' if same else 'DIFF'}")
        if not same:
            failures.append(f"benchmark: {label} recovery={rv!r} baseline={base!r}")
    print(f"  => BENCHMARK: {OK if not [f for f in failures if f.startswith('benchmark')] else BAD}")

    # ---------- VERDICT ----------
    print("=" * 64)
    verdict = "PASS" if not failures else "FAIL"
    print(f"RECOVERY TEST: {verdict}")
    if failures:
        print("FAILURES:")
        for f in failures:
            print(" -", f)
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
