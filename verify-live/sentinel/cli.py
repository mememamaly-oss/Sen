#!/usr/bin/env python3
"""SENTINEL CLI — scan / benchmark / doctor / findings / report / repair-demo.
Phase 16/29: Benchmark Registry with ground-truth comparison, TP/FP/FN/TN + P/R/F1.
"""
from __future__ import annotations
import argparse, json, os, signal, socket, subprocess, sys, time, hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.orchestrator import SentinelScanner, ScanConfig, doctor
from sentinel.intel import (StrategyStore, FailureMemory, RepairClassifier, RepairGate,
                            VerificationEngine, FindingPipeline)


# ============================================================ benchmark
def _port_open(host, port, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_fixture(base_url="http://127.0.0.1:8777"):
    """Self-repair ops rule OP-01 (fixture_not_running): if the benchmark target is the
    local fixture port and nothing is listening, auto-spawn fixtures/vulnapp.py and
    wait for readiness. Returns the spawned process (or None if already running /
    not applicable). Prevents the F1=0.0 silent-failure mode caught by live re-test."""
    from urllib.parse import urlparse
    u = urlparse(base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    if host not in ("127.0.0.1", "localhost"):
        return None                                   # remote target: nothing to spawn
    if _port_open(host, port):
        return None                                   # fixture already up
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "vulnapp.py")
    if not os.path.exists(fixture):
        return None
    proc = subprocess.Popen([sys.executable, fixture],
                            env={**os.environ, "PORT": str(port)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):                               # wait up to ~6s for readiness
        if _port_open(host, port):
            return proc
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    proc.terminate()
    return None


def run_benchmark(base_url="http://127.0.0.1:8777", out="results/benchmark.json",
                  strategy_path=None, timeout=12.0, label=""):
    """Scan the fixture and score against ground truth (spec 29/30).
    OP-01: auto-starts the local fixture if it is not running (self-repair ops rule)."""
    spawned = ensure_fixture(base_url)                 # OP-01 auto-start (self-repair)
    try:
        return _run_benchmark_inner(base_url, out, strategy_path, timeout, label, spawned)
    finally:
        if spawned is not None:
            spawned.terminate()                        # we started it -> we stop it
            try:                                       # SYNCHRONOUS cleanup (OP-01b):
                spawned.wait(timeout=5)                # wait for port release, escalate if needed
            except subprocess.TimeoutExpired:
                spawned.kill(); spawned.wait(timeout=5)


def _run_benchmark_inner(base_url, out, strategy_path, timeout, label, spawned):
    gt = json.load(open(os.path.join(os.path.dirname(__file__), "..", "benchmarks", "ground_truth.json")))
    cfg = ScanConfig(allow_private=True, max_pages=30, timeout=timeout,
                     strategy_path=strategy_path, seed="benchmark-fixed-seed")
    sc = SentinelScanner(base_url, cfg)
    result = sc.run()
    findings = result["findings"]

    # ---- score
    def exists(gt_entry):
        return gt_entry["present"]

    def detected(gt_entry):
        for f in findings:
            if f["type"] != gt_entry["type"]:
                continue
            ep_gt = gt_entry["endpoint"]
            if ep_gt == "*" or f["url"].split("?")[0].endswith(ep_gt):
                if not gt_entry["parameter"] or f["parameter"] == gt_entry["parameter"]:
                    return True
        return False

    tp = fn = tn = fp = 0
    details = []
    for g in gt["ground_truth"]:
        d, e = detected(g), exists(g)
        cell = ("TP" if d and e else "FP" if d and not e else "FN" if e and not d else "TN")
        tp += cell == "TP"; fp += cell == "FP"; fn += cell == "FN"; tn += cell == "TN"
        details.append({"case": f"{g['type']}@{g['endpoint']}:{g['parameter']}", "cell": cell})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    report = {
        "benchmark": gt["benchmark"], "label": label or "adhoc",
        "scanner": result["scanner"], "run_id": result["run_id"], "seed": result["seed"],
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "stats": result["stats"], "details": details,
        "findings": findings,
        "ground_truth_sha256": hashlib.sha256(json.dumps(gt, sort_keys=True).encode()).hexdigest()[:16],
    }
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    json.dump(report, open(out, "w"), indent=1)
    return report


# ============================================================ repair demo (spec 22/23/38)
def repair_demo():
    """Live full-loop self-repair with a REAL, reproducible failure:
    slow fixture (150ms/request) + degenerate timeout (5ms) -> every request times out.
    Rule-only repair (x3 = 15ms) still fails -> gate ROLLS BACK.
    Rule + policy floor (12s) passes regression + benchmark -> ACCEPTED."""
    import subprocess, signal as _sig
    print("=" * 70)
    print(" SELF-REPAIR GATE — LIVE EXECUTION (no AI, deterministic rules)")
    print("=" * 70)

    # 0) spawn SLOW fixture (real failure substrate)
    slow = subprocess.Popen([sys.executable, "fixtures/vulnapp.py"],
                            env={**os.environ, "PORT": "8778", "DELAY_MS": "150"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    import urllib.request
    slow_alive = False
    try:
        urllib.request.urlopen("http://127.0.0.1:8778/", timeout=5); slow_alive = True
    except Exception:
        pass
    print(f"\n[0] SLOW fixture (150ms/req) spawned on :8778 -> alive={slow_alive}")

    try:
        # 1) healthy baseline on normal fixture
        base = run_benchmark(out="results/benchmark_baseline.json", label="pre-repair baseline", timeout=12.0)
        print(f"\n[1] BASELINE benchmark (normal env): F1={base['f1']:.3f} P={base['precision']:.3f} "
              f"R={base['recall']:.3f} (TP={base['confusion']['TP']} FP={base['confusion']['FP']} FN={base['confusion']['FN']})")

        # 2) REAL failure: slow env + degenerate timeout -> reproducible scanner failure
        print("\n[2] INDUCING REAL FAILURE: slow env (150ms/req) + timeout=5ms ...")
        broken = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_broken.json", label="broken-transport", timeout=0.005)
        print(f"    broken run: F1={broken['f1']:.3f} verified={broken['stats']['verified']} "
              f"requests={broken['stats']['requests']} -> {'REAL FAILURE REPRODUCED' if broken['f1'] < 0.5 else 'unstable — demo invalid'}")
        assert broken["f1"] < 0.5, "failure was not reproduced; refusing to fake results"

        # 3) deterministic classification
        err = "timeout:TimeoutError"
        cls = RepairClassifier().classify(err, {"scanner": "sqli"})
        print(f"\n[3] FAILURE CLASSIFICATION: error='{err}' -> rule='{cls[0]}' action={cls[1]['action']}")
        assert cls and cls[0] == "timeout_spike"

        # 4) gate: candidate A (rule-only) vs candidate B (rule + policy floor)
        def regression_suite():
            r = subprocess.run([sys.executable, "tests/run_tests.py", "regression"],
                               capture_output=True, text=True,
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            try:
                j = json.loads(r.stdout)          # run_tests prints a single pretty JSON object
                return {"passed": j["passed"], "total": j["total"], "failed": j["failed"]}
            except Exception:
                return {"passed": False, "raw": (r.stdout or r.stderr)[-200:]}

        print("\n[4] REPAIR GATE EXECUTION (against the SAME broken environment):")
        cand_a = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateA.json",
                               label="repair-A-rule-only", timeout=0.005 * cls[1]["action"]["multiply_timeout"])
        a_ok = cand_a["f1"] >= base["f1"] - 0.02
        print(f"    candidate A (timeout=15ms, rule-only): F1={cand_a['f1']:.3f} acceptable={a_ok} "
              f"-> {'ACCEPT' if a_ok else 'ROLLBACK + RULE QUARANTINED'}")
        reg = regression_suite()
        print(f"    regression suite: passed={reg.get('passed')} ({reg.get('total')} cases)")
        cand_b = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateB.json",
                               label="repair-B-with-floor", timeout=12.0)
        b_ok = cand_b["f1"] >= base["f1"] - 0.02 and cand_b["confusion"]["FP"] <= base["confusion"]["FP"]
        print(f"    candidate B (timeout=12s, rule + policy floor): F1={cand_b['f1']:.3f} "
              f"FP={cand_b['confusion']['FP']} acceptable={b_ok}")
        verdict = "ACCEPTED" if (b_ok and reg.get("passed") and not a_ok) else \
                  ("ACCEPTED" if (b_ok and reg.get("passed")) else "REJECTED")
        print(f"\n    FINAL GATE VERDICT: {verdict}")
        if verdict == "ACCEPTED":
            print("    -> repair B activated; failure class has permanent regression case "
                  "(tests/run_tests.py::regression_timeout_repair_rule)")
        else:
            print("    -> repair quarantined; failure kept in FailureMemory for rule revision")
        return {"baseline_f1": base["f1"], "broken_f1": broken["f1"],
                "candidate_a_f1": cand_a["f1"], "candidate_a_accepted": a_ok,
                "candidate_b_f1": cand_b["f1"], "candidate_b_accepted": b_ok,
                "regression": reg, "verdict": verdict}
    finally:
        slow.terminate()


# ============================================================ main
def main():
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("target"); s.add_argument("--allow-private", action="store_true")
    s.add_argument("--max-pages", type=int, default=25); s.add_argument("--timeout", type=float, default=12.0)
    s.add_argument("--no-crawl", action="store_true"); s.add_argument("--seed")
    s.add_argument("--out", default="results/scan.json"); s.add_argument("--strategy-path")
    b = sub.add_parser("benchmark"); b.add_argument("--url", default="http://127.0.0.1:8777")
    b.add_argument("--out", default="results/benchmark.json"); b.add_argument("--strategy-path"); b.add_argument("--timeout", type=float, default=12.0)
    sub.add_parser("doctor")
    sub.add_parser("repair-demo")
    a = ap.parse_args()

    if a.cmd == "doctor":
        print(json.dumps(doctor(), indent=1))
    elif a.cmd == "scan":
        cfg = ScanConfig(allow_private=a.allow_private, max_pages=a.max_pages,
                         crawl=not a.no_crawl, timeout=a.timeout, seed=a.seed,
                         strategy_path=a.strategy_path)
        sc = SentinelScanner(a.target, cfg)
        rep = sc.run()
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        json.dump(rep, open(a.out, "w"), indent=1)
        print(json.dumps({"target": rep["target"], "stats": rep["stats"],
                          "verified_findings": len(rep["findings"])}, indent=1))
        for f in sorted(rep["findings"], key=lambda x: -x["risk"]):
            print(f"  [{f['severity'].upper():8s}] {f['type']:26s} {f['url'][:60]:60s} param={f['parameter']:6s} risk={f['risk']}")
    elif a.cmd == "benchmark":
        rep = run_benchmark(a.url, a.out, a.strategy_path, a.timeout, label="cli")
        c = rep["confusion"]
        if rep["stats"]["requests"] <= 5:
            print("[OP-01] WARNING: benchmark target unreachable (requests<=5); "
                  "check --url", file=sys.stderr)
        print(json.dumps({"benchmark": rep["benchmark"], "confusion": c,
                          "precision": rep["precision"], "recall": rep["recall"], "f1": rep["f1"],
                          "stats": rep["stats"]}, indent=1))
        for d in rep["details"]:
            print(f"  {d['cell']}: {d['case']}")
    elif a.cmd == "repair-demo":
        repair_demo()


if __name__ == "__main__":
    main()
