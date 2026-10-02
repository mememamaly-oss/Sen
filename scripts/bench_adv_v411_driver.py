#!/usr/bin/env python3
"""bench-adv driver (Task 7-d, 2026-10-03): run the FROZEN v4.1.1 engine against
the v4.2.0 EXTENDED adversarial benchmark (fixture v11 + 75-case ground truth).

Why this exists: the stock 73-case bench scored F1=1.000 on BOTH v4.1.1 (broken
oracles) and v4.2.0 (fixed oracles) — it had ZERO discriminating power over the
VF-01..04 fixes. The extended bench adds two adversarial cases in the exact
disagreement zone. Expected:
    v4.2.0  -> 38 TP / 0 FP / 0 FN / 37 TN  (F1 = 1.000)   [verified separately]
    v4.1.1  -> 38 TP / 2 FP / 0 FN / 35 TN  (F1 < 1.000)   [this driver]
The two FPs are the whole point: the old weak oracles (VR-13 r.ok, VR-14 r.ok)
verify endpoints that are NOT vulnerable.

Constraints honored:
  - build-v411 is the FROZEN baseline: this driver only IMPORTS it (sys.path),
    never modifies a byte. The scan config mirrors v411's own run_benchmark().
  - The fixture spawned is build-v420's EXTENDED vulnapp.py (fixture v11),
    on an ephemeral port, fresh process per run (ENG-20 doctrine).
  - Scoring uses build-v420's extended ground_truth.json (75 cases).

Output: build-v420/results/bench_v411_adv_{n}.json — same report shape as the
official bench (run_id, confusion, f1, details, findings) so the two runs are
directly comparable. Prints ONLY a compact summary (no giant stdout).
"""
import json
import os
import socket
import subprocess
import sys
import time

V411_ROOT = "/home/z/my-project/build-v411"          # FROZEN engine (import only)
V420_ROOT = "/home/z/my-project/build-v420"          # live engine + extended fixture
OUT = os.path.join(V420_ROOT, "results")

sys.path.insert(0, V411_ROOT)

from sentinel.orchestrator import SentinelScanner, ScanConfig  # noqa: E402  (v4.1.1 engine)
from sentinel.oast import OastServer                 # noqa: E402
from sentinel.auth import AuthProfile                 # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spawn_fixture(port: int):
    fixture = os.path.join(V420_ROOT, "fixtures", "vulnapp.py")
    proc = subprocess.Popen([sys.executable, fixture],
                            env={**os.environ, "PORT": str(port)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return proc
        except OSError:
            if proc.poll() is not None:
                return None
            time.sleep(0.1)
    proc.terminate()
    return None


def score(findings, gt):
    def detected(g):
        for f in findings:
            if f["type"] != g["type"]:
                continue
            if g["endpoint"] == "*" or f["url"].split("?")[0].endswith(g["endpoint"]):
                if not g["parameter"] or f["parameter"] == g["parameter"]:
                    return True
        return False

    tp = fn = tn = fp = 0
    details = []
    for g in gt["ground_truth"]:
        d, e = detected(g), g["present"]
        cell = ("TP" if d and e else "FP" if d and not e
                else "FN" if e and not d else "TN")
        tp += cell == "TP"; fp += cell == "FP"
        fn += cell == "FN"; tn += cell == "TN"
        details.append({"case": f"{g['type']}@{g['endpoint']}:{g['parameter']}",
                        "cell": cell})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}, details, precision, recall, f1


def main():
    run_n = sys.argv[1] if len(sys.argv) > 1 else "1"
    port = free_port()
    proc = spawn_fixture(port)
    if proc is None:
        print("FATAL: could not spawn extended fixture")
        sys.exit(2)
    base_url = f"http://127.0.0.1:{port}"
    gt = json.load(open(os.path.join(V420_ROOT, "benchmarks", "ground_truth.json")))
    print(f"[driver] engine=build-v411 (frozen) fixture=build-v420/v11 port={port} "
          f"gt_cases={len(gt['ground_truth'])} run={run_n}")
    try:
        oast = OastServer()
        try:
            auth = AuthProfile(login_url=base_url.rstrip("/") + "/login",
                               username="demo", password="demo123",
                               user_field="uid", pass_field="passw",
                               success_marker="Sign Off")
            authz_cfg = json.load(open(os.path.join(V411_ROOT,
                                                    "benchmarks", "authz_accounts.json")))
            cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                             seed="benchmark-fixed-seed",
                             oast=oast, auth=auth, authz=authz_cfg,
                             workflow=True, logic_active=True)
            sc = SentinelScanner(base_url, cfg)
            result = sc.run()
        finally:
            oast.stop()
        findings = result["findings"]
        confusion, details, precision, recall, f1 = score(findings, gt)
        report = {
            "benchmark": gt["benchmark"], "label": f"bench-adv-frozen-v411-run{run_n}",
            "scanner": result["scanner"], "run_id": result["run_id"],
            "seed": result["seed"], "confusion": confusion,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "details": details, "findings": findings,
            "ground_truth_sha256": __import__("hashlib").sha256(
                json.dumps(gt, sort_keys=True).encode()).hexdigest()[:16],
        }
        out = os.path.join(OUT, f"bench_v411_adv_{run_n}.json")
        json.dump(report, open(out, "w"), indent=1)
        print(f"[driver] engine={result['scanner']} run_id={result['run_id']}")
        print(f"[driver] confusion={confusion}  precision={precision:.4f} "
              f"recall={recall:.4f}  F1={f1:.4f}")
        adv = [c for c in details
               if "subscribe-echo" in c["case"] or "nosql-lockout" in c["case"]]
        print(f"[driver] adversarial cases: {adv}")
        fps = [c["case"] for c in details if c["cell"] == "FP"]
        print(f"[driver] FP list: {fps if fps else 'NONE'}")
        print(f"[driver] report -> {out}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=5)


if __name__ == "__main__":
    main()
