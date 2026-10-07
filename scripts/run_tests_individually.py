#!/usr/bin/env python3
"""Run suite tests individually with per-test timeouts to find hangs."""
import subprocess, sys, os, json, time

tests = sys.argv[1:]
root = "/home/z/my-project/build-v430"
env = dict(os.environ)
results = []
for t in tests:
    t0 = time.time()
    env2 = dict(env)
    env2["SENTINEL_TEST_FILTER"] = t
    try:
        r = subprocess.run([sys.executable, "tests/run_tests.py", t],
                           cwd=root, capture_output=True, text=True, timeout=90, env=env2)
        dt = time.time() - t0
        try:
            d = json.loads(r.stdout)
            ran = [c for c in d["cases"] if not c.get("skipped")]
            ok = all(c["ok"] for c in ran) if ran else None
            err = next((c.get("error", "")[:110] for c in ran if not c["ok"]), "")
        except Exception:
            ok, err = "CRASH", (r.stdout[-120:] + r.stderr[-120:]).replace("\n", " ")
        print(f"{dt:6.1f}s {str(ok):<6} {t}  {err}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"   HANG(>90s) {t}", flush=True)
