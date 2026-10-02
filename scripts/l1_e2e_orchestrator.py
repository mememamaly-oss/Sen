#!/usr/bin/env python3
"""SENTINEL L1 gate — E2E orchestrator: fresh temp DB + production standalone
server on a temp port, then scripts/saas_e2e_test.py (68 checks, full product
flow incl. a live engine scan). Mirrors the L1-R E2E gate.
Usage: python3 scripts/l1_e2e_orchestrator.py [--port 3013] [--keep]
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request


def wait_ready(base: str, timeout: float = 60.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(base + "/api/bootstrap", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(1.0)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3013)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    root = "/home/z/my-project"
    tmp = f"/tmp/e2e-l1-e2e-{a.port}"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(f"{tmp}/data", exist_ok=True)
    base = f"http://localhost:{a.port}"

    r = subprocess.run(["bun", "run", "db:push"], cwd=root,
                       env={**os.environ, "DATABASE_URL": f"file:{tmp}/data/test.db"},
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("db:push FAILED:", r.stderr[-400:])
        return 2
    print(f"[1] temp schema pushed: {tmp}/data/test.db")

    env = {**os.environ,
           "DATABASE_URL": f"file:{tmp}/data/test.db",
           "NEXTAUTH_URL": base,
           "SENTINEL_DATA_DIR": f"{tmp}/data",
           "PORT": str(a.port), "HOSTNAME": "127.0.0.1",
           "NODE_ENV": "production"}
    log = open(f"{tmp}/server.log", "wb")
    srv = subprocess.Popen(["bun", "server.js"], cwd=f"{root}/.next/standalone",
                           env=env, stdout=log, stderr=log, preexec_fn=os.setsid)
    print(f"[2] server pid={srv.pid} on {base}")
    try:
        if not wait_ready(base):
            print("server FAILED to become ready:")
            print(open(f"{tmp}/server.log").read()[-800:])
            return 3
        print("[3] server ready")
        r = subprocess.run(
            [sys.executable, f"{root}/scripts/saas_e2e_test.py", "--base", base],
            cwd=root)
        ok = r.returncode == 0
        print(f"[4] SaaS E2E suite exit={r.returncode} -> {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 4
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
        except Exception:
            pass
        log.close()
        if not a.keep:
            time.sleep(1)
            shutil.rmtree(tmp, ignore_errors=True)
            print(f"[5] temp instance + {tmp} removed")


if __name__ == "__main__":
    sys.exit(main())
