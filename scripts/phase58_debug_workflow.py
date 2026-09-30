#!/usr/bin/env python3
"""Phase 58 debug: run ONLY the workflow phase against a live fixture with a
full traceback, to pinpoint the 'unhashable type: Endpoint' failure."""
import json, os, subprocess, sys, time, traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "verify-live"))
os.chdir(os.path.join(ROOT, "verify-live"))

import http.client
FIXT = os.path.join(ROOT, "verify-live", "fixtures", "vulnapp.py")
PORT = 8793


def spawn():
    p = subprocess.Popen([sys.executable, FIXT],
                         env={**os.environ, "PORT": str(PORT)},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            http.client.HTTPConnection("127.0.0.1", PORT, timeout=1).request("GET", "/")
            return p
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("fixture did not start")


def main():
    proc = spawn()
    try:
        from sentinel.core import ScopeRule, EventBus
        from sentinel.auth import AuthProfile, AuthEngine
        from sentinel.http_engine import RequestEngine
        from sentinel.discovery import DiscoveryEngine
        from sentinel.workflow import WorkflowEngine

        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        bus = EventBus("dbg-wf")
        eng = RequestEngine(scope, bus, timeout=8)
        profile = AuthProfile(login_url=f"http://127.0.0.1:{PORT}/login",
                              username="demo", password="demo123",
                              user_field="uid", pass_field="passw",
                              success_marker="Sign Off")
        assert AuthEngine(profile, eng, bus).login(), "login failed"
        d = DiscoveryEngine(eng, 30)
        found, _, _ = d.crawl(f"http://127.0.0.1:{PORT}/",
                              extra_seeds=[f"http://127.0.0.1:{PORT}/home"])
        eps = list(found)
        print(f"endpoints: {len(eps)}")
        we = WorkflowEngine()
        res = we.run(eps, eng, scope, bus, profile, authz_sessions={}, timeout=8,
                     logic_active=True)
        print(json.dumps(res["stats"], indent=1, default=str)[:2500])
        for f in res["findings"]:
            print("FINDING:", f.type, f.endpoint_url, f.parameter, f.status)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        proc.terminate(); proc.wait(timeout=5)


if __name__ == "__main__":
    main()
