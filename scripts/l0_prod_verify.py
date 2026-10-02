#!/usr/bin/env python3
"""L0: production API verification — cross-tenant attack against the LIVE
production server on the MAIN database (run after scripts/bootstrap_demo_data.py).

The mandatory test from the L0 order (section 8), executed against real
production, API-direct (not via UI):

    Org A session -> request Finding belonging to Org B -> DENY/404, no sensitive data
    Org A session -> request Finding belonging to Org A -> ALLOW

Plus the reverse direction, anonymous, enumeration spot-checks, the audit
evidence trail, and a page-health sweep of every product route.

Victim org setup (all through real product flows, idempotent on re-runs):
  admin (OWNER of Org A "Sentinel SOC")
    -> adds Q to Org A (MEMBER)
    -> Q creates Org B (OWNER)          [admin is NOT a member of Org B]
    -> Q adds R to Org B (MEMBER only)
    -> R scans the managed demo target in Org B -> real engine findings

Usage: python3 scripts/l0_prod_verify.py [--base http://localhost:3000]
Exit 0 = PASS. Evidence -> saas-data/l0_prod_verify.json
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from typing import Any

PASS = 0
FAIL = 0
RESULTS: list[dict] = []
EVIDENCE: dict[str, Any] = {"responses": {}}

ADMIN_EMAIL = "admin@sentinel.local"
ADMIN_PASS = "Sentinel-P0!Admin"
Q_EMAIL = "l0-prod-q@sentinel.local"
Q_PASS = "L0-Prod-Q-Pass-1"
R_EMAIL = "l0-prod-r@sentinel.local"
R_PASS = "L0-Prod-R-Pass-1"
VICTIM_ORG = "L0 Prod Victim Org"


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    RESULTS.append({"name": name, "status": status, "detail": detail[:300]})
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


class Client:
    def __init__(self, base: str):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, body=None, form=None, raw=False, timeout=60):
        url = self.base + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(r, timeout=timeout) as res:
                text = res.read().decode()
                code = res.status
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            code = e.code
        if raw:
            return code, text
        try:
            return code, json.loads(text)
        except json.JSONDecodeError:
            return code, text

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, body=None, form=None, **kw):
        return self.req("POST", path, body=body, form=form, **kw)

    def login(self, email, password) -> bool:
        code, csrf = self.get("/api/auth/csrf")
        if code != 200:
            return False
        code, _ = self.post("/api/auth/callback/credentials", form={
            "csrfToken": csrf["csrfToken"], "email": email,
            "password": password, "json": "true"}, raw=True)
        return code == 200


def wait_scan(c: Client, scan_id: str, org_id: str, timeout_sec: float = 420.0):
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        code, d = c.get(f"/api/scans/{scan_id}?orgId={org_id}")
        if code == 200:
            st = d.get("scan", {}).get("status")
            if st == "COMPLETED":
                return d
            if st in ("FAILED", "CANCELLED"):
                return None
        time.sleep(3.0)
    return None


def completed_scan_with_findings(c: Client, org_id: str):
    """Return (scan_id, findingsCount) of a COMPLETED scan with findings, or None."""
    code, d = c.get(f"/api/scans?orgId={org_id}&limit=50")
    if code != 200:
        return None
    for s in d.get("scans", []):
        if s.get("status") == "COMPLETED" and s.get("findingsCount", 0) > 0:
            return s["id"], s["findingsCount"]
    return None


def get_a_finding(c: Client, scan_id: str, org_id: str):
    code, d = c.get(f"/api/scans/{scan_id}/findings?orgId={org_id}&limit=500")
    if code != 200 or not d.get("findings"):
        return None
    fs = [f for f in d["findings"] if f.get("hasProof")] or d["findings"]
    return fs[0]["id"]


def denied_clean(resp) -> tuple[bool, str]:
    if not isinstance(resp, dict):
        return False, f"non-JSON body: {str(resp)[:120]}"
    keys = sorted(resp.keys())
    if keys != ["error"]:
        return False, f"leaked keys: {keys}"
    return True, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:3000")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    t0 = time.time()

    # ── Org A: the bootstrapped production admin ───────────────────────────
    a = Client(base)
    if not check("prodA.admin_login", a.login(ADMIN_EMAIL, ADMIN_PASS)):
        return 2
    code, me = a.get("/api/me")
    org_a = me["orgs"][0]["id"]
    EVIDENCE["org_a"] = org_a
    check("prodA.admin_org_found", code == 200 and bool(org_a), f"orgs={[o['id'] for o in me.get('orgs', [])]}")

    # ensure org A has a completed scan with findings
    got = completed_scan_with_findings(a, org_a)
    if got is None:
        code, r = a.post("/api/targets", body={"orgId": org_a, "isDemo": True})
        tid = r.get("id") if code == 200 else None
        # target may already exist (409-ish) — find it
        if code != 200:
            code, ts = a.get(f"/api/targets?orgId={org_a}")
            demo = [t for t in ts.get("targets", []) if t.get("isDemo")]
            tid = demo[0]["id"] if demo else None
        code, r = a.post("/api/scans", body={"orgId": org_a, "targetId": tid})
        check("prodA.scan_started", code == 200, str(r))
        final = wait_scan(a, r["id"], org_a)
        check("prodA.scan_completed", final is not None and final["scan"]["findingsCount"] > 0)
        got = completed_scan_with_findings(a, org_a)
    scan_a, n_a = got if got else (None, 0)
    finding_a = get_a_finding(a, scan_a, org_a) if scan_a else None
    check("prodA.finding_available", bool(finding_a), f"scan={scan_a} n={n_a}")
    EVIDENCE["finding_a"] = finding_a
    if not finding_a:
        return 2

    # ── Org B: the victim org (admin is NOT a member) ──────────────────────
    q = Client(base)
    if not q.login(Q_EMAIL, Q_PASS):
        code, r = a.post(f"/api/orgs/{org_a}/members", body={
            "email": Q_EMAIL, "name": "L0 Prod Bridge", "password": Q_PASS, "role": "MEMBER"})
        check("prodB.add_Q", code == 200, str(r))
        check("prodB.login_Q", q.login(Q_EMAIL, Q_PASS))
    else:
        check("prodB.login_Q_existing", True)
    # find or create the victim org
    code, me_q = q.get("/api/me")
    org_b = None
    for o in me_q.get("orgs", []):
        code, od = q.get(f"/api/orgs/{o['id']}")
        if code == 200 and od.get("org", {}).get("name") == VICTIM_ORG:
            org_b = o["id"]
            break
    if not org_b:
        code, r = q.post("/api/orgs", body={"name": VICTIM_ORG})
        check("prodB.Q_creates_victim_org", code == 200, str(r))
        org_b = r["id"]
    else:
        check("prodB.victim_org_reused", True)
    EVIDENCE["org_b"] = org_b

    # R: member of org B only
    rcl = Client(base)
    if not rcl.login(R_EMAIL, R_PASS):
        code, r = q.post(f"/api/orgs/{org_b}/members", body={
            "email": R_EMAIL, "name": "L0 Prod Victim User", "password": R_PASS, "role": "MEMBER"})
        check("prodB.add_R", code == 200, str(r))
        check("prodB.login_R", rcl.login(R_EMAIL, R_PASS))
    else:
        check("prodB.login_R_existing", True)
    code, me_r = rcl.get("/api/me")
    check("prodB.R_member_of_orgB_only",
          [o["id"] for o in me_r.get("orgs", [])] == [org_b],
          f"orgs={[o['id'] for o in me_r.get('orgs', [])]}")

    # admin (Org A) must NOT be a member of Org B
    code, me_a = a.get("/api/me")
    admin_orgs = [o["id"] for o in me_a.get("orgs", [])]
    check("prodB.admin_NOT_member_of_orgB", org_b not in admin_orgs, f"admin_orgs={admin_orgs}")

    # ensure org B has a completed scan with findings
    got = completed_scan_with_findings(rcl, org_b)
    if got is None:
        code, r = rcl.post("/api/targets", body={"orgId": org_b, "isDemo": True})
        tid = r.get("id") if code == 200 else None
        if code != 200:
            code, ts = rcl.get(f"/api/targets?orgId={org_b}")
            demo = [t for t in ts.get("targets", []) if t.get("isDemo")]
            tid = demo[0]["id"] if demo else None
        code, r = rcl.post("/api/scans", body={"orgId": org_b, "targetId": tid})
        check("prodB.scan_started", code == 200, str(r))
        final = wait_scan(rcl, r["id"], org_b)
        check("prodB.scan_completed", final is not None and final["scan"]["findingsCount"] > 0)
        got = completed_scan_with_findings(rcl, org_b)
    scan_b, n_b = got if got else (None, 0)
    finding_b = get_a_finding(rcl, scan_b, org_b) if scan_b else None
    check("prodB.finding_available", bool(finding_b), f"scan={scan_b} n={n_b}")
    EVIDENCE["finding_b"] = finding_b
    if not finding_b:
        return 2

    # ── THE MANDATORY PRODUCTION TEST (L0 order §8) ────────────────────────
    # Org A session -> Finding of Org B -> DENY 404, NO sensitive response data
    code, d = a.get(f"/api/findings/{finding_b}?orgId={org_b}")
    EVIDENCE["responses"]["orgA_to_orgB_finding"] = {"status": code, "body": d}
    ok = code == 404
    why = f"code={code}"
    if ok:
        ok, why = denied_clean(d)
    check("MANDATORY.orgA_session_orgB_finding_DENY_404_no_sensitive_data", ok, why)

    # Org A session -> Finding of Org A -> ALLOW
    code, d = a.get(f"/api/findings/{finding_a}?orgId={org_a}")
    EVIDENCE["responses"]["orgA_to_orgA_finding"] = {"status": code,
                                                     "keys": sorted(d.keys()) if isinstance(d, dict) else str(d)[:100]}
    ok = code == 200 and isinstance(d, dict) and "evidence" in d and "verification" in d
    check("MANDATORY.orgA_session_orgA_finding_ALLOW_200", ok, f"code={code}")

    # reverse direction: R (Org B) -> finding of Org A with victim orgId
    code, d = rcl.get(f"/api/findings/{finding_a}?orgId={org_a}")
    EVIDENCE["responses"]["orgB_to_orgA_finding"] = {"status": code, "body": d}
    ok = code == 404
    why = f"code={code}"
    if ok:
        ok, why = denied_clean(d)
    check("prod.reverse_orgB_to_orgA_DENY_404", ok, why)

    # anonymous
    anon = Client(base)
    code, d = anon.get(f"/api/findings/{finding_a}?orgId={org_a}")
    EVIDENCE["responses"]["anonymous"] = {"status": code, "body": d}
    check("prod.anonymous_DENY_401", code == 401, f"code={code}")

    # enumeration spot-check on production
    for label, fid, oid in [
        ("victim_orgId", finding_b, org_b),
        ("own_orgId", finding_b, org_a),
        ("fabricated_id_victim_org", "cmupj0000fabricated0000000000", org_b),
    ]:
        code, d = a.get(f"/api/findings/{fid}?orgId={oid}")
        EVIDENCE["responses"][f"enum_{label}"] = {"status": code, "body": d}
        ok = code == 404
        why = f"code={code}"
        if ok:
            ok, why = denied_clean(d)
        check(f"prod.enumeration_{label}_404_clean", ok, why)

    # audit evidence in the victim org
    code, logs = rcl.get(f"/api/audit?orgId={org_b}&limit=200")
    acts = [l["action"] for l in logs.get("logs", [])] if code == 200 else []
    check("prod.audit_records_cross_tenant_attempt",
          code == 200 and "rbac.org_access_denied" in acts,
          f"code={code} denied_count={acts.count('rbac.org_access_denied')}")

    # ── product page health (session) — no regression of existing product ──
    for page in ["/overview", "/targets", "/scans", "/findings", "/reports",
                 "/twin", "/audit", "/organization"]:
        code, html = a.get(page, raw=True)
        ok = code == 200 and "<html" in html[:2000].lower()
        EVIDENCE["responses"][f"page{page}"] = {"status": code}
        check(f"prod.page{page.replace('/', '_')}", ok, f"code={code}")
    # finding detail page (own org, real finding)
    code, html = a.get(f"/findings/{finding_a}", raw=True)
    check("prod.page_finding_detail", code == 200 and "<html" in html[:2000].lower(), f"code={code}")

    # ── summary + evidence ──────────────────────────────────────────────────
    dt = time.time() - t0
    print("\n" + "=" * 64)
    print(f"L0 PRODUCTION VERIFICATION: {PASS} passed, {FAIL} failed  (duration {dt:.0f}s)")
    print("=" * 64)
    with open("/home/z/my-project/saas-data/l0_prod_verify.json", "w") as f:
        json.dump({"base": base, "passed": PASS, "failed": FAIL, "duration": dt,
                   "evidence": EVIDENCE, "results": RESULTS}, f, indent=1)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
