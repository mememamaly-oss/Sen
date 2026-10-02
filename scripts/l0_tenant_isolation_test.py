#!/usr/bin/env python3
"""SENTINEL L0 — Permanent tenant-isolation ATTACK tests for /api/findings/:id.

Regression gate for the L0 security fix (cross-tenant finding access on
src/app/api/findings/[id]/route.ts). Runs the full attack matrix against a
running instance with a FRESH database (use scripts/l0_isolation_orchestrator.py).

Identities are created ONLY through real product flows (no fabricated rows):
  P = bootstrap admin, OWNER of org A only (attacker against org B)
  Q = user added by P to org A (MEMBER), then creates org B (OWNER of B)
  R = user added by Q to org B (MEMBER of org B only — attacker against org A)
  org A scans the managed demo target -> real engine findings (finding A)
  org B scans the managed demo target -> real engine findings (finding B)

Attack matrix (all against GET /api/findings/:id?orgId=):
   1. same tenant            P -> finding A, orgId=A              ALLOW 200
   2. same tenant (victim)   R -> finding B, orgId=B              ALLOW 200
   3. cross-tenant +         P -> finding B, orgId=B              DENY 404  <- most dangerous:
      EXPLICIT VICTIM orgId                                                 attacker supplies the
                                                                            victim's own orgId
   4. cross-tenant, own org  P -> finding B, orgId=A              DENY 404
   5. reverse + victim orgId R -> finding A, orgId=A              DENY 404
   6. reverse, own org       R -> finding A, orgId=B              DENY 404
   7. anonymous              no session -> finding A / B          DENY 401
   8. enumeration            P varies findingId x orgId matrix    404, body == {"error": ...}
                                — no existence / evidence / reproduction / verification /
                                impact / metadata / timestamps / organization leak
   9. control: Q (member of BOTH orgs) reads both findings         ALLOW 200
  10. RBAC: org-A VIEWER can READ finding A (read is VIEWER+)     ALLOW 200
  11. bad input: missing orgId -> 400 ; garbage id -> 404
  12. audit: rbac.org_access_denied recorded in org A (R's attack)
             and in org B (P's attack) — tenant-isolation evidence trail

Usage: python3 scripts/l0_tenant_isolation_test.py [--base http://localhost:3002]
Exit 0 = all pass. Results JSON -> saas-data/l0_isolation_results.json
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

BASE = "http://localhost:3002"
PASS = 0
FAIL = 0
RESULTS: list[dict] = []

# Fields that must NEVER appear in a denied response (leak matrix)
FORBIDDEN_KEYS = [
    "evidence", "verification", "impact", "reproduction", "remediation",
    "fingerprint", "engineId", "createdAt", "finding", "scan", "target",
    "severity", "confidence", "risk", "method", "url", "parameter", "status",
]


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    RESULTS.append({"name": name, "status": status, "detail": detail[:300]})
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


class Client:
    """Minimal HTTP client with cookie jar (NextAuth credentials flow)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def req(self, method: str, path: str, body: dict | None = None, form: dict | None = None,
            expect_json: bool = True) -> tuple[int, Any]:
        url = BASE + path
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
            with self.opener.open(r, timeout=120) as res:
                raw = res.read().decode()
                code = res.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            code = e.code
        if expect_json:
            try:
                return code, json.loads(raw)
            except json.JSONDecodeError:
                return code, raw
        return code, raw

    def get(self, path: str, **kw):
        return self.req("GET", path, **kw)

    def post(self, path: str, body: dict | None = None, form: dict | None = None, **kw):
        return self.req("POST", path, body=body, form=form, **kw)

    def login(self, email: str, password: str) -> bool:
        code, csrf = self.get("/api/auth/csrf")
        if code != 200:
            return False
        code, _ = self.post(
            "/api/auth/callback/credentials",
            form={"csrfToken": csrf["csrfToken"], "email": email,
                  "password": password, "json": "true"},
            expect_json=False,
        )
        return code == 200

    def session_ok(self) -> bool:
        code, me = self.get("/api/me")
        return code == 200 and "user" in me


def wait_scan(client: Client, scan_id: str, org_id: str, timeout_sec: float = 330.0) -> dict | None:
    """Poll a scan to COMPLETED; return the final scan payload or None."""
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        code, d = client.get(f"/api/scans/{scan_id}?orgId={org_id}")
        if code == 200:
            st = d.get("scan", {}).get("status")
            if st == "COMPLETED":
                return d
            if st in ("FAILED", "CANCELLED"):
                print(f"    scan {scan_id} -> {st}: {d['scan'].get('error')}")
                return None
        time.sleep(2.5)
    return None


def denied_clean(resp: Any, raw_hint: str = "") -> tuple[bool, str]:
    """A denied response must be a JSON object with ONLY an 'error' key and
    must not mention any finding field or the victim org id."""
    if not isinstance(resp, dict):
        return False, f"response is not a JSON object: {str(resp)[:120]}"
    keys = sorted(resp.keys())
    if keys != ["error"]:
        return False, f"leaked keys {keys}"
    if raw_hint and raw_hint in json.dumps(resp):
        return False, "victim org id appears in response"
    return True, ""


def main() -> int:
    global BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()
    BASE = args.base.rstrip("/")

    t0 = time.time()
    suffix = str(int(time.time()))[-6:]

    # ── setup ──────────────────────────────────────────────────────────────
    p = Client()  # attacker against org B (OWNER of org A only)
    code, boot = p.get("/api/bootstrap")
    if not check("setup.bootstrap_status", code == 200 and "needsBootstrap" in boot, str(boot)):
        return 2
    if not boot.get("needsBootstrap"):
        print("FATAL: database is not fresh (needsBootstrap=false). "
              "Run via scripts/l0_isolation_orchestrator.py (temp DB) or reset the DB first.")
        return 2

    code, r = p.post("/api/bootstrap", body={
        "email": f"l0-p-{suffix}@sentinel.test", "name": "L0 Attacker A",
        "password": "L0-Pass-AAAA-1", "orgName": f"L0 Org A {suffix}",
    })
    check("setup.bootstrap_admin_P", code == 200, str(r))
    check("setup.login_P", p.login(f"l0-p-{suffix}@sentinel.test", "L0-Pass-AAAA-1") and p.session_ok())

    code, me = p.get("/api/me")
    org_a = me["orgs"][0]["id"]
    check("setup.P_owner_of_orgA_only", len(me["orgs"]) == 1 and me["orgs"][0]["role"] == "OWNER",
          f"orgs={[(o['id'], o['role']) for o in me.get('orgs', [])]}")

    # Q: member of org A (created by P), then creates org B and becomes its OWNER
    q = Client()
    code, r = p.post(f"/api/orgs/{org_a}/members", body={
        "email": f"l0-q-{suffix}@sentinel.test", "name": "L0 Bridge Q",
        "password": "L0-Pass-BBBB-1", "role": "MEMBER",
    })
    check("setup.add_Q_to_orgA", code == 200, str(r))
    check("setup.login_Q", q.login(f"l0-q-{suffix}@sentinel.test", "L0-Pass-BBBB-1") and q.session_ok())
    code, r = q.post("/api/orgs", body={"name": f"L0 Org B {suffix}"})
    check("setup.Q_creates_orgB", code == 200, str(r))
    org_b = r["id"]

    # R: member of org B ONLY (created by Q via org B members API)
    rcl = Client()
    code, r = q.post(f"/api/orgs/{org_b}/members", body={
        "email": f"l0-r-{suffix}@sentinel.test", "name": "L0 Attacker B",
        "password": "L0-Pass-CCCC-1", "role": "MEMBER",
    })
    check("setup.add_R_to_orgB", code == 200, str(r))
    check("setup.login_R", rcl.login(f"l0-r-{suffix}@sentinel.test", "L0-Pass-CCCC-1") and rcl.session_ok())
    code, me_r = rcl.get("/api/me")
    check("setup.R_member_of_orgB_only",
          len(me_r["orgs"]) == 1 and me_r["orgs"][0]["id"] == org_b,
          f"orgs={[o['id'] for o in me_r.get('orgs', [])]}")

    # ── real engine scans: findings for BOTH orgs (no fabricated rows) ─────
    code, r = p.post("/api/targets", body={"orgId": org_a, "isDemo": True})
    check("setup.orgA_demo_target", code == 200, str(r))
    target_a = r.get("id")
    code, r = p.post("/api/scans", body={
        "orgId": org_a, "targetId": target_a,
        "options": {"maxPages": 25, "allowPrivate": True, "noBrowser": False},
    })
    check("setup.orgA_scan_start", code == 200, str(r))
    scan_a = r.get("id")
    final_a = wait_scan(p, scan_a, org_a)
    n_a = final_a["scan"]["findingsCount"] if final_a else -1
    check("setup.orgA_scan_completed_with_findings", n_a > 0, f"findings={n_a}")

    code, r = rcl.post("/api/targets", body={"orgId": org_b, "isDemo": True})
    check("setup.orgB_demo_target", code == 200, str(r))
    target_b = r.get("id")
    code, r = rcl.post("/api/scans", body={
        "orgId": org_b, "targetId": target_b,
        "options": {"maxPages": 25, "allowPrivate": True, "noBrowser": False},
    })
    check("setup.orgB_scan_start", code == 200, str(r))
    scan_b = r.get("id")
    final_b = wait_scan(rcl, scan_b, org_b)
    n_b = final_b["scan"]["findingsCount"] if final_b else -1
    check("setup.orgB_scan_completed_with_findings", n_b > 0, f"findings={n_b}")

    if n_a <= 0 or n_b <= 0:
        print("FATAL: both orgs need real findings for the attack matrix.")
        return 2

    code, findings_a = p.get(f"/api/scans/{scan_a}/findings?orgId={org_a}")
    code_b, findings_b = rcl.get(f"/api/scans/{scan_b}/findings?orgId={org_b}")
    check("setup.orgA_findings_listed", code == 200 and len(findings_a["findings"]) > 0)
    check("setup.orgB_findings_listed", code_b == 200 and len(findings_b["findings"]) > 0)
    fa = [f for f in findings_a["findings"] if f.get("hasProof")] or findings_a["findings"]
    fb = [f for f in findings_b["findings"] if f.get("hasProof")] or findings_b["findings"]
    finding_a = fa[0]["id"]
    finding_b = fb[0]["id"]
    finding_b2 = fb[min(1, len(fb) - 1)]["id"]  # a second real org-B finding

    # ── attacks ────────────────────────────────────────────────────────────
    # 1. same tenant: P -> finding A (orgId = own org) = ALLOW with full payload
    code, d = p.get(f"/api/findings/{finding_a}?orgId={org_a}")
    ok = code == 200 and isinstance(d.get("evidence"), list) and "verification" in d
    check("attack1.same_tenant_orgA_ALLOW", ok, f"code={code}")

    # 2. same tenant (victim org): R -> finding B = ALLOW
    code, d = rcl.get(f"/api/findings/{finding_b}?orgId={org_b}")
    ok = code == 200 and isinstance(d.get("evidence"), list) and "verification" in d
    check("attack2.same_tenant_orgB_ALLOW", ok, f"code={code}")

    # 3. THE KILLER: P (authenticated) + finding of org B + EXPLICIT victim orgId=orgB
    code, d = p.get(f"/api/findings/{finding_b}?orgId={org_b}")
    ok, why = (code == 404, "") if code == 404 else (False, f"code={code} — LEAK!")
    if ok:
        ok, why = denied_clean(d)
    check("attack3.cross_tenant_VICTIM_orgId_DENY_404", ok, why or f"code={code}")

    # 4. cross-tenant with own orgId: P -> finding B + orgId=orgA
    code, d = p.get(f"/api/findings/{finding_b}?orgId={org_a}")
    ok, why = (code == 404, "") if code == 404 else (False, f"code={code}")
    if ok:
        ok, why = denied_clean(d)
    check("attack4.cross_tenant_own_orgId_DENY_404", ok, why or f"code={code}")

    # 5. reverse direction + victim orgId: R -> finding A + orgId=orgA
    code, d = rcl.get(f"/api/findings/{finding_a}?orgId={org_a}")
    ok, why = (code == 404, "") if code == 404 else (False, f"code={code}")
    if ok:
        ok, why = denied_clean(d)
    check("attack5.reverse_VICTIM_orgId_DENY_404", ok, why or f"code={code}")

    # 6. reverse with own orgId: R -> finding A + orgId=orgB
    code, d = rcl.get(f"/api/findings/{finding_a}?orgId={org_b}")
    ok, why = (code == 404, "") if code == 404 else (False, f"code={code}")
    if ok:
        ok, why = denied_clean(d)
    check("attack6.reverse_own_orgId_DENY_404", ok, why or f"code={code}")

    # 7. anonymous (no session at all)
    anon = Client()
    code, d = anon.get(f"/api/findings/{finding_a}?orgId={org_a}")
    check("attack7.anonymous_denied_401", code == 401, f"code={code}")
    code, d = anon.get(f"/api/findings/{finding_b}?orgId={org_b}")
    check("attack7b.anonymous_victim_orgId_denied_401", code == 401, f"code={code}")

    # 8. enumeration matrix: P varies findingId x orgId — every denied response
    #    must be a bare {"error": ...} with no finding field, no org leak.
    fake1 = "cmupj00000fakefindingid0000000"
    fake2 = "does-not-exist-at-all"
    matrix = [
        (finding_b, org_b, "real B finding + victim orgId"),
        (finding_b2, org_b, "real B finding #2 + victim orgId"),
        (finding_b, org_a, "real B finding + own orgId"),
        (finding_b2, org_a, "real B finding #2 + own orgId"),
        (fake1, org_a, "fabricated id + own orgId"),
        (fake2, org_b, "fabricated id + victim orgId"),
        (finding_a, "cmupj0000fakenonexistentorg00000", "real A finding + fabricated orgId"),
    ]
    enum_all_ok = True
    enum_detail = []
    for fid, oid, label in matrix:
        code, d = p.get(f"/api/findings/{fid}?orgId={oid}")
        ok = code == 404
        why = f"code={code}"
        if ok:
            ok, why = denied_clean(d, raw_hint=org_b if oid == org_b else "")
        if not ok:
            enum_all_ok = False
            enum_detail.append(f"{label}: {why}")
    check("attack8.enumeration_matrix_all_404_clean", enum_all_ok,
          "; ".join(enum_detail) if enum_detail else f"{len(matrix)} combos verified")

    # 8b. cross-tenant real finding vs nonexistent finding are indistinguishable
    #     (same status code + same response key set for the attacker P)
    code_x, d_x = p.get(f"/api/findings/{finding_b}?orgId={org_b}")      # real, in org B
    code_n, d_n = p.get(f"/api/findings/{fake1}?orgId={org_b}")          # fake, org B
    shape_x = sorted(d_x.keys()) if isinstance(d_x, dict) else str(d_x)[:80]
    shape_n = sorted(d_n.keys()) if isinstance(d_n, dict) else str(d_n)[:80]
    check("attack8b.cross_tenant_vs_nonexistent_indistinguishable",
          code_x == code_n == 404 and shape_x == shape_n == ["error"],
          f"codes=({code_x},{code_n}) shapes=({shape_x},{shape_n})")

    # 9. control: Q is a legitimate member of BOTH orgs — must read both (200)
    code, d = q.get(f"/api/findings/{finding_a}?orgId={org_a}")
    check("control9.Q_reads_orgA_finding_200", code == 200, f"code={code}")
    code, d = q.get(f"/api/findings/{finding_b}?orgId={org_b}")
    check("control9b.Q_reads_orgB_finding_200", code == 200, f"code={code}")

    # 10. RBAC: VIEWER of org A can READ a finding (read floor is VIEWER+)
    v = Client()
    code, r = p.post(f"/api/orgs/{org_a}/members", body={
        "email": f"l0-v-{suffix}@sentinel.test", "name": "L0 Viewer",
        "password": "L0-Pass-DDDD-1", "role": "VIEWER",
    })
    check("setup.add_VIEWER_to_orgA", code == 200, str(r))
    check("setup.login_V", v.login(f"l0-v-{suffix}@sentinel.test", "L0-Pass-DDDD-1") and v.session_ok())
    code, d = v.get(f"/api/findings/{finding_a}?orgId={org_a}")
    check("attack10.viewer_same_org_read_ALLOW_200", code == 200, f"code={code}")

    # 11. bad input handling
    code, d = p.get(f"/api/findings/{finding_a}")
    check("attack11.missing_orgId_400", code == 400, f"code={code}")
    code, d = p.get(f"/api/findings/{fake2}?orgId={org_a}")
    ok = code == 404 and isinstance(d, dict) and sorted(d.keys()) == ["error"]
    check("attack11b.garbage_id_404_clean", ok, f"code={code}")

    # 12. audit trail: cross-tenant attempts must be recorded for the VICTIM org
    code, logs = p.get(f"/api/audit?orgId={org_a}&limit=200")
    actions_a = [l["action"] for l in logs.get("logs", [])] if code == 200 else []
    ok = code == 200 and any(a == "rbac.org_access_denied" for a in actions_a)
    check("attack12.audit_records_R_attack_on_orgA", ok,
          f"code={code} rbac_denials={actions_a.count('rbac.org_access_denied')}")
    code, logs = rcl.get(f"/api/audit?orgId={org_b}&limit=200")
    actions_b = [l["action"] for l in logs.get("logs", [])] if code == 200 else []
    ok = code == 200 and any(a == "rbac.org_access_denied" for a in actions_b)
    check("attack12b.audit_records_P_attack_on_orgB", ok,
          f"code={code} rbac_denials={actions_b.count('rbac.org_access_denied')}")

    # ── summary ────────────────────────────────────────────────────────────
    dt = time.time() - t0
    print("\n" + "=" * 64)
    print(f"SENTINEL L0 TENANT-ISOLATION ATTACKS: {PASS} passed, {FAIL} failed  (duration {dt:.0f}s)")
    print("=" * 64)
    with open("/home/z/my-project/saas-data/l0_isolation_results.json", "w") as f:
        json.dump({"suite": "l0_tenant_isolation", "base": BASE, "passed": PASS,
                   "failed": FAIL, "duration": dt,
                   "org_a": org_a, "org_b": org_b, "scan_a": scan_a, "scan_b": scan_b,
                   "findings_a": n_a, "findings_b": n_b, "results": RESULTS}, f, indent=1)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
