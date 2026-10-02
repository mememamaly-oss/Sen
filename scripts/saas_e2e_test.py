#!/usr/bin/env python3
"""SENTINEL SaaS P0 — End-to-End functional + tenant-isolation + RBAC test.

Exercises the full platform flow over HTTP against the running dev server:
  bootstrap → login → orgs → members (RBAC) → targets → scan (live) →
  findings (evidence/repro/impact/remediation) → coverage/boundary → reports
  + negative tests (VIEWER/MEMBER restrictions, cross-org isolation).

Usage: python3 scripts/saas_e2e_test.py [--base http://localhost:3000]
"""
import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.parse
import http.cookiejar
from typing import Any

BASE = "http://localhost:3000"

PASS = 0
FAIL = 0
RESULTS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    RESULTS.append({"name": name, "status": status, "detail": detail[:300]})
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


class Client:
    """Minimal HTTP client with cookie jar (NextAuth flow support)."""

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

    def delete(self, path: str, **kw):
        return self.req("DELETE", path, **kw)

    def patch(self, path: str, body: dict | None = None, **kw):
        return self.req("PATCH", path, body=body, **kw)

    # NextAuth credentials login
    def login(self, email: str, password: str) -> bool:
        code, csrf = self.get("/api/auth/csrf")
        if code != 200:
            return False
        code, _ = self.post(
            "/api/auth/callback/credentials",
            form={
                "csrfToken": csrf["csrfToken"],
                "email": email,
                "password": password,
                "json": "true",
            },
            expect_json=False,
        )
        return code == 200

    def session_ok(self) -> bool:
        code, me = self.get("/api/me")
        return code == 200 and "user" in me


def main() -> int:
    global BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()
    BASE = args.base.rstrip("/")

    t0 = time.time()
    admin = Client()

    # ── 0. reset check: bootstrap status ────────────────────────────────────
    code, boot = admin.get("/api/bootstrap")
    check("bootstrap.status", code == 200 and "needsBootstrap" in boot)

    suffix = str(int(time.time()))[-6:]
    admin_email = f"e2e-admin-{suffix}@sentinel.test"
    org2_email = f"e2e-org2-{suffix}@sentinel.test"

    if boot.get("needsBootstrap"):
        code, r = admin.post("/api/bootstrap", body={
            "email": admin_email, "name": "E2E Admin",
            "password": "E2E-Admin-Pass-1", "orgName": "E2E Security Org",
        })
        check("bootstrap.create_admin", code == 200, str(r))
    else:
        # platform already bootstrapped (browser tests ran before) — login with
        # the known e2e account created earlier, or create org with existing flow
        admin_email = "e2e-admin@sentinel.test"
        # try login; if unknown, create dedicated users via members API is impossible
        # without an admin, so we reuse the existing first admin session.
        ok = admin.login(admin_email, "E2E-Admin-Pass-1")
        if not ok:
            print("NOTE: platform already bootstrapped with a different admin.")
            print("      Re-run against a fresh DB, or delete db/custom.db first.")
            return 2

    ok = admin.login(admin_email, "E2E-Admin-Pass-1")
    check("admin.login", ok and admin.session_ok())

    # ── 1. me + orgs ────────────────────────────────────────────────────────
    code, me = admin.get("/api/me")
    check("me.returns_user_and_orgs", code == 200 and len(me.get("orgs", [])) >= 1)
    org1 = me["orgs"][0]
    org1_id = org1["id"]
    check("me.owner_role", org1["role"] == "OWNER", f"role={org1['role']}")

    # create a second org for isolation tests
    code, r = admin.post("/api/orgs", body={"name": f"E2E Second Org {suffix}"})
    check("org.create_second", code == 200, str(r))
    org2_id = r["id"] if code == 200 else None

    # ── 2. members + RBAC setup ─────────────────────────────────────────────
    roles_users = [
        ("e2e-viewer@sentinel.test", "E2E Viewer", "VIEWER"),
        ("e2e-member@sentinel.test", "E2E Member", "MEMBER"),
        ("e2e-admin@sentinel.test", "E2E Admin2", "ADMIN"),
    ]
    member_ids = {}
    for email, name, role in roles_users:
        code, r = admin.post(f"/api/orgs/{org1_id}/members", body={
            "email": email, "name": name, "password": "E2E-Member-Pass-1", "role": role,
        })
        check(f"member.add_{role.lower()}", code == 200, str(r))
        if code == 200:
            member_ids[role] = r.get("userId")

    code, members = admin.get(f"/api/orgs/{org1_id}/members")
    check("member.list", code == 200 and len(members.get("members", [])) == 4)

    # separate user owning ONLY org2 (isolation proof)
    org2_client = Client()
    code, r = admin.post(f"/api/orgs/{org2_id}/members", body={
        "email": org2_email, "name": "Org2 Owner", "password": "E2E-Org2-Pass-1", "role": "OWNER",
    })
    # only OWNER may grant OWNER — admin is OWNER of org2 (creator) so this works
    check("member.add_org2_owner", code == 200, str(r))
    ok = org2_client.login(org2_email, "E2E-Org2-Pass-1")
    code, me2 = org2_client.get("/api/me")
    check("org2_owner.login_and_isolated", ok and code == 200 and
          [o["id"] for o in me2["orgs"]] == [org2_id],
          f"orgs={[o['id'] for o in me2.get('orgs', [])]}")

    # ── 3. targets ──────────────────────────────────────────────────────────
    code, r = admin.post("/api/targets", body={"orgId": org1_id, "isDemo": True})
    check("target.add_demo", code == 200, str(r))
    demo_target_id = r.get("id") if code == 200 else None

    code, r = admin.post("/api/targets", body={
        "orgId": org1_id, "name": "Unreachable", "url": "http://127.0.0.1:59999",
    })
    check("target.add_custom", code == 200, str(r))

    # invalid URL rejected
    code, r = admin.post("/api/targets", body={"orgId": org1_id, "url": "ftp://bad"})
    check("target.invalid_url_rejected", code == 400, str(r))

    code, targets = admin.get(f"/api/targets?orgId={org1_id}")
    check("target.list", code == 200 and len(targets.get("targets", [])) == 2)
    check("target.demo_url", any(t["url"] == "http://127.0.0.1:8777" for t in targets.get("targets", [])))

    # ── 4. RBAC negative tests (before scanning) ────────────────────────────
    viewer = Client(); viewer.login("e2e-viewer@sentinel.test", "E2E-Member-Pass-1")
    member = Client(); member.login("e2e-member@sentinel.test", "E2E-Member-Pass-1")
    admin2 = Client(); admin2.login("e2e-admin@sentinel.test", "E2E-Member-Pass-1")

    code, r = viewer.post("/api/targets", body={"orgId": org1_id, "url": "http://x.example"})
    check("rbac.viewer_cannot_create_target", code == 403, f"code={code}")

    code, r = viewer.post("/api/scans", body={"orgId": org1_id, "targetId": demo_target_id})
    check("rbac.viewer_cannot_scan", code == 403, f"code={code}")

    code, r = member.post(f"/api/orgs/{org1_id}/members", body={
        "email": "nope@x.test", "password": "12345678", "role": "VIEWER"})
    check("rbac.member_cannot_add_members", code == 403, f"code={code}")

    code, r = member.delete(f"/api/targets/{demo_target_id}?orgId={org1_id}")
    check("rbac.member_cannot_delete_others_target", code == 403, f"code={code}")

    # ADMIN can grant roles but not OWNER
    code, r = admin2.post(f"/api/orgs/{org1_id}/members", body={
        "email": f"late-user-{suffix}@sentinel.test", "password": "12345678", "role": "OWNER"})
    check("rbac.admin_cannot_grant_owner", code == 403, f"code={code}")

    # ── 5. tenant isolation ─────────────────────────────────────────────────
    code, r = org2_client.get(f"/api/targets?orgId={org1_id}")
    check("isolation.org2_cannot_list_org1_targets", code == 404, f"code={code}")

    code, r = org2_client.post("/api/scans", body={"orgId": org1_id, "targetId": demo_target_id})
    check("isolation.org2_cannot_scan_org1_target", code in (403, 404), f"code={code}")

    code, r = org2_client.get(f"/api/orgs/{org1_id}")
    check("isolation.org2_cannot_view_org1_overview", code == 404, f"code={code}")

    # nonexistent org id → 404
    code, r = admin.get("/api/targets?orgId=does-not-exist")
    check("isolation.nonexistent_org_404", code == 404, f"code={code}")

    # ── 6. scan lifecycle (live engine) ─────────────────────────────────────
    code, r = admin.post("/api/scans", body={
        "orgId": org1_id, "targetId": demo_target_id,
        "options": {"maxPages": 25, "allowPrivate": True, "noBrowser": False},
    })
    check("scan.start", code == 200, str(r))
    scan_id = r.get("id") if code == 200 else None

    # duplicate scan rejected (serialization per target)
    code, r = admin.post("/api/scans", body={"orgId": org1_id, "targetId": demo_target_id})
    check("scan.duplicate_rejected_409", code == 409, f"code={code}")

    # poll progress
    completed = False
    progress_seen = False
    poll_count = 0
    while scan_id and poll_count < 120:  # up to ~5 min
        poll_count += 1
        code, d = admin.get(f"/api/scans/{scan_id}?orgId={org1_id}")
        if code == 200:
            st = d["scan"]["status"]
            pr = d["progress"]
            if st in ("RUNNING", "QUEUED"):
                progress_seen = progress_seen or (pr.get("elapsedSec", 0) > 0)
            if st == "COMPLETED":
                completed = True
                final = d
                break
            if st in ("FAILED", "CANCELLED"):
                check("scan.completed", False, f"status={st} error={d['scan'].get('error')}")
                break
        time.sleep(2.5)
    check("scan.progress_visible", progress_seen, "no elapsed time observed while running")
    check("scan.completed", completed, f"polls={poll_count}")

    if completed:
        s = final["scan"]
        check("scan.scanner_is_v411", s["scanner"] == "sentinel-core/4.1.1", s.get("scanner", ""))
        check("scan.has_runid", bool(s.get("runId")), str(s.get("runId")))
        check("scan.findings_imported", s["findingsCount"] > 50, f"findings={s['findingsCount']}")
        check("scan.stats_present", bool(s.get("stats")), str(s.get("stats"))[:120])
        check("scan.by_severity", isinstance(s.get("bySeverity"), dict) and sum(s["bySeverity"].values()) == s["findingsCount"])

        # ── 7. findings + detail ────────────────────────────────────────────
        code, findings = admin.get(f"/api/scans/{scan_id}/findings?orgId={org1_id}")
        check("findings.list", code == 200 and len(findings["findings"]) > 50, f"n={len(findings.get('findings', []))}")
        check("findings.types_grouped", len(findings.get("types", [])) >= 8, f"types={len(findings.get('types', []))}")

        crit = [f for f in findings["findings"] if f["severity"] == "critical"]
        # prefer a finding that carries an Evidence-OS reproduction recipe
        with_proof = [f for f in findings["findings"] if f.get("hasProof")]
        target_finding = (with_proof or crit or findings["findings"])[0]
        code, fd = admin.get(f"/api/findings/{target_finding['id']}?orgId={org1_id}")
        check("finding.detail", code == 200, str(fd)[:150])
        if code == 200:
            check("finding.evidence_chain", isinstance(fd.get("evidence"), list) and len(fd["evidence"]) > 0)
            check("finding.verification", isinstance(fd.get("verification"), dict) and "method" in fd["verification"])
            check("finding.impact", isinstance(fd.get("impact"), dict) and "grade" in fd["impact"])
            check("finding.reproduction_recipe",
                  isinstance(fd.get("reproduction"), dict) and len(fd["reproduction"].get("reproduction", [])) > 0,
                  "no reproduction steps in stored proof")
            check("finding.remediation_guidance", isinstance(fd.get("remediation"), dict) and len(fd["remediation"].get("steps", [])) > 0)

        # severity filter
        code, f2 = admin.get(f"/api/scans/{scan_id}/findings?orgId={org1_id}&severity=critical")
        check("findings.severity_filter", code == 200 and
              all(x["severity"] == "critical" for x in f2["findings"]))

        # ── 8. coverage + boundary ──────────────────────────────────────────
        code, cov = admin.get(f"/api/scans/{scan_id}/coverage?orgId={org1_id}")
        check("coverage.endpoint", code == 200, str(cov)[:120])
        if code == 200 and cov.get("coverage"):
            c = cov["coverage"]
            check("coverage.metrics", c.get("discovered", 0) > 0 and c.get("tested", 0) > 0)
            check("coverage.pct_100", c.get("coverage_pct") == 100.0, f"pct={c.get('coverage_pct')}")
            check("coverage.endpoints_map", isinstance(c.get("endpoints"), list) and len(c["endpoints"]) > 10)
            check("coverage.boundary_records", cov.get("boundary", {}).get("records", 0) >= 1,
                  str(cov.get("boundary", {}))[:120])

        # ── 9. reports ──────────────────────────────────────────────────────
        report_ids = {}
        for fmt in ["HTML", "SARIF", "EXECUTIVE"]:
            code, r = admin.post("/api/reports", body={"orgId": org1_id, "scanId": scan_id, "format": fmt})
            check(f"report.create_{fmt.lower()}", code == 200, str(r))
            if code == 200:
                report_ids[fmt] = r["id"]
        code, reports = admin.get(f"/api/reports?orgId={org1_id}")
        check("report.list", code == 200 and len(reports["reports"]) >= 3)
        if "HTML" in report_ids:
            code, rd = admin.get(f"/api/reports/{report_ids['HTML']}?orgId={org1_id}")
            check("report.html_content", code == 200 and "<html" in rd.get("content", "").lower()[:2000])
        if "SARIF" in report_ids:
            code, rd = admin.get(f"/api/reports/{report_ids['SARIF']}?orgId={org1_id}")
            try:
                sarif = json.loads(rd.get("content", "{}"))
                sarif_ok = sarif.get("$schema", "").find("sarif") >= 0 or "runs" in sarif
            except Exception:
                sarif_ok = False
            check("report.sarif_valid_json", code == 200 and sarif_ok)

        # unreachable target: the engine model is HONEST COMPLETION, not failure —
        # 0 findings + transport_error skip reason + boundary account
        code, r = admin.post("/api/scans", body={
            "orgId": org1_id, "targetId": [t for t in targets["targets"] if "59999" in t["url"]][0]["id"]})
        # engine will fail fast (connection refused) — poll briefly
        unreachable_scan = r.get("id")
        for _ in range(12):
            code, d = admin.get(f"/api/scans/{unreachable_scan}?orgId={org1_id}")
            if d.get("scan", {}).get("status") in ("FAILED", "COMPLETED"):
                break
            time.sleep(2)
        st = d.get("scan", {}).get("status")
        check("scan.unreachable_honest_completion", st == "COMPLETED", f"status={st}")
        code, cov = admin.get(f"/api/scans/{unreachable_scan}/coverage?orgId={org1_id}")
        skips = ((cov.get("coverage") or {}).get("skip_reasons") or {})
        check("scan.unreachable_transport_error_documented", "transport_error" in skips, f"skips={skips}")
        check("scan.unreachable_zero_findings", d.get("scan", {}).get("findingsCount") == 0,
              f"findings={d.get('scan', {}).get('findingsCount')}")
        # report on a completed zero-finding scan works (honest empty report)
        code, r = admin.post("/api/reports", body={"orgId": org1_id, "scanId": unreachable_scan, "format": "HTML"})
        check("report.zero_finding_scan_works", code == 200, f"code={code}")

        # ── 10. isolation on findings/reports ───────────────────────────────
        code, r = org2_client.get(f"/api/findings/{target_finding['id']}?orgId={org2_id}")
        check("isolation.org2_cannot_read_org1_finding", code in (403, 404), f"code={code}")
        if "HTML" in report_ids:
            code, r = org2_client.get(f"/api/reports/{report_ids['HTML']}?orgId={org2_id}")
            check("isolation.org2_cannot_read_org1_report", code in (403, 404), f"code={code}")

    # ── 11. viewer read access (positive) ───────────────────────────────────
    code, r = viewer.get(f"/api/scans?orgId={org1_id}")
    check("rbac.viewer_can_read_scans", code == 200, f"code={code}")
    code, r = viewer.get(f"/api/targets?orgId={org1_id}")
    check("rbac.viewer_can_read_targets", code == 200, f"code={code}")

    # ── 12. audit log shows denials (tenant isolation evidence) ─────────────
    code, logs = admin.get(f"/api/audit?orgId={org1_id}")
    if check("audit.list", code == 200):
        actions = [l["action"] for l in logs.get("logs", [])]
        check("audit.rbac_denials_recorded", any(a.startswith("rbac.") for a in actions),
              f"actions={actions[:10]}")
        check("audit.scan_completed_recorded", "scan.completed" in actions)

    # ── 13. member role lifecycle ───────────────────────────────────────────
    code, members = admin.get(f"/api/orgs/{org1_id}/members")
    mem_admin2 = [m for m in members["members"] if m["email"] == "e2e-admin@sentinel.test"][0]
    code, r = admin.patch(f"/api/orgs/{org1_id}/members/{mem_admin2['id']}", body={"role": "MEMBER"})
    check("member.role_change", code == 200, str(r))
    code, r = admin.delete(f"/api/orgs/{org1_id}/members/{mem_admin2['id']}")
    check("member.remove", code == 200, str(r))

    # ── summary ─────────────────────────────────────────────────────────────
    dt = time.time() - t0
    print("\n" + "=" * 64)
    print(f"SENTINEL SaaS E2E: {PASS} passed, {FAIL} failed  (duration {dt:.0f}s)")
    print("=" * 64)
    with open("/home/z/my-project/saas-data/e2e_results.json", "w") as f:
        json.dump({"passed": PASS, "failed": FAIL, "duration": dt, "results": RESULTS}, f, indent=1)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
