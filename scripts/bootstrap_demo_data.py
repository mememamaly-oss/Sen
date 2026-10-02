#!/usr/bin/env python3
"""R3-d: Restore the SaaS demo dataset on the FRESH DB after rollback #2.

All data is generated through the REAL product flow (bootstrap → login →
members → managed demo target → REAL engine scan → findings import → reports).
No fabricated rows: every finding comes from a live engine run.

Usage: python3 scripts/bootstrap_demo_data.py [--base http://localhost:3000]
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.parse
import http.cookiejar

BASE = "http://localhost:3000"
ADMIN_EMAIL = "admin@sentinel.local"
ADMIN_PASS = "Sentinel-P0!Admin"
ORG_NAME = "Sentinel SOC"


class Client:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, body=None, form=None):
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
            with self.opener.open(r, timeout=30) as resp:
                raw = resp.read().decode()
                try:
                    return resp.status, json.loads(raw)
                except Exception:
                    return resp.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw

    def get(self, path):
        return self.req("GET", path)

    def post(self, path, body=None, form=None):
        return self.req("POST", path, body=body, form=form)

    def login(self, email, password):
        code, csrf = self.get("/api/auth/csrf")
        if code != 200:
            return False
        code, _ = self.post("/api/auth/callback/credentials", form={
            "csrfToken": csrf["csrfToken"], "email": email,
            "password": password, "json": "true"})
        return code == 200


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--scans", type=int, default=2)
    args = ap.parse_args()
    base = args.base.rstrip("/")
    c = Client(base)

    # 1. bootstrap status
    code, boot = c.get("/api/bootstrap")
    assert code == 200 and "needsBootstrap" in boot, f"server not ready: {code}"
    if boot["needsBootstrap"]:
        code, r = c.post("/api/bootstrap", body={
            "email": ADMIN_EMAIL, "password": ADMIN_PASS,
            "name": "Platform Admin", "orgName": ORG_NAME})
        assert code == 200, f"bootstrap failed: {code} {r}"
        print("[1] bootstrap: admin created")
    else:
        print("[1] bootstrap: already exists")

    assert c.login(ADMIN_EMAIL, ADMIN_PASS), "admin login failed"
    print("[2] login: OK")

    code, me = c.get("/api/me")
    assert code == 200, f"/api/me {code}"
    org = me["orgs"][0]
    org_id, org_name, role = org["id"], org.get("name", ""), org["role"]
    print(f"[3] me: org={org_name!r} role={role} id={org_id[:8]}")

    # 4. team members (real users via members API)
    members = [
        ("sara@sentinel.local", "سارة العتيبي", "MEMBER", "Sara-Member-1"),
        ("khalid@sentinel.local", "خالد المطيري", "VIEWER", "Khalid-Viewer-1"),
    ]
    for email, name, mrole, pw in members:
        code, r = c.post(f"/api/orgs/{org_id}/members",
                         body={"email": email, "name": name, "password": pw, "role": mrole})
        print(f"[4] member {email}: {code} {('OK' if code==200 else r)}")

    # 5. managed demo target (platform starts engine fixture vulnapp on :8777)
    code, targets = c.get(f"/api/targets?orgId={org_id}")
    existing = [t for t in targets.get("targets", []) if "8777" in t.get("url", "")]
    if existing:
        target = existing[0]
        print(f"[5] demo target exists: {target['name']!r} {target['url']}")
    else:
        code, r = c.post("/api/targets", body={
            "orgId": org_id, "isDemo": True,
            "description": "تطبيق تجريبي محلي يديره النظام — هدف تدريب داخلي للتقييم"})
        if code == 409:
            code, targets = c.get(f"/api/targets?orgId={org_id}")
            existing = [t for t in targets.get("targets", []) if "8777" in t.get("url", "")]
            assert existing, f"409 but target not found: {r}"
            target = existing[0]
            print(f"[5] demo target exists (409 race): {target['name']!r}")
        else:
            assert code == 200, f"target create failed: {code} {r}"
            target = {"id": r["id"], "name": r["name"], "url": r["url"]}
            print(f"[5] demo target created: {target['name']!r} -> {target['url']}")

    # 6..n scans (real engine runs; serialized per target by the platform)
    scan_ids = []
    for n in range(1, args.scans + 1):
        while True:
            code, r = c.post("/api/scans", body={"orgId": org_id, "targetId": target["id"]})
            if code == 200:
                break
            if code != 409:
                raise AssertionError(f"scan start failed: {code} {r}")
            # a scan is already active (e.g. started by an earlier run) —
            # find it, wait for it to finish, then try again.
            code, lst = c.get(f"/api/scans?orgId={org_id}&targetId={target['id']}")
            active = [s["id"] for s in lst.get("scans", []) if s["status"] in ("QUEUED", "RUNNING")]
            if not active:
                print(f"[6.{n}] 409 with no active scan — retry in 5s")
                time.sleep(5)
                continue
            act = active[0]
            print(f"[6.{n}] waiting for active scan {act[:8]} …")
            t0 = time.time()
            while time.time() - t0 < 300:
                code, s = c.get(f"/api/scans/{act}?orgId={org_id}")
                st = s.get("scan", {}).get("status")
                if st in ("COMPLETED", "FAILED", "CANCELLED"):
                    scan_ids.append(act)
                    print(f"[7.w{len(scan_ids)}] waited scan {st} after {int(time.time()-t0)}s "
                          f"(findings={s['scan'].get('findingsCount', 0)})")
                    break
                time.sleep(3)
            else:
                raise AssertionError("active scan did not finish in 300s")
        scan_id = r["id"]
        scan_ids.append(scan_id)
        print(f"[6.{n}] scan started: {scan_id[:8]}")

        # poll until terminal (reconcile imports findings on GET)
        t0, status, findings_n = time.time(), None, 0
        while time.time() - t0 < 300:
            code, s = c.get(f"/api/scans/{scan_id}?orgId={org_id}")
            assert code == 200, f"scan poll {code}"
            status = s["scan"]["status"]
            if status in ("COMPLETED", "FAILED"):
                prog = s.get("progress", {}) or {}
                print(f"[7.{n}] scan {status} after {int(time.time()-t0)}s "
                      f"(findings={s['scan'].get('findingsCount', 0)}, "
                      f"coverage={prog.get('coveragePct', '?')}%)")
                break
            time.sleep(3)
        else:
            print(f"[7.{n}] TIMEOUT waiting for scan {scan_id[:8]} (status={status})")
            sys.exit(2)
        if status != "COMPLETED":
            print(f"[7.{n}] scan did not complete: {status}")
            sys.exit(2)

    # 8. reports for the latest scan (2 formats)
    latest = scan_ids[-1]
    for fmt in ("HTML", "SARIF"):
        code, r = c.post("/api/reports", body={"orgId": org_id, "scanId": latest, "format": fmt})
        print(f"[8] report {fmt}: {code} {('OK ' + r.get('title', '')[:60]) if code==200 else r}")

    # 9. summary
    code, tg = c.get(f"/api/targets?orgId={org_id}")
    code, lst = c.get(f"/api/scans?orgId={org_id}&targetId={target['id']}")
    code, fl = c.get(f"/api/scans/{latest}/findings?orgId={org_id}")
    n_findings = len(fl.get("findings", [])) if isinstance(fl, dict) else sum(
        s.get("findingsCount", 0) for s in lst.get("scans", []))
    code, rp = c.get(f"/api/reports?orgId={org_id}")
    n_reports = len(rp.get("reports", [])) if isinstance(rp, dict) else "?"
    print(f"[9] SUMMARY: targets={len(tg.get('targets', []))} scans={len(lst.get('scans', []))} "
          f"findings(latest)={n_findings} reports={n_reports}")
    print("DEMO DATA READY — all rows generated by real product flows")


if __name__ == "__main__":
    main()
