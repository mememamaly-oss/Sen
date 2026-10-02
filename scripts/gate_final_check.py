#!/usr/bin/env python3
"""SENTINEL — Final Gate (pre-UI/UX) checks 5 & 6 against the PRODUCTION build.

Gate 5: Two consecutive scans on the SAME target -> no race / no conflict.
        Includes a rapid double-start race probe (expect 200 + 409).
Gate 6: Dead/unavailable target -> honest completion, ZERO findings.

Runs against http://localhost:3000 (production standalone server).
Evidence: saas-data/gate_final_results.json
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from typing import Any

BASE = "http://localhost:3000"
ADMIN_EMAIL = "admin@sentinel.local"
ADMIN_PASS = "Sentinel-P0!Admin"

RESULTS: list[dict] = []
PASS = 0
FAIL = 0


def check(gate: str, name: str, ok: bool, detail: str = "") -> bool:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    RESULTS.append({"gate": gate, "name": name, "status": status, "detail": detail[:400]})
    print(f"[{status}] ({gate}) {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


class Client:
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

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, body=None, form=None, **kw):
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


def wait_scan(client: Client, org_id: str, scan_id: str, label: str,
              max_seconds: int = 480) -> dict | None:
    """Poll a scan to terminal state; return final scan payload dict."""
    t0 = time.time()
    poll = 0
    while time.time() - t0 < max_seconds:
        poll += 1
        code, d = client.get(f"/api/scans/{scan_id}?orgId={org_id}")
        if code == 200:
            st = d["scan"]["status"]
            if st == "COMPLETED":
                print(f"    {label}: COMPLETED after {time.time()-t0:.0f}s "
                      f"(polls={poll})")
                return d
            if st in ("FAILED", "CANCELLED"):
                print(f"    {label}: terminal {st}: {d['scan'].get('error')}")
                return d
        time.sleep(2.5)
    print(f"    {label}: TIMEOUT after {max_seconds}s")
    return None


def fingerprint(findings: list[dict]) -> tuple:
    """Substance fingerprint of a findings list (order-insensitive)."""
    items = []
    for f in findings:
        items.append((
            f.get("type", ""), f.get("title", ""), f.get("severity", ""),
            f.get("endpoint", "") or f.get("path", "") or "",
            f.get("param", "") or "",
        ))
    return tuple(sorted(items))


def main() -> int:
    t_start = time.time()
    admin = Client()

    # ── setup: login + org + demo target ────────────────────────────────────
    ok = admin.login(ADMIN_EMAIL, ADMIN_PASS)
    check("5", "admin.login_on_production", ok, "login failed")
    if not ok:
        return 2

    code, me = admin.get("/api/me")
    check("5", "me.ok", code == 200 and len(me.get("orgs", [])) >= 1)
    org = next((o for o in me["orgs"] if o.get("name") == "E2E Security Org"),
               me["orgs"][0])
    org_id = org["id"]

    code, targets = admin.get(f"/api/targets?orgId={org_id}")
    demo = next((t for t in targets.get("targets", []) if t["url"].startswith("http://127.0.0.1:8777")), None)
    check("5", "demo_target_found", demo is not None, str(targets)[:200])
    if demo is None:
        return 2
    demo_id = demo["id"]

    opts = {"maxPages": 25, "allowPrivate": True, "noBrowser": False}

    # ── GATE 5: consecutive scans on the SAME target ────────────────────────
    # 5a. race probe: two rapid starts -> exactly one 200 + one 409
    code_a, r_a = admin.post("/api/scans", body={"orgId": org_id, "targetId": demo_id, "options": opts})
    code_b, r_b = admin.post("/api/scans", body={"orgId": org_id, "targetId": demo_id, "options": opts})
    codes = sorted([code_a, code_b])
    check("5", "race_probe_double_start", codes == [200, 409],
          f"codes=({code_a},{code_b})")
    scan1 = r_a.get("id") if code_a == 200 else r_b.get("id")
    if scan1 is None:
        check("5", "scan1_started", False,
              f"both starts failed: ({code_a}) {str(r_a)[:200]} / ({code_b}) {str(r_b)[:200]}")
        return 2

    # 5b. first scan completes
    d1 = wait_scan(admin, org_id, scan1, "scan#1")
    if d1 is None or d1.get("scan") is None:
        check("5", "scan1_completed", False, f"scan1={scan1} never reached terminal state")
        return 2
    check("5", "scan1_completed", d1["scan"]["status"] == "COMPLETED",
          f"status={d1['scan']['status']}")
    s1 = d1["scan"]
    run1, fc1 = s1.get("runId"), len(d1.get("findings", []) or [])
    code, fl1 = admin.get(f"/api/scans/{scan1}/findings?orgId={org_id}")
    list1 = fl1.get("findings", [])
    check("5", "scan1_findings_listed", code == 200 and len(list1) > 50,
          f"n={len(list1)}")
    fp1 = fingerprint(list1)

    # 5c. IMMEDIATELY start scan #2 on the same target
    code, r2 = admin.post("/api/scans", body={"orgId": org_id, "targetId": demo_id, "options": opts})
    check("5", "scan2_started_immediately_after_scan1", code == 200, f"code={code} body={str(r2)[:200]}")
    if code != 200:
        return 2
    scan2 = r2["id"]

    d2 = wait_scan(admin, org_id, scan2, "scan#2")
    if d2 is None or d2.get("scan") is None:
        check("5", "scan2_completed", False, f"scan2={scan2} never reached terminal state")
        return 2
    check("5", "scan2_completed", d2["scan"]["status"] == "COMPLETED",
          f"status={d2['scan']['status']}")
    s2 = d2["scan"]
    run2 = s2.get("runId")
    code, fl2 = admin.get(f"/api/scans/{scan2}/findings?orgId={org_id}")
    list2 = fl2.get("findings", [])
    check("5", "scan2_findings_listed", code == 200 and len(list2) > 50,
          f"n={len(list2)}")
    fp2 = fingerprint(list2)

    # 5d. no race / no conflict assertions
    check("5", "distinct_run_ids", run1 and run2 and run1 != run2, f"{run1} vs {run2}")
    check("5", "distinct_scan_ids", scan1 != scan2, f"{scan1} vs {scan2}")
    check("5", "same_target_same_findings_count",
          len(list1) == len(list2) and len(list1) > 0,
          f"scan1={len(list1)} scan2={len(list2)}")
    check("5", "findings_substance_identical_no_cross_contamination",
          fp1 == fp2,
          f"fingerprints differ: {len(fp1)} vs {len(fp2)} tuples")
    check("5", "scan2_after_scan1_no_state_corruption",
          s2.get("scanner") == "sentinel-core/4.1.1" and bool(s2.get("stats")),
          f"scanner={s2.get('scanner')}")

    # 5e. scan history shows both, in order
    code, hist = admin.get(f"/api/scans?orgId={org_id}")
    ids = [s["id"] for s in hist.get("scans", [])]
    check("5", "history_lists_both_scans", scan1 in ids and scan2 in ids)

    # 5f. on-disk artifacts are separate per scan (no file collisions)
    import os
    a1 = f"/home/z/my-project/saas-data/scans/{scan1}"
    a2 = f"/home/z/my-project/saas-data/scans/{scan2}"
    check("5", "artifacts_separate_dirs",
          os.path.isdir(a1) and os.path.isdir(a2) and a1 != a2)
    check("5", "artifacts_result_json_each",
          os.path.isfile(f"{a1}/result.json") and os.path.isfile(f"{a2}/result.json"))
    store = f"/home/z/my-project/saas-data/stores/{demo_id}.db"
    check("5", "per_target_store_db_exists", os.path.isfile(store))

    # ── GATE 6: dead target honesty ─────────────────────────────────────────
    DEAD_URL = "http://127.0.0.1:59998"
    code, all_targets = admin.get(f"/api/targets?orgId={org_id}")
    dead = next((t for t in all_targets.get("targets", []) if t["url"].rstrip("/") == DEAD_URL), None)
    if dead is not None:
        check("6", "dead_target_created", True, "reusing existing dead target (idempotent re-run)")
        dead_id = dead["id"]
    else:
        code, r = admin.post("/api/targets", body={
            "orgId": org_id, "name": "Dead Target Gate", "url": DEAD_URL,
        })
        check("6", "dead_target_created", code == 200, str(r)[:200])
        dead_id = r.get("id") if code == 200 else None

    code, r = admin.post("/api/scans", body={"orgId": org_id, "targetId": dead_id, "options": opts})
    check("6", "dead_target_scan_started", code == 200, f"code={code} body={str(r)[:200]}")
    dead_scan = r.get("id") if code == 200 else None
    if dead_scan is None:
        # cannot continue section 6 — record and skip to summary
        out = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "base": BASE,
            "mode": "production standalone build",
            "passed": PASS, "failed": FAIL, "results": RESULTS,
        }
        with open("/home/z/my-project/saas-data/gate_final_results.json", "w") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"\n=== GATE 5+6: {PASS} PASS / {FAIL} FAIL (dead scan could not start) ===")
        return 1

    dd = wait_scan(admin, org_id, dead_scan, "dead-scan", max_seconds=180)
    ds = dd["scan"] if dd else {}
    check("6", "dead_target_honest_completion",
          dd is not None and ds.get("status") == "COMPLETED",
          f"status={ds.get('status')} error={ds.get('error')}")
    check("6", "dead_target_zero_findings",
          ds.get("status") == "COMPLETED" and (ds.get("findingsCount") or 0) == 0,
          f"findingsCount={ds.get('findingsCount')}")

    code, fl = admin.get(f"/api/scans/{dead_scan}/findings?orgId={org_id}")
    check("6", "dead_target_findings_list_empty",
          code == 200 and len(fl.get("findings", [])) == 0,
          f"n={len(fl.get('findings', []))}")
    check("6", "no_fabricated_findings",
          (ds.get("findingsCount") or 0) == 0 and len(fl.get("findings", [])) == 0)

    # honest skip reason documented in engine log or stats
    log_path = f"/home/z/my-project/saas-data/scans/{dead_scan}/log.txt"
    skip_evidence = ""
    if os.path.isfile(log_path):
        log = open(log_path, errors="replace").read()
        for kw in ["transport", "unreachable", "refused", "connect", "skip"]:
            if kw.lower() in log.lower():
                skip_evidence = kw
                break
    stats = ds.get("stats") or {}
    check("6", "unreachability_documented",
          bool(skip_evidence) or bool(stats),
          f"log_keyword={skip_evidence or 'none'} stats={'yes' if stats else 'no'}")

    # ── summary ─────────────────────────────────────────────────────────────
    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "base": BASE,
        "mode": "production standalone build",
        "passed": PASS, "failed": FAIL,
        "scan1": {"id": scan1, "runId": run1, "findings": len(list1)},
        "scan2": {"id": scan2, "runId": run2, "findings": len(list2)},
        "dead_scan": {"id": dead_scan, "status": ds.get("status"),
                      "findings": ds.get("findingsCount")},
        "results": RESULTS,
    }
    with open("/home/z/my-project/saas-data/gate_final_results.json", "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print()
    print(f"=== GATE 5+6: {PASS} PASS / {FAIL} FAIL  ({time.time()-t_start:.0f}s) ===")
    print("saved: saas-data/gate_final_results.json")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
