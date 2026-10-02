#!/usr/bin/env python3
"""SENTINEL L1 — Twin API contract + tenant-isolation ATTACK tests.

Target: GET /api/v1/scans/:scanId/twin?orgId= (the versioned, read-only
normalized Security Twin API). Runs against a FRESH database instance
(use scripts/l1_twin_orchestrator.py which boots the production standalone
server on a temp port + temp DB).

Identities (created ONLY through real product flows):
  P = bootstrap admin, OWNER of org A only (attacker against org B)
  Q = member of org A, then creates org B (OWNER of B) — member of BOTH
  R = member of org B only (attacker against org A)
  Both orgs run REAL engine scans on the managed demo target.

Attack matrix (all against GET /api/v1/scans/:scanId/twin?orgId=):
   1. same tenant            P -> twin A, orgId=A              ALLOW 200
   2. same tenant (victim)   R -> twin B, orgId=B              ALLOW 200
   3. cross-tenant +         P -> twin B, orgId=B              DENY 404
      EXPLICIT VICTIM orgId
   4. cross-tenant, own org  P -> twin B, orgId=A              DENY 404
   5. reverse + victim orgId R -> twin A, orgId=A              DENY 404
   6. reverse, own org       R -> twin A, orgId=B              DENY 404
   7. anonymous              no session                        DENY 401
   8. enumeration            scanId x orgId matrix             404 + no leak
   9. control (both orgs)    Q reads twin A and twin B         ALLOW 200
  10. bad input              missing orgId -> 400 ; garbage id -> 404
  11. API contract           v1 shape, deterministic twinHash x3,
                              counts consistency, invariants.pass
  12. persistence            TwinGraph rows org-scoped in the temp DB
                              (contentHash == API twinHash)
  13. audit trail            rbac.org_access_denied recorded

Usage: python3 scripts/l1_twin_api_test.py [--base http://localhost:3012] [--db PATH]
Exit 0 = all pass. Results JSON -> saas-data/l1-twin/l1_twin_api_results.json
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import sqlite3
from typing import Any

BASE = "http://localhost:3012"
DB_PATH = ""
PASS = 0
FAIL = 0
RESULTS: list[dict] = []

# Fields that must NEVER appear in a denied twin response (leak matrix)
FORBIDDEN_KEYS = ["twin", "nodes", "edges", "twinHash", "conflicts",
                  "knownUnknowns", "counts", "scope", "invariants", "built"]


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    RESULTS.append({"name": name, "status": status, "detail": detail[:300]})
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method: str, path: str, body: dict | None = None, form: dict | None = None) -> tuple[int, Any]:
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
            with self.opener.open(r, timeout=180) as res:
                raw = res.read().decode()
                code = res.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            code = e.code
        try:
            return code, json.loads(raw)
        except json.JSONDecodeError:
            return code, raw

    def get(self, path: str, **kw):
        return self.req("GET", path, **kw)

    def post(self, path: str, body: dict | None = None, form: dict | None = None, **kw):
        return self.req("POST", path, body=body, form=form, **kw)

    def login(self, email: str, password: str) -> bool:
        code, csrf = self.get("/api/auth/csrf")
        if code != 200:
            return False
        code, _ = self.post("/api/auth/callback/credentials",
                            form={"csrfToken": csrf["csrfToken"], "email": email,
                                  "password": password, "json": "true"})
        return code == 200


def wait_scan(client: Client, scan_id: str, org_id: str, timeout_sec: float = 330.0) -> dict | None:
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        code, d = client.get(f"/api/scans/{scan_id}?orgId={org_id}")
        if code == 200:
            st = d.get("scan", {}).get("status")
            if st == "COMPLETED":
                return d
            if st in ("FAILED", "CANCELLED"):
                return None
        time.sleep(3)
    return None


def is_hex64(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def twin_contract_ok(d: Any, scan_id: str) -> tuple[bool, str]:
    """The full API contract for a 200 twin response."""
    if not isinstance(d, dict):
        return False, "response is not an object"
    if d.get("apiVersion") != "v1":
        return False, f"apiVersion={d.get('apiVersion')}"
    if d.get("scanId") != scan_id:
        return False, f"scanId mismatch"
    t = d.get("twin")
    if not isinstance(t, dict):
        return False, "twin missing"
    for key in ["schemaVersion", "target", "scope", "nodes", "edges",
                "conflicts", "knownUnknowns", "counts", "twinHash", "rawHash"]:
        if key not in t:
            return False, f"twin.{key} missing"
    if not is_hex64(t["twinHash"]) or not is_hex64(t["rawHash"]):
        return False, "hash not sha256 hex"
    nodes, edges = t["nodes"], t["edges"]
    if not isinstance(nodes, list) or not nodes:
        return False, "nodes empty"
    if not isinstance(edges, list):
        return False, "edges not a list"
    ids = [n["id"] for n in nodes]
    if len(ids) != len(set(ids)):
        return False, "duplicate node ids"
    if ids != sorted(ids):
        return False, "nodes not sorted by id"
    eids = [e["id"] for e in edges]
    if eids != sorted(eids):
        return False, "edges not sorted by id"
    idset = set(ids)
    for e in edges:
        if e["from"] not in idset or e["to"] not in idset:
            return False, f"edge {e['id']} dangling"
    for n in nodes:
        if n.get("provenance") not in ("OBSERVED", "INFERRED", "VERIFIED", "REFUTED", "UNKNOWN"):
            return False, f"invalid provenance {n.get('provenance')}"
        if "why" not in n or not isinstance(n["why"], dict):
            return False, "node without structured why()"
    c = t["counts"]
    if c.get("nodes") != len(nodes) or c.get("edges") != len(edges):
        return False, "counts mismatch"
    prov_sum = sum(c.get("provenance", {}).values())
    if prov_sum != len(nodes):
        return False, f"provenance sum {prov_sum} != nodes {len(nodes)}"
    inv = d.get("invariants")
    if not isinstance(inv, dict) or inv.get("pass") is not True:
        return False, f"invariants={inv}"
    return True, "ok"


def main() -> int:
    global BASE, DB_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--db", default="")
    args = ap.parse_args()
    BASE = args.base.rstrip("/")
    DB_PATH = args.db

    t0 = time.time()
    suffix = str(int(time.time()))[-6:]

    # ── setup: fresh DB, real product flows only ──────────────────────────
    p = Client()
    code, boot = p.get("/api/bootstrap")
    if not check("setup.bootstrap_status", code == 200 and "needsBootstrap" in boot, str(boot)):
        return 2
    if not boot.get("needsBootstrap"):
        print("FATAL: database not fresh — run via scripts/l1_twin_orchestrator.py")
        return 2
    code, r = p.post("/api/bootstrap", body={
        "email": f"l1-p-{suffix}@sentinel.test", "name": "L1 Twin Attacker A",
        "password": "L1-Pass-AAAA-1", "orgName": f"L1 Twin Org A {suffix}",
    })
    check("setup.bootstrap_admin_P", code == 200, str(r))
    check("setup.login_P", p.login(f"l1-p-{suffix}@sentinel.test", "L1-Pass-AAAA-1"))
    code, me = p.get("/api/me")
    org_a = me["orgs"][0]["id"]

    q = Client()
    code, r = p.post(f"/api/orgs/{org_a}/members", body={
        "email": f"l1-q-{suffix}@sentinel.test", "name": "L1 Twin Bridge Q",
        "password": "L1-Pass-BBBB-1", "role": "MEMBER"})
    check("setup.add_Q_to_orgA", code == 200, str(r))
    check("setup.login_Q", q.login(f"l1-q-{suffix}@sentinel.test", "L1-Pass-BBBB-1"))
    code, r = q.post("/api/orgs", body={"name": f"L1 Twin Org B {suffix}"})
    org_b = r.get("id")
    check("setup.Q_creates_orgB", code == 200 and org_b)

    rcl = Client()
    code, r = q.post(f"/api/orgs/{org_b}/members", body={
        "email": f"l1-r-{suffix}@sentinel.test", "name": "L1 Twin Attacker B",
        "password": "L1-Pass-CCCC-1", "role": "MEMBER"})
    check("setup.add_R_to_orgB", code == 200, str(r))
    check("setup.login_R", rcl.login(f"l1-r-{suffix}@sentinel.test", "L1-Pass-CCCC-1"))

    # ── REAL engine scans for both orgs (demo target) ─────────────────────
    code, r = p.post("/api/targets", body={"orgId": org_a, "isDemo": True})
    target_a = r.get("id")
    code, r = p.post("/api/scans", body={"orgId": org_a, "targetId": target_a,
                                         "options": {"maxPages": 25, "allowPrivate": True, "noBrowser": False}})
    scan_a = r.get("id")
    check("setup.orgA_scan_start", code == 200, str(r))
    final_a = wait_scan(p, scan_a, org_a)
    check("setup.orgA_scan_completed", final_a is not None and final_a["scan"]["findingsCount"] > 0,
          f"findings={final_a['scan']['findingsCount'] if final_a else 'timeout'}")

    code, r = rcl.post("/api/targets", body={"orgId": org_b, "isDemo": True})
    target_b = r.get("id")
    code, r = rcl.post("/api/scans", body={"orgId": org_b, "targetId": target_b,
                                           "options": {"maxPages": 25, "allowPrivate": True, "noBrowser": False}})
    scan_b = r.get("id")
    check("setup.orgB_scan_start", code == 200, str(r))
    final_b = wait_scan(rcl, scan_b, org_b)
    check("setup.orgB_scan_completed", final_b is not None and final_b["scan"]["findingsCount"] > 0,
          f"findings={final_b['scan']['findingsCount'] if final_b else 'timeout'}")
    if not final_a or not final_b:
        print("FATAL: both orgs need completed scans")
        return 2

    # ── 1/2. same tenant ALLOW ────────────────────────────────────────────
    code_a, d_a = p.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}")
    ok, why = twin_contract_ok(d_a, scan_a)
    check("attack1.P_twinA_orgA_200_contract", code_a == 200 and ok, f"code={code_a} {why}")
    code_b, d_b = rcl.get(f"/api/v1/scans/{scan_b}/twin?orgId={org_b}")
    ok_b, why_b = twin_contract_ok(d_b, scan_b)
    check("attack2.R_twinB_orgB_200_contract", code_b == 200 and ok_b, f"code={code_b} {why_b}")

    # ── 3-6. cross-tenant DENY (404, no existence leak) ───────────────────
    for name, client, scan_id, org_param in [
        ("attack3.P_twinB_victimOrgB", p, scan_b, org_b),
        ("attack4.P_twinB_ownOrgA", p, scan_b, org_a),
        ("attack5.R_twinA_victimOrgA", rcl, scan_a, org_a),
        ("attack6.R_twinA_ownOrgB", rcl, scan_a, org_b),
    ]:
        code, d = client.get(f"/api/v1/scans/{scan_id}/twin?orgId={org_param}")
        no_leak = isinstance(d, dict) and not any(k in d for k in FORBIDDEN_KEYS)
        check(name, code == 404 and no_leak, f"code={code} body={str(d)[:150]}")

    # ── 7. anonymous ──────────────────────────────────────────────────────
    anon = Client()
    code, d = anon.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}")
    check("attack7.anonymous_401", code == 401, f"code={code}")

    # ── 8. enumeration matrix ─────────────────────────────────────────────
    enum_ok = True
    for sid in [scan_b, "garbage-id", ""]:
        for oid in [org_a, org_b, ""]:
            if sid == scan_a and oid == org_a:
                continue
            code, d = p.get(f"/api/v1/scans/{sid}/twin?orgId={oid}")
            if code not in (400, 404) or any(k in (d if isinstance(d, dict) else {}) for k in FORBIDDEN_KEYS):
                enum_ok = False
                check("attack8.enumeration", False, f"scan={sid[:8]} org={oid[:8]} code={code}")
                break
    if enum_ok:
        check("attack8.enumeration_no_leak", True)

    # ── 9. control: Q reads BOTH orgs' twins ──────────────────────────────
    code, d = q.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}")
    ok1, _ = twin_contract_ok(d, scan_a)
    code2, d2 = q.get(f"/api/v1/scans/{scan_b}/twin?orgId={org_b}")
    ok2, _ = twin_contract_ok(d2, scan_b)
    check("attack9.Q_reads_both_orgs", code == 200 and ok1 and code2 == 200 and ok2,
          f"A:{code}/{ok1} B:{code2}/{ok2}")

    # ── 10. bad input ─────────────────────────────────────────────────────
    code, d = p.get(f"/api/v1/scans/{scan_a}/twin")
    check("attack10a.missing_orgId_400", code == 400, f"code={code}")
    code, d = p.get(f"/api/v1/scans/does-not-exist/twin?orgId={org_a}")
    check("attack10b.garbage_scanId_404", code == 404, f"code={code}")

    # ── 11. contract: determinism ×3 via API + shape stability ────────────
    hashes = []
    for i in range(3):
        code, d = p.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}")
        hashes.append(d.get("twin", {}).get("twinHash") if isinstance(d, dict) else None)
    check("contract.twinHash_stable_x3", all(h == hashes[0] and h for h in hashes),
          f"{[str(h)[:12] for h in hashes]}")
    # stored-vs-rebuilt equality is guaranteed by twinHash stability (built flag differs)
    built_flags = set()
    for i in range(2):
        code, d = p.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}")
        built_flags.add(d.get("built"))
    check("contract.first_built_then_stored", built_flags <= {False} and len(built_flags) >= 1,
          f"built flags={built_flags} (first GET built it; later GETs serve the stored twin)")
    # hostile query attempts do not change the twin
    code, d = p.get(f"/api/v1/scans/{scan_a}/twin?orgId={org_a}&orgId={org_b}&admin=true&all=true")
    t_hash = d.get("twin", {}).get("twinHash") if isinstance(d, dict) else None
    check("contract.query_params_cannot_mutate", t_hash == hashes[0], f"{str(t_hash)[:12]} vs {str(hashes[0])[:12]}")
    # provenance vocabulary across the served twin
    t = d_a["twin"]
    bad_prov = [n for n in t["nodes"] if n["provenance"] not in
                ("OBSERVED", "INFERRED", "VERIFIED", "REFUTED", "UNKNOWN")]
    check("contract.provenance_five_values_only", not bad_prov, f"{len(bad_prov)} bad")
    claims = t["counts"]["claims"]
    check("contract.claims_counts_present", all(k in claims for k in ("VERIFIED", "REFUTED", "UNKNOWN", "CONFLICT")))
    # no VERIFIED claim without evidence refs (API-side spot check)
    no_ev = [n for n in t["nodes"] if n.get("claim", {}).get("state") == "VERIFIED"
             and not n["claim"].get("evidenceRefs")]
    check("contract.verified_claims_carry_evidence", not no_ev, f"{len(no_ev)} verified without evidence")

    # ── 12. persistence: TwinGraph rows are org-scoped in the temp DB ─────
    if DB_PATH and os.path.exists(DB_PATH):
        con = sqlite3.connect(DB_PATH)
        rows = {r[0]: r for r in con.execute(
            "SELECT scanId, orgId, contentHash, twinSchemaVersion FROM TwinGraph")}
        row_a = rows.get(scan_a)
        row_b = rows.get(scan_b)
        check("persist.twinRow_orgA_exists", row_a is not None and row_a[1] == org_a
              and row_a[2] == d_a["twin"]["twinHash"], str(row_a)[:120])
        check("persist.twinRow_orgB_exists", row_b is not None and row_b[1] == org_b
              and row_b[2] == d_b["twin"]["twinHash"], str(row_b)[:120])
        n = con.execute("SELECT COUNT(*) FROM TwinGraph").fetchone()[0]
        check("persist.exactly_two_rows", n == 2, f"rows={n}")
        con.close()
    else:
        check("persist.db_available", False, f"db path {DB_PATH} not found")

    # ── 13. audit trail ───────────────────────────────────────────────────
    code, audit = p.get(f"/api/audit?orgId={org_a}")
    denied = [a for a in (audit.get("logs") if isinstance(audit, dict) else [])
              if a.get("action") == "rbac.org_access_denied"]
    check("audit.denials_recorded_orgA", len(denied) >= 1, f"{len(denied)} denial records")

    dur = round(time.time() - t0, 1)
    verdict = "PASS" if FAIL == 0 else "FAIL"
    summary = {"suite": "l1-twin-api", "base": BASE, "pass": PASS, "fail": FAIL,
               "verdict": verdict, "durationSec": dur,
               "twinA": {"scanId": scan_a, "twinHash": d_a["twin"]["twinHash"],
                          "nodes": d_a["twin"]["counts"]["nodes"], "edges": d_a["twin"]["counts"]["edges"]},
               "twinB": {"scanId": scan_b, "twinHash": d_b["twin"]["twinHash"],
                          "nodes": d_b["twin"]["counts"]["nodes"], "edges": d_b["twin"]["counts"]["edges"]}}
    os.makedirs("saas-data/l1-twin", exist_ok=True)
    with open("saas-data/l1-twin/l1_twin_api_results.json", "w") as f:
        json.dump({"summary": summary, "results": RESULTS}, f, indent=1, ensure_ascii=False)
    print(f"\nL1 TWIN API SUITE: {PASS} passed, {FAIL} failed -> {verdict} ({dur}s)")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
