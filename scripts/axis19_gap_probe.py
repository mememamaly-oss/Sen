#!/usr/bin/env python3
"""19-AXIS GAP PROBE (2026-10-23) — the security surfaces NOT covered by the
existing batteries, executed against the PRODUCTION standalone build on :3100
(fresh scratch DB per run). Every check prints PASS/FAIL with raw evidence.

New coverage in this probe (vs qa_live_battery + greengate_browser):
  G1  MEMBER self-role-escalation via PATCH members/[mid]  -> must be 403
  G2  MEMBER deleting another member                       -> must be 403
  G3  OWNER changing a member role (positive control)      -> 200 + audited
  G4  OWNER demoting the last OWNER (self)                 -> must be 409
  G5  Cross-org IDOR on findings/[id]                      -> must be 404
  G6  CORS: evil Origin never echoed (no ACAO header)      -> no header
  G7  POST /api/bootstrap AFTER setup                      -> must be 409
  G8  Concurrent scan start on same target                 -> exactly 1 wins
  G9  5 concurrent report generations (same scan)          -> all 200
  G10 Session cookie flags (httpOnly + sameSite)           -> both present
  G11 Malformed body / wrong content-type                  -> 400, not 500
  G12 Audit log records role changes; no DELETE/POST on /api/audit
"""
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:3100"
OUT = []


def check(tid, name, ok, evidence):
    OUT.append({"id": tid, "name": name, "status": "PASS" if ok else "FAIL", "evidence": str(evidence)[:300]})
    print(f"[{'PASS' if ok else 'FAIL'}] {tid} {name}\n       {str(evidence)[:240]}")


class Client:
    def __init__(self):
        self.cookies = {}
        self.setcookie = []

    def absorb(self, resp):
        for raw in resp.headers.get_all("Set-Cookie") or []:
            self.setcookie.append(raw)
            pair = raw.split(";")[0]
            eq = pair.find("=")
            if eq > 0:
                self.cookies[pair[:eq].strip()] = pair[eq + 1:].strip()

    def req(self, method, path, body=None, form=None, is_json=True, headers=None):
        url = BASE + path
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            data = "&".join(f"{k}={v}" for k, v in form.items()).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        try:
            r = opener.open(req, timeout=60)
            self.absorb(r)
            return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            self.absorb(e)
            return e.code, dict(e.headers), e.read()


def login(email, password):
    """NextAuth credentials login: csrf first, then callback (proven flow)."""
    c = Client()
    c.req("GET", "/api/auth/csrf")
    # csrf token arrives in the JSON body AND sets the csrf cookie
    st, h, b = c.req("GET", "/api/auth/csrf")
    import json as _json
    csrf = _json.loads(b).get("csrfToken", "")
    st, h, b = c.req("POST", "/api/auth/callback/credentials", form={
        "email": email, "password": password, "csrfToken": csrf, "json": "true"})
    return c


def main():
    suffix = secrets.token_hex(4)

    # --- setup: bootstrap owner (no session from bootstrap!) then LOGIN ---
    anon = Client()
    st, h, b = anon.req("POST", "/api/bootstrap", {"name": "Gap Owner", "email": f"gap-{suffix}@t.local",
                                                    "password": "Gap-2026-Strong!", "orgName": "Gap Org"})
    check("PRE", "bootstrap precondition", st == 200, f"HTTP {st}")
    owner = login(f"gap-{suffix}@t.local", "Gap-2026-Strong!")
    st, h, b = owner.req("GET", "/api/me")
    check("PRE1", "owner session established", st == 200, f"/api/me HTTP {st} body={b[:60]!r}")
    st, h, b = owner.req("GET", "/api/orgs")
    orgs = json.loads(b).get("orgs") or []
    org_id = orgs[0].get("id", "") if orgs else ""

    # members: one MEMBER, one VIEWER (POST returns userId; membership ids come from GET)
    st, h, b = owner.req("POST", f"/api/orgs/{org_id}/members", {"email": f"mem-{suffix}@t.local", "name": "M", "role": "MEMBER", "password": "Str0ngPass!123"})
    ok_m1 = st == 200
    st, h, b = owner.req("POST", f"/api/orgs/{org_id}/members", {"email": f"view-{suffix}@t.local", "name": "V", "role": "VIEWER", "password": "Str0ngPass!123"})
    ok_m2 = st == 200
    st, h, b = owner.req("GET", f"/api/orgs/{org_id}/members")
    members_list = json.loads(b).get("members") or []
    mid_member = next((m["id"] for m in members_list if m.get("email") == f"mem-{suffix}@t.local"), "")
    mid_viewer = next((m["id"] for m in members_list if m.get("email") == f"view-{suffix}@t.local"), "")
    check("PRE2", "members created", ok_m1 and ok_m2 and bool(mid_member and mid_viewer),
          f"member={mid_member[:8]}... viewer={mid_viewer[:8]}... (membership ids from GET)")

    member = login(f"mem-{suffix}@t.local", "Str0ngPass!123")
    st, h, b = member.req("GET", "/api/me")
    check("PRE3", "member session established", st == 200, f"/api/me HTTP {st}")

    # --- G1: MEMBER self-escalation via PATCH ---
    st, h, b = member.req("PATCH", f"/api/orgs/{org_id}/members/{mid_member}", {"role": "OWNER"})
    check("G1", "MEMBER self-escalation to OWNER rejected", st in (403, 404), f"HTTP {st} body={b[:90]!r}")

    # --- G2: MEMBER deleting the VIEWER ---
    st, h, b = member.req("DELETE", f"/api/orgs/{org_id}/members/{mid_viewer}")
    check("G2", "MEMBER deleting another member rejected", st in (403, 404), f"HTTP {st} body={b[:90]!r}")

    # --- G3: OWNER changes member role (positive control + audit trail) ---
    st, h, b = owner.req("PATCH", f"/api/orgs/{org_id}/members/{mid_member}", {"role": "VIEWER"})
    ok3 = st == 200
    st, h, b = owner.req("PATCH", f"/api/orgs/{org_id}/members/{mid_member}", {"role": "MEMBER"})
    ok3 = ok3 and st == 200
    st, h, b = owner.req("GET", f"/api/audit?orgId={org_id}&limit=50")
    actions = [l.get("action") for l in json.loads(b).get("logs", [])]
    check("G3", "OWNER role changes work + audited", ok3 and "member.role_changed" in actions,
          f"patch rc ok={ok3}; audit has role_changed={'member.role_changed' in actions}; actions sample={actions[:6]}")

    # --- G4: OWNER demotes self (last owner) ---
    st, h, b = owner.req("GET", f"/api/orgs/{org_id}/members")
    own_mid = next((m["id"] for m in json.loads(b).get("members", []) if m.get("role") == "OWNER"), "")
    st, h, b = owner.req("PATCH", f"/api/orgs/{org_id}/members/{own_mid}", {"role": "MEMBER"})
    check("G4", "last-OWNER demotion refused", st == 409, f"HTTP {st} body={b[:90]!r}")

    # --- second org + cross-org IDOR (G5) ---
    st, h, b = owner.req("POST", "/api/orgs", {"name": "Second Org"})
    org2 = json.loads(b).get("id", "")
    check("PRE4", "second org created", st == 200 and bool(org2), f"HTTP {st} org2={org2[:10]}...")

    # create a finding in org2? simpler: demo target + scan in org2, then member (org1 only) requests its findings
    st, h, b = owner.req("POST", "/api/targets", {"orgId": org2, "isDemo": True})
    tgt2 = json.loads(b).get("id", "")
    st, h, b = owner.req("POST", "/api/scans", {"orgId": org2, "targetId": tgt2})
    scan2 = json.loads(b).get("id", "")
    fin2_id = ""
    if scan2:
        for _ in range(90):
            time.sleep(2)
            st, h, b = owner.req("GET", f"/api/scans/{scan2}?orgId={org2}")
            sc = json.loads(b).get("scan") or json.loads(b)
            if sc.get("status") in ("COMPLETED", "FAILED"):
                break
        st, h, b = owner.req("GET", f"/api/scans/{scan2}/findings?orgId={org2}")
        fins = json.loads(b).get("findings") or []
        fin2_id = fins[0].get("id", "") if fins else ""

    if fin2_id:
        st, h, b = member.req("GET", f"/api/findings/{fin2_id}?orgId={org2}")
        check("G5", "cross-org finding access (org1 member -> org2 finding) = 404", st == 404, f"HTTP {st} body={b[:80]!r}")
    else:
        st, h, b = member.req("GET", f"/api/scans/{scan2}?orgId={org2}")
        check("G5", "cross-org scan access (org1 member -> org2 scan) = 404", st == 404, f"HTTP {st} (scan-level IDOR) findings fetch skipped body={b[:60]!r}")

    # --- G6: CORS probe ---
    st, h, b = owner.req("GET", "/api/me", headers={"Origin": "https://evil.example"})
    acao = h.get("Access-Control-Allow-Origin") or h.get("access-control-allow-origin")
    check("G6", "no Access-Control-Allow-Origin echoed for evil origin", acao is None,
          f"ACAO header={'ABSENT (good)' if acao is None else acao!r}; status={st}")

    # --- G7: bootstrap after setup ---
    st, h, b = owner.req("POST", "/api/bootstrap", {"name": "X", "email": "x@x.io", "password": "12345678", "orgName": "X"})
    check("G7", "POST bootstrap after setup = 409", st == 409, f"HTTP {st} body={b[:90]!r}")

    # --- G8: concurrent scan start (same target) — serialization ---
    st, h, b = owner.req("POST", "/api/targets", {"orgId": org_id, "isDemo": True})
    tgt1 = json.loads(b).get("id", "")
    results = []
    def start_scan():
        c = Client()
        c.cookies = dict(owner.cookies)
        stx, hx, bx = c.req("POST", "/api/scans", {"orgId": org_id, "targetId": tgt1})
        results.append(stx)
    threads = [threading.Thread(target=start_scan) for _ in range(3)]
    for t in threads: t.start()
    for t in threads: t.join()
    created = sum(1 for r in results if r == 200)
    check("G8", "3 concurrent scan starts -> exactly 1 accepted", created == 1,
          f"statuses={results} accepted={created} (409 serialized the rest)")

    # --- G9: concurrent report generation x5 on the SAME completed scan ---
    if scan2:
        rep_results = []
        def gen_report():
            c = Client(); c.cookies = dict(owner.cookies)
            stx, hx, bx = c.req("POST", "/api/reports", {"orgId": org2, "scanId": scan2, "format": "HTML"})
            rep_results.append(stx)
        threads = [threading.Thread(target=gen_report) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        ok9 = all(r == 200 for r in rep_results)
        check("G9", "5 concurrent report generations all succeed", ok9, f"statuses={rep_results}")
    else:
        check("G9", "5 concurrent report generations", False, "no completed scan available")

    # --- G10: session cookie flags ---
    raw_sc = [c for c in owner.setcookie if "session-token" in c]
    flags = raw_sc[0].lower() if raw_sc else ""
    check("G10", "session cookie: httpOnly + sameSite present",
          "httponly" in flags and "samesite" in flags, f"set-cookie sample={raw_sc[0][:110] if raw_sc else 'NONE'!r}")

    # --- G11: malformed bodies handled gracefully ---
    req = urllib.request.Request(BASE + "/api/targets", data=b"{not-json", method="POST",
                                 headers={"Content-Type": "application/json", "Cookie": "; ".join(f"{k}={v}" for k, v in owner.cookies.items())})
    try:
        r = urllib.request.urlopen(req, timeout=15)
        st11 = r.status
    except urllib.error.HTTPError as e:
        st11 = e.code
    check("G11", "malformed JSON -> 4xx (no 500 crash)", 400 <= st11 < 500, f"HTTP {st11}")

    # --- G12: audit immutability surface ---
    st, h, b = owner.req("POST", "/api/audit", {"action": "forged"})
    st2, h2, b2 = owner.req("DELETE", "/api/audit")
    st3, h3, b3 = owner.req("PUT", "/api/audit", {"action": "forged"})
    check("G12", "audit endpoint is read-only (POST/PUT/DELETE not routable)",
          st in (404, 405) and st2 in (404, 405) and st3 in (404, 405),
          f"POST={st} DELETE={st2} PUT={st3}")

    summary = {}
    for c in OUT:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    print("\nSUMMARY:", summary)
    with open("qa-results/axis19_gap_probe_results.json", "w") as f:
        json.dump(OUT, f, ensure_ascii=False, indent=2)
    return 0 if summary.get("FAIL", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
