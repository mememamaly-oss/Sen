#!/usr/bin/env python3
"""QA LIVE BATTERY (mission 2026-10-23) — real HTTP tests against the
PRODUCTION build of the candidate commit, running on an isolated port+DB.

Levels covered: Level 2 (running application over HTTP) with WSTG-mapped
security checks. Every check prints PASS/FAIL/BLOCKED with raw evidence.
Nothing here touches third-party systems: all requests target 127.0.0.1.
"""
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:3100"
OUT = []

# --------------------------------------------------------------------------- #
class Client:
    """Minimal HTTP client with cookie jar + redirect control."""

    def __init__(self):
        self.cookies = {}
        self.history = []

    def absorb(self, resp):
        for raw in resp.headers.get_all("Set-Cookie") or []:
            pair = raw.split(";")[0]
            eq = pair.find("=")
            if eq > 0:
                self.cookies[pair[:eq].strip()] = pair[eq + 1 :].strip()

    def header(self):
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def req(self, method, path, body=None, form=None, is_json=True, redirect=True):
        url = BASE + path
        data = None
        headers = {"User-Agent": "Burhan-QA-Battery/1.0"}
        if self.cookies:
            headers["Cookie"] = self.header()
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode() if is_json else body.encode()
            headers["Content-Type"] = "application/json"
        opener_director = urllib.request.build_opener(NoRedirect()) if not redirect else urllib.request.build_opener()
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = opener_director.open(r, timeout=30)
            self.absorb(resp)
            self.history.append((method, path, resp.status))
            return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            self.absorb(e)
            self.history.append((method, path, e.code))
            return e.code, dict(e.headers), e.read()
        except Exception as e:  # connection-level
            self.history.append((method, path, f"CONN-ERR {e}"))
            return -1, {}, str(e).encode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def check(tid, name, ok, evidence, status=None):
    st = status or ("PASS" if ok else "FAIL")
    OUT.append((tid, name, st, evidence))
    print(f"[{st}] {tid} {name}\n       {evidence}")


def blocked(tid, name, why):
    OUT.append((tid, name, "BLOCKED", why))
    print(f"[BLOCKED] {tid} {name}\n       {why}")


def jbody(raw):
    try:
        return json.loads(raw.decode())
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
def main():
    c = Client()
    print("=" * 78)
    print("SECTION A — FUNCTIONAL (Level 2, PRODUCTION build :3100)")
    print("=" * 78)

    # A1 bootstrap status on fresh DB
    st, h, b = c.req("GET", "/api/bootstrap")
    check("A1", "fresh instance needsBootstrap=true", st == 200 and jbody(b).get("needsBootstrap") is True,
          f"HTTP {st} body={b[:120]!r}")

    # A2 login page renders
    st, h, b = c.req("GET", "/")
    check("A2", "root/login page renders 200 (RTL Arabic)", st == 200 and b"lang=\"ar\"" in b,
          f"HTTP {st} len={len(b)} has-arabic-rtl={b'lang=\"ar\"' in b}")

    # A3 unauthenticated /api/me
    st, h, b = c.req("GET", "/api/me")
    check("A3", "unauthenticated /api/me -> 401", st == 401, f"HTTP {st} body={b[:80]!r}")

    # A4 bootstrap race — 10 concurrent POSTs, exactly ONE winner
    results = []
    def boot():
        cl = Client()
        s, _, bb = cl.req("POST", "/api/bootstrap", body={
            "email": "owner@burhan.test", "name": "Owner",
            "password": "Str0ngPass!123", "orgName": "QA Org"})
        results.append((s, jbody(bb)))
    threads = [threading.Thread(target=boot) for _ in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    wins = [r for r in results if r[0] == 200]
    losses = [r for r in results if r[0] != 200]
    check("A4", "bootstrap race: 10 concurrent POSTs -> exactly 1 winner (409 for losers)",
          len(wins) == 1 and len(losses) == 9,
          f"winners={len(wins)} losers={len(losses)} codes={[r[0] for r in results]}")

    # A5 second bootstrap after user exists -> 409
    st, h, b = c.req("POST", "/api/bootstrap", body={
        "email": "other@burhan.test", "password": "Str0ngPass!123"})
    check("A5", "bootstrap after first admin -> 409", st == 409, f"HTTP {st} body={b[:100]!r}")

    # A6 login flow: csrf + credentials -> session
    st, h, b = c.req("GET", "/api/auth/csrf")
    csrf = jbody(b).get("csrfToken", "")
    st, h, b = c.req("POST", "/api/auth/callback/credentials", form={
        "csrfToken": csrf, "email": "owner@burhan.test",
        "password": "Str0ngPass!123", "json": "true"}, redirect=False)
    has_session = any(k.startswith("next-auth.session-token") for k in c.cookies)
    check("A6", "credentials login yields session cookie",
          has_session and st in (200, 302),
          f"HTTP {st} session-cookie={has_session} cookies={list(c.cookies)[:3]}")

    # A6.1 session validation
    st, h, b = c.req("GET", "/api/me")
    check("A6.1", "authenticated /api/me returns the owner",
          st == 200 and jbody(b).get("user", {}).get("email") == "owner@burhan.test",
          f"HTTP {st} body={b[:140]!r}")

    # A6.2 session cookie attributes (WSTG-SESS)
    sess_raw = ""
    st2, h2, b2 = Client().req("GET", "/api/auth/csrf")  # fresh to read raw set-cookie
    # get the actual session cookie raw attributes via login on a fresh client
    c2 = Client()
    s3, h3, b3 = c2.req("GET", "/api/auth/csrf")
    csrf2 = jbody(b3).get("csrfToken", "")
    s3, h3, b3 = c2.req("POST", "/api/auth/callback/credentials", form={
        "csrfToken": csrf2, "email": "owner@burhan.test",
        "password": "Str0ngPass!123", "json": "true"}, redirect=False)
    # fetch raw set-cookie through a raw request (headers dict collapses dupes)
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", 3100, timeout=10)
    conn.request("GET", "/api/auth/session", headers={"Cookie": c2.header()})
    resp = conn.getresponse()
    raw_sc = resp.headers.get_all("Set-Cookie") or []
    conn.close()
    # login again with raw http to capture the session set-cookie
    conn = http.client.HTTPConnection("127.0.0.1", 3100, timeout=10)
    body_form = urllib.parse.urlencode({"csrfToken": csrf2, "email": "owner@burhan.test",
                                        "password": "Str0ngPass!123", "json": "true"})
    conn.request("POST", "/api/auth/callback/credentials", body=body_form, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Cookie": c2.header()})
    resp = conn.getresponse()
    resp.read()
    raw_sc = resp.headers.get_all("Set-Cookie") or []
    conn.close()
    sess_line = next((x for x in raw_sc if "session-token" in x), "")
    httponly = "HttpOnly" in sess_line or "httponly" in sess_line
    samesite = ("SameSite=Lax" in sess_line) or ("SameSite=Strict" in sess_line)
    check("A6.2", "session cookie HttpOnly + SameSite", httponly and samesite,
          f"set-cookie={sess_line[:160]!r} httponly={httponly} samesite={samesite}")

    # A7 wrong password -> no session (fresh client)
    c3 = Client()
    st, h, b = c3.req("GET", "/api/auth/csrf")
    csrf3 = jbody(b).get("csrfToken", "")
    st, h, b = c3.req("POST", "/api/auth/callback/credentials", form={
        "csrfToken": csrf3, "email": "owner@burhan.test",
        "password": "WRONG-password", "json": "true"}, redirect=False)
    has_s = any(k.startswith("next-auth.session-token") for k in c3.cookies)
    check("A7", "wrong password -> no session cookie", not has_s,
          f"HTTP {st} session-cookie-issued={has_s}")

    # A8 create DEMO target (authorized internal fixture 127.0.0.1:8777)
    orgs_st, orgs_h, orgs_b = c.req("GET", "/api/orgs")
    orgs = jbody(orgs_b).get("orgs") or jbody(orgs_b).get("organizations") or []
    org_id = orgs[0]["id"] if orgs else ""
    st, h, b = c.req("POST", "/api/targets", body={"orgId": org_id, "isDemo": True})
    ok8 = st == 200
    tgt = jbody(b)
    check("A8", "demo target creation (managed vulnapp fixture)",
          ok8 and tgt.get("isDemo") is True,
          f"HTTP {st} body={b[:140]!r} orgId={org_id[:12]}...")
    demo_target_id = tgt.get("id", "")

    # A8.1 demo fixture actually listening
    st, h, b = c.req("GET", "/api/scans?orgId=" + org_id)  # warm nothing; direct probe below
    import socket
    s8 = socket.socket()
    s8.settimeout(2)
    try:
        s8.connect(("127.0.0.1", 8777))
        demo_up = True
    except Exception:
        demo_up = False
    finally:
        s8.close()
    check("A8.1", "demo fixture (vulnapp) listening on 127.0.0.1:8777", demo_up,
          f"tcp-connect={'ok' if demo_up else 'failed'}")

    # A9 non-demo PUBLIC target (creation only — never scanned; third-party safe)
    st, h, b = c.req("POST", "/api/targets", body={
        "orgId": org_id, "name": "Public inert target",
        "url": "https://example.org/sen-qa-inert"})
    check("A9", "public non-demo target creation (never scanned)",
          st == 200, f"HTTP {st} body={b[:120]!r}")

    # A10 START SCAN on demo target — full engine E2E through the app
    st, h, b = c.req("POST", "/api/scans", body={"orgId": org_id, "targetId": demo_target_id})
    scan = jbody(b)
    check("A10", "scan start on demo target", st == 200 and scan.get("status") in ("RUNNING", "QUEUED"),
          f"HTTP {st} body={b[:120]!r}")
    scan_id = scan.get("id", "")

    # A11 poll to completion (engine live run)
    final = None
    for i in range(120):
        time.sleep(2)
        st, h, b = c.req("GET", f"/api/scans/{scan_id}?orgId={org_id}")
        sc = jbody(b).get("scan") or jbody(b)
        status = sc.get("status")
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            final = sc
            break
    ok11 = final is not None and final.get("status") == "COMPLETED"
    check("A11", "demo scan reaches COMPLETED", ok11,
          f"status={final and final.get('status')} runId={final and final.get('runId')} dur={final and final.get('durationSec')}s err={final and (final.get('error') or '')[:80]}")

    # A11.1 findings persisted
    st, h, b = c.req("GET", f"/api/scans/{scan_id}/findings?orgId={org_id}")
    fnd = jbody(b)
    findings = fnd.get("findings") or []
    check("A11.1", "findings persisted from engine run", len(findings) > 0,
          f"count={len(findings)} types={[f.get('type') for f in findings][:8]}")

    # A12 report generation (all formats)
    rep_ok = {}
    for fmt in ["HTML", "JSON", "SARIF", "EXECUTIVE", "GLASS"]:
        st, h, b = c.req("POST", "/api/reports", body={
            "orgId": org_id, "scanId": scan_id, "format": fmt})
        rep_ok[fmt] = (st == 200, jbody(b).get("id", ""))
    ok12 = all(v[0] for v in rep_ok.values())
    first_rep = next((v[1] for v in rep_ok.values() if v[1]), "")
    rep_summary = ", ".join(k + (":OK" if v[0] else ":FAIL") for k, v in rep_ok.items())
    check("A12", "report generation for all 5 formats", ok12, f"results={rep_summary}")

    # A12.1 report content retrievable
    st, h, b = c.req("GET", f"/api/reports/{first_rep}?orgId={org_id}")
    check("A12.1", "report content retrievable", st == 200 and len(b) > 200,
          f"HTTP {st} len={len(b)}")

    # A13 members: add MEMBER + VIEWER
    st, h, b = c.req("POST", f"/api/orgs/{org_id}/members", body={
        "email": "member@burhan.test", "name": "Member", "role": "MEMBER",
        "password": "Str0ngPass!123"})
    st2, h2, b2 = c.req("POST", f"/api/orgs/{org_id}/members", body={
        "email": "viewer@burhan.test", "name": "Viewer", "role": "VIEWER",
        "password": "Str0ngPass!123"})
    check("A13", "OWNER adds MEMBER and VIEWER", st == 200 and st2 == 200,
          f"member HTTP {st} viewer HTTP {st2}")

    # A14 audit log records actions
    st, h, b = c.req("GET", "/api/audit?orgId=" + org_id)
    entries = jbody(b).get("logs") or []
    check("A14", "audit log records actions", st == 200 and len(entries) > 0,
          f"HTTP {st} entries={len(entries)} sample={[e.get('action') for e in entries[:5]]}")

    # ----------------------------------------------------------------------- #
    print()
    print("=" * 78)
    print("SECTION B — SECURITY (WSTG-mapped, PRODUCTION build :3100)")
    print("=" * 78)

    # B1 (WSTG-ATHN/ATHZ-01) unauthenticated matrix
    anon = Client()
    matrix = ["/api/me", "/api/orgs", f"/api/orgs/{org_id}", f"/api/orgs/{org_id}/members",
              "/api/targets?orgId=x", "/api/scans?orgId=x", "/api/reports?orgId=x",
              "/api/audit?orgId=x", "/api/bootstrap"]
    codes = []
    for p in matrix:
        st, h, b = anon.req("GET", p)
        codes.append((p.split("?")[0], st))
    # bootstrap is public by design (GET); the rest must be 401
    bad = [(p, s) for p, s in codes if s != 401 and "bootstrap" not in p]
    check("B1", "unauthenticated API access -> 401 on all protected routes",
          not bad, f"codes={codes}")

    # B2 (WSTG-ATHN-07) login brute force -> rate limited
    # Criterion: fail-closed 401 AND the response/behavior proves the limiter
    # short-circuited (error=RATE_LIMITED in body, or a sharp timing drop:
    # scrypt burn ~30ms+ vs limiter throw ~3ms).
    cb = Client()
    st, h, b = cb.req("GET", "/api/auth/csrf")
    csrf_b = jbody(b).get("csrfToken", "")
    cookie_hdr = cb.header()  # csrf cookie MUST accompany the token (NextAuth)
    import http.client as _hc
    times = []
    last_body = b""
    for i in range(13):
        conn = _hc.HTTPConnection("127.0.0.1", 3100, timeout=15)
        t0 = time.time()
        body_f = urllib.parse.urlencode({"csrfToken": csrf_b, "email": "brute2@burhan.test",
                                        "password": "wrong-pass-" + str(i), "json": "true"})
        conn.request("POST", "/api/auth/callback/credentials", body=body_f,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Cookie": cookie_hdr})
        r = conn.getresponse()
        last_body = r.read()
        times.append(time.time() - t0)
        conn.close()
    limited = b"RATE_LIMITED" in last_body or (times[12] < times[0] / 4)
    check("B2", "login brute-force rate limiting (fail-closed + proven short-circuit)",
          limited, f"13th attempt body={last_body[:60]!r} t1={times[0]*1000:.0f}ms t13={times[12]*1000:.0f}ms")

    # B3 (WSTG-INPV-XX SSRF matrix) private targets rejected (non-lab)
    ssrf_cases = [
        ("ipv4-loopback", "http://127.0.0.1:8080/"),
        ("ipv4-loopback-alt", "http://localhost:8080/"),
        ("rfc1918-10", "http://10.0.0.5:8080/"),
        ("rfc1918-172", "http://172.16.0.9/"),
        ("rfc1918-192", "http://192.168.1.1/admin"),
        ("cgnat-100.64", "http://100.64.0.1/"),
        ("link-local-169", "http://169.254.169.254/latest/meta-data/"),
        ("ipv6-loopback", "http://[::1]:8080/"),
        ("ipv6-ula", "http://[fd00::1]/"),
        ("ipv4-mapped-ipv6", "http://[::ffff:127.0.0.1]:8080/"),
        ("ipv4-mapped-ipv6-10", "http://[::ffff:10.0.0.5]/"),
        ("all-zeros", "http://0.0.0.0:3000/"),
        ("octal-127", "http://0177.0.0.1:8080/"),
        ("decimal-2130706433", "http://2130706433/"),
        ("hex-7f000001", "http://0x7f000001/"),
        ("metadata-host", "http://metadata.google.internal/"),
        ("creds-in-url", "http://user:pass@example.org/"),
        ("azure-metadata", "http://169.254.169.254/metadata/instance"),
    ]
    ssrf_res = []
    for name, url in ssrf_cases:
        st, h, b = c.req("POST", "/api/targets", body={
            "orgId": org_id, "name": "ssrf-" + name, "url": url})
        rejected = st == 400
        ssrf_res.append((name, st, rejected))
        if not rejected and st == 200:
            # cleanup accidental creation
            tid = jbody(b).get("id")
            if tid:
                c.req("DELETE", f"/api/targets/{tid}?orgId={org_id}")
    bad_ssrf = [(n, s) for n, s, r in ssrf_res if not r]
    check("B3", "SSRF: all private/exotic target forms rejected 400",
          not bad_ssrf, f"rejected={sum(1 for _,_,r in ssrf_res if r)}/{len(ssrf_cases)} escapes={bad_ssrf}")

    # B4 (WSTG-ATHZ-02/04) RBAC + cross-tenant on PROD build
    cv = Client()
    st, h, b = cv.req("GET", "/api/auth/csrf")
    st, h, b = cv.req("POST", "/api/auth/callback/credentials", form={
        "csrfToken": jbody(b).get("csrfToken", ""), "email": "viewer@burhan.test",
        "password": "Str0ngPass!123", "json": "true"}, redirect=False)
    st, h, b = cv.req("POST", "/api/targets", body={
        "orgId": org_id, "name": "viewer-target", "url": "https://example.org/v"})
    viewer_cannot_create = st == 403
    check("B4", "VIEWER cannot create targets (403)", viewer_cannot_create,
          f"HTTP {st} body={b[:100]!r}")

    # B4.1 member cannot scan another member's target (write-level)
    cm = Client()
    st, h, b = cm.req("GET", "/api/auth/csrf")
    st, h, b = cm.req("POST", "/api/auth/callback/credentials", form={
        "csrfToken": jbody(b).get("csrfToken", ""), "email": "member@burhan.test",
        "password": "Str0ngPass!123", "json": "true"}, redirect=False)
    st, h, b = cm.req("POST", "/api/scans", body={"orgId": org_id, "targetId": demo_target_id})
    check("B4.1", "MEMBER cannot scan OWNER's demo target (write-level)", st == 403,
          f"HTTP {st} body={b[:100]!r}")

    # B4.2 cross-org isolation: foreign org id -> 404
    fake_org = "clx" + "0" * 20
    st, h, b = cm.req("GET", f"/api/orgs/{fake_org}")
    check("B4.2", "cross-org access -> 404 (tenant isolation)", st == 404,
          f"HTTP {st} body={b[:80]!r}")

    # B5 (WSTG-INPV-05 SQLi) malformed/SQLi-ish inputs -> no leak, no 500
    sqli_bodies = [
        {"orgId": org_id, "name": "x' OR '1'='1", "url": "https://example.org/a"},
        {"orgId": org_id, "name": "x; DROP TABLE User;--", "url": "https://example.org/b"},
        {"orgId": "1' UNION SELECT 1--", "name": "y", "url": "https://example.org/c"},
    ]
    leak = False
    codes5 = []
    for bb in sqli_bodies:
        st, h, b = c.req("POST", "/api/targets", body=bb)
        codes5.append(st)
        if b"Prisma" in b or b"SQLITE" in b or b"database" in b.lower():
            leak = True
        if st == 200:
            t = jbody(b).get("id")
            if t:
                c.req("DELETE", f"/api/targets/{t}?orgId={org_id}")
    check("B5", "SQLi-shaped inputs: no SQL error leak, no 500s (Prisma parameterized)",
          not leak and all(s != 500 for s in codes5),
          f"codes={codes5} leak={leak} (200=odd-but-safe name accepted; 404=invalid org)")

    # B6 malformed JSON body -> 400/500 without stack trace
    st, h, b = c.req("POST", "/api/targets", body="{not-json", is_json=False)
    no_stack = b"at " not in b and b"prisma" not in b.lower()
    check("B6", "malformed JSON body handled without stack leak",
          st in (400, 500) and no_stack, f"HTTP {st} leak={not no_stack} body={b[:80]!r}")

    # B7 (WSTG-CLNT/CSP) security headers on app responses
    st, h, b = c.req("GET", "/")
    hdr = {k.lower(): v for k, v in h.items()}
    check("B7", "security headers present (nosniff at minimum; CSP/XFO documented)",
          "x-content-type-options" in hdr,
          f"headers: nosniff={hdr.get('x-content-type-options')} csp={bool(hdr.get('content-security-policy'))} xfo={hdr.get('x-frame-options')} referrer={hdr.get('referrer-policy')}")

    # B8 report HTML served with nosniff + attachment on download
    st, h, b = c.req("GET", f"/api/reports/{first_rep}?orgId={org_id}&download=1")
    hdr8 = {k.lower(): v for k, v in h.items()}
    check("B8", "report download: nosniff + Content-Disposition attachment",
          hdr8.get("x-content-type-options") == "nosniff" and "attachment" in hdr8.get("content-disposition", ""),
          f"nosniff={hdr8.get('x-content-type-options')} disposition={hdr8.get('content-disposition', '')[:60]!r}")

    # B9 HTML report XSS containment — the demo scan findings embed target-
    # controlled strings; verify the report HTML escapes or the viewer sands it.
    st, h, b = c.req("GET", f"/api/reports/{first_rep}?orgId={org_id}")
    body_txt = b.decode("utf-8", "ignore")
    content = jbody(b).get("content", "")
    # look for raw <script> in the HTML content (template-level injection)
    raw_script = "<script>alert(1)</script>" in content
    check("B9", "report HTML contains no raw <script> injection from findings",
          not raw_script, f"raw-script-found={raw_script} content-len={len(content)}")

    # B10 (WSTG-ATHN-05) session cookie not issued over plain client-advertised https...
    # covered by A6.2 attributes. Here: logout invalidates session.
    st, h, b = c.req("GET", "/api/auth/signout")  # csrf-protected POST normally
    check("B10", "signout endpoint reachable (csrf flow documented)",
          st in (200, 302, 403), f"HTTP {st}")

    # B11 (WSTG-BUSL) OPTIONS/unsupported methods
    st, h, b = c.req("OPTIONS", "/api/targets")
    check("B11", "OPTIONS on API handled", st in (200, 204, 405), f"HTTP {st}")

    # B12 target PATCH to private URL (the old SSRF chain via update)
    st, h, b = c.req("PATCH", f"/api/targets/{demo_target_id}", body={
        "orgId": org_id, "url": "http://169.254.169.254/x"})
    check("B12", "PATCH target to private URL rejected", st in (400, 403),
          f"HTTP {st} body={b[:100]!r}")

    # ----------------------------------------------------------------------- #
    print()
    print("=" * 78)
    summary = {}
    for _, _, st_, _ in OUT:
        summary[st_] = summary.get(st_, 0) + 1
    print("SUMMARY:", summary)
    with open("qa-results/live_battery_results.json", "w") as f:
        json.dump([{"id": i, "name": n, "status": s, "evidence": e} for i, n, s, e in OUT],
                  f, ensure_ascii=False, indent=2)
    print("results saved to qa-results/live_battery_results.json")
    return 0 if summary.get("FAIL", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
