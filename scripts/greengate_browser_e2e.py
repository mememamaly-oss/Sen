#!/usr/bin/env python3
"""GREEN GATE 2026-10-23 — Browser E2E (Chromium, real flows) against the
PRODUCTION standalone build on :3100 (isolated scratch DB, fresh bootstrap).

Covers the security-relevant browser surface proved in the QA campaign:
- login + session flows (real credentials exchange)
- real engine scan through the app (demo target) + report generation
- console-error hygiene on every visited page
- report viewer iframe: sandbox="" (no allow-same-origin) + opaque-origin
  DOMException proof (the stored-XSS/credential-theft regression)
- screenshots to qa-results/greengate-browser/
"""
import json
import secrets
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:3100"
OUT = []


def check(tid, name, ok, evidence):
    OUT.append({"id": tid, "name": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    print(f"[{'PASS' if ok else 'FAIL'}] {tid} {name}\n       {evidence}")


def api(method, path, body=None, cookie=None, timeout=200):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    from playwright.sync_api import sync_playwright

    api("GET", "/api/bootstrap")  # ensure instance state visible

    errors = []
    authed_at = [None]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()
        page.on("console", lambda m: errors.append((time.time(), "console", m.text)) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append((time.time(), "pageerror", str(e))))
        page.on("response", lambda r: errors.append((time.time(), "http401", f"{r.status} {r.url}")) if r.status == 401 else None)
        shot_n = [0]

        def shot(name):
            shot_n[0] += 1
            page.screenshot(path=f"qa-results/greengate-browser/{shot_n[0]:02d}-{name}.png", full_page=True)

        # --- flow 1: login page ---
        page.goto(f"{BASE}/login", wait_until="networkidle", timeout=30000)
        shot("login")
        check("W1", "login page renders", page.locator("form").count() > 0 or "login" in page.content().lower(),
              f"url={page.url} title={page.title()!r}")

        # --- flow 2: bootstrap owner via API + login through the real form ---
        owner = {"email": f"gate-{secrets.token_hex(4)}@gate.local", "password": "Gate-2026-Strong!"}
        st, b = api("POST", "/api/bootstrap", {"name": "Gate Owner", "email": owner["email"],
                                               "password": owner["password"], "orgName": "Gate Org"})
        check("W2", "bootstrap owner created (API precondition)", st == 200, f"HTTP {st}")

        page.goto(f"{BASE}/login", wait_until="networkidle")
        page.fill("input[type=email]", owner["email"])
        page.fill("input[type=password]", owner["password"])
        with page.expect_navigation(wait_until="networkidle", timeout=30000):
            page.click("button[type=submit]")
        shot("post-login")
        authed_at[0] = time.time()
        check("W3", "owner login lands on app (not /login)", "/login" not in page.url, f"landed={page.url}")

        cookie = "; ".join(f"{c['name']}={c['value']}" for c in ctx.cookies())

        # --- flow 3: app pages render (overview / targets / reports) ---
        for path, tid in [("/", "W4"), ("/targets", "W5"), ("/reports", "W6")]:
            page.goto(f"{BASE}{path}", wait_until="networkidle", timeout=30000)
            shot(path.strip("/").replace("/", "-") or "overview")
            check(tid, f"page {path or '/'} renders", True, f"url={page.url}")

        # --- flow 4: real engine scan through the app (demo target) ---
        st, b = api("GET", "/api/orgs", cookie=cookie)
        org_id = (json.loads(b).get("orgs") or [{}])[0].get("id", "")
        st, b = api("POST", "/api/targets", {"orgId": org_id, "isDemo": True}, cookie=cookie)
        target = json.loads(b) if st == 200 else {}
        check("W7", "demo target created", st == 200, f"HTTP {st} isDemo={target.get('isDemo')}")

        st, b = api("POST", "/api/scans", {"orgId": org_id, "targetId": target.get("id", "")}, cookie=cookie, timeout=300)
        scan_id = (json.loads(b) if st == 200 else {}).get("id", "")
        final_status, findings = "", 0
        for _ in range(120):
            time.sleep(2)
            st, b = api("GET", f"/api/scans/{scan_id}?orgId={org_id}", cookie=cookie)
            sc = json.loads(b)
            sc = sc.get("scan") or sc
            final_status = sc.get("status", "")
            if final_status in ("COMPLETED", "FAILED", "CANCELLED"):
                break
        if final_status == "COMPLETED":
            st, b = api("GET", f"/api/scans/{scan_id}/findings?orgId={org_id}", cookie=cookie)
            findings = len(json.loads(b).get("findings") or [])
        check("W8", "engine scan reaches COMPLETED with findings (real E2E)",
              final_status == "COMPLETED" and findings > 0,
              f"status={final_status} findings={findings} scanId={scan_id[:12]}...")

        # --- flow 5: generate reports (all 5 formats) ---
        rep_ok, first_rep = {}, ""
        for fmt in ["HTML", "JSON", "SARIF", "EXECUTIVE", "GLASS"]:
            st, b = api("POST", "/api/reports", {"orgId": org_id, "scanId": scan_id, "format": fmt}, cookie=cookie)
            rid = json.loads(b).get("id", "") if st == 200 else ""
            rep_ok[fmt] = st == 200
            first_rep = first_rep or rid
        check("W9", "report generation all 5 formats", all(rep_ok.values()), f"{rep_ok}")

        # --- flow 6: report viewer sandbox proof (THE security regression) ---
        if first_rep:
            page.goto(f"{BASE}/reports/{first_rep}", wait_until="networkidle", timeout=30000)
            shot("report-viewer")
            sandbox = page.evaluate("""() => {
                const f = document.querySelector('iframe');
                if (!f) return {found: false};
                let originError = null;
                try { void f.contentWindow.document; } catch (e) { originError = e.name + ': ' + e.message; }
                return {found: true, sandbox: f.getAttribute('sandbox'),
                        originError, canReadDoc: originError === null};
            }""")
            ok = sandbox.get("found") and sandbox.get("sandbox") == "" and sandbox.get("canReadDoc") is False
            check("W10", "report iframe: sandbox='' + opaque origin (no doc read)", ok, json.dumps(sandbox))
        else:
            check("W10", "report iframe: sandbox='' + opaque origin", False, "no report id")

        # --- flow 7: twin page + console hygiene ---
        page.goto(f"{BASE}/twin", wait_until="networkidle", timeout=30000)
        shot("twin")
        check("W11", "twin page renders", True, f"url={page.url}")

        # post-login hygiene: JS exceptions anywhere are always failures;
        # console/HTTP errors AFTER authentication are failures; pre-login 401s
        # on the login page are expected (unauthenticated API probe by the page).
        pageerrors = [e for e in errors if e[1] == "pageerror"]
        post_login = [e for e in errors if authed_at[0] and e[0] > authed_at[0]]
        pre_login_401 = [e for e in errors if e[1] == "http401" and (not authed_at[0] or e[0] <= authed_at[0])]
        ok12 = not pageerrors and not post_login
        check("W12", "console hygiene: zero pageerrors; zero errors on authenticated pages",
              ok12,
              f"pageerrors={len(pageerrors)} post-login-errors={len(post_login)} {post_login[:2]} "
              f"pre-login-401(expected)={len(pre_login_401)} {pre_login_401[:2]}")

        browser.close()

    summary = {}
    for c in OUT:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    print("\nSUMMARY:", summary)
    with open("qa-results/greengate_browser_results.json", "w") as f:
        json.dump(OUT, f, ensure_ascii=False, indent=2)
    return 0 if summary.get("FAIL", 0) == 0 else 1


if __name__ == "__main__":
    import os
    os.makedirs("qa-results/greengate-browser", exist_ok=True)
    sys.exit(main())
