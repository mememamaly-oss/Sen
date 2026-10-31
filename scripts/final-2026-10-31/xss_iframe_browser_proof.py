#!/usr/bin/env python3
"""REAL-BROWSER XSS + iframe-sandbox proof (owner order 2026-10-31, 2.3+2.4).

Drives Chromium through the real app:
  1. login through the UI,
  2. open the finding whose evidence/parameter/url carry <script> and
     onerror payloads planted by a malicious scanned target -> the payload
     must render as TEXT, never execute,
  3. open the report viewer whose "engine-generated" HTML is deliberately
     hostile -> the iframe must be sandbox="" and neither the embedded
     script nor the nested iframe may reach the parent document.

Usage: python3 xss_iframe_browser_proof.py <findingId> <reportId>
"""
import json
import sys
import time

BASE = "http://127.0.0.1:3199"
RESULTS = []


def check(name, ok, evidence):
    RESULTS.append({"name": name, "ok": ok, "evidence": evidence})
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {evidence}", flush=True)


def main():
    finding_id, report_id = sys.argv[1], sys.argv[2]
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        # ---- login through the real UI ----
        page.goto(f"{BASE}/login", wait_until="networkidle")
        # discover a working admin by actually TRYING each candidate:
        # bola-admin (solo runs) else the bootstrap winner racer0
        # (main-suite runs) — same doctrine as the test suites.
        logged_in = False
        for email, pw in (("bola-admin@integration.test", "Bola-Admin-Passw0rd!"),
                          ("racer0@integration.test", "Racer-Passw0rd!")):
            page.fill('#email', email, timeout=5000)
            page.fill('#pw', pw, timeout=5000)
            page.click('button[type="submit"]')
            try:
                page.wait_for_url(lambda u: "/login" not in u, timeout=8000)
                logged_in = True
                break
            except Exception:
                continue
        assert logged_in, "no admin credentials worked"
        check("UI login as the seeded admin", "/login" not in page.url, page.url)

        # ---- 2.3: the poisoned finding detail page ----
        page.goto(f"{BASE}/findings/{finding_id}", wait_until="networkidle")
        page.wait_for_selector("text=xss_reflected", timeout=15000)
        time.sleep(0.8)  # let any would-be script run
        pwned = page.evaluate("() => window.__xssPwned ?? null")
        attr = page.evaluate("() => window.__attrPwned ?? null")
        check("2.3 finding page: <script> payload did NOT execute", pwned is None, f"window.__xssPwned = {pwned}")
        check("2.3 finding page: onerror payload did NOT execute", attr is None, f"window.__attrPwned = {attr}")
        # the payload must be VISIBLE as escaped text (data is shown, safely)
        body_text = page.evaluate("() => document.body.innerText")
        check("2.3 finding page: payload rendered as TEXT",
              "<script>window.__xssPwned=1</script>" in body_text,
              "the raw payload string appears in innerText (escaped by React)")
        script_in_dom = page.evaluate(
            "() => [...document.querySelectorAll('script')].filter(s => s.textContent.includes('__xssPwned')).length")
        check("2.3 finding page: no injected <script> element in the DOM", script_in_dom == 0, f"count={script_in_dom}")

        # ---- 2.4: the hostile report in the sandboxed iframe ----
        page.goto(f"{BASE}/reports/{report_id}", wait_until="networkidle")
        page.wait_for_selector("iframe", timeout=15000)
        time.sleep(1.2)  # let any would-be escape run
        sandbox = page.evaluate("() => document.querySelector('iframe')?.getAttribute('sandbox')")
        check("2.4 report viewer: iframe sandbox attribute is exactly the empty string",
              sandbox == "", f"sandbox={sandbox!r}")
        parent_pwned = page.evaluate("() => document.body.getAttribute('data-pwned')")
        check("2.4 report viewer: hostile script could NOT touch the parent document",
              parent_pwned is None, f"parent data-pwned = {parent_pwned}")
        title = page.title()
        check("2.4 report viewer: nested iframe could NOT reach top document", "PWNED" not in title, f"title={title!r}")
        # opaque-origin proof: the iframe's own document must not be same-origin
        # with the app (reading it cross-origin throws)
        opaque = page.evaluate(
            """() => { try { const f = document.querySelector('iframe');
                     const x = f.contentDocument; return x === null ? 'null (opaque origin)' : 'READABLE'; }
                   catch (e) { return 'blocked (' + e.name + ')'; } }""")
        check("2.4 report viewer: iframe origin is opaque to the app",
              opaque != "READABLE", f"contentDocument = {opaque}")

        browser.close()

    ok = all(r["ok"] for r in RESULTS)
    print(json.dumps({"all_pass": ok, "checks": RESULTS}, indent=1))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
