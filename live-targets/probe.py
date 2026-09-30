#!/usr/bin/env python3
"""SENTINEL doctrine step 1 — MANUAL FEASIBILITY PROBES against the live
authorized targets (WebGoat :8080/WebGoat, WebWolf :9090/WebWolf) BEFORE any
production scan. Pure stdlib. Produces probe_result.json.
"""
import json, re, sys, urllib.request, urllib.error
from http.cookiejar import CookieJar

WG = "http://127.0.0.1:8080/WebGoat"
WW = "http://127.0.0.1:9090/WebWolf"
UA = "Mozilla/5.0 (X11; Linux x86_64) SENTINEL-probe/3.0.0"


def http(url, data=None, jar=None, headers=None, follow=True):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    if jar is not None:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    else:
        opener = urllib.request.build_opener()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    if not follow:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar) if jar else urllib.request.HTTPHandler(), NoRedirect)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = opener.open(req, timeout=10)
        return r.getcode(), r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return 0, f"__error__ {e}", {}


def form_fields(html):
    """extract (action, {name: type/value}) for every form"""
    out = []
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.S | re.I):
        body = m.group(1)
        act = re.search(r"action=[\"']?([^\"' >]+)", m.group(0))
        fields = {}
        for f in re.finditer(r"<input[^>]*>", body):
            tag = f.group(0)
            nm = re.search(r"name=[\"']?([^\"' >]+)", tag)
            if not nm:
                continue
            ty = re.search(r"type=[\"']?([^\"' >]+)", tag)
            vl = re.search(r"value=[\"']?([^\"' >]*)", tag)
            fields[nm.group(1)] = f"{ty.group(1) if ty else 'text'}:{vl.group(1) if vl else ''}"
        for f in re.finditer(r"<select[^>]*name=[\"']?([^\"' >]+)", body, re.I):
            fields.setdefault(f.group(1), "select:")
        out.append({"action": act.group(1) if act else "", "fields": fields})
    return out


def title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    return m.group(1).strip()[:80] if m else "-"


report = {"webgoat": {}, "webwolf": {}}

# ---------- WebGoat: login page structure ----------
jar = CookieJar()
code, body, hdrs = http(f"{WG}/login", jar=jar)
report["webgoat"]["login_get"] = {"code": code, "title": title(body), "forms": form_fields(body)}

# ---------- attempt seeded guest/guest ----------
def try_login(user, pw):
    data = {}
    for f in report["webgoat"]["login_get"]["forms"]:
        if any(k.startswith("username") for k in f["fields"]) or "user" in " ".join(f["fields"]).lower():
            data = {k: "" for k in f["fields"]}
            break
    data.update({"username": user, "password": pw})
    enc = urllib.parse.urlencode(data).encode()
    c, b, h = http(f"{WG}/login", data=enc, jar=jar)
    ok = ("login" not in (h.get("Location", "") or "")) and c in (200, 302) and ("Invalid" not in b and "error" not in b.lower()[:2000])
    landing = ""
    if c == 302:
        loc = h.get("Location", "")
        c2, b2, _ = http(loc if loc.startswith("http") else WG + loc, jar=jar)
        landing = title(b2)
        ok = c2 == 200
    return {"code": c, "ok": ok, "landing_title": landing, "set_cookie": "JSESSIONID" in json.dumps(hdrs) or True}

import urllib.parse
r = try_login("guest", "guest")
report["webgoat"]["login_guest"] = r

# guest failed -> register a dedicated account
if not r["ok"]:
    jar2 = CookieJar()
    c, b, h = http(f"{WG}/register", jar=jar2)
    forms = form_fields(b)
    report["webgoat"]["register_get"] = {"code": c, "forms": forms}
    fields = {}
    for f in forms:
        fields.update(f["fields"])
    payload = {"username": "sentinel1", "password": "Sentinel!Live1",
               "confirmPassword": "Sentinel!Live1", "email": "sentinel1@webwolf.example",
               "agree": "on"}
    payload = {k: v for k, v in payload.items() if k in fields or k in ("username", "password", "email")}
    enc = urllib.parse.urlencode(payload).encode()
    c, b, h = http(f"{WG}/register", data=enc, jar=jar2, follow=False)
    report["webgoat"]["register_post"] = {"code": c, "location": h.get("Location", "")}
    # login with the new account
    enc = urllib.parse.urlencode({"username": "sentinel1", "password": "Sentinel!Live1"}).encode()
    c, b, h = http(f"{WG}/login", data=enc, jar=jar2)
    report["webgoat"]["login_sentinel1"] = {"code": c, "title": title(b) if c == 200 else "", "ok": c == 200}
    report["webgoat"]["jar"] = "sentinel1"
    jar = jar2
    report["webgoat"]["login_guest"] = r

# ---------- authenticated landing + lesson menu shape ----------
c, b, h = http(f"{WG}/welcome.mvc", jar=jar)
report["webgoat"]["welcome"] = {"code": c, "title": title(b),
                                "lesson_links": len(re.findall(r"lesson", b, re.I))}

# ---------- WebWolf surface ----------
for path in ["/", "/mail", "/landing", "/files", "/images"]:
    c, b, h = http(f"{WW}{path}")
    report["webwolf"][f"get {path}"] = {"code": c, "title": title(b), "forms": form_fields(b)[:2]}

with open("/home/z/my-project/live-targets/probe_result.json", "w") as f:
    json.dump(report, f, indent=1)
print(json.dumps(report, indent=1))
