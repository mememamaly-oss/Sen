#!/usr/bin/env python3
"""Phase 1c — CORRECT registration (register.mvc + matchingPassword + agree),
login, authenticated-landing capture (marker for SENTINEL), WebWolf surface."""
import json, re, urllib.request, urllib.error, urllib.parse
from http.cookiejar import CookieJar

WG = "http://127.0.0.1:8080/WebGoat"
WW = "http://127.0.0.1:9090/WebWolf"
UA = "Mozilla/5.0 (X11; Linux x86_64) SENTINEL-probe/3.0.0"


def http(url, data=None, jar=None, follow=True):
    h = {"User-Agent": UA}
    hs = []
    if jar is not None:
        hs.append(urllib.request.HTTPCookieProcessor(jar))

    class NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    if not follow:
        hs.append(NR)
    op = urllib.request.build_opener(*hs) if hs else urllib.request.build_opener()
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = op.open(req, timeout=10)
        return r.getcode(), r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return 0, f"__error__ {e}", {}


jar = CookieJar()
CREDS = {"username": "sentinel1", "password": "Sentinel!Live1",
         "matchingPassword": "Sentinel!Live1", "agree": "agree"}

c, b, h = http(f"{WG}/register.mvc", data=urllib.parse.urlencode(CREDS).encode(), jar=jar, follow=False)
print("register.mvc POST:", c, "->", h.get("Location", ""))
if c == 200:
    print("  body err hint:", re.findall(r"(error|exists|invalid)[^<]{0,60}", b, re.I)[:3])

c, b, h = http(f"{WG}/login", data=urllib.parse.urlencode(
    {"username": "sentinel1", "password": "Sentinel!Live1"}).encode(), jar=jar, follow=False)
print("login POST:", c, "->", h.get("Location", ""))

c, b, _ = http(f"{WG}/welcome.mvc", jar=jar)
title = re.search(r"<title>(.*?)</title>", b, re.S)
print("welcome.mvc:", c, "| title:", title.group(1).strip()[:60] if title else "-",
      "| has Logout:", "logout" in b.lower(), "| has sentinel1:", "sentinel1" in b.lower())

c, b, _ = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
try:
    menu = json.loads(b)
    print("lessonmenu:", c, "| lessons:", len(menu))
    for m in menu[:4]:
        print("   -", m.get("name", "?"), "|", m.get("link", "?"))
except Exception as e:
    print("lessonmenu:", c, "| not-json:", b[:120])

# forms across the authenticated lesson surface (sample of 3 lesson pages)
samples = {}
for path in ["/WebGoat/sql-injection/lesson1", "/WebGoat/CrossSiteScripting/lesson1",
             "/WebGoat/PathTraversal/lesson1"]:
    c, b, _ = http(f"{WG}{path}", jar=jar)
    forms = []
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", b, re.S | re.I):
        act = re.search(r"action=[\"']?([^\"' >]+)", m.group(0))
        flds = re.findall(r"name=[\"']?([^\"' >]+)", m.group(1))
        forms.append({"action": act.group(1) if act else "", "fields": flds[:6]})
    samples[path] = {"code": c, "forms": forms}
    print(path, "->", c, forms)

# WebWolf authenticated-ish surface (it shares WebGoat's HSQLDB)
jarw = CookieJar()
c, b, _ = http(f"{WW}/landing")
links = sorted(set(re.findall(r"(?:href|src)=[\"'](/[^\"' ]*)", b)))[:15]
print("webwolf /landing:", c, "| links:", links)
for f in re.finditer(r"<form[^>]*>(.*?)</form>", b, re.S | re.I):
    act = re.search(r"action=[\"']?([^\"' >]+)", f.group(0))
    flds = re.findall(r"(?:name|placeholder)=[\"']?([^\"' >]+)", f.group(1))
    print("  webwolf form:", act.group(1) if act else "?", flds[:8])
c, b, _ = http(f"{WW}/mail", data=b"test=1")
print("webwolf POST /mail:", c, "| snippet:", re.sub(r"<[^>]+>", " ", b)[:160])

json.dump({"auth": "sentinel1/Sentinel!Live1", "register_endpoint": "/register.mvc",
           "login_endpoint": "/login", "samples": samples},
          open("/home/z/my-project/live-targets/auth_final.json", "w"), indent=1)
print("SAVED auth_final.json")
