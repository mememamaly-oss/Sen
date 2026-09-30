#!/usr/bin/env python3
"""Phase 1e — registration with a pattern-compliant password; full proof chain."""
import re, urllib.request, urllib.error, urllib.parse, json
from http.cookiejar import CookieJar

WG = "http://127.0.0.1:8080/WebGoat"
UA = "Mozilla/5.0 SENTINEL-probe/3.0.0"

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

USER = "sentinel9x"
PASS = "sentinel-live-2026"

jar = CookieJar()
http(f"{WG}/login", jar=jar)
payload = {"username": USER, "password": PASS, "matchingPassword": PASS, "agree": "on"}
c, b, h = http(f"{WG}/register.mvc", data=urllib.parse.urlencode(payload).encode(), jar=jar, follow=False)
print("register.mvc:", c, "->", h.get("Location", "") or "(re-rendered)")
if c == 200:
    for m in re.finditer(r"error", b):
        s = max(0, m.start() - 80)
        seg = re.sub(r"\s+", " ", b[s:m.start() + 160])
        print("   ctx:", seg[:220])
        break

jar = CookieJar()
http(f"{WG}/login", jar=jar)
c, b, h = http(f"{WG}/login", data=urllib.parse.urlencode({"username": USER, "password": PASS}).encode(), jar=jar, follow=False)
print("login POST:", c, "->", h.get("Location", ""))
c, b, _ = http(f"{WG}/welcome.mvc", jar=jar)
t = re.search(r"<title>(.*?)</title>", b, re.S)
authed = (t and "Login" not in t.group(1))
print("welcome:", c, "| title:", t.group(1).strip()[:50] if t else "-", "| authenticated:", bool(authed))

c, b, _ = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
try:
    menu = json.loads(b)
    print("lessonmenu lessons:", len(menu))
    print("  first:", json.dumps(menu[0])[:220] if menu else "-")
except Exception:
    print("lessonmenu not json (len", len(b), "):", b[:90].replace("\n", " "))

# authenticated lesson pages: real forms
for path in ["/sql-injection/lesson1", "/WebGoat/sql-injection/lesson1",
             "/WebGoat/SqlInjection/attack1"]:
    c, b, _ = http(f"{WG}{path}", jar=jar)
    forms = []
    for m in re.finditer(r"<form[^>]*(.*?)</form>", b, re.S | re.I):
        act = re.search(r"action=[\"']?([^\"' >]+)", m.group(0))
        flds = re.findall(r"name=[\"']?([^\"' >]+)", m.group(1))
        if "username" not in flds:
            forms.append({"action": act.group(1) if act else "?", "fields": flds[:8]})
    t = re.search(r"<title>(.*?)</title>", b, re.S)
    print(f"{path}: {c} | title={t.group(1).strip()[:40] if t else '-'} | real-forms={forms[:2]}")

# creds + auth recipe for the SENTINEL scan
recipe = {"user": USER, "password": PASS,
          "login_page": f"{WG}/login", "login_post": f"{WG}/login",
          "user_field": "username", "pass_field": "password",
          "register": f"{WG}/register.mvc"}
json.dump(recipe, open("/home/z/my-project/live-targets/creds.json", "w"), indent=1)
print("RECIPE:", json.dumps(recipe))
