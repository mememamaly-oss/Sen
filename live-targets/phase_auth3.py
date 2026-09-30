#!/usr/bin/env python3
"""Phase 1d — decisive registration: fresh username, exact error text dump."""
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

def err_blocks(html):
    out = []
    for m in re.finditer(r"<(div|span|p|li)[^>]*(class|id)=[\"'][^\"']*(error|alert|warn)[^\"']*[\"'][^>]*>(.*?)</\1>", html, re.S | re.I):
        txt = re.sub(r"<[^>]+>", " ", m.group(4))
        txt = re.sub(r"\s+", " ", txt).strip()
        if txt:
            out.append(txt[:200])
    return out[:6]

jar = CookieJar()
# step 1: GET the login page first (session + possible dynamic bits)
http(f"{WG}/login", jar=jar)

USER, PASS = "sentinel9x", "Sentinel!Live9"
for agree_val in ["on", "agree", "true"]:
    jar = CookieJar()
    http(f"{WG}/login", jar=jar)
    payload = {"username": USER, "password": PASS, "matchingPassword": PASS, "agree": agree_val}
    c, b, h = http(f"{WG}/register.mvc", data=urllib.parse.urlencode(payload).encode(), jar=jar, follow=False)
    print(f"register.mvc (agree={agree_val!r}):", c, "->", h.get("Location", "") or "(no loc)")
    if c == 200:
        print("   errors:", err_blocks(b))
        continue
    break

# login
jar = CookieJar()
http(f"{WG}/login", jar=jar)
c, b, h = http(f"{WG}/login", data=urllib.parse.urlencode({"username": USER, "password": PASS}).encode(), jar=jar, follow=False)
print("login POST:", c, "->", h.get("Location", ""))

c, b, _ = http(f"{WG}/welcome.mvc", jar=jar)
t = re.search(r"<title>(.*?)</title>", b, re.S)
print("welcome:", c, "| title:", t.group(1).strip()[:50] if t else "-", "| Logout:", "logout" in b.lower(), "| user:", USER in b)

c, b, _ = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
try:
    menu = json.loads(b)
    print("lessonmenu lessons:", len(menu))
    names = [m.get("name") for m in menu[:6]]
    print("  names:", names)
    print("  raw[0]:", json.dumps(menu[0])[:200] if menu else "-")
except Exception:
    print("lessonmenu not json:", b[:100])

# one lesson page with forms
c, b, _ = http(f"{WG}/WebGoat/sql-injection/lesson1", jar=jar) if False else http(f"{WG}/sql-injection/lesson1", jar=jar)
print("lesson page sql-injection/lesson1:", c, "| forms:")
for m in re.finditer(r"<form[^>]*(.*?)</form>", b, re.S | re.I):
    act = re.search(r"action=[\"']?([^\"' >]+)", m.group(0))
    flds = re.findall(r"name=[\"']?([^\"' >]+)", m.group(1))
    print("   ", act.group(1) if act else "?", flds[:8])

json.dump({"user": USER, "pass": PASS}, open("/home/z/my-project/live-targets/creds.json", "w"))
print("CREDS SAVED")
