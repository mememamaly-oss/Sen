#!/usr/bin/env python3
"""Phase 1f — empirical password-rule matrix; capture first register success."""
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

def register(user, pw):
    jar = CookieJar()
    http(f"{WG}/login", jar=jar)
    p = {"username": user, "password": pw, "matchingPassword": pw, "agree": "on"}
    c, b, h = http(f"{WG}/register.mvc", data=urllib.parse.urlencode(p).encode(), jar=jar, follow=False)
    if c != 200:
        return c, h.get("Location", ""), b
    # extract the error near the password form-group
    m = re.search(r'has-error[^>]*>.{0,900}?</div>\s*</div>', b, re.S)
    seg = ""
    if m:
        seg = re.sub(r"<[^>]+>", "|", m.group(0))
        seg = re.sub(r"(\|\s*)+", " | ", seg)
        seg = re.sub(r"\s+", " ", seg)[:300]
    return c, "", seg

CANDS = [("sentinel9x", "test1234"), ("sentinel9x", "test123"),
         ("sentinel9x", "abc12"), ("sentinel9x", "aaaaaaaa"),
         ("sentinel9x", "abc12345678"), ("sentinel9x", "abc123456789012"),
         ("sentinel9x", "a1"), ("sentinel9x", "abcdefgh123456")]
ok_user = ok_pw = None
for u, p in CANDS:
    c, loc, info = register(u, p)
    print(f"register({u!r}, {p!r}): {c} {loc or ''} {info[:160]}")
    if c != 200:
        ok_user, ok_pw = u, p
        print("SUCCESS with", u, p)
        break

if not ok_user:
    print("ALL CANDIDATES FAILED")
else:
    jar = CookieJar()
    http(f"{WG}/login", jar=jar)
    c, b, h = http(f"{WG}/login", data=urllib.parse.urlencode(
        {"username": ok_user, "password": ok_pw}).encode(), jar=jar, follow=False)
    print("login POST:", c, "->", h.get("Location", ""))
    c, b, _ = http(f"{WG}/welcome.mvc", jar=jar)
    t = re.search(r"<title>(.*?)</title>", b, re.S)
    print("welcome:", c, "| title:", (t.group(1).strip()[:50] if t else "-"))
    c, b, _ = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
    try:
        menu = json.loads(b)
        print("lessonmenu lessons:", len(menu), "| first:", json.dumps(menu[0])[:200] if menu else "-")
    except Exception:
        print("lessonmenu not-json:", b[:80].replace("\n", " "))
    if ok_pw != "test1234":
        json.dump({"user": ok_user, "password": ok_pw},
                  open("/home/z/my-project/live-targets/creds.json", "w"))
        print("CREDS SAVED:", ok_user, ok_pw)
