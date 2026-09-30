#!/usr/bin/env python3
"""Phase 1b — precise auth feasibility: dump real register/login HTML,
register with the EXACT required fields, prove an auth-only endpoint opens."""
import json, re, sys, urllib.request, urllib.error, urllib.parse
from http.cookiejar import CookieJar

WG = "http://127.0.0.1:8080/WebGoat"
UA = "Mozilla/5.0 (X11; Linux x86_64) SENTINEL-probe/3.0.0"


def http(url, data=None, jar=None, follow=True, extra=None):
    h = {"User-Agent": UA}
    if extra:
        h.update(extra)
    handlers = []
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    if not follow:
        handlers.append(NoRedirect)
    op = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = op.open(req, timeout=10)
        return r.getcode(), r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return 0, f"__error__ {e}", {}


jar = CookieJar()

# 1) raw dump of login + register pages
c1, login_html, _ = http(f"{WG}/login", jar=jar)
c2, reg_html, _ = http(f"{WG}/register", jar=jar)
print("== /login forms ==")
for m in re.finditer(r"<form[^>]*>.*?</form>", login_html + " || " + reg_html, re.S | re.I):
    print(m.group(0)[:600].replace("\n", " "))
    print("---")

print("== register page inputs ==")
for f in re.finditer(r"<input[^>]*>", reg_html, re.I):
    print(f.group(0)[:200])

# 2) register with ALL plausible fields
payload = {"username": "sentinel1", "password": "Sentinel!Live1", "confirmPassword": "Sentinel!Live1",
           "email": "sentinel1@webwolf.example", "agree": "true"}
enc = urllib.parse.urlencode(payload).encode()
c3, b3, h3 = http(f"{WG}/register", data=enc, jar=jar, follow=False)
print("== register POST ==", c3, "->", h3.get("Location", ""), "| body has 'error':",
      bool(re.search(r"error|exist|invalid", b3, re.I)))

# 3) login
enc = urllib.parse.urlencode({"username": "sentinel1", "password": "Sentinel!Live1"}).encode()
c4, b4, h4 = http(f"{WG}/login", data=enc, jar=jar, follow=False)
print("== login POST ==", c4, "->", h4.get("Location", ""), "| len:", len(b4))

# 4) auth-only proof: lesson menu + welcome.mvc with the session
c5, b5, _ = http(f"{WG}/welcome.mvc", jar=jar)
c6, b6, _ = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
menu = json.loads(b6) if b6.strip().startswith(("[", "{")) else []
print("== welcome.mvc ==", c5, "| title:", re.search(r"<title>(.*?)</title>", b5, re.S).group(1).strip()[:60])
print("== lessonmenu.mvc ==", c6, "| lessons:", len(menu) if isinstance(menu, list) else b6[:120])
print("== menu sample ==", json.dumps(menu[:2])[:400] if menu else "-")

# candidate success markers for SENTINEL --auth-success-marker
for marker in ["Logout", "logout", "Welcome", "lesson", "sentinel1"]:
    print(f"marker {marker!r} on welcome:", marker in b5)

# 5) WebWolf raw landing (find its real forms)
jarw = CookieJar()
c7, b7, _ = http("http://127.0.0.1:9090/WebWolf/landing")
print("== webwolf /landing ==", c7, "| forms:")
for m in re.finditer(r"<form[^>]*>.*?</form>", b7, re.S | re.I):
    print(m.group(0)[:400].replace("\n", " "))
print("== webwolf links ==", sorted(set(re.findall(r"href=[\"'](/WebWolf[^\"' ]*)", b7)))[:12])

out = {"register_post": c3, "login_post": c4, "welcome": c5, "menu_lessons": len(menu) if isinstance(menu, list) else -1}
json.dump(out, open("/home/z/my-project/live-targets/auth_state.json", "w"))
print("RESULT", out)
