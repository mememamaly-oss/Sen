#!/usr/bin/env python3
"""Phase 2b — resolve WebGoat lesson URLs from the authenticated lesson menu,
probe them, and emit a seed list for the deeper scan."""
import re, json, urllib.request, urllib.error
from http.cookiejar import CookieJar

WG = "http://127.0.0.1:8080/WebGoat"
UA = "Mozilla/5.0 SENTINEL-probe/3.0.0"

def http(url, jar=None, data=None):
    h = {"User-Agent": UA}
    hs = [urllib.request.HTTPCookieProcessor(jar)] if jar else []
    op = urllib.request.build_opener(*hs) if hs else urllib.request.build_opener()
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = op.open(req, timeout=10)
        return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"__error__ {e}"

jar = CookieJar()
http(f"{WG}/login", jar=jar)  # session
http(f"{WG}/login", data=f"username=sentinel9x&password=test1234".encode(), jar=jar)

c, b = http(f"{WG}/service/lessonmenu.mvc", jar=jar)
menu = json.loads(b)
links = []

def walk(nodes):
    for n in nodes:
        l = n.get("link", "")
        if l.startswith("#lesson/") and l not in links:
            links.append(l)
        walk(n.get("children", []))

walk(menu)
print("lesson links:", len(links))
print(json.dumps(links, indent=1)[:1500])

# probe candidate URL shapes for each link
probe = {}
for l in links:
    frag = l[len("#lesson/"):]           # e.g. "SqlInjection.lesson"
    cands = [f"{WG}/{frag}", f"{WG}/{frag.replace('.', '/')}", f"{WG}/lesson/{frag}"]
    found = None
    for u in cands:
        c, b = http(u, jar=jar)
        if c == 200 and "Login Page" not in b[:2000]:
            found = u
            probe[frag] = {"url": u, "code": c,
                           "forms": len(re.findall(r"<form", b, re.I)),
                           "title": (re.search(r"<title>(.*?)</title>", b, re.S) or [None, "-"])[1].strip()[:40]}
            break
    if not found:
        probe[frag] = {"url": None, "codes": [http(u, jar=jar)[0] for u in cands]}

ok = {k: v for k, v in probe.items() if v.get("url")}
print(f"resolvable: {len(ok)}/{len(links)}")
for k, v in list(ok.items())[:20]:
    print("  ", k, "->", v["url"], "| forms:", v["forms"], "|", v["title"])

seeds = sorted({v["url"] for v in ok.values()})
json.dump(seeds, open("/home/z/my-project/live-targets/lesson_seeds.json", "w"), indent=1)
print("SEEDS SAVED:", len(seeds))
