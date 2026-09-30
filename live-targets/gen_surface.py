#!/usr/bin/env python3
"""Generate an OpenAPI surface doc for WebGoat 8.2.2 from the authenticated
lesson pages: every <form> on every lesson page -> path+method+parameters."""
import json, re, urllib.request, urllib.error

WG = "http://127.0.0.1:8080/WebGoat"
OUT = "/home/z/my-project/live-targets/webgoat_surface_openapi.json"
LESSONS = "http://127.0.0.1:8080/WebGoat/{L}"


class Sess:
    def __init__(self):
        self.cookies = {}

    def _absorb(self, hh):
        try:
            raw = hh.get_all("Set-Cookie") or []
        except Exception:
            raw = [hh.get("Set-Cookie")] if hh.get("Set-Cookie") else []
        for sc in raw:
            f = sc.split(";")[0]
            if "=" in f:
                n, v = f.split("=", 1)
                self.cookies[n.strip()] = v.strip()

    def req(self, url, data=None, follow=True):
        h = {"User-Agent": "SENTINEL-probe/3.0.0"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        hs = []
        if not follow:
            class NR(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            hs.append(NR())
        op = urllib.request.build_opener(*hs)
        r = urllib.request.Request(url, data=data, headers=h)
        try:
            resp = op.open(r, timeout=10)
            code, body, hh = resp.getcode(), resp.read().decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            code, body, hh = e.code, e.read().decode("utf-8", "replace"), e.headers
        self._absorb(hh)
        return code, body, hh


def example_for(name):
    n = (name or "").lower()
    if "user" in n or "account" in n:
        return "guest"
    if "pass" in n:
        return "test1234"
    if "mail" in n or "email" in n:
        return "sentinel@webwolf.example"
    if any(k in n for k in ("id", "num", "qty", "amount", "count", "number")):
        return "1"
    if "url" in n or "host" in n or "server" in n:
        return "http://127.0.0.1:9090/WebWolf"
    if "file" in n or "path" in n or "filename" in n:
        return "test.txt"
    return "test"


s = Sess()
s.req(f"{WG}/login")
s.req(f"{WG}/login", data=b"username=sentinel9x&password=test1234", follow=False)

c, b, _ = s.req(f"{WG}/service/lessonmenu.mvc")
menu = json.loads(b)
links = []


def walk(ns):
    for n in (ns or []):
        l = n.get("link") or ""
        if isinstance(l, str) and l.startswith("#lesson/"):
            links.append(l[len("#lesson/"):])
        walk(n.get("children"))


walk(menu)

paths = {}


def add(path, method, fields, note):
    if not path or path.startswith("#"):
        return
    if not path.startswith("/"):
        path = "/" + path
    key = path if path in paths else path
    ops = paths.setdefault(key, {})
    if method in ops:  # merge fields
        for f in fields:
            names = {p["name"] for p in ops[method].get("parameters", [])}
            if f not in names:
                ops[method]["parameters"].append(
                    {"name": f, "in": "query", "schema": {"example": example_for(f)}})
        return
    ops[method] = {
        "summary": note,
        "parameters": [{"name": f, "in": "query", "schema": {"example": example_for(f)}}
                       for f in fields],
    }


lesson_pages = []
for frag in links:
    url = f"{WG}/{frag}"
    c, b, _ = s.req(url)
    if c != 200 or "Login Page" in b[:3000]:
        continue
    lesson_pages.append(url)
    add(f"/WebGoat/{frag}", "get", [], f"lesson page {frag}")
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", b, re.S | re.I):
        head = m.group(0)
        act = re.search(r"action=[\"']?([^\"' >]+)", head)
        meth = re.search(r"method=[\"']?([^\"' >]+)", head)
        action = act.group(1) if act else ""
        if action.startswith("http"):
            action = action[len("http://127.0.0.1:8080"):]
        if action.startswith("#"):
            continue
        if not action:
            continue
        if not action.startswith("/"):
            action = "/WebGoat/" + action.lstrip("/")
        fields = []
        for f in re.finditer(r"<(input|select|textarea)[^>]*>", m.group(1), re.I):
            nm = re.search(r"name=[\"']?([^\"' >]+)", f.group(0))
            if nm and nm.group(1) not in fields:
                fields.append(nm.group(1))
        method = (meth.group(1) if meth else "post").lower()
        add(action, method, fields, f"form on {frag}")

# service endpoints (authenticated JSON surface)
for p in ["/WebGoat/service/lessonmenu.mvc", "/WebGoat/service/lessonoverview.mvc",
          "/WebGoat/service/solution.mvc", "/WebGoat/service/reportcard.mvc",
          "/WebGoat/service/progress.mvc"]:
    add(p, "get", [], "webgoat service")

doc = {
    "openapi": "3.0.0",
    "info": {"title": "WebGoat 8.2.2 lesson surface (operator-supplied seed)",
             "version": "8.2.2-sentinel"},
    "servers": [{"url": "http://127.0.0.1:8080"}],
    "paths": paths,
}
json.dump(doc, open(OUT, "w"), indent=1)
n_ops = sum(len(v) for v in paths.values())
print(f"LESSON PAGES: {len(lesson_pages)} | PATHS: {len(paths)} | OPERATIONS: {n_ops}")
print("saved ->", OUT)
for k in sorted(paths)[:12]:
    print("  ", k, list(paths[k]))
