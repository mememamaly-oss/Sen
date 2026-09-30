#!/usr/bin/env python3
"""Phase 1 — manual feasibility probes for ginandjuice.shop under SENTINEL v3.0.0.
Doctrine: plain GETs + form inventory only (no payloads). Predict the workflow
engine's honest result BEFORE the production scan.
"""
import re, json, urllib.request, urllib.error, urllib.parse

BASE = "https://ginandjuice.shop"
UA = {"User-Agent": "SENTINEL-v300-manual-probe/3.0.0"}

def get(path, method="GET", data=None, headers=None):
    url = BASE + path
    h = dict(UA)
    if headers: h.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return None, f"ERR {type(e).__name__}: {e}", {}

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.S | re.I)
INPUT_RE = re.compile(r"<(?:input|textarea|select|button)\b([^>]*)>", re.I)

def forms_of(html):
    out = []
    for m in FORM_RE.finditer(html):
        attrs, inner = m.group(1), m.group(2)
        action = re.search(r'action\s*=\s*["\']?([^"\'\s>]+)', attrs, re.I)
        method = re.search(r'method\s*=\s*["\']?([^"\'\s>]+)', attrs, re.I)
        fields = []
        for im in INPUT_RE.finditer(inner):
            a = im.group(1)
            n = re.search(r'name\s*=\s*["\']?([^"\'\s>]+)', a, re.I)
            t = re.search(r'type\s*=\s*["\']?([^"\'\s>]+)', a, re.I)
            if n: fields.append(f"{n.group(1)}:{t.group(1) if t else 'text'}")
        out.append({"action": action.group(1) if action else "",
                    "method": (method.group(1) if method else "GET").upper(),
                    "fields": fields})
    return out

pages = ["/", "/catalog", "/blog", "/login", "/admin", "/search", "/catalog/subscribe",
         "/catalog/product/stock", "/robots.txt", "/sitemap.xml"]
report = {"pages": {}, "forms": [], "notes": []}

for p in pages:
    st, body, hdrs = get(p)
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    report["pages"][p] = {
        "status": st,
        "title": (title.group(1).strip()[:80] if title else ""),
        "ctype": hdrs.get("Content-Type", ""),
        "len": len(body) if isinstance(body, str) else 0,
        "server": hdrs.get("Server", ""), "xbackend": hdrs.get("x-backend", ""),
    }
    if isinstance(body, str):
        for f in forms_of(body):
            f["found_on"] = p
            report["forms"].append(f)

# catalog first product page (link harvest)
st, body, _ = get("/catalog")
links = sorted(set(re.findall(r'href="(/catalog/product/[^"]+)"', body)))[:3]
report["notes"].append(f"product links sample: {links}")
for pl in links[:2]:
    st, body, _ = get(pl)
    for f in forms_of(body):
        f["found_on"] = pl
        report["forms"].append(f)
    # stock-check endpoint shape (OPTIONS-like: GET behavior only)
    st2, b2, h2 = get("/catalog/product/stock")
    report["notes"].append(f"GET /catalog/product/stock -> {st2} {b2[:120]!r}")

# blog post page
st, body, _ = get("/blog")
blinks = sorted(set(re.findall(r'href="(/blog/post/[^"]+)"', body)))[:2]
for pl in blinks:
    st, body, _ = get(pl)
    for f in forms_of(body):
        f["found_on"] = pl
        report["forms"].append(f)
report["notes"].append(f"blog links sample: {blinks}")

# div pseudo-form check on subscribe page (v2.2.0 knowledge: data-action pseudo-form)
st, body, _ = get("/catalog")
has_pseudo = "data-action" in body
csrf_in_page = bool(re.search(r"csrf", body, re.I))
report["notes"].append(f"root/catalog data-action pseudo-form: {has_pseudo}, csrf mention: {csrf_in_page}")

print(json.dumps(report, indent=1))
