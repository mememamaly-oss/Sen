#!/usr/bin/env python3
"""Phase 55 live feasibility probes — manual, evidence-first (per phase doctrine):
probe each new class on the authorized target BEFORE the production scan, so the
production run's findings/negatives are interpreted against ground reality."""
import json, ssl, urllib.request, urllib.error, hashlib

BASE = "https://ginandjuice.shop"
CTX = ssl.create_default_context()
UA = {"User-Agent": "sentinel-probe/2.7-manual"}

def req(url, headers=None, method="GET", data=None):
    h = dict(UA); h.update(headers or {})
    r = urllib.request.Request(url, headers=h, method=method,
                               data=data.encode() if data else None)
    try:
        with urllib.request.urlopen(r, timeout=20, context=CTX) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, f"ERR {type(e).__name__}: {e}"

print("=" * 72)
print("1) HOST HEADER — canary Host on / and /blog (their link-manipulation page)")
for path in ("/", "/blog"):
    canary = f"sentinel-hh-{hashlib.sha1(path.encode()).hexdigest()[:10]}.example"
    st, hd, body = req(BASE + path, {"Host": canary})
    where = ([("body", canary in body)] +
             [(k, canary in v) for k, v in hd.items() if isinstance(v, str)])
    hits = [w for w, hit in where if hit]
    print(f"   {path}: HTTP {st} | Host canary {canary!r} reflected in: {hits or 'NOWHERE (honest negative)'}")

print()
print("2) SSTI — {{7*7}} / ${{7*7}} on the two known reflection params")
for url in (BASE + "/catalog?searchTerm=%7B%7B7*7%7D%7D",
            BASE + "/catalog?category=%7B%7B7*7%7D%7D"):
    st, hd, body = req(url)
    lit = "{{7*7}}" in body
    calc = "49" in body
    print(f"   {url.split('.shop')[1][:40]}: HTTP {st} | literal reflected: {lit} | computed 49: {calc}"
          f"  -> {'SILENT (reflection only)' if lit and not calc else 'CHECK'}")

print()
print("3) CSRF — hostile-origin POST on the subscribe action (known POST surface)")
st, hd, body = req(BASE + "/catalog/subscribe", method="POST",
                   headers={"Origin": "https://csrf-probe.example",
                            "Referer": "https://csrf-probe.example/x",
                            "Content-Type": "application/x-www-form-urlencoded"},
                   data="email=probe%40example.com")
print(f"   POST /catalog/subscribe w/ hostile Origin: HTTP {st} | body[:120]: {body[:120]!r}")
st2, _, _ = req(BASE + "/catalog/subscribe", method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data="email=probe%40example.com")
print(f"   POST /catalog/subscribe baseline        : HTTP {st2}")

print()
print("4) JWT — any eyJ... tokens on the auth-ish surfaces?")
found = []
for path in ("/", "/login", "/catalog"):
    st, hd, body = req(BASE + path)
    hay = body + " ".join(f"{k}={v}" for k, v in hd.items() if k.lower() == "set-cookie")
    import re
    m = re.search(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.([A-Za-z0-9_-]*)", hay)
    if m:
        found.append((path, m.group(0)[:50]))
print(f"   JWTs found: {found or 'NONE (honest negative — session-cookie app)'}")

print()
print("5) NoSQL — JSON operator probe on subscribe (JSON API surface)")
st, hd, body = req(BASE + "/catalog/subscribe", method="POST",
                   headers={"Origin": "https://csrf-probe.example",
                            "Content-Type": "application/json"},
                   data='{"email": {"$ne": "x"}}')
print(f"   POST JSON operator: HTTP {st} | body[:120]: {body[:120]!r}")
