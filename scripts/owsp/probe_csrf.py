#!/usr/bin/env python3
"""owsp_probe_csrf.py — decide empirically whether Spring CSRF 403-blocks the
engine's POST probes to /challenge/{name}: (1) manual form replay WITH crawled
token+session, (2) WITHOUT token, (3) the EXACT mutation bodies SQLiDetector
would send for the discovered endpoint (does _csrf ride along?)."""
import sys, json, re
import urllib.request, urllib.parse
import http.cookiejar

BASE = "http://localhost:8080"
sys.path.insert(0, "/home/z/my-project/build-v423")

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get(url):
    with op.open(url, timeout=10) as r:
        return r.status, r.read().decode("utf-8", "replace")

def post(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]

st, html = get(BASE + "/challenge/challenge-1")
m = re.search(r'name="_csrf"[^>]*value="([^"]+)"', html) or re.search(r'value="([^"]+)"[^>]*name="_csrf"', html)
token = m.group(1) if m else ""
print(f"[1] GET page {st}; _csrf token captured: {bool(token)} ({token[:16]}...)")
print(f"[1] session cookies: {[c.name for c in cj]}")

st2, body2 = post(BASE + "/challenge/challenge-1",
                  {"solution": "sentinel'probe", "_csrf": token, "action": "submit"})
print(f"[2] POST WITH token -> {st2} ({len(body2)}B) {body2[:120]!r}")

st3, body3 = post(BASE + "/challenge/challenge-1", {"solution": "sentinel'probe"})
print(f"[3] POST WITHOUT token -> {st3} {body3[:150]!r}")

# --- (4) the engine's actual mutation bodies
from sentinel.http_engine import RequestEngine
from sentinel.core import ScopeRule, EventBus
from sentinel.discovery import DiscoveryEngine
from sentinel.detect import SQLiDetector

scope = ScopeRule(allowed_domains=["localhost"], allow_private=True)
eng = RequestEngine(scope, EventBus("run-owspdisc2"), timeout=10.0)
disc = DiscoveryEngine(eng, max_pages=2)
endpoints, _, _ = disc.crawl(BASE + "/challenge/challenge-1")
ep = None
for e in endpoints:
    if e.method == "POST" and "challenge-1" in e.url:
        ep = e; break
print(f"[4] endpoint found: {ep is not None}; params={[(p.name, p.kind.value, p.value[:12] if p.value else '') for p in ep.parameters] if ep else None}")
if ep:
    det = SQLiDetector(eng, EventBus("run-owspdisc2"))
    cands = det.candidates(ep)
    print(f"[4] sqli candidates: {len(cands)}")
    for strat, m2 in cands[:4]:
        rendered = eng._render(m2) if hasattr(eng, "_render") else None
        if rendered:
            url2, headers, body_r = rendered if isinstance(rendered, tuple) else (rendered, None, None)
            print(f"    {strat}: url={url2[:80]} body={str(body_r)[:160]}")
        else:
            print(f"    {strat}: mutation param={m2.param_name} payload={str(m2.payload)[:60]} siblings={getattr(m2, 'sibling_params', None) is not None}")
