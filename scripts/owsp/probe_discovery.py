#!/usr/bin/env python3
"""owsp_probe_discovery.py — run the REAL DiscoveryEngine against live WrongSecrets
and print every discovered endpoint with method + params. Discriminates where the
candidate=0 collapse happens: discovery (no POST form endpoints) vs planner."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v423")

from sentinel.http_engine import RequestEngine
from sentinel.core import ScopeRule, EventBus
from sentinel.discovery import DiscoveryEngine

BASE = "http://localhost:8080"
scope = ScopeRule(allowed_domains=["localhost"], allow_private=True)
eng = RequestEngine(scope, EventBus("run-owspdisc"), timeout=10.0)
disc = DiscoveryEngine(eng, max_pages=12)
endpoints, js_hits, stats = disc.crawl(BASE)

eps = sorted(endpoints if isinstance(endpoints, list) else list(endpoints.values()), key=lambda e: (e.method, e.url))
posts = [e for e in eps if e.method == "POST"]
print(f"[disc] total endpoints={len(eps)}  POST={len(posts)}  js_hits={len(js_hits)}")
print(f"[disc] stats={stats}")
for e in posts[:8]:
    print(f"[disc] POST {e.url} params={[(p.name, p.kind.value) for p in e.parameters]} src={e.source}")
if not posts:
    print("[disc] !!! NO POST ENDPOINTS DISCOVERED — form extraction produced nothing")
# sample of GETs with params
gets_p = [e for e in eps if e.method == "GET" and e.parameters]
print(f"[disc] GET-with-params: {len(gets_p)}")
for e in gets_p[:5]:
    print(f"[disc] GET {e.url} params={[(p.name, p.kind.value) for p in e.parameters]}")
