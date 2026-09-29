#!/usr/bin/env python3
"""Phase 54 live validation (1/3): passive WAF + technology fingerprinting on the
four AUTHORIZED demo targets. Zero attack payloads — plain GETs of pages the
public site serves anyone; the FingerprintCollector observes what the targets
actually emit. Honest by construction: no signature hits -> waf null.

Usage: python scripts_live_fingerprint.py  (writes /tmp/live_fingerprint.json)
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.core import ScopeRule, EventBus, Endpoint, Target
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.fingerprint import FingerprintCollector

TARGETS = [
    "https://ginandjuice.shop",
    "https://demo.testfire.net",
    "http://testasp.vulnweb.com",
    "http://testaspnet.vulnweb.com",
]
# plain pages each site serves publicly (no probing, no payloads)
PAGES = ["/", "/login", "/about", "/blog", "/search?query=hello", "/admin", "/contact"]

out = {}
for t in TARGETS:
    tgt = Target(t)
    eng = RequestEngine(ScopeRule(allowed_domains=[tgt.host], allow_private=False),
                        EventBus("live-fp"), timeout=15)
    fp = FingerprintCollector()
    pages = []
    for p in PAGES:
        try:
            r = eng.send(RequestMutation(endpoint=Endpoint(url=t.rstrip("/") + p),
                                         note="fingerprint-baseline"))
        except Exception as e:
            r = None
        if r is None or r.error or not r.status:
            pages.append({"path": p, "status": 0, "note": (getattr(r, "error", "") or "err")[:60]})
            continue
        fp.observe(r)
        pages.append({"path": p, "status": r.status})
    out[t] = {"pages": pages, "fingerprint": fp.summary()}
    print(f"--- {t}")
    for pg in pages:
        print(f"    {pg['status']:3d} {pg['path']}")
    s = out[t]["fingerprint"]
    print("    WAF :", s["waf"])
    print("    TECH:", json.dumps(s["tech"], ensure_ascii=False)[:300])

json.dump(out, open("/tmp/live_fingerprint.json", "w"), indent=1)
print("\nsaved /tmp/live_fingerprint.json")
