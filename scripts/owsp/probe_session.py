#!/usr/bin/env python3
"""owsp_probe_session.py — against LIVE WrongSecrets: crawl challenge-1 (token+session),
then fire the sqli battery and print (strategy, status, body-marker) + cookie evolution.
Answers: do probes carry action=submit + a session-valid _csrf?"""
import sys, re
sys.path.insert(0, "/home/z/my-project/build-v423")
BASE = "http://localhost:8080"

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.discovery import DiscoveryEngine
from sentinel.detect import SQLiDetector

scope = ScopeRule(allowed_domains=["localhost"], allow_private=True)
bus = EventBus("run-owspsess")
eng = RequestEngine(scope, bus, timeout=10.0)
disc = DiscoveryEngine(eng, max_pages=2)
endpoints, _, _ = disc.crawl(BASE + "/challenge/challenge-1")
ep = None
for e in endpoints:
    if e.method == "POST" and "challenge-1" in e.url:
        ep = e; break
print(f"[sess] endpoint params: {[(p.name, p.kind.value, (p.value or '')[:14]) for p in ep.parameters]}")
print(f"[sess] engine cookie jar: {getattr(eng, 'cookies', None) or getattr(getattr(eng,'session',None), 'cookies', None)}")

det = SQLiDetector(eng, bus)
cands = det.candidates(ep)
print(f"[sess] sqli probes: {len(cands)}")
for strat, m in cands[:8]:
    r = eng.send(m)
    body = (r.body or "")[:90].replace("\n", " ")
    marker = "PROCESSED" if "challenge" in (r.body or "")[:2000] and r.status == 200 else ""
    print(f"  {strat:18s} -> {r.status} len={len(r.body or '')} {marker} | {body[:70]!r}")
