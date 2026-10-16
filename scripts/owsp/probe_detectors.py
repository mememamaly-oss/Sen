#!/usr/bin/env python3
"""owsp_probe_detectors.py — for the discovered WrongSecrets POST endpoint, run
EVERY detector's candidates() and check which rendered mutations carry the
submit-button pair (action=submit) and _csrf."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v423")
BASE = "http://localhost:8080"

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.discovery import DiscoveryEngine
from sentinel import detect

scope = ScopeRule(allowed_domains=["localhost"], allow_private=True)
bus = EventBus("run-owspdet")
eng = RequestEngine(scope, bus, timeout=10.0)
disc = DiscoveryEngine(eng, max_pages=2)
endpoints, _, _ = disc.crawl(BASE + "/challenge/challenge-1")
ep = None
for e in endpoints:
    if e.method == "POST" and "challenge-1" in e.url:
        ep = e; break
print(f"[det] endpoint: {ep.url} params={[(p.name, p.kind.value) for p in ep.parameters]}")

for cls in detect.ACTIVE_DETECTORS:
    det = cls(eng, bus)
    try:
        cands = det.candidates(ep)
    except Exception as ex:
        print(f"[det] {det.name}: candidates() error {ex}")
        continue
    n_ok = n_tot = 0
    sample = None
    for c in cands:
        m = c[1] if isinstance(c, tuple) else c
        n_tot += 1
        try:
            rendered = eng._render(m)
            body = ""
            if isinstance(rendered, tuple):
                body = str(rendered[-1] or "")
            elif isinstance(rendered, (list,)) and len(rendered) >= 3:
                body = str(rendered[2] or "")
            if "action=submit" in body:
                n_ok += 1
            elif sample is None:
                sample = body[:90]
        except Exception:
            pass
    print(f"[det] {det.name:12s}: {n_ok}/{n_tot} mutations carry action=submit" +
          (f"  sample-missing: {sample!r}" if n_ok < n_tot else ""))
