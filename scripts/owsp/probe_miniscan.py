#!/usr/bin/env python3
"""owsp_probe_miniscan.py — in-process mini-scan of live WrongSecrets with the
REAL orchestrator + journal, then dump every request touching /challenge/ POST:
status, whether _csrf was carried, and what the server said. Discriminates the
candidates=0 collapse: probes-not-sent vs probes-403-blocked vs analyzer-silent."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v423")

BASE = "http://localhost:8080"

from sentinel.core import Target
from sentinel.orchestrator import SentinelScanner, ScanConfig

cfg = ScanConfig(allow_private=True, max_pages=4, crawl=True, active=True, passive=True,
                 timeout=10.0, seed="owsp-mini-01", browser=False)
orch = SentinelScanner(BASE, cfg)
result = orch.run()

st = result.get("stats", {})
print("[mini] stats:", st)
fs = result.get("findings", [])
print("[mini] findings:", len(fs))

# journal: memory module attached to the bus? try orchestrator journal attr
entries = list(getattr(orch.bus, "request_journal", {}).values())
print("[mini] journal entries:", len(entries))
npost = 0
for e in entries:
    d = e if isinstance(e, dict) else vars(e)
    req = d.get("request") or d
    url = str(d.get("url") or req.get("url") or "")
    method = str(d.get("method") or req.get("method") or "")
    if "challenge" in url and method == "POST":
        npost += 1
        if npost <= 6:
            body = str(d.get("body") or req.get("body") or "")[:200]
            print(f"[mini] POST {url} -> {d.get('status')} len={d.get('body_len', d.get('length', '?'))} body={body[:150]}")
print(f"[mini] POST-to-/challenge requests in journal: {npost}")
if npost == 0:
    print("[mini] !!! ZERO POST probes were sent to the challenge forms")
