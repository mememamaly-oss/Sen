#!/usr/bin/env python3
"""owsp_probe_fullscan.py — replicate the CLI scan in-process (localhost: local
OAST), then dump EVERY journal POST to /challenge: status + request body. Shows
whether action=submit + _csrf ride along in the FULL pipeline."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v423")
BASE = "http://localhost:8080"

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.oast import make_oast

cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                 seed="owsp-ws-01", browser=True)
cfg.oast = make_oast("localhost", mode="local")
sc = SentinelScanner(BASE, cfg)
rep = sc.run()

st = rep["stats"]
print("[fs] stats:", {k: v for k, v in st.items() if isinstance(v, (int, str, float))})
b = st.get("boundary", {})
print("[fs] uniform-reject records:", b.get("by_category", {}).get("active/uniform-reject"))

jr = getattr(sc.bus, "request_journal", {})
posts = []
for k, v in jr.items():
    req = v.get("request", {})
    if req.get("method") == "POST" and "/challenge/" in (req.get("url") or ""):
        posts.append((k, req.get("url"), v.get("response", {}).get("status"), req.get("body", "")))
print(f"[fs] journal POSTs to /challenge: {len(posts)}")
for k, url, status, body in posts[:6]:
    print(f"  {status} {url[-28:]} body={body[:110]!r}")
if posts:
    statuses = {}
    for _k, _u, s, _b in posts:
        statuses[s] = statuses.get(s, 0) + 1
    print(f"[fs] POST status histogram: {statuses}")
    has_action = sum(1 for _k,_u,_s,bd in posts if "action=submit" in (bd or ""))
    has_csrf = sum(1 for _k,_u,_s,bd in posts if "_csrf=" in (bd or ""))
    print(f"[fs] bodies containing action=submit: {has_action}/{len(posts)}; _csrf: {has_csrf}/{len(posts)}")
    bad = [(k,u,s,bd) for k,u,s,bd in posts if s == 405]
    if bad:
        print("[fs] SAMPLE 405 request body (full):")
        print("   ", bad[0][3][:400])
        print("[fs] its url:", bad[0][1])
    ok200 = [(k,u,s,bd) for k,u,s,bd in posts if s == 200]
    if ok200:
        print("[fs] SAMPLE 200 request body (full):")
        print("   ", ok200[0][3][:400])
        print("[fs] its url:", ok200[0][1])
