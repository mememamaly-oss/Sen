#!/usr/bin/env python3
"""Inspect the real round-7 journals for the shapes the L3 planner needs."""
import json
import sys

sys.path.insert(0, "/home/z/my-project/build-v423")
from sentinel import apath

BASE = "/home/z/my-project/build-v423/results/live_v430/"

d = json.load(open(BASE + "ginjuice.json", encoding="utf-8"))
j = d["stats"]["request_journal"]
print("=== ginjuice CRLF-shaped entries (category param with %0d):")
for rid, e in sorted(j.items()):
    req = e.get("request") or {}
    url = (req.get("url", "") + " " + (req.get("body") or ""))
    if "catalog" in url.lower() and ("%0d" in url.lower()):
        print(rid, repr(url)[:170])

ctx = apath._Ctx(d)
f = next(x for x in ctx.findings if x.get("type") == "http_response_header_injection")
print("finding:", f.get("url"), "param:", f.get("parameter"), "method:", f.get("method"))
rids = ctx.proving_entries(f)
print("proving rids:", rids)
for rid in rids:
    entry = j.get(rid) or {}
    req = entry.get("request") or {}
    print("  ", rid, repr((req.get("url") or "")[:130]))

g = json.load(open(BASE + "gruyere2.json", encoding="utf-8"))
jg = g["stats"]["request_journal"]
print("=== gruyere saveprofile entries:")
for rid, e in sorted(jg.items()):
    req = e.get("request") or {}
    if "saveprofile" in req.get("url", ""):
        print(rid, req.get("method"), repr((req.get("url") or "")[:110]),
              "body:", repr((req.get("body") or "")[:110]))
print("=== gruyere stored finding record:")
gf = next(x for x in g["findings"] if x.get("type") == "xss_stored" and x.get("status") == "verified")
print(json.dumps({k: gf.get(k) for k in ("url", "parameter", "method", "evidence")},
                 ensure_ascii=False, indent=1)[:900])
