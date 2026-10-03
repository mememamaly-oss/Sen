#!/usr/bin/env python3
"""Live debug: stored-XSS flow against live testaspnet /Comments.aspx."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v423")
from urllib.parse import parse_qs

from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule, EventBus,
                           DiscoverySource)
from sentinel.http_engine import RequestEngine
from sentinel.detect import StoredXSSDetector, fresh_form, stored_xss_flow

eng = RequestEngine(ScopeRule(allowed_domains=["testaspnet.vulnweb.com"]),
                    EventBus("live-dbg-aspnet"), timeout=12.0)

URL = "http://testaspnet.vulnweb.com/Comments.aspx?id=0"
ep = Endpoint(url=URL, method="POST",
              parameters=[Parameter("__VIEWSTATE", ParamLocation.BODY, "STALE"),
                          Parameter("tbComment", ParamLocation.BODY),
                          Parameter("tbName", ParamLocation.BODY)],
              source=DiscoverySource.CRAWL_FORM,
              tags=[f"form_origin:{URL}"])

det = StoredXSSDetector(eng, EventBus("dbg"))
print("content gate:", det._content_form(ep))
o, form = fresh_form(eng, URL, ep)
print("fresh_form:", o.status, o.error, "| form:", "None" if form is None else
      [(n, v[:20], t) for n, v, t in form["fields"]])
print("  action:", form["_action_abs"] if form else None, "| method:", form["method"] if form else None)
_o, _s, hits = stored_xss_flow(eng, ep, "tbComment", "<sentinelst0>", URL)
print("flow: submit ->", _s.status if _s else None, _s.error if _s else "",
      f"({_s.status}B)" if _s and _s.status else "")
if _s is not None and _s.body:
    print("  submit body head:", _s.body[:200].replace("\n", " "))
print("hits:", [(u[:60], r1.status) for u, r1, r2 in hits])
cands = det.run(ep)
print("detector:", [(c.type, c.parameter) for c in cands])
