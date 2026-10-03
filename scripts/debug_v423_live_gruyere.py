#!/usr/bin/env python3
"""Live debug: run StoredXSSDetector against the live gruyere instance
exactly as the scan would (endpoint as discovery builds it)."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v423")
from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule, EventBus,
                           DiscoverySource)
from sentinel.http_engine import RequestEngine
from sentinel.detect import StoredXSSDetector, fresh_form, stored_xss_flow

INST = "604549489843762004437581306279903220761"
BASE = f"https://google-gruyere.appspot.com/{INST}/"

import ssl
# gruyere has valid TLS; default context fine

eng = RequestEngine(ScopeRule(allowed_domains=["google-gruyere.appspot.com"]),
                    EventBus("live-dbg"), timeout=12.0)

# endpoint exactly as discovery's crawl() builds it:
# _mk_endpoint(action, CRAWL_FORM, params=[(name, value)...], method=form method)
ep = Endpoint(url=f"{BASE}saveprofile", method="GET",
              parameters=[Parameter("action", ParamLocation.QUERY, "new"),
                          Parameter("uid", ParamLocation.QUERY, ""),
                          Parameter("pw", ParamLocation.QUERY, ""),
                          Parameter("is_author", ParamLocation.QUERY, "True")],
              source=DiscoverySource.CRAWL_FORM,
              tags=[f"form_origin:{BASE}newaccount.gtl"])

det = StoredXSSDetector(eng, EventBus("live-dbg"))
print("gate source:", ep.source == DiscoverySource.CRAWL_FORM, "| method:", ep.method)
print("gate content:", det._content_form(ep))
print("origin:", det._origin_of(ep))
o, form = fresh_form(eng, det._origin_of(ep), ep)
print("fresh_form: status", o.status if o else None, "err", o.error if o else None,
      "| form:", "None" if form is None else form["fields"])
if form:
    print("  action_abs:", form["_action_abs"], "| method:", form["method"])
_o, _s, hits = stored_xss_flow(eng, ep, "uid", "<sentinelst0>", det._origin_of(ep))
print("flow: submit", _s.status if _s else None, _s.error if _s else "",
      "| hits:", [(u[-40:], r1.status) for u, r1, r2 in hits])
cands = det.run(ep)
print("detector run:", [(c.type, c.parameter) for c in cands])
