#!/usr/bin/env python3
"""TB-1b live debug: send the engine's EXACT header-name mutation shape to
BenchmarkTest00251 and inspect what comes back (why did the live minispec
stay silent while the hand probe is LIVE?)."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.core import Endpoint, EventBus, ScopeRule
from sentinel.http_engine import RequestEngine, RequestMutation

M1, M2 = "sentineltb1marker", "sentineltb2marker"
eng = RequestEngine(ScopeRule("http://localhost:8080/benchmark/", allow_private=True), EventBus("tb1b-debug"), timeout=10)
ep = Endpoint(url="http://localhost:8080/benchmark/trustbound-00/BenchmarkTest00251",
              method="POST")
for tag, hdrs in (("hn1", {M1: "1"}), ("hn2", {M2: "1"})):
    r = eng.send(RequestMutation(endpoint=ep, extra_headers=hdrs, note=f"tb-{tag}"))
    print(f"--- {tag}: status={r.status} err={r.error!r}")
    body = r.body or ""
    print("   M1 in body:", M1 in body, "| M2 in body:", M2 in body)
    print("   body[:160]:", repr(body[:160]))
