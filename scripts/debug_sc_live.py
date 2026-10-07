#!/usr/bin/env python3
"""Live probe: why SecureCookieDetector is silent on the Benchmark.
Sends the endpoint POST via the real engine and inspects the response headers
as the engine represents them."""
import sys
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestMutation, RequestEngine

# engine-level direct send
eng = RequestEngine(scope=ScopeRule(allow_private=True, allowed_hosts=None), bus=EventBus("scdbg"), timeout=8)
r = eng.send(RequestMutation(endpoint=Endpoint(url="http://localhost:8080/benchmark/securecookie-00/BenchmarkTest00087"),
                             note="probe"))
print("status:", r.status if r else None)
print("headers type:", type(r.headers).__name__ if r else None)
print("headers:", dict(r.headers) if r else None)
sc = (r.headers or {}).get("set-cookie") if r else None
sc2 = (r.headers or {}).get("Set-Cookie") if r else None
print("get('set-cookie'):", repr(sc))
print("get('Set-Cookie'):", repr(sc2))
print("body[:200]:", (r.body or "")[:200] if r else None)

# and the raw HTTP layer for ground truth
import urllib.request
req = urllib.request.Request("http://localhost:8080/benchmark/securecookie-00/BenchmarkTest00087", method="POST")
with urllib.request.urlopen(req, timeout=8) as resp:
    print("RAW Set-Cookie:", resp.headers.get_all("Set-Cookie"))
    print("RAW body[:200]:", resp.read()[:200])
