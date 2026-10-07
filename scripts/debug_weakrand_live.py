#!/usr/bin/env python3
"""Debug the weakrand phase live against BenchmarkTest00066 (Math.random)."""
import sys
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.weakrand import WeakRandomPhase
from sentinel import jrand

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("wrdbg"), timeout=6)
ep = Endpoint(url="http://localhost:8080/benchmark/weakrand-00/BenchmarkTest00066", method="POST")
ep.parameters = [Parameter("BenchmarkTest00066", ParamLocation.BODY, "foo")]

ph = WeakRandomPhase(eng, EventBus("wrdbg"))
c = ph._fetch_cookie(ep)
print("fetch_cookie:", c)

# three consecutive samples
vals = []
for i in range(3):
    c = ph._fetch_cookie(ep)
    if c: vals.append((c[0], c[1]))
print("samples:", vals)

# try the chain family manually
f = ph._family_chain(ep, "rememberMe00066") if c else None
print("family_chain:", f)
# and the relation family
f2 = ph._family_relation(ep, "rememberMe00066", "double") if c else None
print("family_relation:", f2)
