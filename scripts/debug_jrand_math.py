#!/usr/bin/env python3
"""Verify jrand's LCG math end-to-end synthetically (Java semantics in Python),
then against live captured triples."""
import sys
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel import jrand

# ---- synthetic: emulate java.util.Random exactly ----
def java_nextdouble(seed48):
    """One nextDouble from a state, returning (double, new_state)."""
    s = seed48
    s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
    a = s >> 22                     # next(26)
    s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
    b = s >> 21                     # next(27)
    d = ((a << 27) + b) / float(1 << 53)
    return d, s

def cookie_text(d):
    # Java Double.toString shortest repr, substring(2)
    t = repr(d)
    if 'e' in t or 'E' in t:
        return None
    if t.startswith('0.'):
        return t[2:]
    return None

import random
ok = 0
for trial in range(20):
    seed = random.getrandbits(48)
    s = seed
    d1, s = java_nextdouble(s)   # cookie1 consumed the FIRST nextDouble...
    d2, s = java_nextdouble(s)   # wait: nextDouble does TWO next() calls internally
    # redo: each nextDouble = two next() calls; my java_nextdouble already does both
    d3, s = java_nextdouble(s)
    c1t, c2t, c3t = cookie_text(d1), cookie_text(d2), cookie_text(d3)
    if not (c1t and c2t and c3t):
        continue
    # run the phase's math
    dd1 = jrand.double_from_cookie(c1t)
    dd2 = jrand.double_from_cookie(c2t)
    if dd1 is None or dd2 is None:
        print('parse fail', c1t, c2t); continue
    cands = []
    for s1 in jrand.recover_state_nextdouble(dd1):
        s_after = jrand.next_state(s1)
        if jrand.predict_double_int(s_after) == dd2:
            cands.append(s_after)
    if not cands:
        print(f'trial {trial}: NO candidates d1={dd1} d2={dd2}')
        continue
    s_after = cands[0]
    s_before3 = jrand.next_state(jrand.next_state(s_after))
    pred = jrand.double_int_to_cookie(jrand.predict_double_int(s_before3))
    match = (pred == c3t) or (pred.lstrip('0') == c3t.lstrip('0'))
    print(f'trial {trial}: pred={pred!r} actual={c3t!r} match={match}')
    ok += 1 if match else 0
print(f'synthetic chain: {ok} matches')

# ---- live: capture 3 consecutive cookies from the real page ----
from sentinel.core import Endpoint, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.weakrand import WeakRandomPhase
eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("wrdbg2"), timeout=6)
ep = Endpoint(url="http://localhost:8080/benchmark/weakrand-00/BenchmarkTest00066", method="POST")
ph = WeakRandomPhase(eng, EventBus("wrdbg2"))
triple = []
for i in range(3):
    c = ph._fetch_cookie(ep)
    if c: triple.append(c[1])
print('live triple:', triple)
if len(triple) == 3:
    dd1 = jrand.double_from_cookie(triple[0]); dd2 = jrand.double_from_cookie(triple[1])
    print('parsed:', dd1, dd2)
    if dd1 is not None and dd2 is not None:
        cands = []
        for s1 in jrand.recover_state_nextdouble(dd1):
            if jrand.predict_double_int(jrand.next_state(s1)) == dd2:
                cands.append(jrand.next_state(s1))
        print('live candidates:', len(cands))
        if cands:
            s_before3 = jrand.next_state(jrand.next_state(cands[0]))
            pred = jrand.double_int_to_cookie(jrand.predict_double_int(s_before3))
            print('live predicted:', pred, 'actual:', triple[2], 'MATCH' if pred == triple[2] else 'MISS')
