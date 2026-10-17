#!/usr/bin/env python3
"""STEP 1 — LIVE DIAGNOSTIC on RequestEngine._scope_ok AS IT IS ON DISK.
Zero modification, zero network: _scope_ok is pure URL/scope string logic.
Provenance: prints the sha256 of the engine file under test so the raw output
is bound to the exact bytes on disk.

Scope shapes tested (both are real constructions):
  A. orchestrator.py:117 default for a demo.testfire.net target:
     allowed_domains=['demo.testfire.net'], allowed_hosts=[]
  B. the registered-domain shape (what the nottestfire/eviltestfire probes
     were designed to expose — a bare endswith() would fire HERE):
     allowed_domains=['testfire.net'], allowed_hosts=[]
Controls (must stay ACCEPTED):
  - sub.demo.testfire.net under shape A (legit subdomain)
  - demo.testfire.net itself under shape A
  - www.testfire.net under shape B (legit subdomain of the registered domain)
  - testfire.net itself under shape B
Attack probes (must be REJECTED):
  1. https://nottestfire.net/...
  2. https://eviltestfire.net/...
  3. https://demo.testfire.net.attacker.com/...   (reverse-direction confirm)
"""
import hashlib
import sys

sys.path.insert(0, "/home/z/my-project/build-v430")

from sentinel.core import ScopeRule, EventBus          # noqa: E402
from sentinel.http_engine import RequestEngine        # noqa: E402

ENGINE_FILE = "/home/z/my-project/build-v430/sentinel/http_engine.py"
src = open(ENGINE_FILE, "rb").read()
print(f"engine file: {ENGINE_FILE}")
print(f"engine sha256: {hashlib.sha256(src).hexdigest()}")
print()

PROBES = [
    "https://nottestfire.net/x",
    "https://eviltestfire.net/x",
    "https://demo.testfire.net.attacker.com/x",
]
CONTROLS_A = [
    "https://demo.testfire.net/bank/main.jsp",
    "https://sub.demo.testfire.net/bank/main.jsp",
]
CONTROLS_B = [
    "https://testfire.net/bank/main.jsp",
    "https://www.testfire.net/bank/main.jsp",
]

print("=== SHAPE A: allowed_domains=['demo.testfire.net'] (orchestrator.py:117 default) ===")
eng_a = RequestEngine(ScopeRule(allowed_domains=["demo.testfire.net"]),
                      EventBus("diag-shape-a"), timeout=5.0)
for url in PROBES:
    ok, why = eng_a._scope_ok(url)
    print(f"  _scope_ok({url!r}) -> {ok!r}, {why!r}")
for url in CONTROLS_A:
    ok, why = eng_a._scope_ok(url)
    print(f"  [control] _scope_ok({url!r}) -> {ok!r}, {why!r}")

print()
print("=== SHAPE B: allowed_domains=['testfire.net'] (registered-domain form) ===")
eng_b = RequestEngine(ScopeRule(allowed_domains=["testfire.net"]),
                      EventBus("diag-shape-b"), timeout=5.0)
for url in PROBES:
    ok, why = eng_b._scope_ok(url)
    print(f"  _scope_ok({url!r}) -> {ok!r}, {why!r}")
for url in CONTROLS_B:
    ok, why = eng_b._scope_ok(url)
    print(f"  [control] _scope_ok({url!r}) -> {ok!r}, {why!r}")

print()
print("=== VERDICT ===")
results = {}
for url in PROBES:
    results[url] = (eng_a._scope_ok(url)[0], eng_b._scope_ok(url)[0])
all_false = all(not v for pair in results.values() for v in pair)
controls_ok = (all(eng_a._scope_ok(u)[0] for u in CONTROLS_A)
               and all(eng_b._scope_ok(u)[0] for u in CONTROLS_B))
for url, (ra, rb) in results.items():
    print(f"  {url}: shapeA={ra} shapeB={rb}")
print(f"ALL THREE PROBES REJECTED (both shapes): {all_false}")
print(f"LEGITIMATE SUBDOMAIN CONTROLS STILL ACCEPTED: {controls_ok}")
if all_false and controls_ok:
    print("STATUS: NO VULNERABILITY — the on-disk gate already enforces the dot boundary")
    sys.exit(0)
else:
    print("STATUS: VULNERABILITY INDICATED — proceed to Step 2 (fix)")
    sys.exit(1)
