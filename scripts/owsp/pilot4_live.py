#!/usr/bin/env python3
"""Pilot 4 — final diagnostics: raw Set-Cookie vs engine parse, K-advance scan,
cmdi 00497 trace, VR-24, exists chain via FOS-created Test.txt, FIS probe."""
import sys, json, re, base64, subprocess, time
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel import jrand

BASE = "http://localhost:8080/benchmark"
SRC = "/home/z/my-project/tools/benchmark-src"
import yaml
_S = yaml.safe_load(open(SRC + "/data/openapi.yaml"))
PATHS = {p.rsplit("/", 1)[-1]: p for p in _S["paths"] if "/BenchmarkTest" in p}

def mk(test, method="POST"):
    p = PATHS[test]
    ep = Endpoint(url=BASE + p, method=method)
    d = _S["paths"][p].get("post") or _S["paths"][p].get("get") or {}
    for prm in d.get("parameters", []) or []:
        loc = {"query": ParamLocation.QUERY, "header": ParamLocation.HEADER,
               "cookie": ParamLocation.COOKIE}.get(prm.get("in"), ParamLocation.QUERY)
        ep.parameters.append(Parameter(prm["name"], loc, prm.get("schema", {}).get("default", "") or "1"))
    for ct, blob in ((d.get("requestBody") or {}).get("content", {})).items():
        for pn, pd in ((blob.get("schema") or {}).get("properties") or {}).items():
            ep.parameters.append(Parameter(pn, ParamLocation.BODY, pd.get("default", "") or "sentinel"))
    return ep

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("p4"), timeout=8)

def send(ep, name, value, loc=None, note="p4"):
    m = RequestMutation(endpoint=ep, param_name=name, param_value=value, note=note)
    if loc is not None: m.param_location = loc
    return eng.send(m)

print("=== A) raw Set-Cookie for 00160 (nextBytes) ===")
r = subprocess.run(["curl", "-s", "-D", "-", "-o", "/dev/null", "-X", "POST",
                    BASE + PATHS["BenchmarkTest00160"]], capture_output=True, text=True)
for ln in r.stdout.splitlines():
    if ln.lower().startswith("set-cookie"):
        print("  RAW:", ln.strip()[:130])

print("=== B) K-advance scan on 00085 (nextLong), 6 samples ===")
from sentinel.weakrand import WeakRandomPhase
ph = WeakRandomPhase(eng, EventBus("p4"))
ep = mk("BenchmarkTest00085")
seeds = []
for i in range(6):
    t0 = time.monotonic_ns()
    c = ph._fetch_cookie(ep)
    t1 = time.monotonic_ns()
    st = jrand.recover_state_nextlong(jrand.parse_java_long(c[1]))
    if st is not None:
        seeds.append((jrand.seed_from_state(st), (t0 + t1) // 2, t0, t1))
for i in range(len(seeds) - 1):
    s1, m1, a1, b1 = seeds[i]
    s2, m2, a2, b2 = seeds[i + 1]
    found_k = None
    for K in (1, 2, 3):
        u1 = None
        # brute t1 in the measured window for this K, check t2 lands in window2
        for t1 in range(a1, b1 + 1, 997):     # sampled window (coarse)
            u1c = (s1 ^ (t1 & jrand.MASK48)) & jrand.MASK48
            u2c = u1c
            for _ in range(K):
                u2c = (u2c * (jrand.UNIQ_MULT & jrand.MASK48)) & jrand.MASK48
            t2c = (s2 ^ u2c) & jrand.MASK48
            if a2 <= t2c <= b2:
                found_k = K; break
        if found_k: break
    print(f"  pair {i+1}->{i+2}: K={found_k}")

print("=== C) cmdi 00497 env-array trace ===")
ep = mk("BenchmarkTest00497")
for pv, tag in (("FOO=echo SENTINEL5858XX", "env"), ("echo SENTINEL5858XX", "bare"),
                ("benchmark", "base")):
    r = send(ep, "BenchmarkTest00497", pv)
    b = r.body or ""
    mark = "SENTINEL5858XX" in b
    print(f"  {tag:5} -> {r.status} len={len(b)} marker={mark} {b[:100]!r}")

print("=== D) VR on 00403 securecookie candidate ===")
from sentinel.detect import SecureCookieDetector
from sentinel.intel import VerificationEngine
scd = SecureCookieDetector(eng, EventBus("p4"))
cand = scd.run(mk("BenchmarkTest00403"))
if cand:
    ve = VerificationEngine(engine=eng, bus=EventBus("p4"), oast=None)
    out = ve.verify(cand, mk("BenchmarkTest00403"))
    print("  verify ->", out.status, "conf:", out.confidence,
          "|", (out.verification.notes[:110] if out.verification else ""))
else:
    print("  no candidate")

print("=== E) exists chain: FOS creates Test.txt, then dir-exists flips ===")
epf = mk("BenchmarkTest00028")
r = send(epf, "BenchmarkTest00028", "Test.txt")
print("  FOS create Test.txt ->", r.status, len(r.body or ""), (r.body or "")[:50])
ep11 = mk("BenchmarkTest00011")
for pv in ("testfiles", "sentinel-missing-zz", "../" * 6 + "testfiles", "testfiles2"):
    r = send(ep11, "BenchmarkTest00011", pv, loc=ParamLocation.HEADER)
    b = (r.body or "")
    print(f"  exists hdr param={pv:24} ->", "EXISTS!" if "already exists" in b else "missing",
          f"({r.status})")

print("=== F) FIS read probe (00529) ===")
epfis = mk("BenchmarkTest00529")
for pv in ("../../../../../../etc/passwd", "etc/passwd", "FileName", "SafeText"):
    r = send(epfis, "BenchmarkTest00529", pv)
    b = r.body or ""
    print(f"  FIS {pv:34} -> {r.status} len={len(b)} {b[:80]!r}")

print("=== G) cmdi names-channel (00498 family) ===")
epc = mk("BenchmarkTest00498")
r = send(epc, "FOO=echo SENTINEL5858XX", "BenchmarkTest00498")
b = r.body or ""
print("  name=FOO=echo... ->", r.status, len(b), "marker:", "SENTINEL5858XX" in b, b[:90])
r = send(epc, "FOO=echo NOTSENTINEL", "BenchmarkTest00498")
print("  control ->", r.status, len(r.body or ""), "marker:", "SENTINEL5858XX" in (r.body or ""))
