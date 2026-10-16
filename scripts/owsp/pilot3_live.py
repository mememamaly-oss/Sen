#!/usr/bin/env python3
"""Pilot 3 — instrumented debugging: weakrand bytes/double/math families, FOS
truncate, VR-24 securecookie, exists shapes."""
import sys, json, re, base64, time
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

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("p3"), timeout=8)

def send(ep, name, value, loc=None, note="p3"):
    m = RequestMutation(endpoint=ep, param_name=name, param_value=value, note=note)
    if loc is not None: m.param_location = loc
    return eng.send(m)

from sentinel.weakrand import WeakRandomPhase
ph = WeakRandomPhase(eng, EventBus("p3"))

def sample(ep):
    t0 = time.monotonic_ns()
    c = ph._fetch_cookie(ep)
    t1 = time.monotonic_ns()
    return c, (t0 + t1) // 2, t1 - t0

print("=== A) instrumented relation family: bytes(00160), double(00161) ===")
for t, kind in (("BenchmarkTest00160", "bytes"), ("BenchmarkTest00161", "double"),
                ("BenchmarkTest00085", "long")):
    ep = mk(t)
    samples = [sample(ep) for _ in range(3)]
    print(f"\n  {t} [{kind}] samples (rtt ms):",
          [(c[1][:12] if c else None, (rtt // 100000) / 10) for c, _, rtt in samples])
    seeds = []
    for c, ts, rtt in samples:
        val = c[1].strip()
        if kind == "long":
            st = jrand.recover_state_nextlong(jrand.parse_java_long(val))
        elif kind == "double":
            d53 = jrand.double_from_cookie(val)
            print("    d53:", d53)
            cands = jrand.recover_state_nextdouble(d53) if d53 is not None else []
            print("    double candidates:", [hex(x) for x in cands])
            st = cands[0] if cands else None
        else:
            bs = base64.b64decode(val + "===")[:10]
            st = jrand.recover_state_nextbytes(bs)
        if st is None:
            print("    STATE RECOVERY FAILED for", val[:20]); break
        seeds.append((jrand.seed_from_state(st), ts))
    if len(seeds) == 3:
        for W in (1 << 23, 1 << 24, 1 << 25):
            sol = jrand.uniquifier_relation_solve(seeds[0][0], seeds[1][0],
                                                  seeds[0][1], seeds[1][1], window=W)
            print(f"    solve W=2^{W.bit_length()-1}:", "OK" if sol else "FAIL")
            if sol:
                u1, t1s, t2s = sol
                u3 = ((u1 * jrand.UNIQ_MULT % jrand.MOD64) * jrand.UNIQ_MULT % jrand.MOD64) & jrand.MASK48
                t3 = seeds[2][0] ^ u3
                d3 = (t3 - (seeds[2][1] & jrand.MASK48)) & jrand.MASK48
                print(f"    forward confirm d3 delta = {d3} (want <= 2^23 or wrap)")
                break

print("\n=== B) chain family trace on 00461 (Math.random FN) ===")
t = "BenchmarkTest00461"
src = open(SRC + "/src/main/java/org/owasp/benchmark/testcode/" + t + ".java").read()
m = re.search(r"String rememberMeKey = ([^;]+);", src)
print("  token code:", m.group(1) if m else "?")
ep = mk(t)
vals = []
for i in range(4):
    c = ph._fetch_cookie(ep)
    vals.append(c[1] if c else None)
    print(f"  sample {i+1}: {c[1] if c else None}")
d1 = jrand.double_from_cookie(vals[0]) if vals[0] else None
d2 = jrand.double_from_cookie(vals[1]) if vals[1] else None
print("  d1, d2:", d1, d2)
if d1 is not None and d2 is not None:
    cands = []
    for s1 in jrand.recover_state_nextdouble(d1):
        s_after = jrand.next_state(s1)
        if jrand.predict_double_int(s_after) == d2:
            cands.append(s_after)
    print("  chain candidates:", len(cands))
    if cands:
        s_b3 = jrand.next_state(jrand.next_state(cands[0]))
        pred = jrand.double_int_to_cookie(jrand.predict_double_int(s_b3))
        print("  predicted sample3:", pred, "actual:", vals[2])

print("\n=== C) FOS truncate mechanics ===")
import subprocess
print(subprocess.run(["ls", "-la", SRC + "/testfiles/"], capture_output=True, text=True).stdout[:600])
ep = mk("BenchmarkTest00028")
for pv in ("passwordFile.txt", "sentinel-fos-new.txt"):
    r = send(ep, "BenchmarkTest00028", pv)
    print(f"  FOS {pv:24} -> {r.status} len={len(r.body or '')} {(r.body or '')[:60]!r}")
# after FOS on passwordFile.txt: does the artifact still hold old lines?
ep2 = mk("BenchmarkTest00001")
r = send(ep2, "BenchmarkTest00001", "passwordFile.txt", loc=ParamLocation.HEADER)
b = r.body or ""
print("  read after FOS:", len(b), "bytes;",
      "LINES:", b.count("value="), "| first:", b[:100].replace("\n", "|"))

print("\n=== D) VR-24 on 00403 candidate ===")
from sentinel.detect import SecureCookieDetector
from sentinel.intel import Verifier
scd = SecureCookieDetector(eng, EventBus("p3"))
cand = scd.run(mk("BenchmarkTest00403"))
print("  candidate:", cand.type if cand else None, "param:", cand.parameter if cand else None)
if cand:
    v = Verifier(engine=eng, bus=EventBus("p3"), oast=None)
    out = v.verify(cand, mk("BenchmarkTest00403"))
    print("  verify ->", out.status, "conf:", out.confidence,
          (out.verification.notes[:100] if out.verification else ""))

print("\n=== E) exists-FN shape histogram ===")
d = json.load(open('/home/z/my-project/build-v430/results/owsp/benchmark/eval_v430_final_v430.json'))
TCD = SRC + "/src/main/java/org/owasp/benchmark/testcode/"
import collections
hist = collections.Counter()
for t in d["per_category"]["pathtraver"]["fn_tests"]:
    s = open(TCD + t + ".java").read()
    if "FileOutputStream" in s: hist["FOS"] += 1
    elif "FileInputStream" in s: hist["FIS:" + ("echo" if "println" in s else "quiet")] += 1
    elif re.search(r'new java\.io\.File\([^)]*,\s*"/Test\.txt"\)', s): hist["exists:file+Test.txt"] += 1
    elif ".exists()" in s: hist["exists:plain"] += 1
    else: hist["other"] += 1
print(" ", dict(hist))

print("\n=== F) exists:file+Test.txt — what dirs contain Test.txt? ===")
r = send(mk("BenchmarkTest00011"), "BenchmarkTest00011", "testfiles", loc=ParamLocation.HEADER)
print("  param=testfiles ->", (r.body or "")[-80:].replace("\n", "|"))
r = send(mk("BenchmarkTest00011"), "BenchmarkTest00011", "/home/z/my-project/tools/benchmark-src/testfiles", loc=ParamLocation.HEADER)
print("  param=abs-testfiles ->", (r.body or "")[-80:].replace("\n", "|"))
