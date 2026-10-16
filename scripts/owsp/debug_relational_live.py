#!/usr/bin/env python3
"""GTP-13 debug: why doesn't the seedUniquifier relation family fire live?
Tests the full relation pipeline manually against nextLong/nextBytes/nextDouble
weakrand endpoints on the live Benchmark."""
import sys, time, base64, urllib.request, http.cookiejar

sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel import jrand

BASE = "http://localhost:8080/benchmark"

def fetch(test, folder="weakrand-00"):
    """Stateless fetch; returns (cookie_name, cookie_value, t_center_ns)."""
    url = f"{BASE}/{folder}/{test}"
    t0 = time.monotonic_ns()
    req = urllib.request.Request(url, method="POST",
                                 data=f"{test}=x".encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    # no cookie jar -> fresh session -> fresh rememberMe cookie
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener(NoRedirect)
    try:
        r = op.open(req, timeout=8)
        scs = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        scs = e.headers.get_all("Set-Cookie") or []
    t1 = time.monotonic_ns()
    for line in scs:
        if "rememberMe" in line:
            name = line.split("=")[0].strip()
            val = line.split("=")[1].split(";")[0]
            return name, val, (t0 + t1) // 2
    return None, None, (t0 + t1) // 2


def test_nextlong(test):
    samples = []
    for _ in range(3):
        n, v, t = fetch(test)
        if v is None:
            print(f"  {test}: NO cookie"); return
        st = jrand.recover_state_nextlong(jrand.parse_java_long(v))
        print(f"  {test}: cookie {n}={v[:26]}  state_recovery={'OK '+hex(st) if st is not None else 'FAIL'}")
        if st is None: return
        samples.append((jrand.seed_from_state(st), t))
    sol = jrand.uniquifier_relation_solve(samples[0][0], samples[1][0],
                                          samples[0][1], samples[1][1], window=1 << 23)
    print(f"  {test}: relation solve -> {sol is not None}")
    if sol:
        u1, t1, t2 = sol
        u3 = ((u1 * jrand.UNIQ_MULT % jrand.MOD64) * jrand.UNIQ_MULT % jrand.MOD64) & jrand.MASK48
        t3 = samples[2][0] ^ u3
        d3 = (t3 - (samples[2][1] & jrand.MASK48)) & jrand.MASK48
        print(f"  {test}: 3rd-sample delta = {d3} (want < ~8M or > MASK-8M)")


def test_nextbytes(test):
    samples = []
    for _ in range(3):
        n, v, t = fetch(test)
        if v is None:
            print(f"  {test}: NO cookie"); return
        try:
            bs = base64.b64decode(v + "===")[:10]
        except Exception as e:
            print(f"  {test}: b64 fail {e}"); return
        st = jrand.recover_state_nextbytes(bs)
        print(f"  {test}: cookie {n}={v[:26]}  state_recovery={'OK' if st is not None else 'FAIL'}")
        if st is None: return
        samples.append((jrand.seed_from_state(st), t))
    sol = jrand.uniquifier_relation_solve(samples[0][0], samples[1][0],
                                          samples[0][1], samples[1][1], window=1 << 23)
    print(f"  {test}: relation solve -> {sol is not None}")


def test_nextdouble(test):
    samples = []
    for i in range(3):
        n, v, t = fetch(test)
        if v is None:
            print(f"  {test}: NO cookie"); return
        d = jrand.double_from_cookie(v)
        print(f"  {test}: cookie {n}={v[:26]}  double_int={d is not None}")
        if d is None: return
        cands = jrand.recover_state_nextdouble(d)
        print(f"    candidates: {len(cands)}")
        if not cands: return
        samples.append((cands, t))
    # try each candidate pair combo
    for c1 in samples[0][0][:4]:
        for c2 in samples[1][0][:4]:
            s1 = jrand.seed_from_state(c1); s2 = jrand.seed_from_state(c2)
            sol = jrand.uniquifier_relation_solve(s1, s2, samples[0][1], samples[1][1], window=1 << 23)
            if sol:
                print(f"  {test}: relation solve OK with cands {c1},{c2}")
                return
    print(f"  {test}: relation solve FAIL across all candidate pairs")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "long"
    tests = {"long": ("BenchmarkTest00085", test_nextlong),
             "bytes": ("BenchmarkTest00160", test_nextbytes),
             "double": ("BenchmarkTest00161", test_nextdouble)}
    t, fn = tests[which]
    print(f"== {which} family: {t} ==")
    fn(t)
