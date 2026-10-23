#!/usr/bin/env python3
"""AXIS 18 (2026-10-23) — LIMITED, REPRODUCIBLE local load test against the
PRODUCTION standalone build on :3100 (fresh scratch DB).

Deliberately bounded (per the master directive: no synthetic/meaningless
performance claims): 2 scenarios, all loopback, fixed request counts.
  S1: authenticated API reads (/api/scans list) — 120 requests, 12 concurrent
  S2: authenticated page renders (overview HTML) — 60 requests, 6 concurrent
Metrics: latency percentiles (p50/p90/p99), throughput, error count,
        server RSS before/after (leak indicator), verdict thresholds.

This is a single-pod, single-process, warm-cache SMOKE-scale measurement —
NOT an internet-scale benchmark. Numbers are comparable only to themselves
across runs on the same pod.
"""
import concurrent.futures
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:3100"


def http(method, path, body=None, cookie=None, timeout=30):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})},
        method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(4096)
            return time.perf_counter() - t0, r.status
    except urllib.error.HTTPError as e:
        e.read(256)
        return time.perf_counter() - t0, e.code


def login(email, password):
    c = {}
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(c.__setitem__ if False else None)) if False else None
    # minimal manual cookie flow
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.open(urllib.request.Request(BASE + "/api/auth/csrf"), timeout=15).read()
    csrf = json.loads(op.open(urllib.request.Request(BASE + "/api/auth/csrf"), timeout=15).read())["csrfToken"]
    data = f"csrfToken={csrf}&email={email}&password={password}&json=true".encode()
    req = urllib.request.Request(BASE + "/api/auth/callback/credentials", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    class NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op2 = urllib.request.build_opener(NR(), urllib.request.HTTPCookieProcessor(jar))
    try:
        op2.open(req, timeout=15)
    except urllib.error.HTTPError:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in jar)


def pct(sorted_lat, p):
    if not sorted_lat:
        return -1
    idx = min(len(sorted_lat) - 1, int(p / 100 * len(sorted_lat)))
    return sorted_lat[idx]


def scenario(name, fn, count, workers, cookie):
    lat, errs = [], 0
    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fn, cookie) for _ in range(count)]
        for f in futs:
            dt, st = f.result()
            lat.append(dt * 1000)
            if st >= 500:
                errs += 1
    wall = time.perf_counter() - t0
    lat.sort()
    return {
        "scenario": name, "requests": count, "concurrency": workers,
        "wall_sec": round(wall, 2), "rps": round(count / wall, 1),
        "p50_ms": round(pct(lat, 50), 1), "p90_ms": round(pct(lat, 90), 1),
        "p99_ms": round(pct(lat, 99), 1), "max_ms": round(lat[-1], 1),
        "errors_5xx": errs,
    }


def server_rss_kb():
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-C", "bun"], text=True)
        return sum(int(x) for x in out.split())
    except Exception:
        return -1


def main():
    suffix = secrets.token_hex(3)
    urllib.request.urlopen(urllib.request.Request(
        BASE + "/api/bootstrap",
        data=json.dumps({"name": "Load", "email": f"load-{suffix}@t.local",
                         "password": "Load-2026-Strong!", "orgName": "Load"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=20).read()

    cookie = login(f"load-{suffix}@t.local", "Load-2026-Strong!")
    st, _ = http("GET", "/api/me", cookie=cookie)
    print(f"login ok (api/me latency {st*1000:.0f}ms)")

    rss_before = server_rss_kb()

    s1 = scenario("S1 api reads (/api/scans)", lambda ck: http("GET", "/api/scans?limit=20", cookie=ck),
                  count=120, workers=12, cookie=cookie)
    s2 = scenario("S2 page render (overview)", lambda ck: http("GET", "/", cookie=ck),
                  count=60, workers=6, cookie=cookie)

    time.sleep(2)
    rss_after = server_rss_kb()

    results = {
        "meta": {
            "date": "2026-10-23", "target": BASE + " (production standalone, fresh scratch DB)",
            "scale": "SMOKE-scale, single pod, loopback only — comparable only across identical runs",
            "server_rss_before_kb": rss_before, "server_rss_after_kb": rss_after,
            "rss_delta_kb": rss_after - rss_before,
        },
        "scenarios": [s1, s2],
        "verdicts": {},
    }

    v = {}
    v["S1_p99_under_2000ms"] = s1["p99_ms"] < 2000
    v["S1_zero_5xx"] = s1["errors_5xx"] == 0
    v["S2_p99_under_3000ms"] = s2["p99_ms"] < 3000
    v["S2_zero_5xx"] = s2["errors_5xx"] == 0
    v["rss_growth_under_150MB"] = (rss_after - rss_before) < 150 * 1024
    results["verdicts"] = v

    print(json.dumps(results, indent=2, ensure_ascii=False))
    with open("qa-results/axis18_load_test.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return 0 if all(v.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
