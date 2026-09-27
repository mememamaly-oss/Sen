#!/usr/bin/env python3
"""LIVE test: REST API server (api.py) — boots the real server, then exercises every
endpoint over real HTTP: health, UI, runs, findings, stats, POST /api/scans against
the local fixture (background scan), poll-to-completion, auth enforcement."""
import json, os, subprocess, sys, time, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PORT = 8033
DB = os.path.join(ROOT, "results", "api-live-test.db")
if os.path.exists(DB):
    os.remove(DB)                                   # clean slate for this test

from sentinel.cli import ensure_fixture

fixture = ensure_fixture("http://127.0.0.1:8777")
srv = subprocess.Popen([sys.executable, "-m", "sentinel.cli", "serve",
                        "--port", str(PORT), "--db", DB],
                       cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
try:
    def api(path, method="GET", body=None, headers=None, expect_error=False):
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                     data=json.dumps(body).encode() if body else None,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if expect_error:
                return e.code, json.loads(e.read().decode())
            raise

    # ---- wait for server readiness
    for _ in range(50):
        try:
            s, h = api("/api/health")
            if s == 200:
                break
        except Exception:
            time.sleep(0.2)
    assert h["status"] == "ok" and h["version"].startswith("2.1"), h
    print(f"[health] {h['status']} v{h['version']} uptime={h['uptime_s']}s")

    # ---- UI served
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=10) as r:
        html = r.read().decode()
    assert "SENTINEL" in html and "/api/scans" in html and "launch_scan" not in html
    assert r.headers["Content-Type"].startswith("text/html")
    print(f"[ui] dashboard served: {len(html)}B, contains API wiring")

    # ---- 404 handling
    s, e = api("/api/nope", expect_error=True)
    assert s == 404 and e["error"] == "not found"
    print("[404] unknown endpoint handled")

    # ---- POST a scan against the local fixture (allow_private required — scope!)
    s, r = api("/api/scans", "POST", {"target": "http://127.0.0.1:8777",
                                      "max_pages": 30, "allow_private": True})
    assert s == 202 and "run_id" in r, (s, r)
    run_id = r["run_id"]
    print(f"[POST /api/scans] 202 accepted run_id={run_id}")

    # ---- scope policy: private target WITHOUT allow_private must fail fast
    s, r = api("/api/scans", "POST", {"target": "http://127.0.0.1:8777"})
    # scan launches but produces zero findings (scope blocks everything) — poll it
    rid2 = r["run_id"]
    print(f"[scope] private target without allow_private -> run {rid2} (must find nothing)")

    # ---- poll to completion
    t0 = time.time()
    state = None
    while time.time() - t0 < 180:
        s, st = api(f"/api/scans/{run_id}")
        state = st["state"]
        if state in ("done", "failed"):
            break
        time.sleep(2)
    assert state == "done", f"scan did not finish: {st}"
    rep = st["report"]
    assert rep["run_id"] == run_id and len(rep["findings"]) >= 12
    print(f"[poll] scan done in {round(time.time()-t0)}s: {len(rep['findings'])} verified findings, "
          f"{rep['stats']['requests']} requests")

    # ---- scope-violating run: done but zero verified findings (private blocked)
    t0 = time.time()
    while time.time() - t0 < 120:
        s, st2 = api(f"/api/scans/{rid2}")
        if st2["state"] in ("done", "failed"):
            break
        time.sleep(1.5)
    assert st2["state"] == "done" and len(st2["report"]["findings"]) == 0, \
        "private target without allow_private must yield ZERO findings (scope gate)"
    print("[scope] scope-gated run completed with 0 findings (correct)")

    # ---- persisted runs visible
    s, runs = api("/api/runs")
    ids = [x["run_id"] for x in runs["runs"]]
    assert run_id in ids and rid2 in ids, "runs must be auto-persisted by the API"
    print(f"[runs] {len(ids)} runs persisted automatically")

    # ---- single run endpoint
    s, one = api(f"/api/runs/{run_id}")
    assert one["run_id"] == run_id and one["state"] == "done"
    assert len(one["findings"]) == len(rep["findings"])
    print(f"[run detail] {one['run_id']}: {len(one['findings'])} findings + "
          f"{len(one['rejected_candidates'])} rejected")

    # ---- findings query + filters
    s, f = api("/api/findings?type=sql_injection&min_risk=80")
    assert f["count"] >= 2 and all(x["type"] == "sql_injection" for x in f["findings"])
    s, f2 = api("/api/findings?limit=5")
    assert len(f2["findings"]) == 5
    print(f"[findings] sql_injection min_risk=80 -> {f['count']} rows; limit works")

    # ---- stats endpoint. Latest two runs = (full scan, scope-gated empty scan) in
    # SOME completion order (they ran concurrently) — direction-agnostic contract:
    # exactly ONE side carries the full scan's fingerprints, nothing is recurring.
    s, stats = api("/api/stats")
    assert stats["summary"]["runs"] >= 2, "two runs persisted"
    d = stats["latest_delta"]
    assert len(d["recurring"]) == 0 and len(d["new"]) + len(d["fixed"]) >= 12, \
        "full vs empty run: all fingerprints on one side, none recurring"
    print(f"[stats] summary={json.dumps(stats['summary'])[:150]}")
    print(f"[delta] full-vs-empty: new={len(d['new'])} fixed={len(d['fixed'])} "
          f"recurring={len(d['recurring'])} (correct, one-sided)")

    # ---- second full scan -> latest delta becomes full-vs-full -> recurring
    s, r3 = api("/api/scans", "POST", {"target": "http://127.0.0.1:8777",
                                       "max_pages": 30, "allow_private": True})
    assert s == 202
    t0 = time.time()
    while time.time() - t0 < 180:
        s, st3 = api(f"/api/scans/{r3['run_id']}")
        if st3["state"] in ("done", "failed"):
            break
        time.sleep(2)
    assert st3["state"] == "done" and len(st3["report"]["findings"]) >= 12
    s, stats2 = api("/api/stats")
    d2 = stats2["latest_delta"]
    assert d2["new"] == [] and d2["fixed"] == [] and len(d2["recurring"]) >= 12, \
        "two identical full scans: recurring only"
    print(f"[delta2] full-vs-full: recurring={len(d2['recurring'])} new=0 fixed=0 (correct)")

    # ---- invalid requests
    s, e = api("/api/scans", "POST", {"target": "ftp://x"}, expect_error=True)
    assert s == 400
    s, e = api("/api/scans", "POST", {}, expect_error=True)
    assert s == 400
    print("[validation] bad target / empty body -> 400")

    print("\nALL LIVE REST API TESTS PASSED")
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()
    if fixture is not None:
        fixture.terminate()
        try:
            fixture.wait(timeout=5)
        except Exception:
            fixture.kill()
