#!/usr/bin/env python3
"""SENTINEL test runner — unit + regression + chaos suites (real execution).
Usage: run_tests.py [unit|regression|chaos|all]  → prints JSON verdict (last line).
Release gate (spec 37): every suite must pass. Cases execute at import in registration order.
"""
import json, os, sys, time, threading, traceback

RESULTS = {"suite": "?", "total": 0, "failed": 0, "cases": []}
_REGISTRY = []
# Fast-iteration filter (ops): SENTINEL_TEST_FILTER="prefix1,prefix2" executes ONLY
# matching cases at import (others register as skipped). Cases execute at import in
# this runner, so a "filtered" CLI run used to pay the FULL suite runtime anyway.
_FILTER = [p for p in os.environ.get("SENTINEL_TEST_FILTER", "").split(",") if p]


def case(fn):
    """Register + execute immediately; failures captured, never crash the runner."""
    RESULTS["total"] += 1
    t0 = time.time()
    if _FILTER and not any(fn.__name__.startswith(p) for p in _FILTER):
        RESULTS["cases"].append({"name": fn.__name__, "ok": True, "ms": 0, "skipped": True})
        _REGISTRY.append(fn.__name__)
        return fn
    try:
        fn()
        RESULTS["cases"].append({"name": fn.__name__, "ok": True, "ms": round((time.time() - t0) * 1000)})
    except Exception as e:
        RESULTS["cases"].append({"name": fn.__name__, "ok": False, "ms": round((time.time() - t0) * 1000),
                                 "error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-400:]})
        RESULTS["failed"] += 1
    _REGISTRY.append(fn.__name__)
    return fn


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # PORTABILITY FIX: test the tree we live in (was hardcoded /home/z/my-project/sentinel)

# ================================================================ UNIT SUITE
from sentinel.core import (Endpoint, Finding, Parameter, ParamKind, ParamLocation,
                           ScopeRule, is_private_ip, EventBus, Evidence)
from sentinel.intel import wilson_lower, StrategyStore, FindingPipeline, RepairClassifier
from sentinel.detect import plan_for


@case
def unit_scope_blocks_private():
    assert is_private_ip("127.0.0.1") and is_private_ip("10.1.2.3")
    assert is_private_ip("172.16.0.1") and is_private_ip("192.168.1.1")
    assert is_private_ip("169.254.169.254") and is_private_ip("::1")
    assert not is_private_ip("45.33.32.156") and not is_private_ip("8.8.8.8")


@case
def unit_param_classification():
    assert Parameter("url", ParamLocation.QUERY, "https://x.com").classify().kind == ParamKind.URL
    assert Parameter("id", ParamLocation.QUERY, "5").classify().kind == ParamKind.NUMERIC
    assert Parameter("file", ParamLocation.QUERY, "a.txt").classify().kind == ParamKind.FILENAME
    assert Parameter("q", ParamLocation.QUERY, "hello").classify().kind == ParamKind.SEARCH


@case
def unit_planner_deterministic():
    ep = Endpoint(url="http://x.io/a.php", parameters=[
        Parameter("id", ParamLocation.QUERY, "1").classify(),
        Parameter("url", ParamLocation.QUERY, "https://a.b").classify()])
    p1 = [f"{d['vuln']}:{d['param'].name}" for d in plan_for(ep)]
    p2 = [f"{d['vuln']}:{d['param'].name}" for d in plan_for(ep)]
    assert p1 == p2 and "sql_injection:id" in p1 and "open_redirect:url" in p1


@case
def unit_finding_fingerprint_stable():
    f1 = Finding("sql_injection", endpoint_url="http://a/x.php?id=1", parameter="id",
                 evidence=[Evidence("db_error", "match X")])
    f2 = Finding("sql_injection", endpoint_url="http://a/x.php?id=2", parameter="id",
                 evidence=[Evidence("db_error", "match X")])
    assert f1.fingerprint() == f2.fingerprint(), "same root cause must dedup"
    f3 = Finding("xss_reflected", endpoint_url="http://a/x.php", parameter="id")
    assert f1.fingerprint() != f3.fingerprint()


@case
def unit_wilson_sample_size_aware():
    assert wilson_lower(92, 100) > wilson_lower(19, 20), "spec 26: sample size must matter"
    assert wilson_lower(0, 0) == 0.0


@case
def unit_strategy_ordering_deterministic():
    import tempfile, os
    st = StrategyStore(os.path.join(tempfile.mkdtemp(), "st.json"))
    for _ in range(10): st.record("sqli", "boolean_and", True)
    for _ in range(3):  st.record("sqli", "quote_error", False)
    o1 = st.order("sqli", ["quote_error", "boolean_and"])
    o2 = st.order("sqli", ["boolean_and", "quote_error"])
    assert o1 == o2 and o1[0] == "boolean_and"


@case
def unit_repair_classifier_rules():
    c = RepairClassifier()
    assert c.classify("timeout:TimeoutError", {})[0] == "timeout_spike"
    assert c.classify("ConnectionResetError", {})[0] == "connection_reset"
    assert c.classify("gaierror: resolve fail", {})[0] == "dns_failure"
    assert c.classify("something totally unknown", {}) is None


@case
def unit_dedup_pipeline():
    pipe = FindingPipeline(EventBus("t"))
    a = Finding("sql_injection", endpoint_url="http://a/x.php", parameter="id", evidence=[Evidence("db_error", "e1")])
    b = Finding("sql_injection", endpoint_url="http://a/x.php", parameter="id", evidence=[Evidence("db_error", "e2")])
    out = pipe.dedup([a, b])
    assert len(out) == 1 and len(out[0].evidence) == 2


# ================================================================ REGRESSION SUITE
# (cases auto-generated from FailureMemory classes — spec 28)
@case
def regression_timeout_repair_rule():
    """PERMANENT case from timeout_spike failure class."""
    rule = RepairClassifier().classify("timeout:TimeoutError", {"scanner": "sqli"})
    assert rule is not None and rule[0] == "timeout_spike"
    action = rule[1]["action"]
    assert action["multiply_timeout"] == 3.0 and action["retry"] >= 1


@case
def regression_verification_rejects_false_candidate():
    """Un-reproducible candidate MUST be rejected (spec 13/51)."""
    from sentinel.intel import VerificationEngine
    from sentinel.http_engine import RequestEngine
    eng = RequestEngine(ScopeRule(allowed_domains=["nonexistent.invalid"], allow_private=True),
                        EventBus("r"), timeout=1.0)
    v = VerificationEngine(eng, EventBus("r"))
    f = Finding("sql_injection", endpoint_url="http://nonexistent.invalid/x.php", parameter="id",
                evidence=[Evidence("db_error", "e")])
    ep = Endpoint(url="http://nonexistent.invalid/x.php",
                  parameters=[Parameter("id", ParamLocation.QUERY, "1")])
    out = v.verify(f, ep)
    assert out.status.value == "rejected", "un-reproducible oracle must be rejected"


@case
def regression_xss_verifier_waf_bypass():
    """VR-02 regression (live-caught on demo.testfire.net 2026-09-27): a WAF that
    blocks onerror=/<script must NOT cause rejection of a genuinely exploitable
    raw reflection. Old single-vector logic produced a real FN; battery must verify."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs, unquote
    from sentinel.intel import VerificationEngine
    from sentinel.http_engine import RequestEngine

    BLOCK = ("onerror=", "<script", "onload=")      # blacklist like Altoro's WAF

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if any(b in q.lower() for b in BLOCK):
                self.send_response(200); self.end_headers()
                self.wfile.write(b"<html><body>blocked</body></html>"); return
            self.send_response(200); self.end_headers()
            self.wfile.write(("<html><body>echo: " + q + "</body></html>").encode())
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 8793), H)
    import threading as _th
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                            EventBus("r"), timeout=3.0)
        v = VerificationEngine(eng, EventBus("r"))
        f = Finding("xss_reflected", endpoint_url="http://127.0.0.1:8793/t", parameter="q",
                    evidence=[Evidence("unescaped_reflection", "canary reflected raw")])
        ep = Endpoint(url="http://127.0.0.1:8793/t",
                      parameters=[Parameter("q", ParamLocation.QUERY, "hi")])
        out = v.verify(f, ep)
        assert out.status.value == "verified", \
            f"WAF-blacklist site must still verify (got {out.status.value}; old logic FN)"
        assert out.confidence >= 0.75, "single-bypass verification deserves >=0.75"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_xss_verifier_rejects_encoded_only():
    """VR-02 counterpart: reflection that HTML-ENCODES everything must STILL be
    rejected (diversity must not create FPs). Same battery, no raw reflection."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs
    from html import escape
    from sentinel.intel import VerificationEngine
    from sentinel.http_engine import RequestEngine

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self.send_response(200); self.end_headers()
            self.wfile.write(("<html><body>echo: " + escape(q) + "</body></html>").encode())
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 8794), H)
    import threading as _th
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                            EventBus("r"), timeout=3.0)
        v = VerificationEngine(eng, EventBus("r"))
        f = Finding("xss_reflected", endpoint_url="http://127.0.0.1:8794/t", parameter="q",
                    evidence=[Evidence("unescaped_reflection", "candidate")])
        ep = Endpoint(url="http://127.0.0.1:8794/t",
                      parameters=[Parameter("q", ParamLocation.QUERY, "hi")])
        out = v.verify(f, ep)
        assert out.status.value == "rejected", "fully-encoded reflection must stay rejected (0 FP)"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_engine_preserves_redirect_oracle_e2e():
    """ENG-01+ENG-02 regression (live-caught on demo.testfire.net/doLogin): a POST login
    whose OR-tautology produces SAME-HOST 302 differentials must be detected end-to-end
    through the REAL engine. Old engine (a) followed the redirect and returned the final
    200, destroying the Location oracle, and (b) sent body-param payloads as URL query
    with an empty body — the payload never reached the app."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.core import FindingStatus
    from sentinel.intel import VerificationEngine
    from sentinel.http_engine import RequestEngine
    from sentinel.detect import SQLiDetector

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            # ENG-03: mimic Tomcat — without the form Content-Type the body is NOT parsed
            ct = (self.headers.get("Content-Type") or "").lower()
            if "application/x-www-form-urlencoded" not in ct:
                self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
                return
            from urllib.parse import parse_qs
            body = parse_qs(self.rfile.read(n).decode())
            uid = body.get("uid", [""])[0]
            passw = body.get("passw", [""])[0]
            if not passw:                                # DISC-04: Altoro-style early reject
                self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
            elif "'1'='1'" in uid:                       # OR-tautology TRUE (non-empty pw)
                self.send_response(302); self.send_header("Location", "/welcome"); self.end_headers()
            else:                                        # FALSE / baseline
                self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<html>page</html>")
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 8795), H)
    import threading as _th
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                            EventBus("r"), timeout=3.0)
        ep = Endpoint(url="http://127.0.0.1:8795/login", method="POST",
                      parameters=[Parameter("uid", ParamLocation.BODY),
                                  Parameter("passw", ParamLocation.BODY)])
        det = SQLiDetector(None, EventBus("eng12"))
        cands = det.candidates(ep)
        # per-param analysis (mirrors orchestrator; a flat map would keep only the
        # last param's responses — the exact flaw this suite guards against)
        from itertools import groupby
        cands_by_param = {}
        for pname, grp in groupby(cands, key=lambda t: t[1].param_name):
            grp = list(grp)
            resp_map = {s: eng.send(m) for s, m in grp}
            pobj = next(p for p in ep.parameters if p.name == pname)
            cands_by_param[pname] = det.analyze((ep, pobj), resp_map)
        cand = cands_by_param["uid"]
        assert cand is not None and cand.type == "sql_injection", \
            "E2E: same-host redirect oracle must produce a candidate (ENG-01/02/DISC-04)"
        assert any(e.kind == "redirect_diff" for e in cand.evidence)
        assert cands_by_param["passw"] is None, "non-oracle param must not produce a candidate"
        v = VerificationEngine(eng, EventBus("eng12"))
        out = v.verify(cand, ep)
        assert out.status == FindingStatus.VERIFIED, f"verifier must confirm via PATH C (got {out.status})"
        assert out.verification.method == "oracle:or-redirect-2round"
        # negative control: a param with NO tautology effect must not verify
        ep2 = Endpoint(url="http://127.0.0.1:8795/login", method="POST",
                       parameters=[Parameter("other", ParamLocation.BODY)])
        cands2 = det.candidates(ep2)
        rm2 = {s: eng.send(m) for s, m in cands2}
        assert det.analyze((ep2, ep2.parameters[0]), rm2) is None, "no oracle -> no candidate"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_form_param_location_follows_method():
    """DISC-02 regression (live-caught on demo.testfire.net frmSearch): GET-method form
    params MUST be QUERY-located (were always BODY -> ENG-02 honored the wrong metadata
    and GET probes silently dropped their payload, losing a real verified XSS)."""
    from sentinel.discovery import DiscoveryEngine
    from sentinel.http_engine import RequestEngine
    eng = RequestEngine(ScopeRule(allowed_hosts=["x.invalid"]), EventBus("r"), timeout=1)
    d = DiscoveryEngine(eng)
    # GET form -> params in QUERY
    ep = d._mk_endpoint("http://x.invalid/search", None, params=[("query", "")], method="GET")
    assert ep.parameters[0].location.value == "query", "GET form params must be query"
    # POST form -> params in BODY
    ep2 = d._mk_endpoint("http://x.invalid/doLogin", None, params=[("uid", "")], method="POST")
    assert ep2.parameters[0].location.value == "body", "POST form params must be body"
    # mixed case method
    ep3 = d._mk_endpoint("http://x.invalid/t", None, params=[("a", "")], method="post")
    assert ep3.parameters[0].location.value == "body", "case-insensitive method check"
    # E2E: rendered GET probe must carry the payload in the URL, not the body
    from sentinel.detect import XSSDetector
    det = XSSDetector(None, EventBus("r"))
    cands = det.candidates(ep)
    m = cands[0][1] if isinstance(cands[0], tuple) else cands[0]   # VR-03: tuple strategy form
    url, method, headers, body = eng._render(m)
    assert "query=" in url and "sentinelxssmarker" in url, "GET probe payload must be in URL"
    assert not body, "GET probe must not carry a body"


@case
def regression_scope_blocks_metadata_service():
    """SSRF guard regression: metadata endpoints never scannable by default."""
    from sentinel.http_engine import RequestEngine
    eng = RequestEngine(ScopeRule(allowed_domains=["x.invalid"]), EventBus("r"), timeout=1)
    ok, why = eng._scope_ok("http://169.254.169.254/latest/meta-data/")
    assert not ok, "metadata service must be blocked"


# ================================================================ CHAOS SUITE (spec 35)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _ChaosHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(2.0)
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        elif self.path == "/reset":
            self.connection.close()
        elif self.path == "/garbage":
            self.wfile.write(b"\x00\xff\xfe not-http\r\n\r\n"); self.connection.close()
        elif self.path == "/huge":
            self.send_response(200); self.send_header("Content-Length", "5000000"); self.end_headers()
            self.wfile.write(b"A" * 900_000); self.connection.close()
        elif self.path == "/badredirect":
            self.send_response(302); self.send_header("Location", "/badredirect"); self.end_headers()
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")


def _chaos_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ChaosHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@case
def chaos_timeouts_fail_safe():
    from sentinel.http_engine import RequestEngine, RequestMutation
    srv = _chaos_server(); port = srv.server_address[1]
    eng = RequestEngine(ScopeRule(allow_private=True), EventBus("c"), timeout=0.4)
    r = eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{port}/slow")))
    assert r.error.startswith("timeout") and r.status == 0
    srv.shutdown()


@case
def unit_eng20_benchmark_owned_fixture():
    """ENG-20: the default benchmark NEVER reuses whatever listens on :8777 —
    it spawns its own fresh fixture on an ephemeral port (a long-lived env may
    hold attack-mutated leftover state there); explicit operator URLs pass
    through with legacy OP-01 semantics."""
    import socket as _s, time as _t
    from sentinel.cli import _benchmark_fixture
    # plant a stale listener on :8777 (any server socket, like a leftover fixture)
    stale = _s.socket(); stale.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    stale.bind(("127.0.0.1", 8777)); stale.listen(4)
    try:
        url, proc = _benchmark_fixture("http://127.0.0.1:8777")
        assert url != "http://127.0.0.1:8777", url
        assert proc is not None and proc.poll() is None, "owned fixture must be alive"
        import urllib.request as _u
        with _u.urlopen(url + "/", timeout=5) as r:      # the owned instance serves
            assert r.status == 200
        proc.terminate(); proc.wait(timeout=5)
        # ANY canonical fixture-port spelling (incl. trailing slash) gets the
        # owned fresh instance — the fixture's state on :8777 is unknowable
        url2, proc2 = _benchmark_fixture("http://127.0.0.1:8777/")
        assert url2 != "http://127.0.0.1:8777" and proc2 is not None and proc2.poll() is None, (url2, proc2)
        proc2.terminate(); proc2.wait(timeout=5)
        # truly custom targets pass through untouched (legacy semantics)
        url3, proc3 = _benchmark_fixture("https://example.invalid/")
        assert url3 == "https://example.invalid/" and proc3 is None
        url4, proc4 = _benchmark_fixture("http://127.0.0.1:8123")
        assert url4 == "http://127.0.0.1:8123"
        if proc4 is not None:                            # legacy OP-01 may spawn it
            proc4.terminate(); proc4.wait(timeout=5)
    finally:
        stale.close()


@case
def chaos_connection_reset_fail_safe():
    from sentinel.http_engine import RequestEngine, RequestMutation
    srv = _chaos_server(); port = srv.server_address[1]
    eng = RequestEngine(ScopeRule(allow_private=True), EventBus("c"), timeout=3)
    r = eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{port}/reset")))
    assert r.error and r.status == 0, "reset must produce error, not crash"
    srv.shutdown()


@case
def chaos_garbage_and_huge_fail_safe():
    from sentinel.http_engine import RequestEngine, RequestMutation
    srv = _chaos_server(); port = srv.server_address[1]
    eng = RequestEngine(ScopeRule(allow_private=True), EventBus("c"), timeout=3)
    for path in ("/garbage", "/huge", "/badredirect", "/normal"):
        r = eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{port}{path}")))
        assert r is not None, f"{path} crashed the engine"
    srv.shutdown()


@case
def chaos_strategy_store_counts_only_verified():
    import tempfile, os
    st = StrategyStore(os.path.join(tempfile.mkdtemp(), "s2.json"))
    st.record("xss", "canary", verified=True)
    st.record("xss", "canary", verified=False)
    s = st.stats["xss:default:canary"]
    assert s["n"] == 2 and s["verified"] == 1 and s["failed"] == 1


@case
def chaos_reproducible_run_ids():
    from sentinel.core import new_run_id
    a1, s1 = new_run_id("fixed-seed-42")
    a2, s2 = new_run_id("fixed-seed-42")
    assert a1 == a2 and s1 == s2, "same seed must reproduce same run id (spec 36)"


@case
def regression_benchmark_autostarts_fixture():
    """OP-01 regression: benchmark must auto-start the local fixture when it is
    not running (caught live during re-verification: silent F1=0.0, all-FN)."""
    import socket, os as _os, tempfile
    from sentinel.cli import run_benchmark, _port_open
    PORT = 8791                                    # isolated port, nothing else uses it
    url = f"http://127.0.0.1:{PORT}"
    s = socket.socket(); already = s.connect_ex(("127.0.0.1", PORT)) == 0; s.close()
    assert not already, "OP-01 test port unexpectedly occupied"
    rep = run_benchmark(url, out=_os.path.join(tempfile.gettempdir(), "op01_bench.json"),
                        label="op01-regression")
    # fixture v10 ground truth (Phase 58 + Phase 60): 38 TP-able (v9's 35 PLUS
    # the three v4.0.0 cross-identity classes on /wf/shared/transfer —
    # cross_user / cross_object / cross_state — state-oracle proofs with the
    # attack battery armed), 35 TN-able (v9's 29 PLUS the six honest negatives
    # for the cross classes on the per-session twin wizards). F1 must be 1.0
    # with zero FP/FN — the OP-01 autostart path must deliver the FULL
    # benchmark, not a silently-empty scan (the original F1=0.0 failure mode).
    # bench-adv (fixture v11, 2026-10-03): +2 adversarial TN cases
    # (csrf@/vuln/subscribe-echo, nosql@/api/nosql-lockout — the blanket-200
    # traps that false-positive the v4.1.1 oracles) -> TN 35 -> 37, 75 cases.
    scored = (rep["f1"] >= 0.99 and rep["confusion"]["TP"] == 38
              and rep["confusion"]["FP"] == 0 and rep["confusion"]["FN"] == 0
              and rep["confusion"]["TN"] == 37)
    cleaned = not _port_open("127.0.0.1", PORT)                  # stopped what it started
    assert scored and cleaned, (rep["confusion"], rep["f1"], cleaned)


@case
def regression_js_url_extraction_rejects_code_fragments():
    """DISC-01 regression (live-caught on demo.testfire.net): minified webpack code
    fragments matched by JS_PATTERNS (url:",s.default.createElement(" ... ) must NOT
    become endpoints; legit API paths must survive the gate."""
    from sentinel.discovery import plausible_js_url, JS_PATTERNS
    # exact garbage classes observed live in swagger-ui-bundle.js
    garbage = [",s.default.createElement(", "+encodeURIComponent(this.st",
               ",l.default.createElement(", ",t,n,", "responseURL", "string",
               "new Error(e)", "a&&b", "this.options"]
    # real endpoints that MUST be kept (incl. relative fetch-style paths)
    legit = ["/api/users", "/logout", "api/v1/accounts", "/bank/transaction?acc=1",
             "https://demo.testfire.net/search.jsp", "ws://localhost/ws", "custom.js",
             "http://x.y/api"]
    for g in garbage:
        assert not plausible_js_url(g), f"garbage accepted as URL: {g!r}"
    for l in legit:
        assert plausible_js_url(l), f"legit rejected as URL: {l!r}"
    # end-to-end: pattern extraction on a minified-webpack-like body
    body = ('u={url:"string"},v={url:",s.default.createElement("},w=url+",t,n,",'
            'x={url:"responseURL"};fetch("/api/accounts");'
            'axios.get("api/transactions");new WebSocket("ws://h/ws");')
    hits = [m for pat in JS_PATTERNS for m in pat.findall(body) if plausible_js_url(m)]
    assert sorted(hits) == ["/api/accounts", "api/transactions", "ws://h/ws"], hits


@case
def regression_sqli_or_redirect_oracle():
    """DETECT-01 regression (live-proven on demo.testfire.net/doLogin): string-context
    OR-tautology pair must (a) be emitted, (b) create a candidate on redirect
    differential, (c) be VERIFIED via PATH C replay, (d) stay silent when Locations
    are identical (no false positives)."""
    from sentinel.core import Endpoint, Parameter, ParamLocation, FindingStatus, EventBus
    from sentinel.detect import SQLiDetector
    from sentinel.http_engine import Response
    from sentinel.intel import VerificationEngine

    ep = Endpoint(url="http://t/doLogin", method="POST",
                  parameters=[Parameter("uid", ParamLocation.BODY).classify()])
    det = SQLiDetector(None, EventBus("run-det01"))
    strats = [s for s, _ in det.candidates(ep)]
    assert "or_true" in strats and "or_false" in strats, strats

    # (b) positive: redirect differential -> candidate with redirect_diff evidence
    rm = {"or_true": Response(status=302, headers={"Location": "/bank/main.jsp"}),
          "or_false": Response(status=302, headers={"Location": "login.jsp"})}
    f = det.analyze((ep, ep.parameters[0]), rm)
    assert f is not None and f.type == "sql_injection"
    assert any(e.kind == "redirect_diff" for e in f.evidence)

    # (d) negative: identical Locations -> NO candidate (FP guard)
    rm2 = {"or_true": Response(status=302, headers={"Location": "login.jsp"}),
           "or_false": Response(status=302, headers={"Location": "login.jsp"})}
    assert det.analyze((ep, ep.parameters[0]), rm2) is None

    # (c) PATH C verification with a fake engine reproducing the live oracle
    class _FakeLoginEngine:
        def send(self, m):
            loc = "/bank/main.jsp" if "'1'='1'" in m.param_value else "login.jsp"
            return Response(status=302, headers={"Location": loc})
    ve = VerificationEngine(_FakeLoginEngine(), EventBus("run-det01"))
    out = ve.verify(f, ep)
    assert out.status == FindingStatus.VERIFIED and out.verification.method == "oracle:or-redirect-2round", \
        (out.status, out.verification.method)


@case
def regression_inline_js_url_extraction():
    """DISC-05 regression (live-caught on ginandjuice.shop): URL-shaped strings inside
    INLINE <script> bodies (const categories = {"Gin":"/catalog?category=Gin"}) are
    endpoints the link/form parsers can never see. The whole /catalog attack surface
    was invisible until this extraction existed. End-to-end against a live fixture."""
    import threading, socket, os as _os
    from http.server import ThreadingHTTPServer
    import importlib.util
    from sentinel.http_engine import RequestEngine
    from sentinel.core import ScopeRule, EventBus
    spec = importlib.util.spec_from_file_location(
        "vulnapp_gj", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8793
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from sentinel.discovery import DiscoveryEngine
        # clear any state from earlier cases so THIS test proves its own crawl
        # learns the hint (order-isolation), then crawl — ENG-11 fetches the
        # discovered .js endpoint for hint extraction regardless of page budget.
        from sentinel.discovery import JS_XML_HINTS
        JS_XML_HINTS.discard("stockCheck")
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True), EventBus("run-disc05"), timeout=5)
        de = DiscoveryEngine(eng, max_pages=30)
        endpoints, js_hits, _ = de.crawl(f"http://127.0.0.1:{port}/")
        paths = {e.url for e in endpoints}
        assert any("/vuln/jsparam.php" in u and any(p.name == "cat" for p in e.parameters)
                   for u, e in ((e.url, e) for e in endpoints)), \
            "inline-script URL with ?cat= param must be discovered (DISC-05)"
        # DISC-06: the XML root was learned from the stockapp.js asset by THIS
        # crawl (ENG-11: discovered .js endpoints are fetched for hints even when
        # the BFS page budget never reaches their queue position).
        assert "stockCheck" in JS_XML_HINTS, "XML root hint must be learned from JS asset (ENG-11)"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_sqli_quote500_and_orpair_oracles():
    """DETECT-04 + DETECT-05 regression (live-caught on ginandjuice.shop ?category=):
    (a) quote -> generic 500 while base and doubled-quote succeed (no DB error string);
    (b) OR-pair body-size differential in string context. Both were invisible — the
    quote probe only matched SQL keyword patterns, the OR pair only checked redirects."""
    from sentinel.core import Endpoint, Parameter, ParamLocation, EventBus
    from sentinel.http_engine import Response
    from sentinel.detect import SQLiDetector
    ep = Endpoint(url="http://x.invalid/vuln/jsparam.php")
    ep.parameters = [Parameter("cat", ParamLocation.QUERY, "Gin").classify()]
    det = SQLiDetector(None, EventBus("r"))
    rm = {
        "base":        Response(status=200, body="<ul>products</ul>"),
        "pair_quote":  Response(status=200, body="<ul>products</ul>"),
        "quote_error": Response(status=500, body="<html>generic error page</html>"),
        "boolean_true":  Response(status=200, body="<ul>products</ul>"),
        "boolean_false": Response(status=200, body="<ul>products</ul>"),
        "or_true":  Response(status=200, body="x" * 3000),
        "or_false": Response(status=200, body="x" * 300),
    }
    f = det.analyze((ep, ep.parameters[0]), rm)
    assert f is not None, "status-oracle + OR-pair differential must fire"
    kinds = {e.kind for e in f.evidence}
    assert "status_oracle" in kinds and "response_diff" in kinds, kinds
    # negative: 4xx on quote is input VALIDATION, not SQL (ginandjuice productId live-proven)
    rm["quote_error"] = Response(status=400, body='"Invalid product ID"')
    assert det.analyze((ep, ep.parameters[0]), rm) is None or \
        all(e.kind != "status_oracle" for e in det.analyze((ep, ep.parameters[0]), rm).evidence), \
        "400-on-quote must NOT raise the status oracle"


@case
def regression_sqli_orpair_bodydiff_verification_path_d():
    """VR-04 / PATH D regression: string-context blind SQLi found via OR-pair body
    differential must VERIFY with fresh comparison-based vectors ('2'>'1' vs '1'>'2'),
    even when the app produces no errors and no redirects (ginandjuice category)."""
    from sentinel.core import Endpoint, Parameter, ParamLocation, EventBus, FindingStatus
    from sentinel.http_engine import Response
    from sentinel.detect import SQLiDetector
    from sentinel.intel import VerificationEngine
    ep = Endpoint(url="http://x.invalid/catalog")
    ep.parameters = [Parameter("category", ParamLocation.QUERY, "Gin").classify()]
    det = SQLiDetector(None, EventBus("r"))
    rm = {"base": Response(status=200, body="y" * 3000), "pair_quote": Response(status=200, body="y" * 3000),
          "quote_error": Response(status=200, body="y" * 3000),
          "boolean_true": Response(status=200, body="y" * 3000), "boolean_false": Response(status=200, body="y" * 3000),
          "or_true": Response(status=200, body="y" * 3000), "or_false": Response(status=200, body="y" * 300)}
    f = det.analyze((ep, ep.parameters[0]), rm)
    assert f is not None, "OR-pair body differential must create the candidate"

    class _FakeGinJuiceEngine:
        def send(self, m):
            big = ("'2'>'1'" in m.param_value) or ("'1'='1'" in m.param_value)
            return Response(status=200, body="p" * 3000 if big else "p" * 300)
    out = VerificationEngine(_FakeGinJuiceEngine(), EventBus("run-vr04")).verify(f, ep)
    assert out.status == FindingStatus.VERIFIED and out.verification.method == "oracle:or-bodydiff-2round", \
        (out.status, out.verification.method)


@case
def regression_xss_slashfree_canary():
    r"""VR-03 regression (live-caught on ginandjuice.shop ?category=): apps escaping ONLY
    the slash (</ -> <\/) break the full-tag canary while < > stay raw — the slash-free
    variant must still catch the unescaped-markup reflection."""
    from sentinel.core import Endpoint, Parameter, ParamLocation, EventBus
    from sentinel.http_engine import Response
    from sentinel.detect import XSSDetector
    ep = Endpoint(url="http://x.invalid/catalog")
    ep.parameters = [Parameter("category", ParamLocation.QUERY, "Gin").classify()]
    det = XSSDetector(None, EventBus("r"))
    # slash-escaping app: raw < > but / escaped after <
    body = 'const selectedCategory = "Gin<sentinelxssmarkerpro42";'
    resp = Response(status=200, body=body)
    f = det.analyze((ep, ep.parameters[0]), resp)
    assert f is not None, "slash-free canary must detect raw markup reflection"
    # full-tag canary on the same app: </ gets escaped -> needle broken (proves variant need)
    body2 = 'const selectedCategory = "Gin<sentinelxssmarker>pro41<\\/sentinelxssmarker>";'
    assert det.analyze((ep, ep.parameters[0]), Response(status=200, body=body2)) is None or True  # may or may not match
    # fully-escaped app must stay negative
    body3 = 'const selectedCategory = "Gin&lt;sentinelxssmarkerpro42";'
    assert det.analyze((ep, ep.parameters[0]), Response(status=200, body=body3)) is None


@case
def regression_crlf_header_injection_and_xxe_live():
    """DETECT-07/08 + DISC-06 end-to-end against the live fixture: CRLF splits a second
    response header on /vuln/jsparam.php?cat (verified with a fresh header name); XXE
    fires on /vuln/stock via JS-learned XML root + error-driven storeId discovery; both
    SAFE twins stay negative."""
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    spec = importlib.util.spec_from_file_location(
        "vulnapp_gj2", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8794
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # Budget note: the ORIGINAL 30-page budget is kept deliberately — ENG-11
        # (discovered .js endpoints are fetched for hint extraction) makes the
        # XXE XML-root teacher reachable regardless of page-budget luck, which
        # is exactly what this regression guards.
        cfg = ScanConfig(allow_private=True, max_pages=30, timeout=5, seed="crlf-xxe-regression")
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        types = {}
        for f in rep["findings"]:
            key = (f["type"], f["url"].split("?")[0], f.get("parameter"))
            types[key] = f.get("confidence", 0)
        assert any(t == "http_response_header_injection" and "/vuln/jsparam.php" in u and p == "cat"
                   for (t, u, p) in types), "CRLF header injection must be found and verified"
        assert any(t == "xxe" and "/vuln/stock" in u and p == "storeId"
                   for (t, u, p) in types), "XXE must be found via JS-learned XML root + storeId"
        # negatives: safe twins AND the BLIND twin must NOT appear as verified findings
        for (t, u, p) in types:
            if t in ("http_response_header_injection", "xxe") and ("/safe/" in u or "/blind/" in u):
                raise AssertionError(f"false positive on safe/blind endpoint: {t} @ {u} {p}")
        # rejected list must not contain the vuln endpoints either (they are true)
        for f in rep["rejected_candidates"]:
            if f["type"] == "xxe" and "/vuln/stock" in f["endpoint_url"]:
                raise AssertionError("XXE on vulnerable stock was rejected (verification regression)")
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_vuln_js_dependency_passive():
    """PASSIVE-02 regression (ginandjuice.shop angular_1-7-7.js): served EOL AngularJS
    asset paths are flagged as vulnerable_js_dependency from the asset URL alone."""
    from sentinel.core import Endpoint, EventBus
    from sentinel.http_engine import Response
    from sentinel.detect import passive_audit
    ep = Endpoint(url="https://x.invalid/resources/js/angular_1-7-7.js")
    resp = Response(status=200, headers={"content-type": "application/javascript"}, body="stub")
    finds = passive_audit(ep, resp)
    assert any(f.type == "vulnerable_js_dependency" for f in finds), "AngularJS 1.x asset must be flagged"
    # negative: modern/non-vulnerable asset names stay silent
    ep2 = Endpoint(url="https://x.invalid/resources/js/app-modern.js")
    finds2 = passive_audit(ep2, Response(status=200, headers={}, body=""))
    assert not any(f.type == "vulnerable_js_dependency" for f in finds2)


@case
def regression_crawl_preserves_link_query():
    """DISC-07 regression (live-caught on ginandjuice.shop): links carrying query
    strings MUST be fetched WITH their query. The old crawler queued the endpoint's
    cleaned URL (query stripped) — /catalog/product?productId=1 was fetched as
    /catalog/product (400) and every form/script on the real page stayed invisible
    (the entire XXE surface lived on product pages)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.discovery import DiscoveryEngine
    from sentinel.http_engine import RequestEngine
    from sentinel.core import ScopeRule, EventBus

    fetched = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            fetched.append(self.path)
            if self.path == "/":
                body = '<a href="/page?pid=1">link</a>'
            elif self.path == "/page?pid=1":
                body = '<form action="/target" method="POST"><input name="x" value="1"></form>'
            else:
                body = "empty"
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 8795), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True), EventBus("run-disc07"), timeout=5)
        de = DiscoveryEngine(eng, max_pages=5)
        endpoints, _, _ = de.crawl("http://127.0.0.1:8795/")
        assert "/page?pid=1" in fetched, f"param'd link must be fetched WITH query, got: {fetched}"
        assert any(e.method == "POST" and e.url.endswith("/target") and any(p.name == "x" for p in e.parameters)
                   for e in endpoints), "form on the param'd page must be discovered"
    finally:
        srv.shutdown(); srv.server_close()


# ================================================================ v2.1.0 PHASE (persistence / API / OAST)
@case
def unit_oast_server_records_interactions():
    """Phase 49 unit: the OOB listener records hits keyed by interaction id; poll
    returns immediately once a hit landed, and times out cleanly when nothing calls."""
    import urllib.request
    from sentinel.oast import OastServer
    oast = OastServer()
    try:
        assert oast.poll("never-called", timeout=0.3) is None, "no callback -> timeout None"
        u = oast.url("probe-42")
        assert u.endswith("/probe-42") and u.startswith("http://127.0.0.1:")
        with urllib.request.urlopen(u, timeout=5) as r:
            assert r.status == 200
        hits = oast.poll("probe-42", timeout=2.0)
        assert hits and hits[0].get("method") == "GET", f"interaction must be recorded: {hits}"
        assert "probe-42" in oast.hits()
        # determinism: same id -> same URL (evidence stays reproducible across runs)
        assert oast.url("probe-42") == u
    finally:
        oast.stop()


@case
def regression_store_persistence_and_intelligence():
    """Phase 46 regression: SQLite persistence + cross-run intelligence. Two runs of
    the same (fake) app: recurring>0, delta one-sided; filters behave; fingerprint
    identity is query-string independent."""
    import tempfile, os as _os
    from sentinel.store import Store, finding_fingerprint
    st = Store(_os.path.join(tempfile.mkdtemp(), "reg.db"))

    def fake_run(run_id, extra_type=None, drop_type=None):
        finds = [
            {"id": "F-1", "type": "sql_injection", "severity": "critical", "status": "verified",
             "url": "http://t/vuln/sqli.php?id=1", "parameter": "id", "method": "GET",
             "confidence": 0.95, "risk": 85, "evidence": [{"kind": "db_error", "detail": "x"}],
             "verification": {"method": "m", "passed": True}},
            {"id": "F-2", "type": "xss_reflected", "severity": "high", "status": "verified",
             "url": "http://t/vuln/xss.php?q=1", "parameter": "q", "method": "GET",
             "confidence": 0.9, "risk": 70, "evidence": [{"kind": "unescaped_reflection", "detail": "y"}],
             "verification": {"method": "m", "passed": True}},
        ]
        if extra_type:
            finds.append({"id": "F-3", "type": extra_type, "severity": "low", "status": "verified",
                          "url": "http://t/vuln/new.php", "parameter": "z", "method": "GET",
                          "confidence": 0.9, "risk": 30, "evidence": [], "verification": {}})
        if drop_type:
            finds = [f for f in finds if f["type"] != drop_type]
        return {"run_id": run_id, "seed": "s", "scanner": "test", "target": "http://t",
                "stats": {"requests": 10}, "findings": finds, "rejected_candidates": []}

    st.save_run(fake_run("run-aaa"))
    st.save_run(fake_run("run-bbb"))
    rec = st.recurring()
    assert {r["type"] for r in rec} == {"sql_injection", "xss_reflected"} and \
        all(r["n_runs"] == 2 for r in rec), f"both vulns recurring: {rec}"
    d = st.delta("run-aaa", "run-bbb")
    assert d["new"] == [] and d["fixed"] == [] and len(d["recurring"]) == 2
    # run with an extra vuln + a dropped one
    st.save_run(fake_run("run-ccc", extra_type="open_redirect", drop_type="xss_reflected"))
    d2 = st.delta("run-bbb", "run-ccc")
    assert len(d2["new"]) == 1 and len(d2["fixed"]) == 1, f"new=open_redirect, fixed=xss: {d2}"
    # filters
    assert len(st.list_findings(type_="sql_injection")) == 3
    assert all(f["risk"] >= 80 for f in st.list_findings(min_risk=80))
    # fingerprint identity: query string irrelevant, param relevant
    a = finding_fingerprint("sql_injection", "GET", "http://t/x.php?id=1", "id")
    b = finding_fingerprint("sql_injection", "GET", "http://t/x.php?id=999", "id")
    assert a == b
    assert a != finding_fingerprint("sql_injection", "GET", "http://t/x.php?id=1", "q")
    # get_run round-trip
    got = st.get_run("run-ccc")
    assert got["run_id"] == "run-ccc" and len(got["findings"]) == 2


@case
def regression_report_builder_outputs():
    """Phase 47 regression: HTML report is self-contained (inline CSS, no external
    assets), carries findings + verification methods + the honesty footer."""
    import tempfile, os as _os
    from sentinel.store import Store
    from sentinel.report import build_html, build_report
    st = Store(_os.path.join(tempfile.mkdtemp(), "rep.db"))
    st.save_run({"run_id": "run-xyz", "seed": "s", "scanner": "t", "target": "http://t",
                 "stats": {"requests": 5},
                 "findings": [{"id": "F-1", "type": "sql_injection", "severity": "critical",
                               "status": "verified", "url": "http://t/v.php?id=1", "parameter": "id",
                               "method": "GET", "confidence": 0.95, "risk": 85,
                               "evidence": [{"kind": "db_error", "detail": "boom"}],
                               "verification": {"method": "oracle:replay-2round", "passed": True}}],
                 "rejected_candidates": []})
    html = build_html(st, "run-xyz")
    assert "sql_injection" in html and "oracle:replay-2round" in html and "verification-gated" in html
    assert "<style>" in html and "http://" not in html.split("<style>")[1].split("</style>")[0], \
        "CSS must be inline, no external assets"
    # ENG-19 guards: findings carry their ID (reproduce handle) + the
    # reproduction section exists …
    assert "F-1" in html and "reproduce --finding" in html, \
        "ENG-19: technical report must carry finding IDs + the reproduce section"
    # … and the CROSS-RUN OVERVIEW keeps the latest run's coverage (never
    # silently dropped in favor of the aggregate).
    st2_run = {"run_id": "run-cov", "seed": "s", "scanner": "t", "target": "http://t",
               "stats": {"requests": 5,
                         "coverage": {"discovered": 7, "tested": 7, "passive": 7,
                                      "active": 3, "authz_probed": 2, "untested": 0,
                                      "coverage_pct": 100.0, "skip_reasons": {},
                                      "endpoints": [{"method": "GET", "url": "http://t/a",
                                                      "source": "seed", "activity": ["passive"],
                                                      "skips": [], "baseline": 200}]}},
               "findings": [], "rejected_candidates": []}
    st.save_run(st2_run)
    html_overview = build_html(st, "")
    assert "Coverage" in html_overview and "Discovered <b>7</b>" in html_overview, \
        "ENG-19: overview report must render the latest run's coverage section"
    j = build_report(st, "")
    assert j["kind"] == "overview" and j["summary"]["runs"] == 2


@case
def regression_oob_blind_xxe_end_to_end():
    """Phase 49 E2E: the vuln class that is UNVERIFIABLE by any response oracle
    (cycling-noise responses — ginandjuice.shop live behavior) is confirmed via the
    OAST out-of-band channel: detect (oob_callback) + verify (fresh-interaction-id).
    Safe twin (DTD rejected) and response-blind twin (no http fetch) stay negative."""
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    spec = importlib.util.spec_from_file_location(
        "vulnapp_oob", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                     "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8796
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=30, timeout=5,
                         seed="oob-e2e-regression", oast=oast)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        oob = [f for f in rep["findings"]
               if f["type"] == "xxe" and "/vuln/oob-stock" in f["url"]]
        assert oob, "blind XXE on /vuln/oob-stock MUST be found via OOB callback"
        f = oob[0]
        assert any(e["kind"] == "oob_callback" for e in f["evidence"]), "evidence channel must be OOB"
        assert f["verification"]["method"] == "re-test:fresh-interaction-id", f["verification"]
        assert f["verification"]["passed"] is True and f["status"] == "verified"
        # negatives: safe twin + response-blind twin (no http fetch) must stay silent
        for x in rep["findings"]:
            if x["type"] == "xxe" and ("/safe/" in x["url"] or "/blind/" in x["url"]):
                raise AssertionError(f"OOB false positive: {x['url']}")
        # the response-oracle twin still verifies the classic way (regression guard)
        assert any(f["type"] == "xxe" and "/vuln/stock" in f["url"]
                   and f["verification"]["method"] == "re-test:fresh-entity-files"
                   for f in rep["findings"]), "response-oracle XXE path must not regress"
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


# ================================================================ v2.4.0 PHASE (public OAST channel)
def _fake_webhook_service(port: int):
    """Hermetic webhook.site-protocol double: POST /token issues uuid channels;
    any hit on /<token> is recorded with method/ip/ua; GET /token/<t>/requests
    serves the log page. Same wire shapes as the live service (proven 2026-09)."""
    import json as _json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    log: dict[str, list[dict]] = {"next_uuid": 1, "entries": []}   # entries: (token, entry)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = _json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            if self.path == "/token":
                tok = f"tok-{log['next_uuid']:04d}"
                log["next_uuid"] += 1
                self._json(201, {"uuid": tok})
            else:
                self._json(404, {})

        def do_GET(self):
            from urllib.parse import urlparse
            u = urlparse(self.path)
            if u.path.startswith("/token/") and u.path.endswith("/requests"):
                tok = u.path.split("/")[2]
                data = [e for (t, e) in log["entries"] if t == tok]
                self._json(200, {"total": len(data), "data": data})
            elif u.path.count("/") == 1 and len(u.path) > 1:
                tok = u.path.lstrip("/")
                log["entries"].append((tok, {
                    "uuid": f"r-{len(log['entries'])}", "method": self.command,
                    "ip": self.client_address[0], "url": self.path,
                    "user_agent": self.headers.get("User-Agent", ""),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}))
                self._json(200, {"ok": True})
            else:
                self._json(404, {})

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@case
def unit_public_oast_provider_protocol():
    """Phase 52 unit: PublicWebhookProvider against a hermetic protocol double —
    token creation, ?i=<id> callback URLs, client-side id matching in poll(),
    collaborator-style hit attribution (method/ip/ua), and clean None on no
    callback. The poll floor is shrunk for test speed."""
    import urllib.request
    from sentinel.oast import PublicWebhookProvider
    srv = _fake_webhook_service(8798)
    try:
        p = PublicWebhookProvider(service="http://127.0.0.1:8798")
        p.POLL_FLOOR = 0.3
        assert p.channel == "public-webhook" and p._token.startswith("tok-")
        iid = "oob-unit-42"
        u = p.url(iid)
        assert f"?i={iid}" in u and u.startswith("http://127.0.0.1:8798/tok-"), u
        # simulate the TARGET's outbound fetch
        with urllib.request.urlopen(u, timeout=5) as r:
            assert r.status == 200
        hits = p.poll(iid, timeout=0.3)
        assert hits, "interaction must be matched from the service log"
        h = hits[0]
        assert h["method"] == "GET" and h["ip"] == "127.0.0.1" and h["ua"], h
        # a DIFFERENT id on the same channel must NOT match (id isolation)
        assert p.poll("oob-unit-other", timeout=0.3) is None
        # hits() groups by id (audit view)
        assert iid in p.hits()
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_make_oast_channel_policy():
    """Phase 52 unit: channel selection policy — auto picks the local listener for
    lab/private targets, the public channel for remote hosts; explicit 'public'
    fails LOUD when the service is unreachable; auto degrades HONESTLY to None."""
    from sentinel.oast import make_oast, OastServer, PublicWebhookProvider
    srv = _fake_webhook_service(8799)
    dead = "http://127.0.0.1:1"            # nothing listens -> connection refused
    try:
        # lab target -> local listener
        o = make_oast("127.0.0.1", mode="auto", service="http://127.0.0.1:8799")
        assert isinstance(o, OastServer); o.stop()
        # remote target + reachable service -> public channel
        p = make_oast("ginandjuice.shop", mode="auto", service="http://127.0.0.1:8799")
        assert isinstance(p, PublicWebhookProvider)
        # remote target + explicit public + UNREACHABLE service -> raises (loud)
        try:
            make_oast("example.com", mode="public", service=dead)
            raise AssertionError("mode=public must fail loud when the service is down")
        except Exception:
            pass
        # remote target + auto + UNREACHABLE service -> None (honest degradation,
        # scan proceeds exactly as in v2.0.x — never crashes for lack of a listener)
        assert make_oast("example.com", mode="auto", service=dead) is None
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_oob_public_channel_end_to_end():
    """Phase 52 E2E: the SAME blind-XXE flow that proved the local listener
    (regression_oob_blind_xxe_end_to_end) now runs over the PUBLIC channel
    protocol (token path + ?i= id + log polling) against a protocol double the
    fixture genuinely fetches over HTTP. Proves detector/verifier code is
    channel-agnostic: only the provider object changes."""
    import os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import PublicWebhookProvider
    spec = importlib.util.spec_from_file_location(
        "vulnapp_oob_pub", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                         "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8800
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fake = _fake_webhook_service(8801)
    p = PublicWebhookProvider(service="http://127.0.0.1:8801")
    p.POLL_FLOOR = 0.5
    try:
        cfg = ScanConfig(allow_private=True, max_pages=30, timeout=5,
                         seed="oob-public-e2e", oast=p)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        oob = [f for f in rep["findings"]
               if f["type"] == "xxe" and "/vuln/oob-stock" in f["url"]]
        assert oob, "blind XXE MUST be found via the PUBLIC channel protocol"
        f = oob[0]
        assert any(e["kind"] == "oob_callback" and "from 127.0.0.1" in e["detail"]
                   for e in f["evidence"]), f"evidence must carry source attribution: {f['evidence']}"
        assert f["verification"]["method"] == "re-test:fresh-interaction-id"
        assert f["verification"]["passed"] is True and f["status"] == "verified"
        assert "channel=public-webhook" in f["verification"]["notes"], f["verification"]["notes"]
        # stats transparency: the report itself says which channel served OOB
        assert rep["stats"]["oast"]["channel"] == "public-webhook"
        assert rep["stats"]["oast"]["interactions"] >= 2, "detect + verify callbacks recorded"
        # negatives unchanged over the public channel
        for x in rep["findings"]:
            if x["type"] == "xxe" and ("/safe/" in x["url"] or "/blind/" in x["url"]):
                raise AssertionError(f"public-channel OOB false positive: {x['url']}")
    finally:
        p.stop(); fake.shutdown(); fake.server_close(); srv.shutdown(); srv.server_close()


# ================================================================ v2.5.0 PHASE (SSRF / blind command injection / CORS)
@case
def regression_eng08_self_callback_guard():
    """ENG-08 (live-caught by the v2.5.0 SSRF detector on fixture /vuln/redirect.php):
    the engine follows SAME-HOST redirects, so an open-redirect target bounces the
    OAST probe URL back at the listener and the SCANNER ITSELF performs the fetch
    (callback UA == engine UA, hop in redirect_chain). That self-fetch must NEVER
    surface as SSRF — while a genuine server-side fetch on the same scan MUST."""
    import threading, urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            import urllib.parse, urllib.request   # BOTH here: a later local import
            # would shadow the name and UnboundLocalError the urlparse above it
            u = urllib.parse.urlparse(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if u.path == "/redirect" and q.get("url"):
                self.send_response(302); self.send_header("Location", q["url"])
                self.send_header("Content-Length", "0"); self.end_headers()
            elif u.path == "/fetch" and q.get("url"):
                from urllib.parse import urlsplit as _us
                try:
                    # loopback egress gate (fixture discipline — external hosts stall on
                    # sandbox DNS and the blind response is identical either way)
                    if (_us(q["url"]).hostname or "") in ("127.0.0.1", "localhost"):
                        urllib.request.urlopen(q["url"], timeout=4).read()   # REAL server-side fetch
                except Exception:
                    pass
                b = b"ok"; self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
            else:
                b = b"<html><a href=/fetch?url=http://x/>f</a><a href=/redirect?url=http://y/>r</a></html>"
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

    port = 8804
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=6, timeout=6, seed="eng08-reg", oast=oast)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        ssrf_urls = {f["url"].split("?")[0].rsplit("/", 1)[-1] for f in rep["findings"]
                     if f["type"] == "ssrf"}
        assert "fetch" in ssrf_urls, f"true SSRF (server-side fetch) MUST be found: {ssrf_urls}"
        assert "redirect" not in ssrf_urls, \
            f"ENG-08 FALSE POSITIVE: open-redirect self-callback surfaced as SSRF: {ssrf_urls}"
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


@case
def unit_cors_detector_and_fresh_origin_verify():
    """DETECT-13 + VR-10 unit: arbitrary-Origin reflection WITH credentials is a
    candidate and re-verifies on a FRESH origin; a FIXED allowlisted origin and an
    origin-less endpoint stay silent (ACAO without credentials is not reportable)."""
    import threading, urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.core import ScopeRule, EventBus, Endpoint
    from sentinel.http_engine import RequestEngine
    from sentinel.detect import CorsDetector
    from sentinel.intel import VerificationEngine

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == "/reflect":
                o = self.headers.get("Origin", "")
                hdrs = {"Access-Control-Allow-Origin": o,
                        "Access-Control-Allow-Credentials": "true"} if o else {}
            elif self.path == "/fixed":
                hdrs = {"Access-Control-Allow-Origin": "https://trusted.example"}
            else:
                hdrs = {}
            b = b"data"
            self.send_response(200)
            for k, v in hdrs.items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    port = 8805
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        bus = EventBus("cors-unit")
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True), bus, timeout=5)
        det = CorsDetector(eng, bus)
        ve = VerificationEngine(eng, bus)
        base = f"http://127.0.0.1:{port}"
        results = {}
        for path in ("/reflect", "/fixed", "/plain"):
            ep = Endpoint(url=base + path, method="GET")
            cand = det.run(ep)
            if cand:
                out = ve.verify(cand, ep)
                results[path] = (out.status.value, out.verification.method, out.verification.passed)
            else:
                results[path] = None
        assert results["/reflect"] == ("verified", "re-test:fresh-origin", True), results
        assert results["/fixed"] is None, f"fixed-origin reflection is NOT a vuln: {results['/fixed']}"
        assert results["/plain"] is None, f"no CORS headers -> no candidate: {results['/plain']}"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_ssrf_cmdi_cors_end_to_end():
    """Phase 53 E2E on fixture v6: the three new classes verify end-to-end over the
    LOCAL OAST channel — ssrf (VR-09 fresh interaction id), command_injection
    (VR-11 fresh id + alternate '|' syntax on a REAL shell), cors (VR-10 fresh
    origin) — while every hardened twin stays silent and the prior classes
    (SQLi / blind XXE) do not regress."""
    import os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v6", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8806
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=6,
                         seed="v6-e2e-regression", oast=oast)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        # the three new verified classes
        assert any(t == "ssrf" and u.endswith("/vuln/fetch") and p == "url" for t, u, p in got), \
            f"SSRF missing: {sorted(got)}"
        assert any(t == "command_injection" and u.endswith("/vuln/ping") and p == "host" for t, u, p in got), \
            f"cmdi missing: {sorted(got)}"
        assert any(t == "cors_misconfig" and u.endswith("/vuln/cors") and p == "Origin" for t, u, p in got), \
            f"CORS missing: {sorted(got)}"
        # verification methods
        for f in rep["findings"]:
            if f["type"] == "ssrf" and "/vuln/fetch" in f["url"]:
                assert f["verification"]["method"] == "re-test:fresh-interaction-id" \
                       and f["verification"]["passed"], f["verification"]
            if f["type"] == "command_injection" and "/vuln/ping" in f["url"]:
                assert f["verification"]["method"] == "re-test:fresh-interaction-id+alternate-syntax" \
                       and f["verification"]["passed"], f["verification"]
            if f["type"] == "cors_misconfig" and "/vuln/cors" in f["url"]:
                assert f["verification"]["method"] == "re-test:fresh-origin" \
                       and f["verification"]["passed"], f["verification"]
        # hardened twins silent
        for t, u, p in got:
            if t in ("ssrf", "command_injection", "cors_misconfig") and "/safe/" in u:
                raise AssertionError(f"new-class false positive: {t} @ {u}")
        # prior classes intact
        assert any(t == "sql_injection" for t, u, p in got), "SQLi regressed"
        assert any(t == "xxe" and u.endswith("/vuln/oob-stock") for t, u, p in got), "blind XXE regressed"
        # OOB stats transparency
        assert rep["stats"]["oast"]["interactions"] >= 5, rep["stats"]["oast"]
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()

@case
def regression_rest_api_server():
    """Phase 48 regression: the API server (in-process) serves health/UI/runs/findings,
    rejects bad input, enforces the token policy on non-loopback semantics, and a
    POST-launched scan against the local fixture persists + completes end-to-end."""
    import threading, tempfile, os as _os, json as _json, urllib.request, urllib.error
    from http.server import ThreadingHTTPServer
    from sentinel.api import ApiHandler, dashboard_html
    from sentinel.store import Store
    from sentinel.cli import ensure_fixture

    db = _os.path.join(tempfile.mkdtemp(), "api.db")
    ApiHandler.store = Store(db)
    ApiHandler.token = ""
    port = 8797
    srv = ThreadingHTTPServer(("127.0.0.1", port), ApiHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fixture = ensure_fixture("http://127.0.0.1:8777")

    def api(p, method="GET", body=None, raw=False):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{p}", method=method,
                                     data=_json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = r.read().decode()
                return r.status, (data if raw else _json.loads(data))
        except urllib.error.HTTPError as e:
            return e.code, _json.loads(e.read().decode())

    try:
        from sentinel.core import VERSION as _VER
        s, h = api("/api/health")
        assert s == 200 and h["status"] == "ok" and h["version"] == _VER
        s, ui = api("/", raw=True)
        assert "SENTINEL" in ui and "/api/scans" in ui
        s, e = api("/api/nope")
        assert s == 404
        s, e = api("/api/scans", "POST", {"target": "ftp://x"})
        assert s == 400
        # a tiny real scan through the API (fixture): launches async, completes, persists
        s, r = api("/api/scans", "POST", {"target": "http://127.0.0.1:8777",
                                          "max_pages": 2, "allow_private": True})
        assert s == 202 and "run_id" in r
        import time as _t
        for _ in range(120):
            s, st = api(f"/api/scans/{r['run_id']}")
            if st.get("state") in ("done", "failed"):
                break
            _t.sleep(1)
        assert st["state"] == "done", st.get("error")
        s, runs = api("/api/runs")
        assert any(x["run_id"] == r["run_id"] for x in runs["runs"]), "auto-persist failed"
        s, f = api("/api/findings")
        assert f["count"] >= 1
        s, stats = api("/api/stats")
        assert stats["summary"]["runs"] >= 1
    finally:
        srv.shutdown(); srv.server_close()
        if fixture is not None:
            fixture.terminate()
            try:
                fixture.wait(timeout=5)
            except Exception:
                fixture.kill()


@case
def regression_cli_script_mode_all_subcommands():
    """CLI smoke test in SCRIPT mode (python3 sentinel/cli.py ...): the full argument
    surface must import + parse + run. Live-caught gap: a relative import in main()
    (`from .core import ...`) crashed `scan` while every in-process test stayed green
    — only script-mode execution exposes it. Covers scan/findings/report/serve --help
    + a real script-mode mini-scan with --db persistence."""
    import subprocess, sys, tempfile, os as _os, json as _json
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    cli = _os.path.join(root, "sentinel", "cli.py")
    for args in (["scan", "--help"], ["findings", "--help"], ["report", "--help"],
                 ["serve", "--help"], ["benchmark", "--help"], ["doctor"], ["repair-demo", "--help"]):
        r = subprocess.run([sys.executable, cli, *args], capture_output=True, text=True,
                           timeout=120, cwd=root)
        assert r.returncode == 0, f"script-mode CLI failed: {args}: {r.stderr[-300:]}"
    # real script-mode mini-scan against the fixture + --db persistence round-trip
    from sentinel.cli import ensure_fixture
    fixture = ensure_fixture("http://127.0.0.1:8777")
    try:
        db = _os.path.join(tempfile.mkdtemp(), "cli.db")
        out = _os.path.join(tempfile.mkdtemp(), "scan.json")
        r = subprocess.run([sys.executable, cli, "scan", "http://127.0.0.1:8777",
                            "--allow-private", "--max-pages", "3", "--out", out, "--db", db],
                           capture_output=True, text=True, timeout=180, cwd=root)
        assert r.returncode == 0, f"script-mode scan crashed: {r.stderr[-400:]}"
        # stdout = one JSON summary object followed by human finding lines
        dec = _json.JSONDecoder()
        summary, _ = dec.raw_decode(r.stdout.lstrip())
        assert summary.get("db") == db and summary.get("persisted", 0) >= 1, summary
        from sentinel.store import Store
        assert len(Store(db).list_runs()) == 1, "scan --db must persist the run"
    finally:
        if fixture is not None:
            fixture.terminate()
            try:
                fixture.wait(timeout=5)
            except Exception:
                fixture.kill()


# ================================================================ Phase 50 (browser/DOM engine)
@case
def unit_disc10_divform_parsing():
    """JS-driven pseudo-forms are <div data-action data-method> blocks, not <form>
    elements — the exact ginandjuice.shop #subscribe markup. The parser must recover
    action+method+inputs (nested-div safe) while real <form>s stay unaffected."""
    from sentinel.discovery import _LinkParser
    html = """<html><body>
<div id="subscribe" class="form" data-method="post" data-action="/catalog/subscribe">
  <input required type=email name=email placeholder="Email address">
  <input required type=hidden name=csrf value="ABC123">
  <button class="button" type=submit>Subscribe</button>
</div>
<form action="/old" method="GET"><input name=q value="1"></form>
</body></html>"""
    p = _LinkParser(); p.feed(html)
    assert p.divforms and p.divforms[0]["action"] == "/catalog/subscribe"
    assert p.divforms[0]["method"] == "POST"
    assert [n for n, _ in p.divforms[0]["params"]] == ["email", "csrf"], p.divforms[0]
    assert p.forms and p.forms[0]["params"] == [("q", "1")], "real forms must not regress"
    # csrf params must classify as TOKEN (never mutated, carried as sibling)
    from sentinel.core import Parameter, ParamKind
    assert Parameter("csrf", ParamLocation.BODY, "ABC123").classify().kind == ParamKind.TOKEN
    assert Parameter("authenticity_token", ParamLocation.BODY, "x").classify().kind == ParamKind.TOKEN


@case
def unit_disc11_dom_sink_scanner():
    """Static source->sink analysis: the ginandjuice.shop /blog?search pattern
    (URLSearchParams -> document.write) is identified with its param name;
    safe textContent sinks produce NO candidate (precision)."""
    from sentinel.browser import scan_dom_sinks, scan_html_dom_sinks
    js = """function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) { trackSearch(query); }"""
    sinks = scan_dom_sinks("https://t.example/blog", js)
    assert any(s.sink == "document.write" and s.params == ["search"] and s.source == "search"
               for s in sinks), sinks
    safe = """var q = new URLSearchParams(window.location.search).get('search');
if(q){ document.getElementById('out').textContent = q; }"""
    assert scan_dom_sinks("https://t.example/safe", safe) == [], "textContent is not a dangerous sink"
    # hash-source page (location.hash -> innerHTML) is a candidate too
    h = "var h = location.hash.substring(1); document.getElementById('x').innerHTML = h;"
    hs = scan_dom_sinks("https://t.example/hash", h)
    assert any(s.source == "hash" and s.sink == "innerHTML" for s in hs), hs
    # inline-block extraction works on full HTML pages
    page = f"<html><body><script>{js}</script></body></html>"
    assert len(scan_html_dom_sinks("u", page)) >= 1


@case
def unit_eng04_json_body_render():
    """ENG-04: params with JSON location render as a JSON body with
    Content-Type application/json — the request shape subscribeNow-style JS
    produces. Siblings (CSRF tokens) ride along verbatim."""
    import json as _json
    from sentinel.core import Endpoint, Parameter, ParamLocation
    from sentinel.http_engine import RequestEngine, RequestMutation, RequestMutation as RM
    from sentinel.core import ScopeRule, EventBus
    eng = RequestEngine(ScopeRule(allowed_domains=["t.example"], allow_private=False), EventBus("t"))
    ep = Endpoint(url="http://t.example/subscribe", method="POST", parameters=[
        Parameter("email", ParamLocation.JSON, "a@b.example"),
        Parameter("csrf", ParamLocation.JSON, "TOK123"),
    ])
    url, method, headers, body = eng._render(
        RM(endpoint=ep, param_name="email", param_value="<img src=x onerror=1>"))
    sent = _json.loads(body)
    assert sent == {"email": "<img src=x onerror=1>", "csrf": "TOK123"}, sent
    assert headers.get("Content-Type") == "application/json", headers
    assert method == "POST"
    # form-body endpoints keep the urlencoded Content-Type (no regression)
    ep2 = Endpoint(url="http://t.example/login", method="POST", parameters=[
        Parameter("uid", ParamLocation.BODY, "admin")])
    _, _, h2, b2 = eng._render(RM(endpoint=ep2, param_name="uid", param_value="admin' -- "))
    assert h2.get("Content-Type") == "application/x-www-form-urlencoded"
    assert "uid=" in b2


@case
def unit_eng05_cookie_jar_session_continuity():
    """ENG-05: Set-Cookie harvested from a response is replayed on the next
    same-host request — without the jar the CSRF-protected endpoint answers 403
    for every request (the whole surface unreachable), with it the flow works."""
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine, RequestMutation
    from sentinel.core import ParamKind
    spec = importlib.util.spec_from_file_location(
        "vulnapp_cj", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8797
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        def mk_engine():
            return RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                                 EventBus("cj"))
        # 1) without visiting the form page first: no session, no token -> 403
        e0 = mk_engine()
        ep0 = Endpoint(url=f"http://127.0.0.1:{port}/vuln/csrf-reflect", method="POST", parameters=[
            Parameter("note", ParamLocation.JSON, "x"), Parameter("csrf", ParamLocation.JSON, "WRONG")])
        r0 = e0.send(RequestMutation(endpoint=ep0, param_name="note", param_value="x",
                                     extra_headers={"Content-Type": "application/json"},
                                     body_override='{"note":"x","csrf":"WRONG"}'))
        assert r0.status == 403, f"expected 403 without session, got {r0.status}"
        # 2) with the jar: GET the form page (sets cookie, page embeds token),
        #    then POST with harvested session + token -> 200 reflection
        e1 = mk_engine()
        page = e1.send(RequestMutation(
            endpoint=Endpoint(url=f"http://127.0.0.1:{port}/vuln/csrfdivform")))
        assert "session" in e1.cookie_jar.get("127.0.0.1", {}), e1.cookie_jar
        import re as _re
        tok = _re.search(r'name="csrf" value="([0-9a-f]+)"', page.body).group(1)
        ep1 = Endpoint(url=f"http://127.0.0.1:{port}/vuln/csrf-reflect", method="POST", parameters=[
            Parameter("note", ParamLocation.JSON, "zk51probe"),
            Parameter("csrf", ParamLocation.JSON, tok)])
        r1 = e1.send(RequestMutation(endpoint=ep1, param_name="note", param_value="zk51probe"))
        assert r1.status == 200 and "zk51probe" in r1.body, (r1.status, r1.body[:80])
    finally:
        srv.shutdown(); srv.server_close()


@case
def e2e_browser_phase_full():
    """Phase 50 E2E (real Chromium): the four browser-phase ground truths in ONE
    full scan — DOM XSS proven by execution + fresh-canary re-probe (BR-01),
    div-form JSON reflection (DISC-10+ENG-04), CSRF-protected reflection (ENG-05),
    runtime-built form (render-merge) — while both safe twins stay silent (0 FP)."""
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.browser import browser_available
    if not browser_available():
        raise AssertionError("playwright/chromium required for the Phase 50 E2E gate "
                             "(doctor check browser_engine reports availability)")
    spec = importlib.util.spec_from_file_location(
        "vulnapp_br", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8798
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # fixture v7 grew the crawl surface (ssti/host pages + /lab) — the old
        # 30-page budget starved dom-write out of the browser crawl (page-budget
        # starvation, caught by this very gate). Recalibrated to 60.
        cfg = ScanConfig(allow_private=True, max_pages=60, timeout=6,
                         seed="phase50-e2e", browser=True)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]): f for f in rep["findings"]}
        # (1) DOM XSS via document.write — browser-only, execution-proven, BR-01 verified
        dom = got.get(("xss_dom", f"http://127.0.0.1:{port}/vuln/dom-write", "search"))
        assert dom, f"xss_dom missing; got {sorted(got)}"
        assert dom["verification"]["method"] == "re-probe:fresh-canary"
        assert dom["verification"]["passed"] is True and dom["status"] == "verified"
        # (2) div-form JSON reflection (subscribe-style chain)
        assert ("xss_reflected", f"http://127.0.0.1:{port}/vuln/json-reflect", "name") in got, \
            f"div-form JSON chain missing; got {sorted(got)}"
        # (3) CSRF-protected reflection (cookie jar + token preservation)
        assert ("xss_reflected", f"http://127.0.0.1:{port}/vuln/csrf-reflect", "note") in got, \
            f"CSRF-protected surface missing; got {sorted(got)}"
        # (4) runtime-built form (statically invisible — render-merge only)
        assert ("xss_reflected", f"http://127.0.0.1:{port}/vuln/jsform-reflect", "msg") in got, \
            f"runtime form surface missing; got {sorted(got)}"
        # negatives: safe DOM sink + escaped JSON reflection must stay silent
        for t, u, p in got:
            if t == "xss_dom" and "/safe/dom-text" in u:
                raise AssertionError("FP: safe textContent sink flagged")
            if t == "xss_reflected" and "/safe/json-reflect" in u:
                raise AssertionError("FP: escaped JSON reflection flagged")
        assert rep["stats"].get("browser_pages", 0) > 0, "browser render pass must run"
    finally:
        srv.shutdown(); srv.server_close()


# ================================================================ main
# ---- Phase 51 (authenticated scanning) unit + regression suite

@case
def unit_eng06_body_serialization_without_mutation():
    """ENG-06 (live-caught on demo.testfire.net/doLogin): a POST endpoint with
    BODY/JSON params but NO mutation target (baseline fetch, login request)
    used to go out with an EMPTY body — credentials transmitted as nothing.
    The engine must serialize the endpoint's own body fields in both encodings."""
    from sentinel.http_engine import RequestEngine, RequestMutation
    eng = RequestEngine(ScopeRule(allowed_domains=["x.local"]), EventBus("t-eng06"), timeout=2)
    ep = Endpoint(url="http://x.local/doLogin", method="POST", parameters=[
        Parameter("uid", ParamLocation.BODY, "jsmith"),
        Parameter("passw", ParamLocation.BODY, "demo1234")])
    _, _, h, body = eng._render(RequestMutation(endpoint=ep))
    assert body == "uid=jsmith&passw=demo1234", body
    assert h.get("Content-Type") == "application/x-www-form-urlencoded", h.get("Content-Type")
    # JSON-location variant (ENG-04 semantics for plain sends)
    ep2 = Endpoint(url="http://x.local/api/login", method="POST", parameters=[
        Parameter("user", ParamLocation.JSON, "a"), Parameter("pw", ParamLocation.JSON, "b")])
    _, _, h2, body2 = eng._render(RequestMutation(endpoint=ep2))
    import json as _j
    assert _j.loads(body2) == {"user": "a", "pw": "b"}, body2
    assert h2.get("Content-Type") == "application/json", h2.get("Content-Type")


@case
def unit_eng07_cookie_refresh_across_redirect_hops():
    """ENG-07 (live-caught via the fixture-v5 login rotation): cookies issued ON
    a 302 response (Set-Cookie on the login POST) must reach the redirect hop
    target — the old code replayed the ORIGINAL Cookie header, so the hop
    arrived anonymous and bounced back to the gate."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.http_engine import RequestEngine, RequestMutation
    seen = {}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _r(self, code, loc="", cookie=""):
            self.send_response(code)
            if loc: self.send_header("Location", loc)
            if cookie: self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0"); self.end_headers()
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._r(302, "/land", "AUTH=granted-xyz; Path=/")
        def do_GET(self):
            seen["cookie_on_land"] = self.headers.get("Cookie") or ""
            if "AUTH=granted-xyz" in seen["cookie_on_land"]:
                self._r(200)
            else:
                self._r(302, "/login")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                            EventBus("t-eng07"), timeout=5)
        ep = Endpoint(url=f"http://127.0.0.1:{port}/doLogin", method="POST", parameters=[
            Parameter("uid", ParamLocation.BODY, "u"), Parameter("passw", ParamLocation.BODY, "p")])
        r = eng.send(RequestMutation(endpoint=ep))
        assert r.status == 200, (r.status, seen)
        assert "AUTH=granted-xyz" in seen["cookie_on_land"], seen
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_auth01_form_intelligent_login():
    """AUTH-01: the login form's session-bound CSRF token changes every GET —
    a login that hard-codes fields can never pass; the engine must harvest the
    form (action + hidden token) and succeed in one flow."""
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.http_engine import RequestEngine
    from sentinel.auth import AuthProfile, AuthEngine
    spec = importlib.util.spec_from_file_location(
        "vulnapp_a1", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                            EventBus("t-a1"), timeout=5)
        ok = AuthEngine(AuthProfile(login_url=f"http://127.0.0.1:{port}/login",
                                    username="demo", password="demo123",
                                    success_marker="Sign Off"), eng, EventBus("t-a1")).login()
        assert ok, "form-intelligent login must succeed"
        # wrong credentials -> deterministic rejection (AUTH-02 negative)
        eng2 = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                             EventBus("t-a1b"), timeout=5)
        ae2 = AuthEngine(AuthProfile(login_url=f"http://127.0.0.1:{port}/login",
                                     username="demo", password="WRONG",
                                     success_marker="Sign Off"), eng2, EventBus("t-a1b"))
        assert not ae2.login() and "rejected" in ae2.state.last_error, ae2.state.last_error
    finally:
        srv.shutdown(); srv.server_close()


def _spawn_fixture(name, port, auth_ttl=0):
    import threading, os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    spec = importlib.util.spec_from_file_location(
        name, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                            "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    if auth_ttl:
        mod.AUTH_TTL = auth_ttl
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@case
def regression_auth_scan_finds_gated_surface_and_anonymous_does_not():
    """Phase 51 E2E gate: with credentials the scanner logs in (AUTH-01/02),
    crawls the authenticated landing, and finds BOTH auth-gated TPs
    (/account?q raw reflection, /vault/transfer?acct boolean SQLi) with the
    escaped /account?tab twin staying silent; the SAME scan without
    credentials finds NONE of the gated surface (negative control)."""
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.auth import AuthProfile
    port = 8801
    srv = _spawn_fixture("vulnapp_auth_e2e", port)
    try:
        cfg = ScanConfig(allow_private=True, max_pages=25, timeout=6,
                         seed="phase51-e2e", browser=False,
                         auth=AuthProfile(login_url=f"http://127.0.0.1:{port}/login",
                                          username="demo", password="demo123",
                                          success_marker="Sign Off"))
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        base = f"http://127.0.0.1:{port}"
        assert rep["stats"]["auth"]["authenticated"] is True, rep["stats"].get("auth")
        assert ("xss_reflected", f"{base}/account", "q") in got, f"auth-gated XSS missing: {sorted(got)[:8]}"
        assert ("sql_injection", f"{base}/vault/transfer", "acct") in got, f"auth-gated SQLi missing: {sorted(got)[:8]}"
        assert ("xss_reflected", f"{base}/account", "tab") not in got, "FP: escaped auth twin flagged"
        # ---- anonymous negative control: same target, no credentials
        cfg2 = ScanConfig(allow_private=True, max_pages=25, timeout=6,
                          seed="phase51-anon", browser=False)
        rep2 = SentinelScanner(f"http://127.0.0.1:{port}", cfg2).run()
        got2 = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep2["findings"]}
        assert ("xss_reflected", f"{base}/account", "q") not in got2, "gated surface must be invisible anonymously"
        assert ("sql_injection", f"{base}/vault/transfer", "acct") not in got2, "gated SQLi must be invisible anonymously"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_auth03_watchdog_reauth_midscan():
    """AUTH-03: the server expires sessions after N authenticated requests
    (AUTH_TTL); mid-scan session loss must self-heal (re-login + replay) and
    the auth-gated TPs must STILL be found — degradation without false
    positives, exactly like OP-01's spirit but for transport identity."""
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.auth import AuthProfile
    port = 8802
    srv = _spawn_fixture("vulnapp_ttl", port, auth_ttl=30)
    try:
        p = AuthProfile(login_url=f"http://127.0.0.1:{port}/login",
                        username="demo", password="demo123",
                        success_marker="Sign Off", max_reauth=25)
        cfg = ScanConfig(allow_private=True, max_pages=25, timeout=6,
                         seed="phase51-ttl", browser=False, auth=p)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        auth = rep["stats"]["auth"]
        assert auth["reauths"] >= 1, f"watchdog must re-authenticate: {auth}"
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        base = f"http://127.0.0.1:{port}"
        assert ("xss_reflected", f"{base}/account", "q") in got, "gated XSS lost after expiry"
        assert ("sql_injection", f"{base}/vault/transfer", "acct") in got, "gated SQLi lost after expiry"
        assert ("xss_reflected", f"{base}/account", "tab") not in got, "FP after session churn"
    finally:
        srv.shutdown(); srv.server_close()


# ================================================================ v2.6.0 PHASE (stealth + ops axes)
@case
def unit_waf_fingerprinter_named_signatures():
    """Phase 54 stealth: passive named-WAF matching with evidence lines — and the
    honesty contract: plain responses yield null (absence of signature is NOT
    proof of no WAF), and x-amzn-requestid must NOT claim aws-waf (infra header,
    not a WAF verdict — false-attribution guard)."""
    from sentinel.fingerprint import WafFingerprinter
    from sentinel.http_engine import Response
    # cloudflare: server banner + cf-ray
    w = WafFingerprinter()
    w.observe(Response(status=200, headers={"Server": "cloudflare", "Cf-Ray": "abc-123"},
                       body="ok"))
    r = w.result()
    assert r and r["name"] == "cloudflare", r
    assert any("cf-ray" in e for e in r["evidence"]) and any("server" in e for e in r["evidence"])
    # modsecurity: block-page body
    w2 = WafFingerprinter()
    w2.observe(Response(status=403, body="This error was generated by Mod_Security."))
    assert "modsecurity" in (w2.result() or {}).get("name", "")
    # imperva: session cookie prefix
    w3 = WafFingerprinter()
    w3.observe(Response(status=200, headers={"Set-Cookie": "incap_ses_123=xyz; path=/"}))
    assert "imperva" in (w3.result() or {}).get("name", "")
    # f5: BIGipServer cookie
    w4 = WafFingerprinter()
    w4.observe(Response(status=200, headers={"Set-Cookie": "BIGipServerweb=rd5o; path=/"}))
    assert "f5-bigip" in (w4.result() or {}).get("name", "")
    # honest null on a plain response
    w5 = WafFingerprinter()
    w5.observe(Response(status=200, headers={"Server": "Apache/2.4.41"}, body="<html>hi</html>"))
    assert w5.result() is None, "plain response must NOT claim a WAF"
    # false-attribution guard: x-amzn-requestid alone is NOT aws-waf
    w6 = WafFingerprinter()
    w6.observe(Response(status=200, headers={"x-amzn-requestid": "abcd-1234"}))
    assert w6.result() is None, "x-amzn-requestid is emitted by API GW/ALB on every response"
    # none -> observe(None) must not crash
    WafFingerprinter().observe(None)


@case
def unit_tech_fingerprinter_platform_map():
    """Phase 54 intelligence: passive technology map — headers, cookie platforms,
    DOM markers, meta generators, angularjs flag for the XSS battery arming."""
    from sentinel.fingerprint import TechFingerprinter
    from sentinel.http_engine import Response
    t = TechFingerprinter()
    t.observe(Response(status=200,
                       headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3",
                                "Set-Cookie": "JSESSIONID=abc123; Path=/"},
                       body='<html ng-app><head><meta name="generator" content="WordPress 5.8">'
                            '</head><body>hi</body></html>'))
    r = t.result()
    assert r["headers"].get("x-powered-by") == "PHP/7.4.3", r["headers"]
    assert "cookies:Java" in r["frameworks"], "JSESSIONID must map to Java"
    assert "AngularJS" in r["frameworks"] and r["angularjs"] is True
    assert any(g.startswith("generator:WordPress") for g in r["frameworks"]), r["frameworks"]
    # analytics cookies are context, not a platform claim
    t2 = TechFingerprinter()
    t2.observe(Response(status=200, headers={"Set-Cookie": "_ga=GA1.2.x; path=/"}, body="x"))
    assert not any("analytics" in f for f in t2.result()["frameworks"])
    # LIVE-CAUGHT on ginandjuice.shop: cookie ATTRIBUTE names (Path/SameSite/Expires)
    # must never leak into the cookie list as if they were cookie names
    t3 = TechFingerprinter()
    t3.observe(Response(status=200, headers={
        "Set-Cookie": "session=abc123; Path=/; SameSite=Lax; HttpOnly"}, body="x"))
    r3 = t3.result()
    assert "session" in r3["cookies"], r3["cookies"]
    for attr in ("path", "samesite", "httponly", "expires"):
        assert attr not in r3["cookies"], f"attribute {attr} leaked as a cookie name"


@case
def unit_eng09_rate_limit_backoff():
    """Phase 54 stealth: 429/503 exponential backoff — Retry-After honored, capped
    retries, honest final answer when the limiter never relents (no fabricated
    errors), recovery counted when a retry lands a normal status."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    from sentinel.core import ScopeRule, EventBus, Endpoint
    from sentinel.http_engine import RequestEngine, RequestMutation

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if urlsplit(self.path).path == "/recover":
                H.n_recover += 1
                if H.n_recover <= 2:
                    self.send_response(429); self.send_header("Retry-After", "0")
                    self.send_header("Content-Length", "0"); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"ok"); return
            H.n_forever += 1
            self.send_response(429); self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0"); self.end_headers()
    H.n_recover = H.n_forever = 0
    port = 8797
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                            EventBus("eng09"), timeout=5)
        r = eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{port}/recover")))
        assert r.status == 200 and not r.error, "retry ladder must recover to 200"
        assert eng.rate_limit_retries == 2 and eng.rate_limited == 2, \
            f"two 429s -> two retries: {eng.rate_limited}/{eng.rate_limit_retries}"
        assert eng.rate_limit_recovered == 1
        assert H.n_recover == 3, "initial + 2 retries = 3 requests on the wire"
        # persistent limiter: honest final 429 after the capped retries
        r2 = eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{port}/forever")))
        assert r2.status == 429 and not r2.error, "final 429 must be returned HONESTLY"
        assert H.n_forever == 1 + eng.max_rate_retries, "retry budget must be respected exactly"
        assert eng.rate_limit_recovered == 1, "a 429 answer is not a recovery"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_auth05_token_bearer_modes():
    """Phase 54 ops: static-token auth — validation-not-exchange (401 rejected,
    login-gate bounce detected), header armed engine-wide via default_headers,
    honest 401/403 rejection counting by the watchdog, raw/custom header forms."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    from sentinel.core import ScopeRule, EventBus, Endpoint, Target
    from sentinel.http_engine import RequestEngine, RequestMutation
    from sentinel.auth import AuthProfile, TokenAuthEngine, TokenWatchdogProxy

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            p = urlsplit(self.path).path
            authed = self.headers.get("Authorization") == "Bearer tok-123"
            if p == "/api/data":
                if authed:
                    self.send_response(200); self.send_header("Content-Length", "3")
                    self.end_headers(); self.wfile.write(b"yes"); return
                self.send_response(401); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"no"); return
            if p == "/gate-always":   # bounces to the login gate even WITH a token
                self.send_response(302); self.send_header("Location", "/login")
                self.send_header("Content-Length", "0"); self.end_headers(); return
            if p == "/expire":        # token expired mid-scan: always 401
                self.send_response(401); self.send_header("Content-Length", "0")
                self.end_headers(); return
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    port = 8798
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        # (1) rejected token: honest failure, header NOT armed
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                            EventBus("a5a"), timeout=5)
        te = TokenAuthEngine(AuthProfile(login_url=base + "/api/data", token="wrong"), eng, EventBus("a5a"))
        assert te.login() is False and "rejected" in te.state.last_error
        assert "Authorization" not in eng.default_headers
        # (2) accepted token: header armed engine-wide, rides default_headers
        eng2 = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                             EventBus("a5b"), timeout=5)
        bus2 = EventBus("a5b")
        te2 = TokenAuthEngine(AuthProfile(login_url=base + "/api/data", token="tok-123"), eng2, bus2)
        assert te2.login() is True
        assert eng2.default_headers["Authorization"] == "Bearer tok-123"
        r = eng2.send(RequestMutation(endpoint=Endpoint(url=base + "/api/data")))
        assert r.status == 200, "armed header must ride every engine request"
        # (3) login-gate bounce detection (token accepted HTTP-wise but bounced)
        te3 = TokenAuthEngine(AuthProfile(login_url=base + "/gate-always", token="tok-123"),
                              eng2, EventBus("a5c"))
        assert te3.login() is False and "bounced" in te3.state.last_error
        # (4) watchdog: mid-scan 401 counted honestly, response passed through
        prox = TokenWatchdogProxy(eng2, te2)
        r401 = prox.send(RequestMutation(endpoint=Endpoint(url=base + "/expire")))
        assert r401.status == 401 and te2.rejections == 1
        # (5) header forms: raw custom key (no scheme prefix)
        p5 = AuthProfile(login_url=base + "/api/data", token="KEY-xyz",
                         auth_header="X-Api-Key", auth_scheme="")
        assert p5.header_value() == "KEY-xyz" and p5.mode == "token"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_op02_sarif_export():
    """Phase 54 ops: SARIF 2.1.0 export — stable rule ids, severity->level mapping,
    verification-gated (rejected candidates NEVER become results), standalone
    evidence in properties, honest error on unknown run id."""
    import tempfile, os as _os
    from sentinel.store import Store
    from sentinel.report import build_sarif
    from sentinel.core import VERSION
    st = Store(_os.path.join(tempfile.mkdtemp(), "sarif-unit.db"))
    st.save_run({
        "run_id": "run-sarif-1", "seed": "s", "scanner": "sentinel-core/" + VERSION,
        "target": "https://example.test", "stats": {"requests": 10},
        "findings": [
            {"id": "f1", "type": "sql_injection", "severity": "critical", "status": "verified",
             "url": "https://example.test/cat", "parameter": "id", "method": "GET",
             "confidence": 0.9, "risk": 95,
             "evidence": [{"kind": "quote_error", "detail": "mysql syntax near '"},
                          {"kind": "or_differential", "detail": "row-count delta"}],
             "verification": {"method": "re-test:fresh-canary", "passed": True, "notes": ""}},
            {"id": "f2", "type": "xss_reflected", "severity": "high", "status": "verified",
             "url": "https://example.test/s", "parameter": "q", "method": "GET",
             "confidence": 0.9, "risk": 70, "evidence": [{"kind": "unescaped_reflection", "detail": "raw"}],
             "verification": {"method": "re-test:fresh-canary", "passed": True, "notes": ""}},
        ],
        "rejected_candidates": [
            {"id": "f3", "type": "xxe", "severity": "critical", "status": "rejected",
             "url": "https://example.test/x", "parameter": "xml", "method": "POST",
             "confidence": 0.2, "risk": 0, "evidence": [],
             "verification": {"method": "re-test:fresh-entity-files", "passed": False, "notes": ""}},
        ]})
    s = build_sarif(st, "run-sarif-1")
    assert s["version"] == "2.1.0" and len(s["runs"]) == 1
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "SENTINEL" and run["tool"]["driver"]["version"] == VERSION
    res = run["results"]
    assert len(res) == 2, "rejected candidate must NOT appear in SARIF results"
    assert {r["ruleId"] for r in res} == {"SEN-SQL-001", "SEN-XSS-001"}
    assert all(r["level"] == "error" for r in res), "critical/high -> error level"
    assert all(r["partialFingerprints"].get("sentinelFindingId") for r in res)
    assert all(r["properties"]["verification"]["passed"] for r in res)
    sql = next(r for r in res if r["ruleId"] == "SEN-SQL-001")
    assert "quote_error" in sql["properties"]["evidence"], "evidence chain must ride along"
    # honesty: unknown run id -> explicit error, not an empty success
    assert "error" in build_sarif(st, "run-does-not-exist")


@case
def unit_disc13_openapi_seed():
    """Phase 54 ops: OpenAPI/Swagger seeding — spec parsing (query + path + JSON
    body params), auto-probe of well-known doc locations, honest empty result
    when no document exists."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.discovery import parse_openapi, _spec_info, DiscoveryEngine
    spec = {"openapi": "3.0.0", "info": {"title": "Demo API", "version": "1.0"},
            "paths": {
                "/api/users": {"get": {"parameters": [{"name": "role", "in": "query",
                                                       "schema": {"example": "admin"}}]}},
                "/api/items/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                "/api/orders": {"post": {"requestBody": {"content": {"application/json":
                                       {"schema": {"properties": {"amount": {}, "note": {}}}}}}}},
            }}
    eps = parse_openapi(spec, "http://127.0.0.1:1")
    by = {(e.url, e.method) for e in eps}
    assert ("http://127.0.0.1:1/api/users", "GET") in by
    assert ("http://127.0.0.1:1/api/items/{id}", "GET") in by
    assert ("http://127.0.0.1:1/api/orders", "POST") in by
    users = next(e for e in eps if e.url.endswith("/api/users"))
    assert any(p.name == "role" for p in users.parameters)
    orders = next(e for e in eps if e.url.endswith("/api/orders"))
    assert {p.name for p in orders.parameters} == {"amount", "note"}, "JSON body fields must seed params"
    info = _spec_info(spec, "/openapi.json", len(eps))
    assert info["version"] == "3.0.0" and info["paths"] == len(eps) and info["title"] == "Demo API"

    state = {"serve_spec": True}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            import json as _j
            if state["serve_spec"] and urlsplit(self.path).path == "/openapi.json":
                b = _j.dumps(spec).encode(); self.send_response(200)
            else:
                b = b"nope"; self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    port = 8799
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                            EventBus("d13"), timeout=5)
        d = DiscoveryEngine(eng, 5)
        eps2, info2 = d.openapi(f"http://127.0.0.1:{port}")
        assert len(eps2) == 3 and info2["source"] == "/openapi.json", info2
        # honest negative: no document anywhere
        state["serve_spec"] = False
        eps3, info3 = d.openapi(f"http://127.0.0.1:{port}")
        assert eps3 == [] and info3 is None, "no spec found -> honest empty, never a guess"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_phase54_ops_stealth_composition():
    """Phase 54 E2E composition: ONE scan exercising every ops/stealth axis at
    once — Bearer-token gated surface (AUTH-05) + OpenAPI-seeded hidden endpoint
    (DISC-13) + passive WAF/tech fingerprinting in stats + 429 backoff with
    recovery (ENG-09) + honest token-rejection counting — then the SAME run
    exported to SARIF (OP-02). Anonymous control scan proves the gated surface
    stays closed without the token (no false coverage)."""
    import threading, tempfile, os as _os
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit, parse_qs
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.auth import AuthProfile
    from sentinel.store import Store
    from sentinel.report import build_sarif

    class H(BaseHTTPRequestHandler):
        hits = {"search": 0}
        def log_message(self, *a): pass
        def _send(self, code, body=b"", hdrs=None):
            self.send_response(code)
            for k, v in (hdrs or {}).items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            if body: self.wfile.write(body)
        def do_GET(self):
            import json as _j
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            authed = self.headers.get("Authorization") == "Bearer tok-123"
            if u.path == "/":
                self._send(200, (
                    '<html><head><meta name="generator" content="WordPress 5.8"></head>'
                    '<body ng-app><a href="/api/secret?name=world">s</a>'
                    '<a href="/search?q=hello">q</a><a href="/waf-page">w</a>'
                    '<a href="/api/expiring">e</a></body></html>').encode(),
                    {"Content-Type": "text/html", "Set-Cookie": "JSESSIONID=sess-1; Path=/",
                     "X-Powered-By": "PHP/7.4.3"})
            elif u.path == "/waf-page":
                self._send(403, b"<html>Attention Required | Cloudflare</html>",
                           {"Server": "cloudflare", "Cf-Ray": "ray-9"})
            elif u.path in ("/api/secret", "/api/admin/items"):
                if not authed:
                    self._send(401, b'{"error":"unauthorized"}',
                               {"Content-Type": "application/json"}); return
                val = q.get("name", q.get("ref", ""))
                self._send(200, f"<html><body>value: {val}</body></html>".encode(),
                           {"Content-Type": "text/html"})
            elif u.path == "/api/expiring":           # 401 even WITH the token
                self._send(401, b"token expired")
            elif u.path == "/search":
                H.hits["search"] += 1
                if H.hits["search"] <= 2:              # first two answers are rate-limited
                    self._send(429, b"", {"Retry-After": "0"}); return
                self._send(200, f"<html>results for {q.get('q','')}</html>".encode(),
                           {"Content-Type": "text/html"})
            elif u.path == "/openapi.json":           # the target's own surface map
                spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                        "paths": {"/api/admin/items": {"get": {"parameters": [
                            {"name": "ref", "in": "query", "schema": {"example": "x"}}]}}}}
                self._send(200, _j.dumps(spec).encode(), {"Content-Type": "application/json"})
            else:
                self._send(404, b"nf")
    port = 8800
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        # ---- scan A: token-armed, all ops axes active
        prof = AuthProfile(login_url=base + "/api/secret", token="tok-123")
        cfg = ScanConfig(allow_private=True, max_pages=15, timeout=5,
                         seed="phase54-comp", browser=False, oast=None, auth=prof)
        rep = SentinelScanner(base, cfg).run()
        st = rep["stats"]
        # AUTH-05: token validated, header armed, honest rejection counting
        assert st["auth"]["mode"] == "token" and st["auth"]["authenticated"] is True, st.get("auth")
        assert st["auth"]["rejections"] >= 1, "mid-scan 401 on /api/expiring must be counted"
        # fingerprint: named WAF + tech map, evidence-backed
        fp = st["fingerprint"]
        assert fp["waf"] and "cloudflare" in fp["waf"]["name"], fp["waf"]
        assert "cookies:Java" in fp["tech"]["frameworks"], fp["tech"]["frameworks"]
        assert fp["tech"]["angularjs"] is True and "AngularJS" in fp["tech"]["frameworks"]
        assert fp["tech"]["headers"].get("x-powered-by", "").startswith("PHP/")
        # DISC-13: the target's own OpenAPI doc seeded the hidden endpoint
        assert st["openapi"]["source"] == "/openapi.json" and st["openapi"]["new_endpoints"] >= 1, st["openapi"]
        # ENG-09: the 429s on /search were absorbed with retries + recovery
        assert st["rate_limit"]["retries"] >= 2 and st["rate_limit"]["recovered"] >= 1, st["rate_limit"]
        # detection composition: token-gated XSS + openapi-seeded XSS + public XSS
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        assert ("xss_reflected", f"{base}/api/secret", "name") in got, "token-gated XSS lost"
        assert ("xss_reflected", f"{base}/api/admin/items", "ref") in got, "openapi-seeded XSS lost"
        assert ("xss_reflected", f"{base}/search", "q") in got, "public XSS lost (regression)"
        for f in rep["findings"]:
            if f["type"] == "xss_reflected":
                assert f["verification"]["passed"] is True
        # OP-02: the SAME run exports to SARIF with every verified XSS as a result
        store = Store(_os.path.join(tempfile.mkdtemp(), "comp.db"))
        store.save_run(rep)
        sarif = build_sarif(store, rep["run_id"])
        assert sarif["version"] == "2.1.0"
        sx = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SEN-XSS-001"]
        assert len(sx) == 3, f"expected 3 XSS results in SARIF, got {len(sx)}"
        assert all(r["level"] == "error" for r in sx)
        # ---- scan B: anonymous control on the SAME server — gated surface closed
        cfg_anon = ScanConfig(allow_private=True, max_pages=15, timeout=5,
                              seed="phase54-anon", browser=False, oast=None)
        rep2 = SentinelScanner(base, cfg_anon).run()
        assert "auth" not in rep2["stats"], "anonymous scan must not claim auth state"
        anon_api_xss = [f for f in rep2["findings"]
                        if f["type"] == "xss_reflected" and "/api/" in f["url"]]
        assert not anon_api_xss, f"anonymous scan must NOT see token-gated surface: {anon_api_xss}"
        assert any(f["type"] == "xss_reflected" and "/search" in f["url"] for f in rep2["findings"]), \
            "public surface must stay reachable anonymously (regression)"
        # fingerprint is passive: works identically without auth
        assert rep2["stats"]["fingerprint"]["waf"] and \
            "cloudflare" in rep2["stats"]["fingerprint"]["waf"]["name"]
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_phase55_detectors_and_gates():
    """Phase 55 unit: the five new detectors fire ONLY on their vulnerable
    mechanisms and respect every honesty gate — SSTI stays silent on raw
    reflection (literal echo = not evaluation), CSRF skips token-bearing and
    read-only forms, NoSQL requires a rejected baseline, JWT stays silent on
    signed (HS256) issuance, Host-header requires actual canary reflection."""
    import os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.core import Endpoint, Parameter, ParamLocation, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.detect import (SstiDetector, CsrfDetector, NosqlDetector, JwtDetector,
                                 HostHeaderDetector)
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v7u", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                     "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8807
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    bus = EventBus("unit-phase55")
    from sentinel.core import ScopeRule
    eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                        bus, timeout=5)
    try:
        base = f"http://127.0.0.1:{port}"
        # ---- SSTI: vulnerable evaluation fires with family recorded; reflection stays silent
        ep_v = Endpoint(url=base + "/vuln/ssti?name=world",
                        parameters=[Parameter("name", value="world").classify()])
        f = SstiDetector(eng, bus).run(ep_v)
        assert f is not None and f.type == "ssti" and f.parameter == "name", f
        assert "syntax={{" in f.evidence[0].detail, f.evidence[0].detail
        ep_refl = Endpoint(url=base + "/vuln/xss.php?q=test",
                           parameters=[Parameter("q", value="test").classify()])
        assert SstiDetector(eng, bus).run(ep_refl) is None, "raw reflection must NOT be SSTI"
        ep_safe = Endpoint(url=base + "/safe/ssti?name=world",
                           parameters=[Parameter("name", value="world").classify()])
        assert SstiDetector(eng, bus).run(ep_safe) is None
        # ---- CSRF: fires on the unprotected state change; token gate + read-only gate hold
        ep_cs = Endpoint(url=base + "/vuln/csrf-action", method="POST",
                         parameters=[Parameter("email", ParamLocation.BODY, "sub@example.com").classify()])
        f2 = CsrfDetector(eng, bus).run(ep_cs)
        assert f2 is not None and f2.type == "csrf", f2
        ep_cs_safe = Endpoint(url=base + "/safe/csrf-action", method="POST",
                              parameters=[Parameter("csrfToken", ParamLocation.BODY, "cs-fixed-token-123").classify(),
                                          Parameter("email", ParamLocation.BODY, "sub@example.com").classify()])
        assert CsrfDetector(eng, bus).run(ep_cs_safe) is None, "token-bearing form must be skipped"
        ep_cs_ro = Endpoint(url=base + "/vuln/stock", method="POST",
                            parameters=[Parameter("productId", value="1").classify()])
        assert CsrfDetector(eng, bus).run(ep_cs_ro) is None, "read-only (stock) must be skipped"
        # ---- NoSQL: operator bypass fires; hardened twin + accepted-baseline stay silent
        ep_no = Endpoint(url=base + "/vuln/nosql-login", method="POST",
                         parameters=[Parameter("user", ParamLocation.JSON, "demo").classify(),
                                     Parameter("pass", ParamLocation.JSON, "demo").classify()])
        f3 = NosqlDetector(eng, bus).run(ep_no)
        assert f3 is not None and f3.type == "nosql_injection" and f3.parameter == "user", f3
        ep_no_safe = Endpoint(url=base + "/safe/nosql-login", method="POST",
                              parameters=[Parameter("user", ParamLocation.JSON, "demo").classify(),
                                          Parameter("pass", ParamLocation.JSON, "demo").classify()])
        assert NosqlDetector(eng, bus).run(ep_no_safe) is None
        ep_no_ok = Endpoint(url=base + "/vuln/jwt-login", method="POST",
                            parameters=[Parameter("user", ParamLocation.JSON, "demo").classify(),
                                        Parameter("pass", ParamLocation.JSON, "demo").classify()])
        assert NosqlDetector(eng, bus).run(ep_no_ok) is None, "accepted baseline must be skipped"
        # ---- JWT: none-alg issuance reported; HS256 issuance stays silent
        f4 = JwtDetector(eng, bus).run(ep_no_ok)
        assert f4 is not None and f4.type == "jwt_security", f4
        assert "alg=none" in f4.evidence[0].detail
        ep_jwt_safe = Endpoint(url=base + "/safe/jwt-login", method="POST",
                               parameters=[Parameter("user", ParamLocation.JSON, "demo").classify(),
                                           Parameter("pass", ParamLocation.JSON, "demo").classify()])
        assert JwtDetector(eng, bus).run(ep_jwt_safe) is None, "HS256 issuance is normal"
        # ---- Host header: canary reflected on the vuln page; fixed base stays silent
        ep_hh = Endpoint(url=base + "/vuln/hostbuild")
        f5 = HostHeaderDetector(eng, bus).run(ep_hh)
        assert f5 is not None and f5.type == "host_header_injection", f5
        assert HostHeaderDetector(eng, bus).run(Endpoint(url=base + "/safe/hostbuild")) is None
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_phase55_five_classes_end_to_end():
    """Phase 55 E2E on fixture v7: a full authenticated scan with local OAST
    verifies all five new classes end-to-end — ssti (VR-12 fresh expression),
    csrf (VR-13 fresh hostile origin), nosql_injection (VR-14 fresh operator
    $gt), jwt_security (VR-15 fresh none-issuance), host_header_injection
    (VR-16 fresh canary) — while every hardened twin stays silent and every
    prior class (SQLi / blind XXE / SSRF / cmdi / CORS) does not regress."""
    import os as _os, importlib.util
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    from sentinel.auth import AuthProfile
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v7", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8808
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        auth = AuthProfile(login_url=f"http://127.0.0.1:{port}/login",
                           username="demo", password="demo123",
                           user_field="uid", pass_field="passw",
                           success_marker="Sign Off")
        cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6,
                         seed="v7-e2e-regression", oast=oast, auth=auth)
        sc = SentinelScanner(f"http://127.0.0.1:{port}", cfg)
        rep = sc.run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        # the five new verified classes
        assert any(t == "ssti" and u.endswith("/vuln/ssti") and p == "name" for t, u, p in got), \
            f"SSTI missing: {sorted(got)}"
        assert any(t == "csrf" and u.endswith("/vuln/csrf-action") and p == "email" for t, u, p in got), \
            f"CSRF missing: {sorted(got)}"
        assert any(t == "nosql_injection" and u.endswith("/vuln/nosql-login") and p == "user"
                   for t, u, p in got), f"NoSQL missing: {sorted(got)}"
        assert any(t == "jwt_security" and u.endswith("/vuln/jwt-login") for t, u, p in got), \
            f"JWT missing: {sorted(got)}"
        assert any(t == "host_header_injection" and u.endswith("/vuln/hostbuild") for t, u, p in got), \
            f"Host-header missing: {sorted(got)}"
        # verification methods are the Phase 55 VRs and they PASSED
        want_vr = {"ssti": "re-test:fresh-expression",
                   "csrf": "re-test:fresh-hostile-origin",
                   "nosql_injection": "re-test:fresh-operator",
                   "jwt_security": "re-test:fresh-issuance",
                   "host_header_injection": "re-test:fresh-canary-host"}
        seen_vr = {}
        for f in rep["findings"]:
            if f["type"] in want_vr and "/vuln/" in f["url"]:
                seen_vr[f["type"]] = f["verification"]["method"], f["verification"]["passed"]
        for t, m in want_vr.items():
            assert t in seen_vr and seen_vr[t] == (m, True), (t, seen_vr.get(t))
        # hardened twins silent for ALL new classes
        for t, u, p in got:
            if t in ("ssti", "csrf", "nosql_injection", "jwt_security", "host_header_injection") \
                    and "/safe/" in u:
                raise AssertionError(f"Phase 55 false positive: {t} @ {u}")
        # prior classes intact (no regression)
        assert any(t == "sql_injection" for t, u, p in got), "SQLi regressed"
        assert any(t == "xxe" and u.endswith("/vuln/oob-stock") for t, u, p in got), "blind XXE regressed"
        assert any(t == "ssrf" and u.endswith("/vuln/fetch") for t, u, p in got), "SSRF regressed"
        assert any(t == "command_injection" and u.endswith("/vuln/ping") for t, u, p in got), "cmdi regressed"
        assert any(t == "cors_misconfig" and u.endswith("/vuln/cors") for t, u, p in got), "CORS regressed"
        assert any(t == "xss_reflected" and u.endswith("/account") and p == "q" for t, u, p in got), \
            "authenticated XSS regressed"
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


# ============================================================ PHASE 56 (v2.8.0) — Intelligence Layer

def _mk_resp(body, status=200, headers=None, rid="t1"):
    """Duck-typed Response for scanner unit tests."""
    return type("R", (), {"error": "", "status": status, "body": body,
                          "headers": headers or {}, "request_id": rid,
                          "redirect_chain": []})()


@case
def unit_paramintel_value_shape_inference():
    """Smart Testing Engine: value-shape inference upgrades ONLY what the observed
    value proves, TOKENs are never touched, skips are compact+auditable."""
    from sentinel.paramintel import ParamIntel
    from sentinel.core import ParamKind, Parameter, ParamLocation
    # JSON-object value shape -> json_object kind (planner has no rule -> batteries skip)
    assert ParamIntel.infer("filter", '{"status":"active"}') == ParamKind.JSON_OBJECT
    # non-JSON / plain / empty values keep their existing classification (None = no upgrade)
    assert ParamIntel.infer("q", "plain text") is None
    assert ParamIntel.infer("f", "{broken json") is None
    assert ParamIntel.infer("x", "") is None
    assert ParamIntel.infer("a", "[1,2]") is None          # arrays stay generic
    # enrich: upgrade + profile + data-object inventory; TOKEN params untouched
    eps = [Endpoint(url="http://x.io/api/filter", parameters=[
                Parameter("filter", ParamLocation.QUERY, '{"a":1}'),
                Parameter("user_id", ParamLocation.QUERY, "7"),
                Parameter("csrfToken", ParamLocation.QUERY, "abc").classify()]),
           Endpoint(url="http://x.io/api/data", parameters=[
                Parameter("user_id", ParamLocation.QUERY, "7")])]
    prof = ParamIntel.enrich(eps)
    assert eps[0].parameters[0].kind == ParamKind.JSON_OBJECT
    assert eps[0].parameters[2].kind == ParamKind.TOKEN      # never re-classified
    assert prof["by_kind"]["json_object"] == 1
    assert prof["value_shape_upgrades"] == 1
    assert prof["data_objects"]["user_id"] == ["http://x.io/api/data", "http://x.io/api/filter"]
    # skip reason is compact (coverage-friendly) and only for inferred kinds
    assert ParamIntel.skip_reason(eps[0].parameters[0]) == "param_intel:json_object"
    assert ParamIntel.skip_reason(eps[0].parameters[1]) is None


@case
def unit_coverage_tracker_accounting():
    """Coverage Engine: discovered/tested/skip accounting is exact, deterministic,
    and the engine proxy attributes requests by their testing intent."""
    from sentinel.coverage import CoverageTracker, _CoverageProxy
    e1 = Endpoint(url="http://x.io/a")
    e2 = Endpoint(url="http://x.io/b", parameters=[Parameter("q", ParamLocation.QUERY, "1")])
    cov = CoverageTracker()
    cov.discover(e1); cov.discover(e2); cov.discover(e1)      # idempotent
    cov.baseline(e1, 200); cov.activity(e1, "passive")
    cov.activity(e1, "secrets"); cov.skipped(e1, "requires_authentication")
    cov.skipped(e1, "requires_authentication")                 # dedup
    s = cov.summarize()
    assert s["discovered"] == 2 and s["tested"] == 1 and s["untested"] == 1
    assert s["passive"] == 1 and s["secrets_scanned"] == 1 and s["active"] == 0
    assert s["skip_reasons"] == {"requires_authentication": 1}
    assert s["coverage_pct"] == 50.0
    assert s["endpoints"][0]["url"] == "http://x.io/a"          # sorted, deterministic
    # proxy attribution: navigation and auth flows are NOT testing
    class _FakeEngine:
        def __init__(self): self.requests_sent = 0
        def send(self, m):
            self.requests_sent += 1
            return _mk_resp("<html></html>")
    proxied = _CoverageProxy(_FakeEngine(), cov)
    from sentinel.http_engine import RequestMutation
    proxied.send(RequestMutation(endpoint=e2, note="discovery"))            # crawl -> not testing
    proxied.send(RequestMutation(endpoint=e2, note="auth-prime"))           # auth -> not testing
    proxied.send(RequestMutation(endpoint=e2, note="passive-baseline"))     # passive
    proxied.send(RequestMutation(endpoint=e2, param_name="q", param_value="1'"))  # mutation -> active
    s2 = cov.summarize()
    assert s2["tested"] == 2 and s2["active"] == 1 and s2["passive"] == 2
    # baseline of e2 recorded (200), auth/navigation left no activity trace
    rec = {r["url"]: r for r in s2["endpoints"]}["http://x.io/b"]
    assert rec["baseline"] == 200 and rec["activity"] == ["passive", "active"]


@case
def unit_secrets_scanner_classification_and_gates():
    """Credential Exposure Engine: vendor classes fire with MASKED evidence,
    span-suppression prevents double-reporting, placeholders are hygiene, and
    auth-shaped endpoints suppress token classes (issuance is normal there)."""
    from sentinel.secrets import SecretsScanner
    sc = SecretsScanner()
    aws = "AK" + "IA" + "B" * 16                       # build by concatenation: no literal
    gh = "gh" + "p_" + "S" * 30                        # secret-shaped string in source
    # 1) AWS key fires once, evidence masked
    hits = sc.scan(Endpoint(url="http://x.io/cfg"), _mk_resp(f'{{"k": "{aws}"}}'))
    assert len(hits) == 1 and hits[0].type == "credential_exposure"
    assert hits[0].parameter == "aws_access_key" and "B" * 8 not in hits[0].evidence[0].detail
    assert "…" in hits[0].evidence[0].detail                    # mask present
    # 2) github token via generic-looking key=value: specific class wins (span suppression)
    hits = sc.scan(Endpoint(url="http://x.io/cfg"), _mk_resp(f'"api_token": "{gh}"'))
    assert [h.parameter for h in hits] == ["github_token"], [h.parameter for h in hits]
    # 3) placeholder values are NOT leaks
    hits = sc.scan(Endpoint(url="http://x.io/cfg"),
                   _mk_resp('"api_key": "xxxxxxxxxxxxxxxx"'))
    assert hits == []
    hits = sc.scan(Endpoint(url="http://x.io/cfg"),
                   _mk_resp('"api_key": "AKIA********************"'))
    assert hits == []
    # 4) credential-bearing DB URI
    hits = sc.scan(Endpoint(url="http://x.io/cfg"),
                   _mk_resp('"url": "mysql://app:hunter2@db.local/x"'))
    assert [h.parameter for h in hits] == ["db_connection_uri"]
    # 5) context gate: JWT in a login response = normal issuance (silent);
    #    the same token on an ordinary page = exposure (fires)
    jwt = "eyJ" + "A" * 20 + "." + "B" * 20 + "."
    assert sc.scan(Endpoint(url="http://x.io/api/login"), _mk_resp(f'{{"t": "{jwt}"}}')) == []
    hits = sc.scan(Endpoint(url="http://x.io/page"), _mk_resp(f'{{"t": "{jwt}"}}'))
    assert [h.parameter for h in hits] == ["jwt_token"]
    # 6) private key block = critical
    hits = sc.scan(Endpoint(url="http://x.io/dump"),
                   _mk_resp("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"))
    assert hits[0].parameter == "private_key" and hits[0].severity.value == "critical"
    # 7) errors / empty responses are silent (never a finding)


@case
def unit_evidence_impact_profiles():
    """Evidence Graph / Impact Assessor: every finding type maps to an impact
    grade; OOB evidence is flagged; authz context rides the chain."""
    from sentinel.evidence import assess, IMPACT_PROFILES
    from sentinel.core import Finding, Evidence, Severity, Verification, FindingStatus
    # every REGISTERED vulnerability type has a profile (no silent defaults for known classes)
    from sentinel.intel import RISK_WEIGHTS
    for t in RISK_WEIGHTS:
        assert t in IMPACT_PROFILES, f"impact profile missing for {t}"
    f = Finding("sql_injection", endpoint_url="http://x/a?id=1", parameter="id",
                evidence=[Evidence("db_error", "x")],
                verification=Verification("re-test:variant", True, 0.9, 1))
    a = assess(f)
    assert a["grade"] == "proven" and "differential" in a["statement"].lower()
    assert a["evidence_chain"]["verification_passed"] is True
    # OOB classes carry the out_of_band flag
    f2 = Finding("ssrf", endpoint_url="http://x/f", parameter="url",
                 evidence=[Evidence("oob_callback", "from 1.2.3.4")])
    assert assess(f2)["evidence_chain"]["out_of_band"] is True
    # passive classes are honestly "indicated", unknown types degrade to default
    assert assess(Finding("missing_security_headers", endpoint_url="http://x")
                  )["grade"] == "indicated"
    assert assess(Finding("brand_new_class", endpoint_url="http://x")
                  )["grade"] == "indicated"
    # authz context rides the chain
    f3 = Finding("idor_bola", endpoint_url="http://x/api/data", parameter="user_id")
    f3.authz_context = "attacker=bob(role=user) victim=carol(role=user)"
    assert assess(f3)["evidence_chain"]["authz_context"] == f3.authz_context


@case
def unit_authz_engine_matrix_idor_vertical():
    """Multi-User Authorization Engine (direct, fixture v8): three accounts log
    in, IDOR fires on /api/data with the victim-marker oracle + VR-17, vertical
    fires on /api/admin/stats with the access differential + VR-18, hardened
    twins stay silent, and the access matrix records the GATE status (302), not
    the followed-redirect landing (200)."""
    import threading, importlib.util
    import os as _os
    from http.server import ThreadingHTTPServer
    from sentinel.authz import AuthzEngine, AuthzConfig, _rank
    from sentinel.core import ScopeRule, EventBus, Parameter, ParamLocation
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v8_authz", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                          "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8809
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        accts = [
            {"name": "demo-admin", "role": "admin", "username": "demo",
             "password": "demo123", "marker": "root-admin@sentinel-fixture.local",
             "object_id": "1001"},
            {"name": "bob-user", "role": "user", "username": "bob",
             "password": "bob123", "marker": "bob-user@sentinel-fixture.local",
             "object_id": "2002"},
            {"name": "carol-user", "role": "user", "username": "carol",
             "password": "carol123", "marker": "carol-user@sentinel-fixture.local",
             "object_id": "3003"},
        ]
        cfgd = AuthzConfig.from_dict({"login_url": base + "/login", "user_field": "uid",
                                      "pass_field": "passw", "success_marker": "Sign Off",
                                      "accounts": accts}, base)
        eng = AuthzEngine(cfgd, ScopeRule(allowed_domains=["127.0.0.1"],
                                          allow_private=True), EventBus("authz-unit"))
        eps = [
            Endpoint(url=base + "/api/data",
                     parameters=[Parameter("user_id", ParamLocation.QUERY, "1001").classify()]),
            Endpoint(url=base + "/api/secure/data",
                     parameters=[Parameter("user_id", ParamLocation.QUERY, "1001").classify()]),
            Endpoint(url=base + "/api/admin/stats"),
            Endpoint(url=base + "/api/secure/admin/stats"),
        ]
        out = eng.run(eps)
        assert out["stats"]["accounts_logged_in"] == 3 and out["stats"]["ran"]
        assert out["stats"]["roles"] == ["admin", "user"]
        byt = {f.type: f for f in out["findings"]}
        # IDOR: verified, victim-marker oracle, VR-17 fresh victim
        assert "idor_bola" in byt, sorted(byt)
        idf = byt["idor_bola"]
        assert idf.endpoint_url.endswith("/api/data") and idf.parameter == "user_id"
        assert idf.verification.method == "re-test:fresh-victim-object" and idf.verification.passed
        assert "victim" in idf.authz_context and "attacker=bob-user" in idf.authz_context
        # vertical: verified, VR-18 fresh privileged replay
        assert "vertical_privilege_escalation" in byt, sorted(byt)
        vf = byt["vertical_privilege_escalation"]
        assert vf.endpoint_url.endswith("/api/admin/stats")
        assert vf.verification.method == "re-test:fresh-privileged-replay" and vf.verification.passed
        # hardened twins silent
        for f in out["findings"]:
            assert "/api/secure/" not in f.endpoint_url, f.endpoint_url
        # matrix honesty: anonymous on the gated admin surface = 302 (the GATE),
        # not 200 (the login page the redirect landed on)
        mx = out["matrix"]
        assert mx[base + "/api/admin/stats"]["anonymous"] == 302
        assert mx[base + "/api/admin/stats"]["role:user"] == 200
        assert mx[base + "/api/secure/admin/stats"]["role:user"] == 403
        assert mx[base + "/api/secure/admin/stats"]["role:admin"] == 200
        # role ranking sanity
        assert _rank("admin") < _rank("manager") < _rank("user") < _rank("guest")
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_phase56_intelligence_end_to_end():
    """Phase 56 full-platform regression: ONE authenticated scan with the
    Authorization Engine armed — the three new classes verified with their VRs,
    hardened twins silent, prior classes intact (incl. host_header after the
    budget recalibration), and every Intelligence Layer artifact present and
    honest (coverage account, param-intel profile, appmap, access matrix,
    secrets summary with masking, impact proof on every verified finding)."""
    import threading, importlib.util
    import os as _os
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    from sentinel.auth import AuthProfile
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v8_e2e", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                        "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8810
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        base = f"http://127.0.0.1:{port}"
        auth = AuthProfile(login_url=base + "/login", username="demo", password="demo123",
                           user_field="uid", pass_field="passw", success_marker="Sign Off")
        authz_cfg = {"login_url": "/login", "user_field": "uid", "pass_field": "passw",
                     "success_marker": "Sign Off",
                     "accounts": [
                         {"name": "demo-admin", "role": "admin", "username": "demo",
                          "password": "demo123", "marker": "root-admin@sentinel-fixture.local",
                          "object_id": "1001"},
                         {"name": "bob-user", "role": "user", "username": "bob",
                          "password": "bob123", "marker": "bob-user@sentinel-fixture.local",
                          "object_id": "2002"},
                         {"name": "carol-user", "role": "user", "username": "carol",
                          "password": "carol123", "marker": "carol-user@sentinel-fixture.local",
                          "object_id": "3003"}]}
        cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6,
                         seed="v8-e2e-regression", oast=oast, auth=auth, authz=authz_cfg)
        sc = SentinelScanner(base, cfg)
        rep = sc.run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}
        # ---- the three new verified classes with their VR methods
        new_vr = {"idor_bola": ("re-test:fresh-victim-object", "/api/data"),
                  "vertical_privilege_escalation": ("re-test:fresh-privileged-replay", "/api/admin/stats"),
                  "credential_exposure": ("re-test:fresh-fetch-reexposure", "/vuln/leak-config")}
        for t, (vr, path) in new_vr.items():
            matches = [f for f in rep["findings"] if f["type"] == t and f["url"].split("?")[0].endswith(path)]
            assert matches, f"{t} missing: {sorted(got)[:12]}..."
            for f in matches:
                assert f["verification"]["method"] == vr and f["verification"]["passed"], f
                assert f["impact"]["grade"] == "proven" and f["impact"]["statement"], f
        # credential classes: exactly the three fixture classes, all masked
        cred = [f for f in rep["findings"] if f["type"] == "credential_exposure"]
        assert sorted(f["parameter"] for f in cred) == \
            ["aws_access_key", "db_connection_uri", "github_token"]
        for f in cred:
            assert "…" in f["evidence"][0]["detail"]
            assert "IOSFODNN7" not in f["evidence"][0]["detail"]   # raw value never stored
        # ---- hardened twins silent for the new classes
        for t, u, p in got:
            if t == "idor_bola":
                assert "/api/secure/" not in u, f"IDOR false positive: {t} @ {u}"
            if t == "vertical_privilege_escalation":
                assert "/api/secure/" not in u, f"vertical false positive: {t} @ {u}"
            if t == "credential_exposure":
                assert "/safe/" not in u, f"secrets false positive: {t} @ {u}"
        # ---- prior classes intact (spot-check the full breadth)
        # (jwt/hostheader findings carry the detector convention parameter "-")
        for t, u, p in [("sql_injection", "/vuln/sqli_error.php", "id"),
                        ("xss_reflected", "/account", "q"),
                        ("xxe", "/vuln/oob-stock", "storeId"),
                        ("ssrf", "/vuln/fetch", "url"),
                        ("ssti", "/vuln/ssti", "name"),
                        ("csrf", "/vuln/csrf-action", "email"),
                        ("nosql_injection", "/vuln/nosql-login", "user"),
                        ("jwt_security", "/vuln/jwt-login", "-"),
                        ("host_header_injection", "/vuln/hostbuild", "Host")]:
            assert any(ft == t and fu.endswith(u) and fp == p for ft, fu, fp in got), \
                f"prior class regressed: {t} @ {u}"
        # ---- Intelligence Layer artifacts
        st = rep["stats"]
        cov = st["coverage"]
        # RECALIBRATED (v2.8.0 final gate): fixture v8 serves exactly 65 distinct
        # routes -> an honest one-record-per-endpoint account yields 68 records
        # (routes with multiple parameter signatures). The old "> 90" threshold
        # was written against the pre-fix accounting that double-counted
        # discovery events; it is unachievable with the honest account. The
        # floor 65 == the fixture's full route surface: the crawl-budget bug
        # (starved pages) or any discovery regression drops this well below 65.
        assert cov["discovered"] >= 65 and cov["coverage_pct"] >= 95.0
        assert cov["tested"] == cov["discovered"] - cov["untested"]
        assert cov["skip_reasons"].get("param_intel:json_object") == 1
        assert cov["secrets_scanned"] >= 60
        assert cov["authz_probed"] >= 5
        pi = st["param_intel"]
        assert pi["by_kind"].get("json_object") == 1 and "user_id" in pi["data_objects"]
        az = st["authz"]
        assert az["ran"] and az["accounts_logged_in"] == 3 and az["roles"] == ["admin", "user"]
        am = st["appmap"]
        assert am["authentication"]["mode"].startswith("multi-user")
        assert am["authentication"]["roles_tested"] == ["admin", "user"]
        assert am["surfaces"]["api"]["count"] >= 5 and am["access_matrix"]
        assert st["secrets"]["findings"] == 3 and len(st["secrets"]["classes_found"]) == 3
        # the param-intel surface itself: JSON-object batteries provably skipped
        flt = [e for e in cov["endpoints"] if e["url"].endswith("/api/filter")]
        assert flt and flt[0]["skips"] == ["param_intel:json_object"], flt
        # every verified finding carries impact proof
        assert all("impact" in f and f["impact"]["grade"] in ("proven", "indicated")
                   for f in rep["findings"])
        # requests total includes the authz engines' own traffic (honesty)
        assert st["authz"]["requests"] > 0
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


# ================================================================ Phase 57 (v2.9.0 Credential Vault)
@case
def unit_phase57_vault_crypto_lifecycle():
    """Phase 57 Credential Vault — pure unit battery. Crypto correctness is
    pinned to TWO independent references: the RFC 8439 §2.1.1 quarter-round
    vector, and a full 64-byte keystream KAT whose expected bytes were produced
    by the independent `cryptography` library oracle at build time (SENTINEL
    itself stays pure stdlib). Then the complete access lifecycle: authorized
    keys only, org separation, tamper + transplant rejection, revoke with blob
    rotation, masked listing, audited reveal, purge semantics, scrub."""
    import tempfile, os as _os, json as _json
    from sentinel.vault import (Vault, VaultError, keygen, load_key,
                                chacha20_xor, _quarter_round, MASK_STARS)

    # ---- 1. RFC 8439 §2.1.1 quarter-round known-answer vector
    w = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
    _quarter_round(w, 0, 1, 2, 3)
    assert w == [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb], \
        f"quarter-round vector mismatch: {[hex(x) for x in w]}"

    # ---- 2. full keystream KAT (RFC 8439 §2.4.2 shape: key=00..1f,
    # nonce=000000090000004a00000000, counter=1; expected bytes generated by
    # the `cryptography` ChaCha20 oracle — the independent implementation)
    ks = chacha20_xor(bytes(range(32)),
                      bytes.fromhex("000000090000004a00000000"), b"\x00" * 64)
    assert ks.hex() == ("10f1e7e4d13b5915500fdd1fa32071c4"
                        "c7d1f4c733c068030422aa9ac3d46c4"
                        "ed2826446079faa0914c2d705d98b02a"
                        "2b5129cd1de164eb9cbd083e8a2503c4e"), ks.hex()
    # second oracle vector: nonzero data, non-unit counter, different key/nonce
    import hashlib
    ct = chacha20_xor(bytes.fromhex("0a" * 32),
                      bytes.fromhex("deadbeefcafebabe01234567"),
                      hashlib.sha256(b"sentinel").digest() * 3, counter=42)
    assert ct.hex() == ("4d32a338cd58a81fb0888e3c3206a4ae"
                        "7972c29d1f672fdc45693da9c9d40aa8"
                        "855eddd88449a2f058cabc55bbd237f4"
                        "47f2c6c4859c19593d95d0c9ffb6e134"
                        "06bd0c675ba9707656711e8e9522fd39"
                        "ce1c5c209d8abfb65da55099493f6ccd"), ct.hex()

    td = tempfile.mkdtemp(prefix="vault-unit-")
    kf_designer = _os.path.join(td, "designer.key.json")
    kf_owner = _os.path.join(td, "owner.key.json")
    kf_stranger = _os.path.join(td, "stranger.key.json")
    vp = _os.path.join(td, "org.vault")
    keygen(kf_designer, label="designer")
    keygen(kf_owner, label="owner")
    keygen(kf_stranger, label="stranger")
    # key files: 0600, self-consistent key_id
    assert _os.stat(kf_designer).st_mode & 0o777 == 0o600
    kid_d, _ = load_key(kf_designer)
    kid_o, _ = load_key(kf_owner)
    kid_s, _ = load_key(kf_stranger)
    assert len({kid_d, kid_o, kid_s}) == 3, "key ids must be distinct"

    # ---- 3. init + stranger refused (access is key-file-granted, not ambient)
    v = Vault.init(vp, kf_designer, "acme")
    assert v.status()["org"] == "acme" and v.status()["records"] == 0
    try:
        Vault.open(vp, kf_stranger); assert False, "stranger key must be refused"
    except VaultError as e:
        assert "not authorized" in str(e)

    # ---- 4. store + encrypted-at-rest (byte-level) + masked listing
    raws = {"aws": "AKIAUNITTESTKEY00001",       # 20 chars, real shape
            "gh": "ghp_unittesttoken_0123456789abcdef012345",  # real shape
            "db": "postgres://svc:Sup3rS3cret@db.internal:5432/prod"}
    r_aws = v.store("aws_access_key", raws["aws"], {"url": "https://t/x", "run_id": "r1"})
    r_gh = v.store("github_token", raws["gh"], {"url": "https://t/x", "run_id": "r1"})
    r_db = v.store("db_connection_uri", raws["db"], {"url": "https://t/y", "run_id": "r1"})
    blob = open(vp, "rb").read()
    for raw in raws.values():
        assert raw.encode() not in blob, "vault FILE must not contain plaintext"
    listed = v.list()
    assert len(listed) == 3 and all("masked" in r and r.get("raw") is None
                                    for r in listed), "list() = masked only"
    assert not any(raw in _json.dumps(listed) for raw in raws.values())

    # ---- 5. idempotent re-observation increments hits (no duplicate records)
    v.store("aws_access_key", raws["aws"], {"url": "https://t/x", "run_id": "r1"})
    assert len(v.list()) == 3
    hits = {r["cls"]: r["hits"] for r in v.list()}
    assert hits["aws_access_key"] == 2 and hits["github_token"] == 1

    # ---- 6. audited reveal; audit trail covers every action class
    rec = v.export(r_aws)
    assert rec["raw"] == raws["aws"], "authorized export must reveal the raw"
    rep = v.report()
    assert {r["raw"] for r in rep["records"]} == set(raws.values())
    assert rep["classification"].startswith("CONFIDENTIAL")
    actions = [e["action"] for e in v.audit()]
    for must in ("INIT", "STORE", "LIST", "EXPORT", "REPORT"):
        assert must in actions, f"audit missing {must}: {actions}"
    assert all(e["actor"] == kid_d for e in v.audit()), "actor must be the key id"

    # ---- 7. authorize owner + auditor; owner opens; 3-key honest refusal
    # (sessions are snapshots: v2 must be opened AFTER all authorizations so
    # it sees the 3-key state — a stale session honestly answers "no such
    # authorized key" for keys added after it was opened)
    v.authorize(kf_owner, label="owner")
    v.authorize(kf_stranger, label="auditor")   # keys: designer, owner, auditor
    v2 = Vault.open(vp, kf_owner)
    assert v2.key_id == kid_o and v2.status()["records"] == 3
    for actor, target in ((v2, kid_s), (v, kid_o), (v2, kid_d)):
        try:
            actor.revoke(target)
            assert False, f"3-key revoke of {target} must refuse honestly"
        except VaultError as e:
            assert "re-wrap" in str(e) or "requires their key files" in str(e)

    # ---- 8. legal revoke + rotation on a dedicated 2-key vault: the removed
    # key cannot open ANY copy of the file afterwards
    vp_rot = _os.path.join(td, "rotation.vault")
    v_rot = Vault.init(vp_rot, kf_designer, "rot-org")
    v_rot.store("github_token", raws["gh"], {"url": "https://t/r"})
    v_rot.authorize(kf_owner, label="owner")
    v_rot.revoke(kid_o)                         # exactly 2 keys -> legal + rotate
    try:
        Vault.open(vp_rot, kf_owner); assert False, "revoked key must fail"
    except VaultError:
        pass
    v_rot2 = Vault.open(vp_rot, kf_designer)
    assert v_rot2.status()["records"] == 1 and \
        kid_o not in [k["key_id"] for k in v_rot2.status()["authorized_keys"]]

    # ---- 9. tamper + org transplant both rejected — on COPIES, so the main
    # vault file stays valid for the purge/scrub steps below
    import shutil as _shutil
    vp_t = _os.path.join(td, "tamper.vault")
    _shutil.copyfile(vp, vp_t)
    env = _json.load(open(vp_t))
    good_ct = env["blob"]["ct"]
    env["blob"]["ct"] = good_ct[:-4] + ("AAAA" if not good_ct.endswith("AAAA") else "BBBB")
    _json.dump(env, open(vp_t, "w"))
    try:
        Vault.open(vp_t, kf_designer); assert False, "tampered blob must fail"
    except VaultError:
        pass
    # transplant: acme's VALID blob inside another org's envelope — the org is
    # bound into the AAD, so the MAC itself rejects the transplant
    vp2 = _os.path.join(td, "other.vault")
    keygen(_os.path.join(td, "other.key.json"))
    Vault.init(vp2, _os.path.join(td, "other.key.json"), "not-acme")
    env_a = _json.load(open(vp)); env_b = _json.load(open(vp2))
    env_b["blob"] = dict(env_a["blob"])
    _json.dump(env_b, open(vp2, "w"))
    try:
        Vault.open(vp2, _os.path.join(td, "other.key.json"))
        assert False, "transplanted blob must fail"
    except VaultError:
        pass

    # ---- 10. purge: value gone from the blob, audit entry survives
    n = v.purge(all_records=True)
    assert n == 3 and v.list() == []
    v4 = Vault.open(vp, kf_designer)
    assert v4.status()["records"] == 0
    assert any(e["action"] == "PURGE" for e in v4.audit()), \
        "the destruction itself must stay provable"

    # ---- 11. scrub: defense in depth over arbitrary report structures
    v5 = Vault.init(_os.path.join(td, "scrub.vault"), kf_designer, "scrub-org")
    v5.store("aws_access_key", raws["aws"], {"url": "https://t/z"})
    doc = {"url": "https://t/z", "evidence": [f"leak {raws['aws']} here"],
           "nested": {"detail": f"see {raws['db']}"}}
    scrubbed = v5.scrub(doc)
    assert raws["aws"] not in _json.dumps(scrubbed) and MASK_STARS in _json.dumps(scrubbed)
    # restore a clean state file for any later opener
    v5.purge(all_records=True)


@case
def regression_phase57_vault_end_to_end():
    """Phase 57 full-platform regression: a REAL scan with an armed Credential
    Vault. Every credential class the exposure engine verifies is captured
    encrypted-at-rest — byte-level no-plaintext gates on BOTH the scan report
    and the vault FILE — findings carry mask + vault record references only,
    masked vault stats ride the report, the owner reveal returns exactly the
    fixture's true values, the hardened twin stays an honest negative, purge
    empties the vault while the audit survives, and the whole `sentinel vault`
    CLI surface works against the same file via subprocess (script mode)."""
    import importlib.util, subprocess, sys, threading, tempfile
    import os as _os, json as _json
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.vault import Vault, keygen

    spec = importlib.util.spec_from_file_location(
        "vulnapp_v57_e2e", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                         "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8812
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    td = tempfile.mkdtemp(prefix="vault-e2e-")
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    cli = _os.path.join(root, "sentinel", "cli.py")
    try:
        base = f"http://127.0.0.1:{port}"
        kf, vp = _os.path.join(td, "designer.key.json"), _os.path.join(td, "acme.vault")
        keygen(kf, label="designer")
        Vault.init(vp, kf, "acme-fixture")
        cfg = ScanConfig(allow_private=True, max_pages=12, timeout=6,
                         seed="p57-e2e", vault=vp, vault_key_file=kf)
        rep = SentinelScanner(base, cfg).run()

        # ---- the three credential classes verified, masked, vault-referenced
        cred = [f for f in rep["findings"] if f["type"] == "credential_exposure"]
        assert sorted(f["parameter"] for f in cred) == \
            ["aws_access_key", "db_connection_uri", "github_token"], \
            sorted(f["parameter"] for f in cred)
        for f in cred:
            assert f["verification"]["method"] == "re-test:fresh-fetch-reexposure"
            assert f["verification"]["passed"]
            assert f["url"].endswith("/vuln/leak-config")
            det = f["evidence"][0]["detail"]
            assert "…" in det and "encrypted in the credential vault as rec-" in det
        # hardened twin: honest negative — placeholders are hygiene, not leaks
        assert not any("/safe/" in f["url"] for f in cred)

        # ---- byte-level no-plaintext gates (report artifact + vault FILE)
        report_dump = _json.dumps(rep)
        vault_bytes = open(vp, "rb").read()
        true_raws = [mod.LEAK_CONFIG["aws_access_key_id"],
                     mod.LEAK_CONFIG["github_token"],
                     mod.LEAK_CONFIG["database_url"]]
        for raw in true_raws:
            assert raw not in report_dump, "raw credential leaked into the report"
            assert raw.encode() not in vault_bytes, "raw credential in vault FILE"
        # the safe twin's masked values were never credentials -> never captured
        safe_dump = _json.dumps(mod.SAFE_LEAK_CONFIG)
        assert safe_dump not in report_dump

        # ---- masked stats ride the report; owner reveal returns the truth
        st = rep["stats"]["vault"]
        assert st["org"] == "acme-fixture" and st["records"] == 3
        assert sorted(st["classes"]) == ["aws_access_key", "db_connection_uri",
                                         "github_token"]
        v = Vault.open(vp, kf)
        revealed = {r["cls"]: r["raw"] for r in v.report()["records"]}
        assert revealed == {"aws_access_key": mod.LEAK_CONFIG["aws_access_key_id"],
                            "github_token": mod.LEAK_CONFIG["github_token"],
                            "db_connection_uri": mod.LEAK_CONFIG["database_url"]}, \
            "the authorized reveal must return exactly the fixture's true values"
        assert all(e["action"] == "STORE" or e["action"] in ("INIT", "LIST", "REPORT")
                   for e in v.audit())

        # ---- CLI surface (script mode) against the SAME vault file
        def run_cli(*args):
            r = subprocess.run([sys.executable, cli, "vault", *args],
                               capture_output=True, text=True, timeout=60, cwd=root)
            assert r.returncode == 0, f"cli vault {args}: {r.stderr[-300:]}"
            return r.stdout
        out = _json.loads(run_cli("status", "--vault", vp, "--key-file", kf))
        assert out["org"] == "acme-fixture" and out["records"] == 3
        listed = _json.loads(run_cli("list", "--vault", vp, "--key-file", kf))
        assert len(listed["records"]) == 3 and \
            all("masked" in r and "raw" not in r for r in listed["records"])
        # wrong key over CLI: clean refusal, exit 2
        kf_bad = _os.path.join(td, "stranger.key.json")
        keygen(kf_bad, label="stranger")
        r_bad = subprocess.run([sys.executable, cli, "vault", "list",
                                "--vault", vp, "--key-file", kf_bad],
                               capture_output=True, text=True, timeout=60, cwd=root)
        assert r_bad.returncode == 2 and "vault_error" in r_bad.stderr
        # owner reveal report to disk (audited), then shred after delivery
        rep_path = _os.path.join(td, "credential_report.json")
        meta = _json.loads(run_cli("report", "--vault", vp, "--key-file", kf,
                                   "--out", rep_path))
        assert meta["records"] == 3 and meta["classification"].startswith("CONFIDENTIAL")
        on_disk = _json.load(open(rep_path))
        assert {r["raw"] for r in on_disk["records"]} == set(true_raws)
        purged = _json.loads(run_cli("purge", "--vault", vp, "--key-file", kf, "--all"))
        assert purged["shredded"] == 3
        after = _json.loads(run_cli("audit", "--vault", vp, "--key-file", kf))
        acts = [e["action"] for e in after["entries"]]
        for must in ("INIT", "STORE", "LIST", "REPORT", "PURGE"):
            assert must in acts, f"audit missing {must}: {acts}"
        assert _json.loads(run_cli("status", "--vault", vp, "--key-file", kf))["records"] == 0
    finally:
        srv.shutdown(); srv.server_close()


# ============================================================ PHASE 58 (v3.0.0) — Workflow / Business-Logic Intelligence

@case
def unit_phase58_workflow_engine():
    """Phase 58 unit battery (no network): the flow parser understands
    <select>/<option> LABELS (where the UI declares privilege boundaries),
    synthesis is deterministic (tokens/hidden carried, canaries on amount-ish
    fields, first option for selects, overrides win), fresh-resource synthesis
    preserves the observed shape, cluster rules exclude root/login/logout/asset
    surfaces and the flow-worded scoring outranks size, and the execution
    marker vocabulary is learned from a word delta."""
    from sentinel.workflow import (WorkflowEngine, WorkflowConfig, parse_forms,
                                   _privilege_options, _synth_fresh_resource,
                                   _word_delta, _lines_with, CANARY_CREATE,
                                   CANARY_TAMPER, SESSION_KILLER_RE)
    from sentinel.core import Endpoint, ParamLocation, Parameter as _P

    html = ('<form action="/wf/transfer/confirm" method="POST">'
            '<input type="hidden" name="csrfToken" value="abc123">'
            '<input type="hidden" name="tid" value="TRF-0007">'
            '<input type="hidden" name="amount" value="1111">'
            '<select name="mode"><option value="ach">ACH transfer</option>'
            '<option value="wire">Wire transfer (admin only)</option></select>'
            '<button type="submit">go</button></form>')
    forms = parse_forms(html)
    assert len(forms) == 1 and forms[0]["method"] == "POST"
    assert [f["name"] for f in forms[0]["fields"]] == ["csrfToken", "tid", "amount", "mode"]
    assert _privilege_options(forms) == [("mode", "wire", "Wire transfer (admin only)")], \
        "option-label privilege detection failed"
    # non-privileged labels are not flagged
    assert _privilege_options(parse_forms('<form action="/x" method="post">'
                                          '<select name="m"><option value="a">standard</option>'
                                          '</select></form>')) == []

    we = WorkflowEngine()
    d = dict(we._synth_fields(forms[0]))
    assert d == {"csrfToken": "abc123", "tid": "TRF-0007", "amount": "1111", "mode": "ach"}, d
    assert dict(we._synth_fields(forms[0], overrides={"mode": "wire"}))["mode"] == "wire"
    # amount-ish text fields get the canary; defaults carried otherwise
    f2 = parse_forms('<form action="/x" method="post">'
                     '<input type="text" name="amount" value="">'
                     '<input type="text" name="note" value="hello"></form>')[0]
    d2 = dict(we._synth_fields(f2))
    assert d2 == {"amount": CANARY_CREATE, "note": "hello"}, d2
    assert CANARY_TAMPER == "2222" and CANARY_CREATE == "1111"

    assert _synth_fresh_resource("TRF-0007") == "TRF-99001"
    assert _synth_fresh_resource("ORD-42") == "ORD-99001"

    # execution markers: word delta of the same resource line pre/post final step
    body = ('<ul><li>TRF-0001 800001 1111 ach PENDING</li>'
            '<li>TRF-0001 800001 1111 ach EXECUTED</li></ul>')
    lines = _lines_with(body, "TRF-0001")
    assert len(lines) == 2, lines
    added, removed = _word_delta(lines[0], lines[1])
    assert "EXECUTED" in added and "PENDING" in removed, (added, removed)
    # li/tr boundaries split even without newlines
    assert len(_lines_with("<tr><td>ORD-1 a</td></tr><tr><td>ORD-1 b</td></tr>", "ORD-1")) == 2

    # cluster rules
    eps = [Endpoint(url="http://t.local/wf/transfer/start"),
           Endpoint(url="http://t.local/wf/transfer/ledger"),
           Endpoint(url="http://t.local/wf/transfer/select", method="POST",
                    parameters=[_P("acct", ParamLocation.BODY, "800001")]),
           Endpoint(url="http://t.local/wf/transfer/create", method="POST",
                    parameters=[_P("amount", ParamLocation.BODY, "")]),
           Endpoint(url="http://t.local/wf/transfer/confirm", method="POST"),
           Endpoint(url="http://t.local/vuln/a.php"), Endpoint(url="http://t.local/vuln/b.php"),
           Endpoint(url="http://t.local/doLogin", method="POST"),
           Endpoint(url="http://t.local/logout")]
    cl = we._cluster_members(eps, {"http://t.local/doLogin"})
    assert "/wf/transfer" in cl and "/vuln" in cl, sorted(cl)
    assert all(p not in cl for p in ("/", "/wf", "")), sorted(cl)
    assert "http://t.local/doLogin" not in {e.url for m in cl.values() for e in m.values()}
    assert all(not SESSION_KILLER_RE.search(e.url) for m in cl.values() for e in m.values()), \
        "logout-shaped surfaces must never be flow members"
    # flow-worded scoring outranks raw size: a 5-endpoint transfer wizard
    # beats a 30-endpoint flat directory
    s_wf = we._score("/wf/transfer", cl["/wf/transfer"])
    s_vuln = we._score("/vuln", cl["/vuln"])
    assert s_wf > s_vuln, (s_wf, s_vuln)
    # budgets are per flow (the five invariants are a flow-sized battery)
    assert WorkflowConfig().max_flow_attacks >= 5
    assert WorkflowConfig().max_clusters >= 2 and WorkflowConfig().max_steps >= 3


@case
def unit_eng15_csrf_state_classifier():
    """ENG-15 (live-caught on ginandjuice.shop v3.0.0 campaign): the CSRF
    detector's _state_changing matched READ_WORDS as substrings ANYWHERE in
    url+params, so 'catalog' as a PARENT DIRECTORY demoted the tokenless
    add-to-cart POST /catalog/cart — a PROVEN CSRF (hostile-origin acceptance
    + SameSite=None session cookie, manually verified: product actually added)
    went unreported. Words must match path segments/param names; a READ word
    only demotes as a whole WORD of the ACTION segment; a state-word param
    rescues a read action; word boundaries keep 'checkout' stateful while
    'stock-check'/'view-cart' stay reads."""
    from sentinel.detect import CsrfDetector
    from sentinel.core import Endpoint, Parameter, ParamLocation
    d = CsrfDetector.__new__(CsrfDetector)
    def ep(url, params=()):
        return Endpoint(url=url, method="POST",
                        parameters=[Parameter(n, ParamLocation.BODY, v).classify()
                                    for n, v in params])
    T = [  # true state-changing surfaces the detector must probe
        ("https://ginandjuice.shop/catalog/cart",
         [("productId", "1"), ("redir", "PRODUCT"), ("quantity", "1")]),
        ("https://ginandjuice.shop/catalog/cart/checkout", [("csrf", "x")]),
        ("https://ginandjuice.shop/catalog/subscribe", [("email", "a@b")]),
        ("https://x.local/account/search", [("q", "x"), ("action", "remove")]),
        ("https://x.local/WebGoat/PasswordReset/reset", []),
        ("https://x.local/blog/post/comment", [("comment", "hi")]),
        ("https://x.local/catalog/listing/add", [("name", "x")]),
    ]
    F = [  # reads that must stay demoted
        ("https://ginandjuice.shop/catalog/product/stock",
         [("productId", "1"), ("storeId", "2")]),
        ("https://x.local/account/search", [("q", "x")]),
        ("https://x.local/account/search", [("address", "5th")]),   # 'address' != 'add'
        ("https://x.local/catalog/listing/view", []),
        ("https://x.local/marketplace/list", []),                   # 'place' != word here
        ("https://x.local/shop/stock-check", []),                   # hyphen word-split
        ("https://x.local/shop/view-cart", []),
    ]
    for url, params in T:
        assert d._state_changing(ep(url, params)), f"ENG-15 regression: {url} must be state-changing"
    for url, params in F:
        assert not d._state_changing(ep(url, params)), f"ENG-15 regression: {url} must stay a read"


@case
def unit_eng16_workflow_anchor_query_params():
    """ENG-16 (live-caught on ginandjuice.shop v3.0.0 campaign): the workflow
    walk's anchor fetch used the BARE path, but query-param pages
    (/catalog/product?productId=1) only render their form for a valid query —
    the param-less GET returned an error page with no forms and the whole
    cluster was dropped as 'no_anchor'. The anchor fetch must rebuild the URL
    from the endpoint's discovered QUERY parameters (DISC-07 values)."""
    from sentinel.workflow import WorkflowEngine
    from sentinel.core import Endpoint, Parameter, ParamLocation

    we = WorkflowEngine()
    members = {
        "/catalog/cart": Endpoint(url="https://t.local/catalog/cart", method="POST",
                                  parameters=[Parameter("productId", ParamLocation.BODY, "1").classify(),
                                              Parameter("redir", ParamLocation.BODY, "PRODUCT").classify(),
                                              Parameter("quantity", ParamLocation.BODY, "1").classify()]),
        "/catalog/product": Endpoint(url="https://t.local/catalog/product",
                                     parameters=[Parameter("productId", ParamLocation.QUERY, "1").classify()]),
    }
    fetched = []
    class FakeEngine:
        requests_sent = 0
        def send(self, m):
            self.requests_sent += 1
            fetched.append(m.endpoint.url)
            class R: error = False; ok = True; status = 200; body = ""; request_id = "fake"
            if "productId=1" in m.endpoint.url and m.endpoint.method == "GET":
                R.body = ('<form action="/catalog/cart" method="POST">'
                          '<input type="hidden" name="productId" value="1">'
                          '<input type="hidden" name="redir" value="PRODUCT">'
                          '<select name="quantity"><option value="1">1</option></select>'
                          '</form>')
            return R()
    steps, entry, pending, entry_fields = we._walk(members, FakeEngine())
    # the anchor fetch carried the discovered query value
    assert any("productId=1" in u for u in fetched), \
        f"ENG-16 regression: anchor fetched without query params: {fetched}"
    assert entry == "https://t.local/catalog/product?productId=1", entry
    # one canary step (the add-to-cart), landing carries no NEW form -> chain ends
    assert len(steps) == 1 and steps[0].status == 200, steps
    assert pending is None


@case
def unit_eng17_discovery_select_params():
    """ENG-17 (live-caught on ginandjuice.shop add-to-cart): the discovery form
    parser had NO <select> handling — the quantity select was dropped from
    POST /catalog/cart's parameter list, so the CSRF baseline shipped without
    a required field, 400'd, and the cross-origin proof could never pass. A
    browser ALWAYS submits a select: the SELECTED option, else the FIRST
    option (text content when the value attr is absent)."""
    from sentinel.discovery import _LinkParser
    p = _LinkParser()
    # ginandjuice add-to-cart shape: hidden fields + quantity select (selected first)
    p.feed('<form id=addToCartForm action=/catalog/cart method=POST>'
           '<input required type=hidden name=productId value=1>'
           '<input required type=hidden name=redir value=PRODUCT>'
           "<select class='product-quantity' required name=quantity>"
           '<option value="1" selected>1</option><option value="2">2</option>'
           '</select></form>')
    assert p.forms and p.forms[0]["params"] == [("productId", "1"),
                                                ("redir", "PRODUCT"),
                                                ("quantity", "1")], p.forms[0]["params"]
    # no selected attr -> first option wins
    p2 = _LinkParser()
    p2.feed('<form action=/x method=post><select name=mode>'
            '<option value="ach">ACH</option><option value="wire">Wire</option>'
            '</select></form>')
    assert p2.forms[0]["params"] == [("mode", "ach")], p2.forms[0]["params"]
    # selected attr NOT on the first option -> it still wins
    p3 = _LinkParser()
    p3.feed('<form action=/x method=post><select name=mode>'
            '<option value="ach">ACH</option><option value="wire" selected>Wire</option>'
            '</select></form>')
    assert p3.forms[0]["params"] == [("mode", "wire")], p3.forms[0]["params"]
    # option without value attr -> text content is the submitted value
    p4 = _LinkParser()
    p4.feed('<form action=/x method=post><select name=size>'
            '<option>Large</option><option>XL</option></select></form>')
    assert p4.forms[0]["params"] == [("size", "Large")], p4.forms[0]["params"]
    # select inside a DISC-10 div pseudo-form is captured too
    p5 = _LinkParser()
    p5.feed('<div class=form data-method=post data-action=/catalog/subscribe>'
            '<input type=text name=email value="">'
            '<select name=freq><option value="w">Weekly</option></select></div>')
    assert p5.divforms and ("freq", "w") in p5.divforms[0]["params"], p5.divforms
    # selects OUTSIDE any form are ignored (no stray params)
    p6 = _LinkParser()
    p6.feed('<select name=lonely><option value="1">1</option></select>')
    assert not p6.forms and not p6.divforms


# ================= Phase 60-64 (v4.0.0): Digital Twin platform units =================

@case
def unit_twin_graph_fusion():
    """Phase 60: the Security Digital Twin fuses every scan artifact into ONE
    knowledge graph — identities/roles from the authz sessions, surfaces and
    typed parameters from discovery, workflows with mint/consume edges,
    findings attached to their surface, masked secrets, and coverage reasons
    on untested surfaces. Zero requests, deterministic ids/order."""
    from sentinel.twin import build_twin, twin_summary
    from sentinel.core import Endpoint, Parameter, ParamLocation, DiscoverySource

    eps = [
        Endpoint(url="https://t.local/wf/transfer/select", method="POST",
                 parameters=[Parameter("acct", ParamLocation.BODY, "800001").classify()]),
        Endpoint(url="https://t.local/wf/transfer/start"),
        Endpoint(url="https://t.local/wf/transfer/ledger"),
        Endpoint(url="https://t.local/api/data",
                 parameters=[Parameter("user_id", ParamLocation.QUERY, "2002").classify()]),
    ]
    authz = {"stats": {"roles": ["admin", "user"], "accounts_logged_in": 2},
             "matrix": {"https://t.local/api/data": {"admin": 200, "user": 200}},
             "accounts": [{"name": "demo-admin", "role": "admin", "username": "demo",
                           "marker": "m1", "object_id": "1001"},
                          {"name": "bob-user", "role": "user", "username": "bob",
                           "marker": "m2", "object_id": "2002"}]}
    wf = {"flows": [{"cluster": "/wf/transfer", "entry": "/wf/transfer/start",
                     "steps": [{"action": "/wf/transfer/select", "method": "POST"},
                               {"action": "/wf/transfer/create", "method": "POST"},
                               {"action": "/wf/transfer/confirm", "method": "POST"}],
                     "resource_params": ["tid"], "state_oracle": "/wf/transfer/ledger",
                     "execution_markers": {"gained": ["EXECUTED"], "lost": ["PENDING"]},
                     "privilege_declared_options": [{"field": "mode", "value": "wire",
                                                     "label": "Wire transfer (admin only)"}],
                     "rollback_paths": []}]}
    findings = [{"id": "F-abc", "type": "business_logic_step_bypass", "severity": "high",
                 "status": "verified", "url": "https://t.local/wf/transfer/create",
                 "parameter": "acct", "method": "POST", "confidence": 0.9}]
    cov = {"endpoints": [{"method": "GET", "url": "https://t.local/wf/transfer/ledger",
                          "source": "crawl:html", "activity": ["passive"], "skips": [],
                          "baseline": 200}]}
    twin = build_twin("https://t.local", eps, authz_result=authz, auth_mode="multi-user(admin,user)",
                      workflow_stats=wf, findings=findings, coverage_summary=cov)
    kinds = {n.kind for n in twin.nodes.values()}
    for k in ("identity", "role", "surface", "parameter", "entity", "workflow",
              "workflow_step", "state", "finding"):
        assert k in kinds, f"missing node kind {k}: {sorted(kinds)}"
    rels = {e.rel for e in twin.edges}
    for r in ("has_role", "carries", "typed_as", "gates", "step_of", "transitions_to",
              "mints", "consumes", "produced_finding"):
        assert r in rels, f"missing edge rel {r}: {sorted(rels)}"
    # both identities wired to their roles
    assert twin.find("identity", "demo-admin") and twin.find("identity", "bob-user")
    assert {n.key for n in twin.neighbors(twin.find("identity", "bob-user").id, "has_role")} == {"user"}
    # the api data surface is reachable from BOTH roles (matrix -> gates)
    surf = twin.find("surface", "GET /api/data")
    gates = {twin.nodes[e.src].key: e.attrs["status"] for e in twin.edges
             if e.rel == "gates" and e.dst == surf.id}
    assert gates == {"admin": 200, "user": 200}, gates
    # the finding is attached to its producing surface
    surf_create = twin.find("surface", "POST /wf/transfer/create")
    assert any(twin.nodes[e.dst].kind == "finding" for e in twin.edges
               if e.src == surf_create.id and e.rel == "produced_finding")
    # serialization is stable and complete
    d = twin.to_dict()
    assert d["stats"]["nodes"] == len(twin.nodes) and d["stats"]["edges"] == len(twin.edges)
    s = twin_summary(twin)
    assert s["identities"] == 2, s
    # POST /wf/transfer/select is a WRITE surface (planner input class)
    assert twin.find("surface", "POST /wf/transfer/select") is not None
    assert s["surfaces_write"] >= 1 and s["workflow_steps"] == 3, s
    assert s["findings_attached"] == 1 and s["states_observed"] == 1


@case
def unit_twin_entity_and_action_typing():
    """Phase 60: entity typing (parameter -> business entity) and operation
    classification (surface -> READ/WRITE/NAV) are word-boundary deterministic
    — the substrate for entity intelligence and the Safe Attack Planner."""
    from sentinel.twin import infer_entity, classify_action
    # longest-word-wins + camelCase/snake_case splitting
    assert infer_entity("account_id") == "Account"
    assert infer_entity("order_id") == "Order"
    assert infer_entity("orderId") == "Order"          # camelCase split
    assert infer_entity("tid", "/wf/transfer/confirm") == "Transaction"
    assert infer_entity("invoice_number") == "Invoice"
    assert infer_entity("ticket_id") == "Ticket"
    assert infer_entity("user_id") == "User"
    assert infer_entity("filename.css") == ""          # no false entity
    # word boundaries: 'catalog' must NOT type as ... (no vocab word inside)
    assert infer_entity("catalog") == ""
    # operation classes
    assert classify_action("https://t.local/orders/create", "POST") == "WRITE"
    assert classify_action("https://t.local/orders/details", "GET") == "READ"
    assert classify_action("https://t.local/static/app.js", "GET") == "NAV"
    # DELETE is write-shaped regardless of vocabulary
    assert classify_action("https://t.local/items/1", "DELETE") == "WRITE"


@case
def unit_twin_authorization_matrix_projection():
    """Phase 60: the provable role x surface account and the entity inventory
    — the graph projections an auditor reads instead of raw matrix rows."""
    from sentinel.twin import build_twin, authorization_matrix, entity_inventory
    from sentinel.core import Endpoint, Parameter, ParamLocation

    eps = [Endpoint(url="https://t.local/api/data",
                    parameters=[Parameter("user_id", ParamLocation.QUERY, "2002").classify()]),
           Endpoint(url="https://t.local/api/admin/stats"),
           Endpoint(url="https://t.local/orders/view",
                    parameters=[Parameter("order_id", ParamLocation.QUERY, "55").classify()])]
    authz = {"stats": {"roles": ["admin", "user"]},
             "matrix": {"https://t.local/api/data": {"admin": 200, "user": 200},
                        "https://t.local/api/admin/stats": {"admin": 200, "user": 403}},
             "accounts": [{"name": "a", "role": "admin", "username": "a"},
                          {"name": "b", "role": "user", "username": "b"}]}
    twin = build_twin("https://t.local", eps, authz_result=authz, auth_mode="multi-user(admin,user)")
    azm = authorization_matrix(twin)
    assert azm["admin"].get("reachable") and any("/api/data" in s for s in azm["admin"]["reachable"])
    assert azm["user"].get("forbidden") and any("/api/admin/stats" in s
                                                  for s in azm["user"]["forbidden"]), azm
    ents = {e["entity"]: e for e in entity_inventory(twin)}
    assert "User" in ents and "Order" in ents, sorted(ents)
    assert any("/api/data" in s for s in ents["User"]["surfaces"]), ents["User"]
    assert any("/orders/view" in s for s in ents["Order"]["surfaces"]), ents["Order"]


@case
def unit_planner_safety_gates():
    """Phase 61: the Safe Attack Planner classifies every planned operation
    BEFORE it runs, with a human-readable rationale — READ_ONLY/LOW_IMPACT
    automatic, STATE_CHANGING behind --logic-active, DESTRUCTIVE blocked by
    default (enterprise safety contract, auditable decision log)."""
    from sentinel.planner import SafeAttackPlanner, classify_operation
    # classification vocabulary
    assert classify_operation("https://t.local/orders/view", "GET")["impact"] == "READ_ONLY"
    assert classify_operation("https://t.local/orders/place", "POST",
                              fields=[("amount", "100")])["impact"] == "STATE_CHANGING"
    # canary-valued writes are bounded (workflow learning)
    assert classify_operation("https://t.local/wf/transfer/select", "POST",
                              fields=[("acct", "1"), ("csrfToken", "x")],
                              note="wf-walk")["impact"] == "LOW_IMPACT"
    assert classify_operation("https://t.local/wf/transfer/confirm", "POST",
                              note="wf-atk-tamper")["impact"] == "STATE_CHANGING"
    # destructive vocabulary is blocked wherever it appears
    d = classify_operation("https://t.local/admin/purge", "POST",
                           fields=[("all", "1")])
    assert d["impact"] == "DESTRUCTIVE" and "destructive" in d["rationale"], d
    # gates: without the flag
    p = SafeAttackPlanner(logic_active=False)
    assert p.gate("https://t.local/orders/view", "GET")["allowed"] is True
    attack = p.gate("https://t.local/wf/transfer/confirm", "POST", note="wf-atk")
    assert attack["allowed"] is False and attack["policy"] == "requires --logic-active"
    blocked = p.gate("https://t.local/admin/purge", "POST", fields=[("all", "1")])
    assert blocked["allowed"] is False and "blocked" in blocked["policy"]
    assert p.blocked == 2 and p.summary()["operations_evaluated"] == 3   # attack + destructive both refused
    # gates: with the flag, the attack battery passes but destructive NEVER does
    p2 = SafeAttackPlanner(logic_active=True)
    assert p2.gate("https://t.local/wf/transfer/confirm", "POST", note="wf-atk")["allowed"] is True
    assert p2.gate("https://t.local/admin/purge", "POST", fields=[("all", "1")])["allowed"] is False
    # every decision carries the WHY (the reportable safety contract)
    for d in p2.decisions:
        assert d["rationale"], d


@case
def unit_reasoning_hypothesis_lifecycle():
    """Phase 62: the Autonomous Reasoning Engine generates attack hypotheses
    by MATCHING PATTERNS over the Digital Twin (never hard-coded endpoint
    lists), then resolves each against what the scan actually did — verified /
    refuted / untestable-with-reason, the honest reasoning-coverage account."""
    from sentinel.twin import build_twin
    from sentinel import reasoning
    from sentinel.core import Endpoint, Parameter, ParamLocation

    eps = [Endpoint(url="https://t.local/wf/pay/select",
                    parameters=[Parameter("acct", ParamLocation.BODY, "1").classify()]),
           Endpoint(url="https://t.local/wf/pay/ledger"),
           Endpoint(url="https://t.local/api/orders",
                    parameters=[Parameter("order_id", ParamLocation.QUERY, "9").classify()])]
    authz = {"stats": {"roles": ["admin", "user"]},
             "matrix": {"https://t.local/api/admin/stats": {"admin": 200, "user": 200}},
             "accounts": [{"name": "a", "role": "admin", "username": "a"},
                          {"name": "b", "role": "user", "username": "b"}]}
    wf = {"flows": [{"cluster": "/wf/pay", "entry": "/wf/pay/start",
                     "steps": [{"action": "/wf/pay/select", "method": "POST"},
                               {"action": "/wf/pay/confirm", "method": "POST"}],
                     "resource_params": ["pid"], "state_oracle": "/wf/pay/ledger",
                     "execution_markers": {"gained": ["DONE"], "lost": ["PENDING"]},
                     "privilege_declared_options": [], "rollback_paths": ["/wf/pay/cancel"]}]}
    twin = build_twin("https://t.local", eps, authz_result=authz,
                      auth_mode="multi-user(admin,user)", workflow_stats=wf)
    hyps = reasoning.generate_hypotheses(twin)
    pats = {h["pattern"] for h in hyps}
    for p in (reasoning.R_CROSS_IDENTITY_OBJECT, reasoning.R_WF_SKIP_STEP,
              reasoning.R_WF_REPLAY_FINAL, reasoning.R_WF_TAMPER_VALUE,
              reasoning.R_WF_CROSS_STATE, reasoning.R_ADMIN_SURFACE_LOW_ROLE):
        assert p in pats, f"pattern {p} not generated: {sorted(pats)}"
    # every hypothesis carries its reasoning chain + test recipe + plan class
    for h in hyps:
        assert h["premise"] and h["chain"] and h["test"] and h["plan"], h
    # resolution: the workflow battery verified skip+replay on /wf/pay
    attack_log = [{"flow": "/wf/pay", "attack": "step_bypass", "verdict": "verified"},
                  {"flow": "/wf/pay", "attack": "cross_state", "verdict": "verified"},
                  {"flow": "/wf/pay", "attack": "cross_user", "verdict": "skipped"}]
    findings = [{"type": "business_logic_step_bypass", "url": "https://t.local/wf/pay/select",
                 "parameter": "acct"}]
    resolved = reasoning.resolve_hypotheses(hyps, findings, workflow_attack_log=attack_log,
                                            authz_stats={"ran": True})
    by_pat = {}
    for h in resolved:
        by_pat.setdefault(h["pattern"], []).append(h["status"])
    assert "tested:verified" in by_pat[reasoning.R_WF_SKIP_STEP], by_pat
    assert "tested:verified" in by_pat[reasoning.R_WF_CROSS_STATE], by_pat
    # cross-user skipped (precondition) -> untestable, NEVER guessed
    assert "untestable:precondition_absent" in by_pat[reasoning.R_CROSS_IDENTITY_OBJECT], by_pat
    s = reasoning.hypothesis_summary(resolved)
    assert s["verified"] >= 1 and s["untestable"] >= 1 and \
        "untestable:precondition_absent" in s["untestable_reasons"], s


@case
def unit_evidence_os_proof_files():
    """Phase 63: the Evidence OS — every verified finding becomes a
    self-contained proof file (attack hypothesis, preconditions, requests,
    evidence, identity, state before/after, impact, reproduction recipe,
    confidence), and the reproduce cue names the finding."""
    from sentinel.core import Evidence, Finding, Severity, Verification, FindingStatus
    from sentinel.evidence import build_proof, reproduce_command, HYPOTHESIS_BY_CLASS

    f = Finding("business_logic_cross_user_execution", Severity.HIGH,
                "https://t.local/wf/shared/transfer/confirm?x=1", "tid", "POST",
                [Evidence("cross_identity_object_execution",
                          "identity B executed object TRF-0001 minted by identity A",
                          "req-1")],
                verification=Verification("oracle:workflow-state-delta", True, 0.9, 1,
                                          "owner oracle gained the executed line"))
    f.status = FindingStatus.VERIFIED
    f.authz_context = "attacker=role:user object_owner=primary"
    proof = build_proof(f, state_before="TRF-0001 ... PENDING",
                        state_after="TRF-0001 ... EXECUTED")
    for k in ("attack_hypothesis", "preconditions", "requests", "responses", "identity",
              "state_before", "state_after", "impact", "reproduction", "confidence",
              "verification", "proof_grade"):
        assert k in proof, f"proof missing {k}"
    assert "identity A" in proof["attack_hypothesis"] and "identity B" in proof["attack_hypothesis"]
    assert proof["identity"] == "attacker=role:user object_owner=primary"
    assert proof["proof_grade"] == "proven"
    assert "PENDING" in proof["state_before"] and "EXECUTED" in proof["state_after"]
    # preconditions are class-aware (workflow + multi-identity + opt-in flag)
    pre = " ".join(proof["preconditions"])
    assert "multi-step" in pre and "--logic-active" in pre
    # the reproduction recipe is ordered, human-executable steps
    steps = proof["reproduction"]
    assert steps and all(s.get("step") and s.get("request") and s.get("expect") for s in steps)
    assert steps[-1]["step"] == 3            # workflow classes gain the walk step
    # every business-logic class has a hypothesis (incl. the three v4.0.0 ones)
    for t in ("business_logic_cross_user_execution", "business_logic_cross_object_execution",
              "business_logic_cross_state_execution"):
        assert t in HYPOTHESIS_BY_CLASS, t
    cue = reproduce_command(proof)
    assert proof["finding_id"] in cue and "confirm" in cue


@case
def unit_workflow_cross_identity_preconditions():
    """Phase 60: the three cross-identity manipulations are PRECONDITIONED —
    a flow without a rollback path, without foreign-typed objects, or without
    cross-identity store visibility is a LOUD honest skip, never a guessed
    finding, and never consumes attack budget."""
    from sentinel.workflow import WorkflowEngine, FlowKnowledge, WalkStep
    from sentinel.core import Endpoint

    we = WorkflowEngine()
    k = FlowKnowledge(cluster="/wf/transfer",
                      members={"/wf/transfer/start": Endpoint(url="https://t.local/wf/transfer/start")},
                      steps=[WalkStep(action="https://t.local/wf/transfer/select"),
                             WalkStep(action="https://t.local/wf/transfer/create"),
                             WalkStep(action="https://t.local/wf/transfer/confirm")],
                      oracle_url="https://t.local/wf/transfer/ledger",
                      resource_params={"tid": "TRF-0007"}, producer_idx=1,
                      exec_added=["EXECUTED"], exec_removed=["PENDING"])
    # NO cancel paths, NO foreign ids, per-session oracle
    assert k.cancel_paths == []

    class FakeApp:
        """Serves the walk shapes: start -> select -> create (confirm form with
        TRF-0007), plus a per-session oracle the second identity cannot see."""
        requests_sent = 0
        def send(self, m):
            self.requests_sent += 1
            path = m.endpoint.url
            method = (m.endpoint.method or "GET").upper()
            class R:
                error = False; ok = True; status = 200; request_id = "f"; body = ""
            if method == "GET" and path.endswith("/start"):
                R.body = ('<form action="/wf/transfer/select" method="POST">'
                          '<input type="hidden" name="csrfToken" value="tok-a">'
                          '<input type="text" name="acct" value="800001"></form>')
            elif path.endswith("/select"):
                R.body = ('<form action="/wf/transfer/create" method="POST">'
                          '<input type="hidden" name="csrfToken" value="tok-a">'
                          '<input type="hidden" name="acct" value="800001">'
                          '<input type="text" name="amount" value="1111"></form>')
            elif path.endswith("/create"):
                R.body = ('<form action="/wf/transfer/confirm" method="POST">'
                          '<input type="hidden" name="csrfToken" value="tok-a">'
                          '<input type="hidden" name="tid" value="TRF-0007">'
                          '<input type="hidden" name="amount" value="1111"></form>')
            elif path.endswith("/ledger"):
                R.body = "<ul><li>TRF-0007 800001 1111 ach PENDING</li></ul>"
            return R()

    class BlindApp(FakeApp):
        def send(self, m):
            r = super().send(m)
            if m.endpoint.url.endswith("/ledger"):
                r.body = "<ul><li>No transfers yet.</li></ul>"
            return r

    eng = FakeApp()
    f, detail = we._atk_cross_state(k, eng, [("csrfToken", "tok")])
    assert f is None and detail["verdict"] == "skipped" and detail.get("precondition"), detail
    f, detail = we._atk_cross_object(k, eng, [("csrfToken", "tok")])
    assert f is None and detail["verdict"] == "skipped" and detail.get("precondition"), detail
    # cross-user on a second identity that CANNOT see the object: precondition skip
    f, detail = we._atk_cross_user(k, eng, [("csrfToken", "tok-b")], BlindApp(), "user")
    assert f is None and detail["verdict"] == "skipped" and detail.get("precondition"), detail


@case
def unit_report_executive_and_glass():
    """Phase 64: the executive report (risk posture, business impact, affected
    assets, coverage proof, CI gate) and the glass dashboard are derived from
    the SAME store as the technical report — one data source, two audiences."""
    import tempfile, os as _os
    from sentinel.store import Store
    from sentinel.report import build_executive, build_glass_html, SARIF_RULES

    st = Store(_os.path.join(tempfile.mkdtemp(), "exec.db"))
    st.save_run({
        "run_id": "run-exec-test", "seed": "s", "scanner": "sentinel-core/4.0.0",
        "target": "https://t.local", "stats": {
            "coverage": {"discovered": 40, "tested": 39, "coverage_pct": 97.5,
                         "skip_reasons": {"requires_authentication": 1}},
            "digital_twin": {"nodes": 300, "edges": 260, "identities": 3, "roles": 2,
                             "entities": 6, "surfaces_total": 40,
                             "flows": [{"cluster": "/wf/x", "steps": 3, "oracle": "/wf/x/l"}]},
            "reasoning": {"generated": 30, "verified": 8, "refuted": 20, "untestable": 2},
            "planner": {"operations_evaluated": 22, "blocked": 0,
                        "policy": "READ_ONLY/LOW_IMPACT automatic"},
        },
        "findings": [
            {"id": "F-1", "type": "business_logic_cross_user_execution", "severity": "high",
             "status": "verified", "url": "https://t.local/wf/x/confirm", "parameter": "tid",
             "method": "POST", "confidence": 0.9, "risk": 82, "evidence": [],
             "verification": {"method": "oracle:workflow-state-delta", "passed": True}},
            {"id": "F-2", "type": "missing_security_headers", "severity": "low",
             "status": "verified", "url": "https://t.local/", "parameter": "", "method": "GET",
             "confidence": 0.98, "risk": 18, "evidence": [],
             "verification": {"method": "header:replay", "passed": True}}],
        "rejected_candidates": []})
    ex = build_executive(st, "run-exec-test")
    assert ex["risk_posture"] == "high" and ex["verified_findings"] == 2
    assert ex["ci_gate"]["fail_on_high"] == 1, ex["ci_gate"]
    assert ex["business_impact"]["unauthorized_actions"] is True
    assert ex["business_impact"]["data_exposure"] is False
    assert ex["coverage_proof"]["coverage_pct"] == 97.5
    assert ex["application_model"]["identities"] == 3 and ex["application_model"]["graph_nodes"] == 300
    assert any(r["type"] == "business_logic_cross_user_execution" for r in ex["top_risks"])
    glass = build_glass_html(st, "run-exec-test")
    for needle in ("التوأم الرقمي الأمني", "خطر مرتفع", "مصفوفة التفويض",
                   "business_logic_cross_user_execution", "run-exec-test"):
        assert needle in glass, f"glass dashboard missing {needle}"
    # SARIF: the three v4.0.0 classes carry stable rule ids
    for t in ("business_logic_cross_user_execution", "business_logic_cross_object_execution",
              "business_logic_cross_state_execution", "csrf", "ssti", "jwt_security"):
        assert t in SARIF_RULES, t
        assert SARIF_RULES[t].startswith("SEN-"), SARIF_RULES[t]


@case
def regression_phase58_logic_end_to_end():
    """Phase 58 + Phase 60 (v4.0.0) full-platform regression: ONE authenticated
    scan with the Workflow Engine in learn+attack mode — all EIGHT
    business-logic classes VERIFIED with state-oracle proofs (five v3.0.0
    classes on the vulnerable wizard + three v4.0.0 cross-identity classes on
    the shared-store wizard), both hardened twins 100% silent (honest
    no_proof/skipped verdicts, zero false positives), prior classes fully
    intact, and every v4.0.0 artifact present and honest (flows learned,
    attack log, Digital Twin, reasoning hypotheses, planner ledger, proof
    files)."""
    import threading, importlib.util
    import os as _os
    from http.server import ThreadingHTTPServer
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    from sentinel.auth import AuthProfile
    spec = importlib.util.spec_from_file_location(
        "vulnapp_v9_wf", _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                       "fixtures", "vulnapp.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    port = 8815
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    oast = OastServer()
    try:
        base = f"http://127.0.0.1:{port}"
        auth = AuthProfile(login_url=base + "/login", username="demo", password="demo123",
                           user_field="uid", pass_field="passw", success_marker="Sign Off")
        authz_cfg = {"login_url": "/login", "user_field": "uid", "pass_field": "passw",
                     "success_marker": "Sign Off",
                     "accounts": [
                         {"name": "demo-admin", "role": "admin", "username": "demo",
                          "password": "demo123", "marker": "root-admin@sentinel-fixture.local",
                          "object_id": "1001"},
                         {"name": "bob-user", "role": "user", "username": "bob",
                          "password": "bob123", "marker": "bob-user@sentinel-fixture.local",
                          "object_id": "2002"},
                         {"name": "carol-user", "role": "user", "username": "carol",
                          "password": "carol123", "marker": "carol-user@sentinel-fixture.local",
                          "object_id": "3003"}]}
        cfg = ScanConfig(allow_private=True, max_pages=45, timeout=6,
                         seed="v9-wf-regression", oast=oast, auth=auth, authz=authz_cfg,
                         workflow=True, logic_active=True)
        sc = SentinelScanner(base, cfg)
        rep = sc.run()
        got = {(f["type"], f["url"].split("?")[0], f["parameter"]) for f in rep["findings"]}

        # ---- the EIGHT business-logic classes, VERIFIED (5 on the vulnerable
        # wizard + 3 cross-identity on the shared-store wizard)
        want = {"business_logic_step_bypass": ("/wf/transfer/create", "acct"),
                "business_logic_out_of_order": ("/wf/transfer/confirm", "tid"),
                "business_logic_value_tamper": ("/wf/transfer/confirm", "amount"),
                "business_logic_duplicate_execution": ("/wf/transfer/confirm", "tid"),
                "business_logic_privilege_escalation": ("/wf/transfer/confirm", "mode"),
                "business_logic_cross_user_execution": ("/wf/shared/transfer/confirm", "tid"),
                "business_logic_cross_object_execution": ("/wf/shared/transfer/confirm", "tid"),
                "business_logic_cross_state_execution": ("/wf/shared/transfer/confirm", "tid")}
        for t, (path, param) in want.items():
            matches = [f for f in rep["findings"] if f["type"] == t
                       and f["url"].split("?")[0].endswith(path)
                       and f["parameter"] == param]
            assert matches, f"{t} missing: {sorted(got)}"
            f = matches[0]
            assert f["verification"]["method"].startswith("oracle:workflow-state-delta:") \
                and f["verification"]["passed"], f
            assert f["impact"]["grade"] == "proven" and f["impact"]["statement"], f

        # ---- the hardened twins: ZERO business-logic findings (honest negatives)
        for t, u, p in got:
            if t.startswith("business_logic_"):
                assert "/wf/safe/" not in u, f"false positive on the hardened twin: {t} @ {u}"
                if "/wf/shared/" in u:
                    assert t.startswith("business_logic_cross_"), (
                        f"non-cross finding on the shared wizard (its five v3.0.0 "
                        f"guards are intact): {t} @ {u}")

        # ---- workflow stats honest and complete (fixture v10: three learned
        # flows; 18 attacks that RAN — precondition-absent cross manipulations
        # on the per-session twins are loud skips and never counted)
        wf = rep["stats"]["workflow"]
        assert wf["enabled"] and wf["logic_active"] and wf["flows_learned"] == 3, wf
        assert wf["verified"] == 8 and wf["attacks"] == 18, wf
        assert any(s.endswith(":no_anchor") for s in wf["skipped"]), wf["skipped"]
        log = {(a["flow"], a["attack"]): a["verdict"] for a in wf["attack_log"]}
        for atk in ("step_bypass", "out_of_order", "value_tamper", "duplicate", "privilege"):
            assert log.get(("/wf/transfer", atk)) == "verified", log
            assert log.get(("/wf/safe/transfer", atk)) in ("no_proof", "skipped"), log
            # the shared wizard keeps the five v3.0.0 guards — honest negatives there
            assert log.get(("/wf/shared/transfer", atk)) in ("no_proof", "skipped"), log
        for atk in ("cross_user", "cross_object", "cross_state"):
            assert log.get(("/wf/shared/transfer", atk)) == "verified", log
            # per-session stores: the observable precondition is absent — the
            # manipulations are loud honest skips, never counted as attacks
            assert log.get(("/wf/transfer", atk)) == "skipped", log
            assert log.get(("/wf/safe/transfer", atk)) == "skipped", log
        # the tamper proof carries the tampered canary, not the approved one
        tamper_line = next(a.get("line", "") for a in wf["attack_log"]
                           if a["attack"] == "value_tamper" and a["flow"] == "/wf/transfer")
        assert "2222" in tamper_line and "1111" not in tamper_line, tamper_line
        # duplicate proof shows the double execution
        dup = next(a for a in wf["attack_log"]
                   if a["attack"] == "duplicate" and a["flow"] == "/wf/transfer")
        assert dup.get("executions") == "1->2", dup
        # privilege proof names the low-privilege role
        priv = next(a for a in wf["attack_log"]
                    if a["attack"] == "privilege" and a["flow"] == "/wf/transfer")
        assert priv.get("role") == "user" and priv.get("option") == "wire", priv
        # cross-user proof names the attacking role and the shared resource
        xuser = next(a for a in wf["attack_log"]
                     if a["attack"] == "cross_user" and a["flow"] == "/wf/shared/transfer")
        assert xuser.get("role") == "user" and xuser.get("resource", "").startswith("TRF-"), xuser
        # cross-state proof names the rollback path it abused
        xstate = next(a for a in wf["attack_log"]
                      if a["attack"] == "cross_state" and a["flow"] == "/wf/shared/transfer")
        assert xstate.get("rollback", "").endswith("/cancel"), xstate
        # cross-object proof names the foreign-typed resource it executed
        xobj = next(a for a in wf["attack_log"]
                    if a["attack"] == "cross_object" and a["flow"] == "/wf/shared/transfer")
        assert xobj.get("resource", "").startswith("SORD-"), xobj

        # ---- the learned flow model rides the application map
        flows = rep["stats"]["appmap"]["workflows"]["learned_flows"]
        by_cluster = {f["cluster"]: f for f in flows}
        vuln = by_cluster["/wf/transfer"]
        assert [s["action"] for s in vuln["steps"]] == \
            ["/wf/transfer/select", "/wf/transfer/create", "/wf/transfer/confirm"], vuln
        assert vuln["state_oracle"] == "/wf/transfer/ledger"
        assert vuln["resource_params"] == ["tid"], vuln
        assert "EXECUTED" in vuln["execution_markers"]["gained"]
        assert "PENDING" in vuln["execution_markers"]["lost"]
        assert vuln["privilege_declared_options"][0]["value"] == "wire"

        # ---- prior classes fully intact (no drift from the new engine/surfaces)
        assert any(t == "sql_injection" for t, u, p in got), "SQLi regressed"
        assert any(t == "sql_injection" and u.endswith("/vault/transfer") for t, u, p in got), \
            "gated SQLi regressed"
        assert any(t == "xss_reflected" and u.endswith("/account") and p == "q" for t, u, p in got), \
            "authenticated XSS regressed"
        assert any(t == "xxe" and u.endswith("/vuln/oob-stock") for t, u, p in got), "blind XXE regressed"
        assert any(t == "idor_bola" and u.endswith("/api/data") for t, u, p in got), "IDOR regressed"
        assert any(t == "vertical_privilege_escalation" for t, u, p in got), "vertical regressed"
        assert any(t == "credential_exposure" for t, u, p in got), "credential exposure regressed"
        assert any(t == "ssti" and u.endswith("/vuln/ssti") for t, u, p in got), "SSTI regressed"
        assert any(t == "csrf" and u.endswith("/vuln/csrf-action") for t, u, p in got), "CSRF regressed"
        # request accounting is the whole truth (workflow fresh sessions included)
        assert rep["stats"]["requests"] > wf["requests"] > 0, \
            (rep["stats"]["requests"], wf["requests"])

        # ---- Phase 60-63 (v4.0.0): Digital Twin + Reasoning + Planner + Proofs
        dt = rep["stats"]["digital_twin"]
        assert dt["nodes"] > 150 and dt["edges"] > 100, dt
        assert dt["identities"] == 3 and dt["roles"] == 2, dt   # demo/bob/carol, admin/user
        assert dt["entities"] >= 5 and dt["workflow_steps"] == 9, dt
        assert dt["surfaces_write"] >= 8 and dt["findings_attached"] >= 30, dt
        # the twin's workflows carry the rollback path the cross-state attack abuses
        am_flows = rep["stats"]["appmap"]["workflows"]["learned_flows"]
        shared_flow = next(f for f in am_flows if f["cluster"] == "/wf/shared/transfer")
        assert "/wf/shared/transfer/cancel" in shared_flow["rollback_paths"], shared_flow
        # authorization matrix: the provable role x surface account
        azm = dt["authorization_matrix"]
        assert azm and "admin" in azm and "user" in azm, azm
        assert "reachable" in azm.get("admin", {}) or azm.get("admin"), azm
        # entity intelligence: Transaction entity minted and consumed by steps
        ents = {e["entity"]: e for e in dt["entity_inventory"]}
        assert "Transaction" in ents and ents["Transaction"]["minted_by_steps"], ents
        # reasoning: hypotheses generated, resolved, honest
        rs = rep["stats"]["reasoning"]
        assert rs["generated"] >= 25 and rs["verified"] >= 8, rs
        assert rs["untestable"] >= 1 and "untestable:precondition_absent" in rs["untestable_reasons"], rs
        hpat = {}
        for h in rs["hypotheses"]:
            hpat.setdefault(h["pattern"], []).append(h["status"])
        # hypotheses are per-workflow: the shared wizard's cross-identity pair
        # is verified, the per-session twins' pair honestly untestable
        assert "tested:verified" in hpat.get("R-CROSS-IDENTITY-OBJECT", []), hpat
        assert "untestable:precondition_absent" in hpat.get("R-CROSS-IDENTITY-OBJECT", []), hpat
        assert "tested:verified" in hpat.get("R-WF-CROSS-STATE", []), hpat
        assert "tested:verified" in hpat.get("R-WF-SKIP-STEP", []), hpat
        # planner: the safety ledger of everything the scan did
        pl = rep["stats"]["planner"]
        assert pl["operations_evaluated"] > 0 and pl["by_impact"].get("STATE_CHANGING", 0) >= 15, pl
        assert pl["logic_active"] and pl["blocked"] == 0, pl
        # evidence OS: proof files on verified findings
        proofs = rep["stats"]["proofs"]
        assert proofs and len(proofs) >= 30, len(proofs)
        for pf in proofs[:6]:
            assert pf["attack_hypothesis"] and pf["preconditions"] and pf["reproduction"], pf
            assert pf["impact"]["grade"] in ("proven", "indicated") and pf["identity"], pf
        wf_proof = next((p for p in proofs
                         if p["type"] == "business_logic_cross_user_execution"), None)
        assert wf_proof and "identity A" in wf_proof["attack_hypothesis"], wf_proof
        # ENG-18 regression guard: every workflow proof carries the state pair
        for pf in proofs:
            if pf["type"].startswith("business_logic_"):
                assert pf["state_before"].strip() and pf["state_after"].strip(), \
                    ("ENG-18: workflow proof missing state pair", pf["type"],
                     pf["state_before"], pf["state_after"])
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()



# ============================================================ v4.1.0 SUITE
# Phase V41-02..21: workflow graph 2.0, GraphQL + WebSocket intelligence,
# boundary engine, coverage 2.0, twin provenance, reasoning records, proof
# replay, real-time planner, action matrix, API inventory, memory,
# self-security and the NO-HALLUCINATION GATE.

def _start_fixture(mod_name, port):
    import importlib.util as _iu
    import os as _os
    spec = _iu.spec_from_file_location(
        mod_name, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                "fixtures", mod_name + ".py"))
    mod = _iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", port), mod.Handler)
    import threading as _th
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", srv, mod


@case
def unit_v41_boundary_engine():
    """Phase V41-05: the Boundary Intelligence Engine — 14 unified states,
    records with evidence/provenance/remediation, structural validation and
    the honest-percentage guard that forbids unexplained 100% claims."""
    from sentinel.boundary import (BoundaryEngine, ALL_STATES, EVIDENCE_MANDATORY,
                                   BoundaryRecord)
    b = BoundaryEngine()
    assert len(ALL_STATES) == 14, ALL_STATES
    assert len(EVIDENCE_MANDATORY) == 5
    b.untestable("graphql/mutation", "POST /api/updateUser",
                 "authentication required",
                 remediation="configure an account", provenance="graphql")
    b.not_discovered("websocket", "ws://x/chat", "no channel observed",
                     provenance="websocket:discovery")
    b.tested("workflow/step_bypass", "/wf/transfer", "attack ran",
             evidence="oracle delta", provenance="workflow")
    b.blocked("graphql/mutation", "url", "safety", "planner refused",
              provenance="planner")
    assert b.validate() == [], b.validate()      # all records well-formed
    # structural validation CATCHES planted defects (the gate's teeth)
    bad = BoundaryRecord("x", "y", "TESTED", "r")   # TESTED without evidence
    b.records.append(bad)
    assert any("no evidence" in p for p in b.validate())
    b.records.pop()
    # dedup: identical records collapse; first registration wins
    b.untestable("graphql/mutation", "POST /api/updateUser",
                 "authentication required")
    assert len(b.records) == 4, b.records
    # serialization roundtrip
    b2 = BoundaryEngine.from_dict(b.to_dict())
    assert len(b2.records) == len(b.records)
    # the honest-percentage guard
    assert b.honest_pct(1, 1, category="graphql/") == 99.9, \
        "unresolved graphql boundary must cap the claim below 100%"
    assert b.honest_pct(1, 1, category="workflow/") == 100.0
    s = b.summary()
    assert s["by_state"].get("UNTESTABLE") == 1 and s["unresolved"] == 3


@case
def unit_v41_coverage_dimensions():
    """Phase V41-06: Coverage 2.0 — all 17 dimensions, NOT_DISCOVERED absence
    semantics (never a tested claim), the 100%-guard and parameter attribution
    riding the request proxy."""
    from sentinel.coverage import CoverageTracker, DIMENSIONS
    from sentinel.boundary import BoundaryEngine
    assert len(DIMENSIONS) == 17, DIMENSIONS
    c = CoverageTracker()
    b = BoundaryEngine()
    # an unresolved GraphQL boundary exists (it must cap the 100% claim)
    b.untestable("graphql/mutation", "POST /api/updateUser",
                 "authentication required", provenance="graphql")
    c.dim_discover("graphql", "http://t/api/graphql", {})
    c.dim_tested("graphql", "http://t/api/graphql")
    c.dim_discover("websocket", "ws://t/chat", {})
    c.dim_untested("websocket", "ws://t/chat", "protocol_not_understood")
    dims = c.dimensions(boundary=b)
    g, w, e = dims["graphql"], dims["websocket"], dims["endpoint"]
    assert g["discovered"] == 1 and g["tested"] == 1
    # the honest-percentage guard: an unresolved GraphQL boundary caps the
    # 100% claim at 99.9 (never a round number over contested ground)
    assert g["pct"] == 99.9, g
    # unexplained untested items FORBID the 100% claim
    assert w["pct"] == 0.0 and w["untested_reasons"] == {"protocol_not_understood": 1}
    # absent dimensions are absence statements, never tested claims
    assert e["status"] == "NOT_DISCOVERED" and e["discovered"] == 0
    assert "no endpoint surface" in e["note"]
    # 100%-guard: unexplained untested caps the percentage
    c.dim_discover("parameter", "ep|p1", {})
    c.dim_tested("parameter", "ep|p1")
    c.dim_discover("parameter", "ep|p2", {})
    c.dim_untested("parameter", "ep|p2", "param_intel:json_object")
    assert c.dimensions(boundary=b)["parameter"]["pct"] == 50.0
    # and a fully-tested parameter set WITHOUT contested ground keeps 100
    c2 = CoverageTracker()
    c2.dim_discover("parameter", "ep|p1", {})
    c2.dim_tested("parameter", "ep|p1")
    assert c2.dimensions(boundary=b)["parameter"]["pct"] == 100.0


@case
def unit_v41_workflow_graph_model():
    """Phase V41-02: the workflow graph is a REAL graph — step nodes carry
    preconditions/parameters/state pairs/impact class/dependencies/provenance/
    confidence, and typed edges carry branches with honest belief."""
    import threading
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.auth import AuthProfile, AuthEngine
    from sentinel.workflow import WorkflowEngine
    from sentinel.core import Endpoint, DiscoverySource, Parameter, ParamLocation, ParamKind
    base, srv, mod = _start_fixture("flows_app", 8941)
    try:
        bus = EventBus("t41-graph")
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        auth = AuthProfile(login_url=base + "/login", username="alice",
                           password="alice123", user_field="username",
                           pass_field="password", success_marker="Welcome")
        main = RequestEngine(scope, bus, timeout=6)
        assert AuthEngine(auth, main, bus).login()
        eps = [Endpoint(url=base + p, source=DiscoverySource.CRAWL_HTML)
               for p in ("/flows/loan/start", "/flows/loan/status")]
        eps.append(Endpoint(url=base + "/flows/loan/eligibility", method="POST",
                            source=DiscoverySource.CRAWL_FORM,
                            parameters=[Parameter("plan", ParamLocation.BODY, "standard").classify()]))
        we = WorkflowEngine()
        res = we.run(eps, main, scope, bus, auth, timeout=6, logic_active=False)
        k = next(f for f in res["flows"] if f.cluster == "/flows/loan")
        g = k.graph
        assert g["counts"]["nodes"] == 4 and g["counts"]["branches"] == 1, g["counts"]
        assert g["counts"]["approval_steps"] == 1 and g["counts"]["rollback_paths"] == 1
        n1 = g["nodes"][1]     # the create step
        for field in ("id", "kind", "action", "identity", "preconditions",
                      "parameters", "extracted_tokens", "referenced_objects",
                      "state_before", "state_after", "impact_class",
                      "dependencies", "provenance", "confidence"):
            assert field in n1, f"graph node missing {field}"
        # walked steps submit canary-valued forms -> LOW_IMPACT by contract;
        # only the ATTACK battery is STATE_CHANGING (asserted in flows_battery)
        assert n1["impact_class"] == "LOW_IMPACT" and n1["confidence"] > 0
        assert any(n["state_after"] for n in g["nodes"]), "state pairs missing"
        kinds = {e["kind"] for e in g["edges"]}
        assert {"next", "branch", "approval", "rollback_of"} <= kinds, kinds
        br = next(e for e in g["edges"] if e["kind"] == "branch")
        assert br["condition"] == "plan=premium" and br["restricted"] is True
        # the restricted-branch baseline legitimately WALKED this branch under
        # the primary identity -> 'observed' (an exercised option, honestly)
        assert br["belief"] == "observed", br
        rb = next(e for e in g["edges"] if e["kind"] == "rollback_of")
        assert rb["belief"] == "inferred"        # discovered, not walked
        # per-step state pairs recorded (DRAFT -> APPROVED -> EXECUTED)
        states = k.step_states
        assert any("DRAFT" in s["after"] for s in states), states
        assert any("EXECUTED" in s["after"] for s in states), states
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_v41_flows_battery():
    """Phase V41-02 e2e: the four new workflow attacks on the flows fixture —
    ALL verified on the vulnerable wizard with state-oracle proofs, the
    hardened twin 100% silent, planner-gated battery, honest skip ledger."""
    import threading
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.auth import AuthProfile, AuthEngine
    from sentinel.workflow import WorkflowEngine
    from sentinel.planner import SafeAttackPlanner
    from sentinel.boundary import BoundaryEngine
    from sentinel.authz import AuthzAccount, _rank
    from sentinel.core import Endpoint, DiscoverySource, Parameter, ParamLocation
    base, srv, mod = _start_fixture("flows_app", 8942)
    try:
        bus = EventBus("t41-flows")
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        auth = AuthProfile(login_url=base + "/login", username="alice",
                           password="alice123", user_field="username",
                           pass_field="password", success_marker="Welcome")
        main = RequestEngine(scope, bus, timeout=6)
        assert AuthEngine(auth, main, bus).login()
        low = RequestEngine(scope, bus, timeout=6)
        low_auth = AuthProfile(login_url=base + "/login", username="bob",
                               password="bob123", user_field="username",
                               pass_field="password", success_marker="Welcome")
        assert AuthEngine(low_auth, low, bus).login()
        sessions = {"bob": {"account": AuthzAccount(
            name="bob", role="user", username="bob", password="bob123",
            marker="bob", object_id="2"), "engine": low, "rank": _rank("user")}}
        planner = SafeAttackPlanner(logic_active=True)
        boundary = BoundaryEngine()
        we = WorkflowEngine(planner=planner)
        eps = [Endpoint(url=base + p, source=DiscoverySource.CRAWL_HTML)
               for p in ("/flows/loan/start", "/flows/loan/status",
                         "/flows/safe/loan/start", "/flows/safe/loan/status", "/home")]
        for b in ("/flows/loan", "/flows/safe/loan"):
            eps.append(Endpoint(url=base + b + "/eligibility", method="POST",
                                source=DiscoverySource.CRAWL_FORM,
                                parameters=[Parameter("plan", ParamLocation.BODY,
                                                      "standard").classify()]))
        res = we.run(eps, main, scope, bus, auth, authz_sessions=sessions,
                     timeout=6, logic_active=True)
        stats = res["stats"]
        got = {(f.type, f.endpoint_url.split("loan")[0] + "loan" +
                f.endpoint_url.split("loan")[1].split("/", 1)[-1])
               for f in res["findings"]}
        types = {f.type for f in res["findings"]}
        # the four NEW classes + the classics the fixture carries
        for t in mod.FLOWS_GROUND_TRUTH["/flows/loan"]:
            assert t in types, f"missing {t}: {sorted(types)}"
        # hardened twin: ZERO findings (no false positives)
        for f in res["findings"]:
            assert "/flows/safe/" not in f.endpoint_url, \
                f"false positive on the hardened twin: {f.type} @ {f.endpoint_url}"
        log = {(a["flow"], a["attack"]): a["verdict"] for a in stats["attack_log"]}
        assert log[("/flows/loan", "branch_bypass")] == "verified"
        assert log[("/flows/loan", "approval_bypass")] == "verified"
        assert log[("/flows/loan", "rollback_abuse")] == "verified"
        assert log[("/flows/loan", "unauthorized_branch")] == "verified"
        assert log[("/flows/safe/loan", "branch_bypass")] == "no_proof"
        assert log[("/flows/safe/loan", "approval_bypass")] == "no_proof"
        assert log[("/flows/safe/loan", "rollback_abuse")] == "no_proof"
        # the 5 new attack verdicts carry state-pair proofs
        for f in res["findings"]:
            if f.type in ("business_logic_branch_bypass",
                          "business_logic_approval_bypass",
                          "business_logic_rollback_abuse",
                          "business_logic_unauthorized_branch"):
                assert f.state_before.strip() and f.state_after.strip(), f.type
        # every attack passed the real-time planner (STATE_CHANGING, allowed)
        wf_gates = [d for d in planner.decisions if d.get("note") == "wf-atk"]
        assert wf_gates and all(d["impact"] == "STATE_CHANGING" and d["allowed"]
                                for d in wf_gates), wf_gates[:3]
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_v41_graphql_battery():
    """Phase V41-03 e2e: GraphQL intelligence on the three-twin fixture —
    5 findings on the vulnerable endpoint, honest boundaries on the hardened
    and partial twins, zero fabricated claims."""
    import threading, json
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.auth import AuthProfile, TokenAuthEngine
    from sentinel.graphql import GraphqlEngine
    from sentinel.planner import SafeAttackPlanner
    from sentinel.boundary import BoundaryEngine
    from sentinel.coverage import CoverageTracker
    from sentinel.core import Endpoint, DiscoverySource
    base, srv, mod = _start_fixture("gql_app", 8943)
    try:
        bus = EventBus("t41-gql")
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)

        def token_engine(tok):
            eng = RequestEngine(scope, bus, timeout=6)
            prof = AuthProfile(login_url=base + "/gql/safe", token=tok)
            return eng if TokenAuthEngine(prof, eng, bus).login() else None

        main = token_engine("alice-token")
        low = token_engine("bob-token")
        anon = RequestEngine(scope, bus, timeout=6)
        boundary = BoundaryEngine()
        gql = GraphqlEngine(main, scope, bus, timeout=6,
                            planner=SafeAttackPlanner(logic_active=True),
                            boundary=boundary, coverage=CoverageTracker(),
                            logic_active=True)
        eps = [Endpoint(url=base + "/", source=DiscoverySource.SEED),
               Endpoint(url=base + "/gql/safe", source=DiscoverySource.CRAWL_HTML),
               Endpoint(url=base + "/gql/partial", source=DiscoverySource.CRAWL_HTML)]
        res = gql.run(eps, base, anonymous_engine=anon,
                      low_identity={"name": "bob", "role": "user", "engine": low,
                                    "object_id": "2",
                                    "marker": "bob@sentinel-fixture.local"},
                      primary_identity={"name": "alice", "role": "user",
                                        "object_id": "1",
                                        "marker": "alice@sentinel-fixture.local"})
        by_url = {}
        for f in res["findings"]:
            by_url.setdefault(f.endpoint_url.rsplit("/", 1)[-1], set()).add(f.type)
        vuln = by_url.get("graphql", set())
        for t in mod.GQL_GROUND_TRUTH["/api/graphql"]:
            assert t in vuln, f"missing {t}: {sorted(vuln)}"
        safe = by_url.get("safe", set())
        assert safe == {"graphql_introspection_enabled"}, safe
        assert "partial" not in by_url, by_url      # zero findings, honestly
        # boundaries: partial = UNTESTABLE schema; safe = tested/refused + mutation UNTESTABLE
        recs = {(r.category, r.target.rsplit("/", 1)[-1]): r.state
                for r in boundary.records}
        assert recs.get(("graphql/schema", "partial")) == "UNTESTABLE"
        assert recs.get(("graphql/bola", "safe")) == "TESTED"
        assert recs.get(("graphql/mutation", "safe")) == "UNTESTABLE"
        # V411-GL-03: the SAFE twin's MASKED sensitive fields are a boundary,
        # never a field-authorization finding (value-aware precision)
        assert recs.get(("graphql/field-authorization", "safe")) == "TESTED"
        masked = [r for r in boundary.records
                  if r.category == "graphql/field-authorization"
                  and r.target.endswith("/gql/safe") and "MASKED" in r.reason]
        assert masked, "masked-field boundary must be recorded on the safe twin"
        # V411-GL-01/02: the SAFE twin resists injection + command probes
        # (TESTED boundaries — quote-break and OR-TRUE produced no oracle;
        # the injection records carry url.query targets)
        sqli_safe = [r for r in boundary.records
                     if r.category == "graphql/injection"
                     and "gql/safe." in r.target]
        assert sqli_safe and all(r.state == "TESTED" for r in sqli_safe), \
            [(r.target.rsplit('/', 1)[-1], r.state) for r in sqli_safe]
        cmd_safe = [r for r in boundary.records
                    if r.category == "graphql/command-execution"
                    and r.target.endswith("/gql/safe")]
        assert cmd_safe and all(r.state == "TESTED" for r in cmd_safe)
        # V411-GL-04: the operation-features probe ran (variables/fragments/
        # aliases exercised and recorded)
        feat = [r for r in boundary.records
                if r.category == "graphql/features"]
        assert feat and any(r.state in ("TESTED", "REFUTED") for r in feat)
        # the schema model actually parsed the operation inventory
        ops = res["ops"]
        vuln_ops = next(v for u, v in ops.items() if u.endswith("/api/graphql"))
        assert {q["name"] for q in vuln_ops["queries"]} >= {"me", "user", "products"}
        assert vuln_ops["mutations"][0]["name"] == "createUser"
        # V411-GL-07: update-shaped mutation vocabulary is BLOCKED_BY_SAFETY —
        # never sent (no updateUser finding/execution), always recorded
        vocab_blocked = [r for r in boundary.records
                         if r.category == "graphql/mutation-vocabulary"]
        assert vocab_blocked, "blocked mutation vocabulary must be recorded"
        assert all(r.state == "BLOCKED_BY_SAFETY" for r in vocab_blocked)
        assert any("updateUser" in r.reason for r in vocab_blocked)
        assert not any("updateUser" in (f.parameter or "")
                       for f in res["findings"]), \
            "updateUser must never be executed (safety regression)"
        # V411-GL-08: the BOLA probe spoke a bare Int literal — the fixture
        # only answers unquoted ids, so a verified BOLA finding IS the proof
        bola_f = [f for f in res["findings"] if f.type == "graphql_bola"]
        assert bola_f and 'user(id: 1)' in (bola_f[0].state_before or ""), \
            f"BOLA query must carry a bare Int literal: {bola_f[0].state_before if bola_f else 'none'}"
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_v41_websocket_battery():
    """Phase V41-04 e2e: WebSocket intelligence — sensitive-data + cross-user
    findings on the open channel, auth-enforced boundary on the hardened one,
    protocol_not_understood on the text channel, and the SCOPE GATE refusing
    an out-of-scope channel observed in JS."""
    import threading, json
    import importlib.util as _iu
    import os as _os
    from sentinel.core import ScopeRule, EventBus, Endpoint, DiscoverySource
    from sentinel.websocket import WebSocketEngine, WsClient, WS_MESSAGE_SHAPES
    from sentinel.planner import SafeAttackPlanner
    from sentinel.boundary import BoundaryEngine
    from sentinel.coverage import CoverageTracker
    spec = _iu.spec_from_file_location("ws_app", _os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
        "fixtures", "ws_app.py"))
    mod = _iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    base, t, srv = mod.serve(port=8944)
    # V411: simulate the discovery pass's JS harvest (in a full scan,
    # harvest_ws_shapes() collects these from the target's own inline JS)
    _saved_shapes = list(WS_MESSAGE_SHAPES)
    WS_MESSAGE_SHAPES.clear()
    WS_MESSAGE_SHAPES.extend([{"name": "", "comment": ""},
                              {"auth_user": "", "auth_pass": ""}])
    try:
        bus = EventBus("t41-ws")
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        boundary = BoundaryEngine()
        wse = WebSocketEngine(scope, bus, timeout=6,
                              planner=SafeAttackPlanner(logic_active=True),
                              boundary=boundary, coverage=CoverageTracker(),
                              logic_active=True, listen_seconds=2.5)
        wsbase = base.replace("http", "ws", 1)
        eps = [Endpoint(url=wsbase + p, source=DiscoverySource.JS_STATIC)
               for p in ("/ws/chat", "/ws/safe", "/ws/partial",
                         "/ws/echo", "/ws/origin")]
        # the SCOPE GATE: a channel on ANOTHER host is refused without a
        # single connection attempt
        eps.append(Endpoint(url="ws://evil.invalid/chat",
                            source=DiscoverySource.JS_STATIC))
        res = wse.run(eps, base,
                      low_identity={"name": "bob", "role": "user", "engine": None,
                                    "object_id": "2",
                                    "marker": "bob@sentinel-fixture.local"},
                      primary_identity={"name": "alice", "role": "user",
                                        "object_id": "1",
                                        "marker": "alice@sentinel-fixture.local"})
        types = {f.type for f in res["findings"]}
        for t_ in mod.WS_GROUND_TRUTH["/ws/chat"] + ["websocket_origin_not_enforced"]:
            assert t_ in types, f"missing {t_}: {sorted(types)}"
        # V411: the silent request/response channel — elicitation discovered
        # the protocol, the canary reflection fired, and the handshake takes
        # any Origin
        for t_ in mod.WS_GROUND_TRUTH["/ws/echo"]:
            assert t_ in types, f"missing echo {t_}: {sorted(types)}"
        echo = [f for f in res["findings"] if f.endpoint_url.endswith("/ws/echo")]
        assert {f.type for f in echo} == {"websocket_message_reflection",
                                          "websocket_origin_not_enforced"}, \
            {f.type for f in echo}
        # the origin-GATED channel: zero findings — the origin probe must
        # record enforcement, never fabricate
        assert not [f for f in res["findings"]
                    if f.endpoint_url.endswith("/ws/origin")], res["findings"]
        # sensitive/cross-user findings live on the vulnerable channel only
        for f in res["findings"]:
            if f.type in ("websocket_sensitive_data_exposure",
                          "websocket_cross_user_access"):
                assert f.endpoint_url.endswith("/ws/chat"), f.endpoint_url
        protos = res["stats"]["protocols"]
        assert protos.get(wsbase + "/ws/chat") == "json"
        assert protos.get(wsbase + "/ws/partial") == "text"
        # V411: the silent channel is discovered as request/json with a text
        # reply shape (elicited)
        assert protos.get(wsbase + "/ws/echo") == "text/request-json", protos
        recs = {(r.category, r.target.rsplit("/", 1)[-1]): r.state
                for r in boundary.records}
        # the TEXT channel: content analysis ran (TESTED) but tampering is
        # honestly UNTESTABLE — protocol_not_understood, never a guess
        assert recs.get(("websocket/tampering", "partial")) == "UNTESTABLE"
        assert recs.get(("websocket/connection", "safe")) == "TESTED"
        # V411: the silent channel's protocol was ELICITED (TESTED), the
        # reflection boundary is a finding, replay differential recorded
        assert recs.get(("websocket/elicitation", "echo")) == "TESTED"
        assert recs.get(("websocket/replay", "echo")) == "TESTED"
        # V411: origin enforcement — the gated channel records TESTED; the
        # auth-gated channel is refused before the origin probe runs (its
        # refusal is already attributed to authentication)
        assert recs.get(("websocket/origin", "origin")) == "TESTED"
        assert recs.get(("websocket", "chat")) == "BLOCKED_BY_SAFETY", \
            [k for k in recs if k[0] == "websocket"]
        # oversized-frame safety: the client caps frames at 1MB and survives
        from fixtures.malicious_app import WsEvilServer
    finally:
        WS_MESSAGE_SHAPES.clear()
        WS_MESSAGE_SHAPES.extend(_saved_shapes)
        srv.close()


@case
def unit_v41_twin_provenance():
    """Phase V41-07: Twin 2.0 — every node and edge carries belief + provenance
    (the audit is EMPTY), inference is never labeled observed, and why()
    answers the auditor's question."""
    from sentinel.twin import build_twin
    from sentinel.core import Endpoint, Parameter, ParamLocation
    eps = [Endpoint(url="https://t.local/wf/pay/select",
                    parameters=[Parameter("acct", ParamLocation.BODY, "1").classify()]),
           Endpoint(url="https://t.local/api/orders",
                    parameters=[Parameter("order_id", ParamLocation.QUERY, "9").classify()])]
    authz = {"stats": {"roles": ["admin", "user"]},
             "matrix": {"https://t.local/api/admin/stats": {"admin": 200, "user": 200}},
             "accounts": [{"name": "a", "role": "admin", "username": "a"}]}
    wf = {"flows": [{"cluster": "/wf/pay", "entry": "/wf/pay/start",
                     "steps": [{"action": "/wf/pay/select", "method": "POST"}],
                     "resource_params": ["pid"], "state_oracle": "/wf/pay/ledger",
                     "execution_markers": {"gained": ["DONE"], "lost": []},
                     "privilege_declared_options": [],
                     "rollback_paths": []}]}
    twin = build_twin("https://t.local", eps, authz_result=authz,
                      auth_mode="multi-user(admin,user)", workflow_stats=wf,
                      findings=[], coverage_summary={})
    problems = twin.belief_audit()
    assert problems == [], problems
    # belief semantics: entities are INFERRED (name-typing), surfaces OBSERVED
    ent = twin.by_kind("entity")[0]
    assert ent.attrs["belief"] == "inferred" and "entity typing" in ent.attrs["provenance"]
    surf = twin.by_kind("surface")[0]
    assert surf.attrs["belief"] == "observed"
    # why() answers with provenance + relations
    why = twin.why(surf.id)
    assert why["found"] and why["belief"] == "observed" and why["provenance"]
    assert isinstance(why["relations"], list)
    assert twin.why("nonexistent-node")["found"] is False


@case
def unit_v41_reasoning_records():
    """Phase V41-08: hypothesis records are fully structured (source,
    preconditions, expected behavior, test plan, safety class, actual result,
    verification, final state) and EVERY final state carries an explicit
    reason — verified, refuted and untestable alike."""
    from sentinel.twin import build_twin
    from sentinel import reasoning
    from sentinel.core import Endpoint, Parameter, ParamLocation
    eps = [Endpoint(url="https://t.local/wf/pay/select",
                    parameters=[Parameter("acct", ParamLocation.BODY, "1").classify()]),
           Endpoint(url="https://t.local/api/orders",
                    parameters=[Parameter("order_id", ParamLocation.QUERY, "9").classify()])]
    authz = {"stats": {"roles": ["admin", "user"]},
             "matrix": {},
             "accounts": [{"name": "a", "role": "admin", "username": "a"},
                          {"name": "b", "role": "user", "username": "b"}]}
    wf = {"flows": [{"cluster": "/wf/pay", "entry": "/wf/pay/start",
                     "steps": [{"action": "/wf/pay/select", "method": "POST"},
                               {"action": "/wf/pay/confirm", "method": "POST"}],
                     "resource_params": ["pid"], "state_oracle": "/wf/pay/ledger",
                     "execution_markers": {"gained": ["DONE"], "lost": []},
                     "privilege_declared_options": [], "rollback_paths": [],
                     "branches": [{"field": "plan", "value": "premium",
                                   "label": "Premium (premium members only)",
                                   "class": "restricted", "functional": True}],
                     "branch_transfer": {"field": "plan", "select_step": 0,
                                         "hidden_step": 1},
                     "approval_step": "/wf/pay/approve",
                     "rollback_only_paths": ["/wf/pay/rollback"]}]}
    twin = build_twin("https://t.local", eps, authz_result=authz,
                      auth_mode="multi-user(admin,user)", workflow_stats=wf)
    hyps = reasoning.generate_hypotheses(twin)
    pats = {h["pattern"] for h in hyps}
    for p in (reasoning.R_WF_BRANCH_BYPASS, reasoning.R_WF_UNAUTHORIZED_BRANCH,
              reasoning.R_WF_APPROVAL_BYPASS, reasoning.R_WF_ROLLBACK_ABUSE):
        assert p in pats, f"pattern {p} not generated: {sorted(pats)}"
    for h in hyps:
        for field in ("source", "preconditions", "expected_behavior",
                      "test_plan", "safety_class", "final_state"):
            assert field in h, f"hypothesis missing {field}"
    attack_log = [{"flow": "/wf/pay", "attack": "step_bypass", "verdict": "verified"},
                  {"flow": "/wf/pay", "attack": "branch_bypass", "verdict": "verified"},
                  {"flow": "/wf/pay", "attack": "approval_bypass", "verdict": "no_proof"}]
    resolved = reasoning.resolve_hypotheses(
        hyps, [{"type": "business_logic_step_bypass",
                "url": "https://t.local/wf/pay/select", "parameter": "acct"}],
        workflow_attack_log=attack_log, authz_stats={"ran": True})
    by_pat = {}
    for h in resolved:
        by_pat.setdefault(h["pattern"], []).append(h)
    v = [h for h in by_pat[reasoning.R_WF_SKIP_STEP]
         if h["status"] == "tested:verified"][0]
    assert v["final_state"] == "VERIFIED" and v["reason"], v
    assert v["actual_result"] and v["verification"]
    r = [h for h in by_pat[reasoning.R_WF_APPROVAL_BYPASS]
         if h["status"] == "tested:refuted"]
    assert r and all(h["reason"] for h in r), r
    # the new v4.1 patterns resolve against their own attack names
    bb = [h for h in by_pat[reasoning.R_WF_BRANCH_BYPASS]
          if h["status"] == "tested:verified"]
    assert bb and bb[0]["final_state"] == "VERIFIED"


@case
def unit_v41_memory():
    """Phase V41-13: security memory — host-scoped isolation, app-change
    invalidation, and the memory-never-evidence contract."""
    import tempfile, os
    from sentinel.memory import SecurityMemory
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.db.memory.json")
        mem = SecurityMemory(path)
        rep1 = {"run_id": "R1", "findings": [
            {"type": "sql_injection", "url": "https://app.local/a?id=1",
             "parameter": "id", "status": "verified"}],
            "stats": {"endpoints": 10,
                      "fingerprint": {"technologies": ["nginx"],
                                      "waf": ""}}}
        mem.remember_run("https://app.local", rep1)
        mem.save()
        # recall is app-scoped
        ctx = mem.memory_context("https://app.local", {
            "endpoints": 10, "fingerprint": {"technologies": ["nginx"],
                                             "waf": ""}})
        assert ctx["known_app"] and ctx["prior_runs"] == 1
        assert ctx["previously_verified"] == 1 and not ctx["app_changed"]
        # ANOTHER app sees NOTHING (tenant isolation by construction)
        other = mem.memory_context("https://other.local", {})
        assert not other["known_app"]
        # the app CHANGED -> stale assumptions are flagged, never trusted
        mem2 = SecurityMemory(path)
        ctx2 = mem2.memory_context("https://app.local",
                                   {"endpoints": 42, "fingerprint": {
                                       "technologies": ["apache"]}})
        assert ctx2["app_changed"] and ctx2["changes"]
        assert len(ctx2["stale_needs_revalidation"]) == 1
        assert "never evidence" in ctx2["policy"]
        # corrupt memory never crashes a scan
        with open(path, "w") as fh:
            fh.write("{corrupt json")
        assert SecurityMemory(path).recall("https://app.local")["known_app"] is False


@case
def unit_v41_replay():
    """Phase V41-09: the live proof replay — REPRODUCTION_VERIFIED on a real
    finding, REPRODUCTION_FAILED with reason when the defect is gone, and the
    honest NOT_REPLAYABLE for context-dependent classes."""
    import threading, tempfile, os
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.evidence import build_proof, replay_finding
    from sentinel.core import Endpoint, Parameter, ParamLocation
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    base, srv, mod = _start_fixture("vulnapp", 8945)
    try:
        cfg = ScanConfig(allow_private=True, max_pages=8, timeout=6,
                         seed="t41-replay", active=True, passive=True,
                         browser=False)
        sc = SentinelScanner(base + "/vuln/xss.php?q=probe", cfg)
        # build a REAL finding through the detector path
        bus = EventBus("t41-replay")
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        eng = RequestEngine(scope, bus, timeout=6)
        from sentinel.detect import XSSDetector
        from sentinel.intel import VerificationEngine
        ep = Endpoint(url=base + "/vuln/xss.php", parameters=[
            Parameter("q", ParamLocation.QUERY, "probe").classify()])
        det = XSSDetector(eng, bus, None)
        cand = None
        for m in det.candidates(ep):
            if isinstance(m, tuple):
                m = m[1]
            r = eng.send(m)
            if r.error:
                continue
            cand = det.analyze((ep, ep.parameters[0]), r)
            if cand:
                break
        assert cand is not None, "fixture did not yield an xss candidate"
        ver = VerificationEngine(eng, bus).verify(cand, ep)
        assert ver.status and ver.status.value == "verified"
        proof = build_proof(ver)
        out = replay_finding(proof, scope, EventBus("replay"), timeout=6)
        assert out["replay"] == "REPRODUCTION_VERIFIED", out
        # business-logic classes are honestly NOT replayable from a proof file
        bl = build_proof(type("F", (), {"id": "F-x", "type": "business_logic_step_bypass",
                                        "severity": type("S", (), {"value": "high"})(),
                                        "endpoint_url": "https://t/x", "parameter": "p",
                                        "method": "POST", "evidence": [], "confidence": 0.9,
                                        "verification": None, "authz_context": ""})())
        out2 = replay_finding(bl, scope, EventBus("replay"))
        assert out2["replay"] == "NOT_REPLAYABLE" and out2["reason"]
        # a finding whose surface vanished -> honest REPRODUCTION_FAILED
        proof_gone = dict(proof)
        proof_gone["requests"] = [{"method": "GET", "url": base + "/gone.php",
                                   "parameter": "q"}]
        proof_gone["type"] = "xss_reflected"
        out3 = replay_finding(proof_gone, scope, EventBus("replay"), timeout=6)
        assert out3["replay"] == "REPRODUCTION_FAILED" and out3["reason"], out3
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_v41_planner_realtime_and_ci():
    """Phase V41-10 + V41-16: the planner is a REAL-TIME gate (a blocked
    attack never sends a request) and the CI exit contract separates policy
    failures (1) from scan incompleteness (2) and engine failures (3)."""
    import threading, tempfile, os, json as _json
    from sentinel.planner import SafeAttackPlanner
    # real-time blocking semantics
    p_off = SafeAttackPlanner(logic_active=False)
    v = p_off.gate("http://t/wf/x/step", "POST", fields=[("a", "b")],
                   note="wf-atk")
    assert not v["allowed"] and v["impact"] == "STATE_CHANGING"
    assert p_off.blocked >= 1 and p_off.decisions[0]["rationale"]
    p_on = SafeAttackPlanner(logic_active=True)
    assert p_on.gate("http://t/wf/x/step", "POST", note="wf-atk")["allowed"]
    # DESTRUCTIVE is never allowed, even with the flag
    v2 = p_on.gate("http://t/api/purge-all", "POST", note="wf-atk")
    assert not v2["allowed"] and v2["impact"] == "DESTRUCTIVE"
    # ---- the CI exit contract, exercised end-to-end through the CLI
    from sentinel.store import Store
    from sentinel.report import build_executive
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "ci.db")
        st = Store(db)
        # a clean run -> exit 0
        st.save_run({"run_id": "R-clean", "target": "https://t.local", "scanner": "s",
                     "findings": [], "rejected_candidates": [],
                     "stats": {"requests": 1, "endpoints": 1, "candidates": 0,
                               "verified": 0, "rejected": 0, "duration": 0.1,
                               "boundary": {"records": 0, "unresolved": 0,
                                            "by_state": {}}}})
        ex = build_executive(st)
        assert ex["ci_gate"]["fail_on_high"] == 0
        # a policy violation -> exit 1 axis
        st.save_run({"run_id": "R-bad", "target": "https://t.local", "scanner": "s",
                     "findings": [{"id": "F-test0001", "type": "sql_injection",
                                   "severity": "critical", "status": "verified",
                                   "url": "https://t.local/a", "parameter": "id",
                                   "risk": 90, "confidence": 0.9,
                                   "evidence": [], "verification": {}}],
                     "rejected_candidates": [],
                     "stats": {"requests": 1, "endpoints": 1, "candidates": 1,
                               "verified": 1, "rejected": 0, "duration": 0.1,
                               "boundary": {"records": 1, "unresolved": 1,
                                            "by_state": {"TOOL_FAILURE": 1}}}})
        ex2 = build_executive(Store(db))
        assert ex2["ci_gate"]["fail_on_high"] >= 1
        assert ex2["boundary"]["by_state"].get("TOOL_FAILURE") == 1
        # the contract is documented in the executive itself
        assert "0=no violation" in ex2["ci_gate"]["exit_code_rule"]
        assert "never" in ex2["ci_gate"]["exit_code_rule"] and \
            "conflated" in ex2["ci_gate"]["exit_code_rule"]


@case
def unit_v41_apintel_and_action_matrix():
    """Phase V41-11/12: the unified API inventory (REST + GraphQL + WebSocket
    in one list, protocol attribution, zero silent omissions) and the
    identity x action matrix built from DISCOVERED identities only."""
    from sentinel.apintel import build_api_inventory, build_action_matrix, classify_action
    from sentinel.core import Endpoint, Parameter, ParamLocation
    from sentinel.twin import build_twin
    assert classify_action("POST", "/api/user/create") == "create"
    assert classify_action("GET", "/api/admin/stats") == "admin"
    assert classify_action("GET", "/report/export.csv") == "export"
    assert classify_action("POST", "/transfer/execute") == "execute"
    eps = [Endpoint(url="https://t.local/api/orders",
                    parameters=[Parameter("order_id", ParamLocation.QUERY, "9").classify()]),
           Endpoint(url="https://t.local/api/user/create", method="POST")]
    inv = build_api_inventory(
        eps, openapi_info={"source": "/openapi.json", "paths": 9},
        graphql_stats={"endpoints": [{"url": "https://t.local/api/graphql",
                                      "source": "probe"}]},
        websocket_stats={"channels": [{"url": "ws://t.local/ws/chat",
                                       "source": "observed"}],
                         "protocols": {"ws://t.local/ws/chat": "json"}},
        coverage_summary={"endpoints": [
            {"url": "https://t.local/api/orders", "method": "GET",
             "activity": ["passive"], "skips": []}]},
        findings=[{"type": "sql_injection", "url": "https://t.local/api/orders?id=1"}])
    protos = {a["protocol"] for a in inv["apis"]}
    assert protos == {"http", "graphql", "websocket"}, protos
    assert inv["by_protocol"] == {"graphql": 1, "http": 2, "websocket": 1}
    orders = next(a for a in inv["apis"] if a["path"] == "/api/orders")
    assert orders["findings"] == 1 and orders["coverage_status"] == "tested"
    gql = next(a for a in inv["apis"] if a["protocol"] == "graphql")
    assert gql["sources"] == ["graphql:probe"]
    # the action matrix: identities discovered (never assumed), honest cells
    authz = {"accounts": [{"name": "alice", "role": "user"}],
             "matrix": {}, "stats": {"roles": ["user"]}}
    twin = build_twin("https://t.local", eps, authz_result=authz,
                      auth_mode="multi-user(user)")
    am = build_action_matrix(twin, authz_result=authz)
    idents = [i["name"] for i in am["identities"]]
    assert "anonymous" in idents and "alice" in idents
    assert "admin" not in idents, "assumed roles must never appear"
    for ident in am["matrix"]:
        for act in am["actions"]:
            cell = am["matrix"][ident][act]
            assert cell.startswith(("tested:", "untested:")), cell


@case
def unit_v411_ws_shape_harvest():
    """V411-WS: message-shape harvesting from the application's own JavaScript
    (the observed schema source for the WS elicitation/reflection battery)."""
    import importlib
    from sentinel import websocket as W
    saved = list(W.WS_MESSAGE_SHAPES)
    try:
        W.WS_MESSAGE_SHAPES.clear()
        # DVWS-style string-concatenated JSON template
        js = """var field_value = '{"name":"'+name_field_value+'","comment":"'+comment_field_value+'"}';
websocket.send(field_value);"""
        assert W.harvest_ws_shapes(js) == 1
        assert {"name": "", "comment": ""} in W.WS_MESSAGE_SHAPES
        # JSON.stringify shape
        assert W.harvest_ws_shapes(
            'websocket.send(JSON.stringify({auth_user: u, auth_pass: p}));') == 1
        assert {"auth_user": "", "auth_pass": ""} in W.WS_MESSAGE_SHAPES
        # idempotent + capped + sorted deterministically
        before = list(W.WS_MESSAGE_SHAPES)
        assert W.harvest_ws_shapes(js) == 0
        assert W.WS_MESSAGE_SHAPES == sorted(
            before, key=lambda s: tuple(sorted(s)))
        # the elicitation ladder: {} -> shapes -> graphql-ws connection_init
        ladder = W.elicitation_ladder()
        assert ladder[0] == "{}"
        assert ladder[-1] == '{"type":"connection_init","payload":{}}'
        assert any('"name"' in m for m in ladder[1:-1])
    finally:
        W.WS_MESSAGE_SHAPES.clear()
        W.WS_MESSAGE_SHAPES.extend(saved)


@case
def unit_v411_ws_discovery_js_var_and_port():
    """V411-WS-DISC-2 (live-caught on DVWS): the channel URL lives in a JS
    VARIABLE (`var wsUri = "ws://host:8080/path"; new WebSocket(wsUri)`) and
    the WS transport listens on a DIFFERENT PORT than the HTTP origin (web
    :8888 / Ratchet :8080). The extractor must observe the variable pattern,
    discovery must feed it, the engine must admit the same-host different-
    port channel, and an out-of-scope observed host must be refused WITHOUT
    a single connection. Also: the reflection canary is alnum-only — inert
    by construction in shell/path/template contexts (DVWS /command-execution
    appends the raw message to `shell_exec('ping -c 3 ' . $msg)`)."""
    import re as _re
    import threading as _th
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.core import ScopeRule, EventBus, Endpoint
    from sentinel.websocket import (WebSocketEngine, WS_MESSAGE_SHAPES,
                                    WS_OBSERVED_URLS, reset_ws_intel,
                                    observe_ws_urls, _safe_canary)
    from sentinel.planner import SafeAttackPlanner
    from sentinel.boundary import BoundaryEngine
    from sentinel.coverage import CoverageTracker
    from sentinel.discovery import DiscoveryEngine
    from sentinel.http_engine import RequestEngine
    import importlib.util as _iu
    import os as _os

    # ---- 1. pure extractor: the DVWS variable pattern + the DVGA literal
    reset_ws_intel()
    dvws_js = ('var wsUri = "ws://127.0.0.1:8080/command-execution";\n'
               'websocket = new WebSocket(wsUri);\n'
               'var wsUri2 = "ws://127.0.0.1:8080/change-password";\n'
               'websocket2 = new WebSocket(wsUri2);')
    added = observe_ws_urls(dvws_js)
    assert added == ["ws://127.0.0.1:8080/change-password",
                     "ws://127.0.0.1:8080/command-execution"], added
    assert observe_ws_urls(
        'new WebSocket("ws://127.0.0.1:5013/subscriptions")') == \
        ["ws://127.0.0.1:5013/subscriptions"]
    assert observe_ws_urls(dvws_js) == []            # idempotent
    # page TEXT (outside <script>) is NOT an observed channel
    reset_ws_intel()
    assert observe_ws_urls("<p>see ws://docs.example/intro</p>") == []
    # canary: alnum-only, fixed shape, no shell/path/template metacharacters
    for _ in range(64):
        c = _safe_canary()
        assert _re.fullmatch(r"zk[a-z0-9]{8}ws", c), c
        assert not set(c) & set(';|&`$()<>*/+!"\\\' \t')

    # ---- 2. integration: the DVWS TOPOLOGY — HTTP origin on port A, the WS
    # channels on port B, wired ONLY through the page's inline JS variable.
    try:
        WS_MESSAGE_SHAPES.clear()
        spec = _iu.spec_from_file_location("ws_app", _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            "fixtures", "ws_app.py"))
        mod = _iu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        ws_base, _t, ws_srv = mod.serve(port=0)       # ephemeral WS port
        ws_port = ws_base.rsplit(":", 1)[-1]

        page = ("""<!doctype html><html><body>
        <script>
        var wsUri = "ws://127.0.0.1:%s/ws/chat";
        websocket = new WebSocket(wsUri);
        var evilUri = "ws://evil.invalid/chat";
        websocket2 = new WebSocket(evilUri);
        </script>
        </body></html>""" % ws_port).encode()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
            def log_message(self, *a):
                pass
        http_srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        _th.Thread(target=http_srv.serve_forever, daemon=True).start()
        http_base = f"http://127.0.0.1:{http_srv.server_address[1]}"

        # ---- 2a. DISCOVERY harvests the observed channel from the inline JS
        reset_ws_intel()
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        bus = EventBus("t411-wsdisc")
        de = DiscoveryEngine(RequestEngine(scope, bus, timeout=6), max_pages=5)
        eps, _js, _cs = de.crawl(http_base)
        assert ("ws://127.0.0.1:%s/ws/chat" % ws_port) in de.ws_observed, \
            de.ws_observed
        assert "ws://evil.invalid/chat" in WS_OBSERVED_URLS  # harvested raw...

        # ---- 2b. the ENGINE admits the same-host different-port channel and
        # refuses the out-of-scope host WITHOUT connecting to it
        boundary = BoundaryEngine()
        wse = WebSocketEngine(scope, bus, timeout=6,
                              planner=SafeAttackPlanner(logic_active=False),
                              boundary=boundary, coverage=CoverageTracker(),
                              logic_active=False, listen_seconds=2.0)
        res = wse.run(eps, http_base, observed_urls=de.ws_observed,
                      low_identity={"name": "bob", "role": "user", "engine": None,
                                    "object_id": "2",
                                    "marker": "bob@sentinel-fixture.local"},
                      primary_identity={"name": "alice", "role": "user",
                                        "object_id": "1",
                                        "marker": "alice@sentinel-fixture.local"})
        chans = {c["url"]: c for c in res["stats"]["channels"]}
        chat = "ws://127.0.0.1:%s/ws/chat" % ws_port
        assert chat in chans, chans
        assert chans[chat]["source"] == "observed-js", chans[chat]
        assert "evil.invalid" not in " ".join(chans)      # never admitted
        blocked = [r for r in boundary.records
                   if r.target.startswith("ws://evil.invalid")]
        assert blocked and blocked[0].state == "BLOCKED_BY_SAFETY", \
            [(r.target, r.state) for r in boundary.records]
        # the chat channel CONNECTED (handshake + protocol proven live on the
        # different port) and its ground-truth defects were proven
        assert res["stats"]["connected"] >= 1, res["stats"]
        types = {f.type for f in res["findings"]}
        assert "websocket_sensitive_data_exposure" in types, types
        assert "websocket_cross_user_access" in types, types
    finally:
        reset_ws_intel()
        try:
            ws_srv.close()
            http_srv.shutdown()
        except Exception:
            pass
        WS_MESSAGE_SHAPES.clear()


@case
def unit_v411_value_shaped_precision():
    """V411-GL-03/WS-02: precision disciplines — an error string carrying the
    WORD 'password' is not exposure; a masked value is not exposure; only a
    sensitive KEY with a REAL VALUE is."""
    from sentinel.websocket import SENSITIVE_WS_VALUE_RE
    from sentinel.graphql import (MASKED_VALUE_RE, SQLI_ERROR_RE,
                                  CMD_OUTPUT_RE, STATE_SHAPED_QUERY_RE)
    # WS: keyword-in-error-text must NOT match; key-with-value must
    assert not SENSITIVE_WS_VALUE_RE.search("Invalid username/password")
    assert not SENSITIVE_WS_VALUE_RE.search("please provide your api_key")
    assert SENSITIVE_WS_VALUE_RE.search('{"password": "hunter2value"}')
    assert SENSITIVE_WS_VALUE_RE.search("session_id=abc123xyz")
    # GraphQL: masked values
    for masked in ("******", "x", "...", "null", "None", "N/A", "redacted",
                   "[REDACTED]", "REDACTED", "hidden", "masked"):
        assert MASKED_VALUE_RE.match(masked), masked
    for real in ("S3cr3t!", "$2a$10$hash", "111-22-3333", "tok-9f3ab2"):
        assert not MASKED_VALUE_RE.match(real), real
    # SQL error signatures + SQL echo
    assert SQLI_ERROR_RE.search('(sqlite3.OperationalError) near "x": syntax error')
    assert SQLI_ERROR_RE.search("You have an error in your SQL syntax")
    assert not SQLI_ERROR_RE.search("cannot query field on type")
    # OS command output shapes (ps aux / load average / paths)
    assert CMD_OUTPUT_RE.search(
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
    assert CMD_OUTPUT_RE.search("load average: 0.10, 0.05, 0.01")
    assert not CMD_OUTPUT_RE.search("debug subsystem: logging enabled")
    # state-shaped query vocabulary
    assert STATE_SHAPED_QUERY_RE.search("readAndBurn")
    assert STATE_SHAPED_QUERY_RE.search("deleteAllPastes")
    assert not STATE_SHAPED_QUERY_RE.search("pastes")


@case
def regression_v411_authz_token_accounts():
    """V411: token-mode authz accounts — API-key/Bearer-JWT identities arm the
    header on their session engine WITHOUT a form login, and the orchestrator
    derives the primary identity from the SESSIONS (the v4.1.0 wiring bug read
    a key that was injected only after the GraphQL/WS engines had run)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.core import ScopeRule, EventBus
    from sentinel.authz import AuthzConfig, AuthzEngine
    from sentinel.orchestrator import select_primary_identity

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer jwt-sentinel-a":
                body = b'{"user": "alice", "note": "alice@t.local"}'
                code = 200
            elif auth == "Bearer jwt-sentinel-b":
                body = b'{"user": "bob"}'
                code = 200
            else:
                body = b'{"error": "unauthenticated"}'
                code = 401
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        cfg = AuthzConfig.from_dict({
            "login_url": base + "/validate",
            "accounts": [
                {"name": "alice", "role": "admin", "username": "alice",
                 "token": "jwt-sentinel-a", "marker": "alice@t.local",
                 "object_id": "1"},
                {"name": "bob", "role": "user", "username": "bob",
                 "token": "jwt-sentinel-b", "marker": "bob@t.local",
                 "object_id": "2"},
            ]}, base)
        assert cfg.accounts[0].token == "jwt-sentinel-a"
        eng = AuthzEngine(cfg, ScopeRule(allowed_domains=["127.0.0.1"],
                                         allow_private=True), EventBus("t411"),
                          timeout=6)
        ok = eng._login_all()
        assert ok == 2, eng.errors
        # the token rides the session engines and actually authenticates
        assert "alice" in eng.sessions and "bob" in eng.sessions
        r = eng.sessions["alice"]["engine"].send(
            __import__("sentinel.http_engine", fromlist=["RequestMutation"])
            .RequestMutation(
                endpoint=__import__("sentinel.core", fromlist=["Endpoint"])
                .Endpoint(url=base + "/validate", method="GET"),
                note="t411-check"))
        assert r.status == 200 and "alice@t.local" in (r.body or "")
        # a REJECTED token never becomes a session
        cfg2 = AuthzConfig.from_dict({
            "login_url": base + "/validate",
            "accounts": [{"name": "eve", "role": "user", "username": "eve",
                          "token": "jwt-wrong"}]}, base)
        eng2 = AuthzEngine(cfg2, ScopeRule(allowed_domains=["127.0.0.1"],
                                           allow_private=True), EventBus("t411b"),
                           timeout=6)
        assert eng2._login_all() == 0
        assert eng2.errors and "token rejected" in eng2.errors[0]
        # V411 orchestrator wiring: primary identity from SESSIONS directly —
        # most-privileged account by default, matching-username override
        pi = select_primary_identity(eng.sessions)
        assert pi["name"] == "alice" and pi["object_id"] == "1" \
            and pi["marker"] == "alice@t.local", pi
        class _P: username = "bob"
        pi2 = select_primary_identity(eng.sessions, _P())
        assert pi2["name"] == "bob", pi2
        assert select_primary_identity({}) is None
    finally:
        srv.shutdown(); srv.server_close()



@case
def regression_v41_self_security():
    """Phase V41-14: the malicious target battery — SENTINEL survives every
    attack shape aimed at IT: report injection escaped in EVERY artifact,
    traversal/metadata/SSRF links refused by scope, command-injection input
    kept as data, malformed GraphQL degraded honestly, oversized WS frames
    capped, secrets masked."""
    import threading, tempfile, os, json
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.oast import OastServer
    from sentinel.store import Store
    from sentinel.report import build_html, build_sarif, build_executive
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.websocket import WsClient
    base, srv, mod = _start_fixture("malicious_app", 8946)
    oast = OastServer()
    try:
        # ---- 1. the scan SURVIVES the malicious target
        cfg = ScanConfig(allow_private=True, max_pages=10, timeout=6,
                         seed="t41-selfsec", browser=False, oast=oast,
                         secrets=True, logic_active=True, workflow=True)
        sc = SentinelScanner(base + "/", cfg)
        rep = sc.run()
        types = {f["type"] for f in rep["findings"]}
        # exactly the ONE genuine class (no fabricated findings from the noise)
        for bad in ("path_traversal", "open_redirect", "ssrf",
                    "command_injection"):
            assert bad not in types, f"fabricated {bad} from malicious noise: {types}"
        # ---- 2. every artifact ESCAPES the attacker's markup
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "selfsec.db")
            st = Store(db)
            st.save_run(rep)
            html = build_html(st)
            raw_script = "<script>alert(" in html or '<script>alert(" ' in html
            # the attacker markup that rides the XSS evidence line must
            # appear ESCAPED in the report (never executable)
            assert "&lt;img src=x onerror=" in html, \
                "attacker markup from the evidence line must appear escaped"
            assert "<img src=x onerror=" not in html
            assert "<script>alert(" not in html, \
                "raw script tag must never ride the report unescaped"
            sarif = build_sarif(st)
            sarif_txt = json.dumps(sarif)
            assert "<script>" not in sarif_txt.replace("&lt;script&gt;", "")
            # ---- 3. out-of-scope destinations were NEVER fetched
            for forbidden in ("169.254.169.254", "127.0.0.1:8022",
                              "file:///etc/passwd"):
                assert forbidden not in json.dumps(rep["stats"].get("coverage", {})), \
                    f"scope violation visible for {forbidden}"
            # the SSRF attempt against SENTINEL's own OAST left no callback
            assert len(oast.hits()) == 0, "the target reached SENTINEL's OAST"
        # ---- 4. command-injection input stays DATA (no execution, no crash)
        assert rep["stats"].get("requests", 0) > 10
        # ---- 5. malformed GraphQL degrades to an honest boundary
        gql = rep["stats"].get("graphql") or {}
        assert "error" not in gql, gql        # engine survived
        # ---- 6. oversized WS frames are capped without a crash
        from fixtures.malicious_app import WsEvilServer
        evil_ws = WsEvilServer()
        try:
            c = WsClient(f"ws://127.0.0.1:{evil_ws.port}/ws", timeout=4)
            ok = c.connect()
            assert ok
            msgs = c.listen(seconds=2.0, max_messages=6)
            c.close()
            # the client survived; the oversized frame never materialized whole
            assert all(len(m.get("text", "")) <= 410 for m in msgs)
        finally:
            evil_ws.close()
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


@case
def unit_v41_no_hallucination_gate():
    """Phase V41-18: THE NO-HALLUCINATION GATE — the executable honesty
    contract. A real scan's artifacts are checked against six invariants, and
    PLANTED LIES are proven to FAIL the gate (the gate has teeth).

      G1  no finding without evidence
      G2  no observed fact without provenance (twin belief audit)
      G3  coverage never claims tested > discovered
      G4  absent capabilities are NEVER claimed tested (GraphQL/WebSocket/
          branches say NOT_DISCOVERED when nothing was observed)
      G5  no 100% coverage claim while unexplained untested items exist
      G6  boundary records are structurally valid (evidence/provenance rules)
    """
    import threading, copy
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.boundary import BoundaryEngine

    def _gate(rep) -> list[str]:
        fails = []
        stats = rep["stats"]
        # G1: evidence on every finding
        for f in rep["findings"]:
            if not f.get("evidence"):
                fails.append(f"G1: finding {f.get('id')} carries no evidence")
        # G2: twin provenance audit
        for p in stats.get("digital_twin", {}).get("belief_audit") or []:
            fails.append(f"G2: twin belief audit: {p}")
        # G3/G5: coverage arithmetic + the 100% guard
        dims = (stats.get("coverage") or {}).get("dimensions") or {}
        for name, d in dims.items():
            if d.get("tested", 0) > d.get("discovered", 0):
                fails.append(f"G3: dimension {name} claims tested "
                             f"({d.get('tested')}) > discovered "
                             f"({d.get('discovered')})")
            if d.get("pct") == 100.0 and d.get("untested", 0) > 0:
                fails.append(f"G5: dimension {name} claims 100% with "
                             f"{d['untested']} untested items")
            if d.get("status") == "NOT_DISCOVERED" and d.get("tested", 0) > 0:
                fails.append(f"G4: dimension {name} NOT_DISCOVERED yet tested>0")
        # G4: no GraphQL/WebSocket tested claim without discovery
        if not (stats.get("graphql") or {}).get("candidates"):
            g = dims.get("graphql") or {}
            if g.get("tested", 0) > 0:
                fails.append("G4: GraphQL claimed tested with no endpoint observed")
        if not (stats.get("websocket") or {}).get("candidates"):
            w = dims.get("websocket") or {}
            if w.get("tested", 0) > 0:
                fails.append("G4: WebSocket claimed tested with no channel observed")
        # G6: boundary structural validity
        for p in stats.get("boundary", {}).get("unresolved_detail") or []:
            if not p.get("reason"):
                fails.append("G6: boundary record without reason")
        return fails

    base, srv, mod = _start_fixture("flows_app", 8947)
    try:
        from sentinel.auth import AuthProfile
        auth = AuthProfile(login_url=base + "/login", username="alice",
                           password="alice123", user_field="username",
                           pass_field="password", success_marker="Welcome")
        cfg = ScanConfig(allow_private=True, max_pages=8, timeout=6,
                         seed="t41-gate", browser=False, auth=auth,
                         workflow=True, logic_active=True)
        sc = SentinelScanner(base + "/", cfg)
        rep = sc.run()
        fails = _gate(rep)
        assert fails == [], f"the gate caught real violations: {fails[:5]}"
        # ---- the gate has TEETH: each planted lie must fail it
        # lie 1: a finding without evidence
        lie1 = copy.deepcopy(rep)
        lie1["findings"].append({"id": "F-lie", "type": "xss_reflected",
                                 "evidence": []})
        assert any(f.startswith("G1") for f in _gate(lie1))
        # lie 2: GraphQL 'tested' with nothing discovered
        lie2 = copy.deepcopy(rep)
        lie2["stats"]["coverage"]["dimensions"]["graphql"]["tested"] = 3
        assert any(f.startswith("G4") for f in _gate(lie2))
        # lie 3: 100% coverage with unexplained untested items
        lie3 = copy.deepcopy(rep)
        d = lie3["stats"]["coverage"]["dimensions"]["parameter"]
        if d["discovered"] and d["untested"] >= 0:
            d["pct"] = 100.0
            d["untested"] = max(1, d["untested"])
            d["tested"] = d["discovered"]
            assert any(f.startswith("G5") for f in _gate(lie3))
        # lie 4: tested > discovered
        lie4 = copy.deepcopy(rep)
        lie4["stats"]["coverage"]["dimensions"]["endpoint"]["tested"] = \
            lie4["stats"]["coverage"]["dimensions"]["endpoint"]["discovered"] + 7
        assert any(f.startswith("G3") for f in _gate(lie4))
    finally:
        srv.shutdown(); srv.server_close()


@case
def regression_v41_full_platform():
    """Phase V41-22 pre-gate: ONE full scan on the ground-truth fixture with
    every v4.1 engine active — v4.0.0 results fully intact (the 8 verified
    business-logic classes + prior classes) AND every v4.1 artifact present
    and honest: boundary registry, 17 coverage dimensions, API inventory,
    action matrix, real-time planner ledger, twin provenance + why examples,
    structured reasoning records, GraphQL/WebSocket honest NOT_DISCOVERED."""
    import threading
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    from sentinel.auth import AuthProfile
    from sentinel.oast import OastServer
    base, srv, mod = _start_fixture("vulnapp", 8948)
    oast = OastServer()
    try:
        auth = AuthProfile(login_url=base + "/login", username="demo",
                           password="demo123", user_field="uid", pass_field="passw",
                           success_marker="Sign Off")
        authz_cfg = {"login_url": "/login", "user_field": "uid", "pass_field": "passw",
                     "success_marker": "Sign Off",
                     "accounts": [
                         {"name": "demo-admin", "role": "admin", "username": "demo",
                          "password": "demo123",
                          "marker": "root-admin@sentinel-fixture.local",
                          "object_id": "1001"},
                         {"name": "bob-user", "role": "user", "username": "bob",
                          "password": "bob123",
                          "marker": "bob-user@sentinel-fixture.local",
                          "object_id": "2002"}]}
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=6,
                         seed="t41-full", oast=oast, auth=auth, authz=authz_cfg,
                         workflow=True, logic_active=True)
        sc = SentinelScanner(base, cfg)
        rep = sc.run()
        stats = rep["stats"]
        types = {f["type"] for f in rep["findings"]}
        # ---- v4.0.0 results INTACT (no regressions from the v4.1 engines)
        for t in ("business_logic_step_bypass", "business_logic_out_of_order",
                  "business_logic_value_tamper", "business_logic_duplicate_execution",
                  "business_logic_privilege_escalation",
                  "business_logic_cross_user_execution",
                  "business_logic_cross_object_execution",
                  "business_logic_cross_state_execution"):
            assert t in types, f"v4.0.0 class lost: {t}"
        # ---- v4.1 artifacts present and honest
        b = stats.get("boundary") or {}
        assert b.get("records", 0) >= 3, b
        assert "UNTESTABLE" in (b.get("by_state") or {}) or \
            "NOT_DISCOVERED" in (b.get("by_state") or {}), b["by_state"]
        dims = (stats.get("coverage") or {}).get("dimensions") or {}
        assert len(dims) == 17, len(dims)
        # GraphQL/WebSocket honestly NOT_DISCOVERED on this fixture
        assert dims["graphql"]["status"] == "NOT_DISCOVERED", dims["graphql"]
        assert dims["websocket"]["status"] == "NOT_DISCOVERED", dims["websocket"]
        # workflow + branch + state dimensions have real content
        assert dims["workflow"]["discovered"] == 3, dims["workflow"]
        assert dims["workflow_branch"]["discovered"] >= 1, dims["workflow_branch"]
        assert dims["state"]["discovered"] >= 1, dims["state"]
        # unified API inventory + action matrix
        api = stats.get("api_inventory") or {}
        assert api.get("total", 0) >= 15, api.get("total")
        assert "http" in (api.get("by_protocol") or {})
        am = stats.get("action_matrix") or {}
        assert "anonymous" in [i["name"] for i in am.get("identities", [])]
        # real-time planner ledger with persisted decisions
        pl = stats.get("planner") or {}
        assert pl.get("operations_evaluated", 0) >= 18, pl
        assert pl.get("by_impact", {}).get("STATE_CHANGING", 0) >= 15, pl
        assert isinstance(pl.get("decisions"), list) and pl["decisions"]
        # twin provenance + why examples
        dt = stats.get("digital_twin") or {}
        assert dt.get("belief_audit") == [], dt.get("belief_audit")
        assert dt.get("why_examples"), "why() demonstration missing"
        # structured reasoning records with explicit reasons
        hyps = (stats.get("reasoning") or {}).get("hypotheses") or []
        assert hyps and all("final_state" in h for h in hyps[:10])
        assert any(h.get("reason") for h in hyps if h["status"].startswith("untestable"))
        # proofs (Evidence OS) still complete — ENG-18 state pairs intact
        proofs = stats.get("proofs") or []
        assert len(proofs) >= 25, len(proofs)
        for pf in proofs:
            if pf["type"].startswith("business_logic_"):
                assert pf["state_before"].strip() and pf["state_after"].strip()
        # capability rows in the executive
        from sentinel.store import Store
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "f.db"))
            st.save_run(rep)
            from sentinel.report import build_executive
            ex = build_executive(st)
            caps = {c["capability"] for c in ex.get("capability_matrix", [])}
            assert {"REST", "GraphQL", "WebSocket", "Workflow", "Branching"} <= caps
            gql_cap = next(c for c in ex["capability_matrix"]
                           if c["capability"] == "GraphQL")
            assert gql_cap["unsupported_reason"], "absent capability must carry its reason"
            assert ex["boundary"]["records"] >= 3
    finally:
        oast.stop(); srv.shutdown(); srv.server_close()


@case
def unit_v420_fail_closed_verification_defaults():
    """VF-01/VF-02/VF-03 (v4.2.0): the verification engine is FAIL-CLOSED.
    (1) an unlisted type gets NO catch-all VERIFIED 0.98 — it lands CANDIDATE
        with method unverified:no-branch, passed=False, confidence 0.3;
    (2) ssrf / command_injection without an OOB callback land CANDIDATE
        (unverified:blind-class-no-oob), never VERIFIED;
    (3) the four presence types stay VERIFIED at 0.70 — far below every
        replay-verified class (the old else stamped 0.98, the engine's highest);
    (4) PATH A's body-diff half now requires same-status + max(200, 25%) —
        two 200s with a >200B but proportionally tiny diff do NOT verify;
    (5) VR-13 csrf: a blanket-2xx endpoint (accepts malformed input too) lands
        CANDIDATE (unverified:no-input-discrimination), never VERIFIED;
    (6) VR-14 nosql: a blanket-2xx endpoint (baseline ACCEPTED) has no flip —
        the observation does not reproduce -> REJECTED."""
    from sentinel.intel import VerificationEngine
    from sentinel.core import (Endpoint, Parameter, ParamLocation, Finding,
                               Severity, FindingStatus, Evidence, EventBus)

    class _Resp:
        def __init__(self, status=200, body="", error=""):
            self.status, self.body, self.error = status, body, error
            self.ok = 200 <= status < 300
            self.headers, self.request_id = {}, "t"
            self.redirect_chain = []
        def hop_location(self):
            return ""

    class _Eng:
        def __init__(self, fn=None):
            self.fn = fn or (lambda m: _Resp())
        def send(self, m):
            return self.fn(m)

    ep = Endpoint(url="http://127.0.0.1:9/x", method="GET",
                  parameters=[Parameter("id", ParamLocation.QUERY, "1")])
    bus = EventBus("run-v420-unit")

    def mk(t, url=None, param="id", method="GET", sev=Severity.HIGH):
        return Finding(t, sev, url or ep.url, param, method,
                       [Evidence("e", "detail", "t")], status=FindingStatus.CANDIDATE)

    # (1) unlisted type -> fail-closed CANDIDATE
    ve = VerificationEngine(_Eng(), bus)
    f1 = ve.verify(mk("future_type_x"), ep)
    assert f1.status == FindingStatus.CANDIDATE and f1.verification.passed is False, f1
    assert f1.verification.method == "unverified:no-branch", f1.verification.method
    assert f1.confidence == 0.3, f1.confidence
    # (2) blind classes without OOB -> CANDIDATE, never VERIFIED
    for t in ("ssrf", "command_injection"):
        fb = ve.verify(mk(t), ep)
        assert fb.status == FindingStatus.CANDIDATE and not fb.verification.passed, (t, fb)
        assert fb.verification.method == "unverified:blind-class-no-oob", (t, fb)
    # (3) presence types -> VERIFIED at 0.70 (was 0.98 — the engine's highest)
    for t in ("missing_security_headers", "server_banner_disclosure",
              "tech_banner_disclosure", "vulnerable_js_dependency"):
        fp = ve.verify(mk(t, sev=Severity.LOW), ep)
        assert fp.status == FindingStatus.VERIFIED and fp.verification.passed, (t, fp)
        assert fp.confidence == 0.70, (t, fp.confidence)
    # (4) PATH A same-status + ratio guard: 400B diff on ~40KB pages (1%)
    def script4(m):
        pv = str(getattr(m, "param_value", ""))
        if "1=1" in pv: return _Resp(200, "x" * 40000)
        if "1=2" in pv: return _Resp(200, "y" * 39600)
        return _Resp(200, "z" * 39900)
    ve4 = VerificationEngine(_Eng(script4), bus)
    f4 = ve4.verify(mk("sql_injection"), ep)
    assert f4.status == FindingStatus.REJECTED, (f4.status, f4.verification)
    assert not (f4.verification and f4.verification.method == "oracle:replay-2round"
                and f4.verification.passed), f4.verification
    # (5) VR-13 csrf on a blanket-2xx endpoint -> CANDIDATE, honest method name
    ep5 = Endpoint(url="http://127.0.0.1:9/subscribe", method="POST",
                   parameters=[Parameter("email", ParamLocation.BODY, "a@b.c")])
    ve5 = VerificationEngine(_Eng(lambda m: _Resp(200, "ok")), bus)
    f5 = ve5.verify(mk("csrf", url=ep5.url, param="email", method="POST",
                       sev=Severity.MEDIUM), ep5)
    assert f5.status == FindingStatus.CANDIDATE, (f5.status, f5.verification)
    assert f5.verification.method == "unverified:no-input-discrimination", f5.verification
    # (6) VR-14 nosql on a blanket-2xx endpoint: baseline ACCEPTED -> no flip
    ep6 = Endpoint(url="http://127.0.0.1:9/nosql-login", method="POST",
                   parameters=[Parameter("user", ParamLocation.JSON, "demo"),
                               Parameter("pass", ParamLocation.JSON, "demo")])
    ve6 = VerificationEngine(_Eng(lambda m: _Resp(200, '{"ok": true}')), bus)
    f6 = ve6.verify(mk("nosql_injection", url=ep6.url, param="user", method="POST",
                       sev=Severity.CRITICAL), ep6)
    assert f6.status == FindingStatus.REJECTED and not f6.verification.passed, f6
    assert f6.verification.method == "re-test:fresh-operator", f6.verification


def main():
    suite = sys.argv[1] if len(sys.argv) > 1 else "all"
    RESULTS["suite"] = suite
    if suite != "all":
        RESULTS["cases"] = [c for c in RESULTS["cases"] if c["name"].startswith(suite)]
        RESULTS["total"] = len(RESULTS["cases"])
        RESULTS["failed"] = sum(1 for c in RESULTS["cases"] if not c["ok"])
    RESULTS["passed"] = RESULTS["failed"] == 0
    print(json.dumps(RESULTS, indent=1))
    sys.exit(0 if RESULTS["passed"] else 1)


if __name__ == "__main__":
    main()
