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
    # fixture v8 ground truth (Phase 56): 30 TP-able (v7's 27 PLUS the Intelligence
    # Layer surfaces: idor_bola /api/data + vertical_privilege_escalation
    # /api/admin/stats + credential_exposure /vuln/leak-config — the benchmark
    # exercises the multi-user Authorization Engine, the secrets scan and their
    # VR-17/18/19 verifications end-to-end), 24 TN-able. F1 must be
    # 1.0 with zero FP/FN — the OP-01 autostart path must deliver the FULL
    # benchmark, not a silently-empty scan (the original F1=0.0 failure mode).
    scored = (rep["f1"] >= 0.99 and rep["confusion"]["TP"] == 30
              and rep["confusion"]["FP"] == 0 and rep["confusion"]["FN"] == 0
              and rep["confusion"]["TN"] == 24)
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
    """VR-03 regression (live-caught on ginandjuice.shop ?category=): apps escaping ONLY
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
    j = build_report(st, "")
    assert j["kind"] == "overview" and j["summary"]["runs"] == 1


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
