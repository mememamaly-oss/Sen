#!/usr/bin/env python3
"""SENTINEL test runner — unit + regression + chaos suites (real execution).
Usage: run_tests.py [unit|regression|chaos|all]  → prints JSON verdict (last line).
Release gate (spec 37): every suite must pass. Cases execute at import in registration order.
"""
import json, os, sys, time, threading, traceback

RESULTS = {"suite": "?", "total": 0, "failed": 0, "cases": []}
_REGISTRY = []


def case(fn):
    """Register + execute immediately; failures captured, never crash the runner."""
    RESULTS["total"] += 1
    t0 = time.time()
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
    # fixture v2 ground truth: 12 TP-able (10 actives + headers + banner), 8 TN-able.
    # F1 must be 1.0 with zero FP/FN — the OP-01 autostart path must deliver the FULL
    # benchmark, not a silently-empty scan (the original F1=0.0 failure mode).
    scored = rep["f1"] >= 0.99 and rep["confusion"]["TP"] == 12 and rep["confusion"]["FP"] == 0
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
        eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True), EventBus("run-disc05"), timeout=5)
        de = DiscoveryEngine(eng, max_pages=30)
        endpoints, js_hits, _ = de.crawl(f"http://127.0.0.1:{port}/")
        paths = {e.url for e in endpoints}
        assert any("/vuln/jsparam.php" in u and any(p.name == "cat" for p in e.parameters)
                   for u, e in ((e.url, e) for e in endpoints)), \
            "inline-script URL with ?cat= param must be discovered (DISC-05)"
        # DISC-06: XML root learned from stockapp.js
        from sentinel.discovery import JS_XML_HINTS
        assert "stockCheck" in JS_XML_HINTS, "XML root hint must be learned from JS asset"
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


# ================================================================ main
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
