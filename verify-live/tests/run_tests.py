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
    scored = rep["f1"] >= 0.99 and rep["confusion"]["TP"] == 7   # full path worked
    cleaned = not _port_open("127.0.0.1", PORT)                  # stopped what it started
    assert scored and cleaned, (rep["confusion"], rep["f1"], cleaned)


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
