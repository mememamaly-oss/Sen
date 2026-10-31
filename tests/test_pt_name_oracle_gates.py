"""PT-D1/PT-D2 NAME-CHANNEL ORACLE GATES (Juice Shop 20.3.0 round, 2026-10-31).

The independent-verification scan of the OFFICIAL Juice Shop release produced
7 path_traversal findings; a 4-request determinism audit + live body
inspection proved all 7 false, in two root-cause classes:

  PT-D2  /api/Products?..=1 -> 500 'internal error' (ORM chokes on the odd
         param NAME) vs control 200 — an input-CRASH differential, not a
         file-existence oracle. Live on: Feedbacks/Products/Quantitys/
         SecurityQuestions/Hints (5 findings).
  PT-D1  /rest/captcha returns a FRESH captcha every request — the endpoint
         differentiates against itself; probe-vs-control measured noise.
         Live on: /rest/captcha header-name + param-name (2 findings).

These tests pin both gates red->green against in-process mock sinks that
reproduce EXACTLY the two Juice Shop behaviors, plus the true-oracle
control case (must keep firing — the fixture's hname sink shape) and the
Benchmark-style exists-flip oracle (trav_pname must keep firing on it).
"""
import http.server
import threading

import pytest


@pytest.fixture(scope="module")
def mock_sinks():
    """Four sinks on one server, keyed by path prefix:
    /crash/*   — PT-D2 shape: any param/header NAME containing '..' -> 500
                 JSON error (Juice Shop ORM crash), anything else -> 200 JSON
    /noise/*   — PT-D1 shape: 200 with a RANDOM token in every body
                 (Juice Shop /rest/captcha shape)
    /oracle/*  — true header-NAME exists-flip ('And file already exists.'
                 vs "But file doesn't exist yet." — the Benchmark oracle)
    /pname/*   — true param-NAME exists-flip (same oracle on the param channel)
    """
    import random

    class Sink(http.server.BaseHTTPRequestHandler):
        def _json(self, code, obj):
            body = (obj if isinstance(obj, str) else
                    __import__("json").dumps(obj)).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            names = set(self.headers.keys())
            from urllib.parse import parse_qs, urlsplit
            qnames = set(parse_qs(urlsplit(self.path).query).keys())
            if path.startswith("/crash/"):
                if any(".." in n for n in names | qnames):
                    self._json(500, {"message": "internal error",
                                     "errors": ["Cannot read properties of undefined (reading 'find')"]})
                self._json(200, {"data": [{"id": 1, "name": "thing"}]})
            elif path.startswith("/noise/"):
                self._json(200, {"captcha": random.randrange(10**9, 10**10),
                                 "token": "%032x" % random.randrange(16**32)})
            elif path.startswith("/oracle/"):
                parent = any(k == ".." for k in names)
                self._json(200, "And file already exists." if parent
                           else "But file doesn't exist yet.")
            elif path.startswith("/pname/"):
                parent = any(n == ".." for n in qnames)
                self._json(200, "And file already exists." if parent
                           else "But file doesn't exist yet.")
            else:
                self._json(404, {"error": "no such sink"})

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _mk():
    from burhan.core import ScopeRule, EventBus
    from burhan.http_engine import RequestEngine
    scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
    bus = EventBus("pt-gates-test")
    return scope, bus, RequestEngine(scope, bus, timeout=6.0)


def test_ptd2_input_crash_differential_is_not_a_file_oracle(mock_sinks):
    """PT-D2: probe 500 (ORM crash on the odd NAME) vs control 200 must stay
    SILENT — the exists-oracle interpretation is disqualified when exactly
    one side is a 5xx."""
    from burhan.core import Endpoint
    from burhan.detect import HeaderNameTraversalDetector, ParamNameTraversalDetector

    for Det, name in ((HeaderNameTraversalDetector, "trav_hname"),
                      (ParamNameTraversalDetector, "trav_pname")):
        scope, bus, engine = _mk()
        det = Det(engine, bus)
        f = det.run(Endpoint(url=mock_sinks + "/crash/list", method="GET"))
        assert f is None, \
            f"{name}: input-crash differential (500-vs-200) must not fire — " \
            f"got {f and f.type}"


def test_ptd1_nondeterministic_endpoint_is_noise_not_oracle(mock_sinks):
    """PT-D1: an endpoint whose bodies vary on their own (captcha shape) must
    stay SILENT after the second-control determinism sample."""
    from burhan.core import Endpoint
    from burhan.detect import HeaderNameTraversalDetector, ParamNameTraversalDetector

    for Det, name in ((HeaderNameTraversalDetector, "trav_hname"),
                      (ParamNameTraversalDetector, "trav_pname")):
        scope, bus, engine = _mk()
        det = Det(engine, bus)
        f = det.run(Endpoint(url=mock_sinks + "/noise/captcha", method="GET"))
        assert f is None, \
            f"{name}: non-deterministic endpoint must not fire — got {f and f.type}"


def test_true_header_name_oracle_still_fires(mock_sinks):
    """Control case: the Benchmark exists-flip oracle must STILL fire through
    both new gates (deterministic + same response class)."""
    from burhan.core import Endpoint
    from burhan.detect import HeaderNameTraversalDetector

    scope, bus, engine = _mk()
    det = HeaderNameTraversalDetector(engine, bus)
    f = det.run(Endpoint(url=mock_sinks + "/oracle/download", method="GET"))
    assert f is not None and f.type == "path_traversal"
    assert f.parameter == "header:.."


def test_true_param_name_oracle_still_fires(mock_sinks):
    """Control case: the param-NAME exists-flip oracle must STILL fire."""
    from burhan.core import Endpoint
    from burhan.detect import ParamNameTraversalDetector

    scope, bus, engine = _mk()
    det = ParamNameTraversalDetector(engine, bus)
    f = det.run(Endpoint(url=mock_sinks + "/pname/download", method="GET"))
    assert f is not None and f.type == "path_traversal"
    assert f.parameter == "param-name:.."
