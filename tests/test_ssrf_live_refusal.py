"""LIVE SSRF-refusal proofs at the ENGINE layer (owner order 2026-10-31, 2.2).

The SaaS app never fetches a user-supplied URL itself — the engine subprocess
is the only egress path. These tests prove, against a REAL local listener,
that the engine:

  1. NEVER connects to a loopback target without --allow-private
     (zero requests, zero listener hits, requests==0 in result.json);
  2. NEVER connects to the cloud-metadata address 169.254.169.254
     (refused before any connection is attempted);
  3. DOES connect to the same loopback listener when --allow-private is
     explicitly passed — proving the refusals above are the scope gate
     working, not a networking artifact.

No external system is touched: every target is loopback or unroutable.
"""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HITS: list[str] = []


class _HitHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        HITS.append(self.path)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def loopback_listener():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HitHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()
    srv.server_close()
    HITS.clear()


def _run_engine(url, tmp_path, extra_args=()):
    out = tmp_path / "result.json"
    db = tmp_path / "store.db"
    p = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "scan", url,
         "--out", str(out), "--db", str(db),
         "--no-browser", "--max-pages", "2", *extra_args],
        capture_output=True, text=True, timeout=120,
    )
    assert p.returncode == 0, f"engine failed: {p.stdout[-800:]} {p.stderr[-800:]}"
    return json.loads(out.read_text())


def test_engine_never_connects_to_loopback_without_allow_private(loopback_listener, tmp_path):
    result = _run_engine(loopback_listener, tmp_path)
    assert result["stats"]["requests"] == 0, "engine sent requests to a loopback target"
    assert HITS == [], f"the loopback listener was reached {len(HITS)} time(s) without --allow-private"


def test_engine_never_connects_to_metadata_address(tmp_path):
    result = _run_engine("http://169.254.169.254/latest/meta-data/", tmp_path)
    assert result["stats"]["requests"] == 0, "engine sent requests to the metadata address"


def test_engine_connects_to_the_same_listener_WITH_allow_private(loopback_listener, tmp_path):
    """Control direction: the gate (not the network) is what blocked above."""
    result = _run_engine(loopback_listener, tmp_path, extra_args=("--allow-private",))
    assert result["stats"]["requests"] >= 1, "engine should have crawled the loopback target"
    assert len(HITS) >= 1, "the loopback listener should have been reached with --allow-private"


# ---------------------------------------------------------------- unit gates
from sentinel.core import Endpoint, ScopeRule, pin_transport_address  # noqa: E402
from sentinel.websocket import WsClient  # noqa: E402
from sentinel.modernsec import _raw_post, _smug_pair  # noqa: E402


def test_pin_transport_address_refuses_private_unless_explicit():
    for host in ("127.0.0.1", "localhost", "10.1.2.3", "169.254.169.254",
                 "192.168.1.1", "172.16.0.9", "100.64.0.1", "[::1]", "0.0.0.0"):
        pinned, why = pin_transport_address(host, 80, allow_private=False)
        assert pinned is None, f"{host} must be refused, got {pinned}"
        assert why, "refusal carries a reason"
    # the explicit override is the ONLY way through
    pinned, why = pin_transport_address("127.0.0.1", 80, allow_private=True)
    assert pinned == "127.0.0.1" and why is None


def test_wsclient_failclosed_without_scope(loopback_listener, tmp_path):
    """scope=None (any out-of-engine caller) = private targets refused."""
    c = WsClient(loopback_listener.replace("http://", "ws://"), timeout=4.0)
    ok = c.connect()
    assert ok is False
    assert "scope-blocked" in c.handshake_body
    assert HITS == [], "raw socket must never have been opened"


def test_wsclient_honors_allow_private_scope(loopback_listener):
    """The control direction: with an explicit allow_private scope the SAME
    client connects (the listener is reached; it answers plain HTTP so the
    websocket handshake itself fails with a non-101 — the TCP connection
    is what proves the policy decision)."""
    before = len(HITS)
    scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
    c = WsClient(loopback_listener.replace("http://", "ws://"), timeout=4.0, scope=scope)
    c.connect()
    c.close()
    assert len(HITS) > before, "allow_private scope must let the raw socket through"


def test_raw_post_refuses_private_without_allow_private(loopback_listener):
    before = len(HITS)
    ms, status = _raw_post("127.0.0.1", loopback_listener.rsplit(":", 1)[1].rstrip("/"),
                           "/", [("Content-Type", "text/plain")], b"x",
                           3.0, allow_private=False)
    assert ms is None and status is None
    assert len(HITS) == before, "the raw timing socket must never have been opened"


def test_raw_post_connects_with_allow_private(loopback_listener):
    port = loopback_listener.rsplit(":", 1)[1].rstrip("/")
    ms, status = _raw_post("127.0.0.1", port, "/",
                           [("Content-Type", "text/plain")], b"x",
                           3.0, allow_private=True)
    assert ms is not None, "control direction must connect"


def test_smug_pair_loopback_carveout_is_gone(loopback_listener):
    """RED->GREEN regression for the removed 127.0.0.1/localhost carve-out:
    before the fix, a loopback endpoint was allowed through even when NOT
    in the scope's allowed domains (the raw timing pair then connected)."""
    from types import SimpleNamespace
    port = loopback_listener.rsplit(":", 1)[1].rstrip("/")
    # _smug_pair only reads st.engine.scope / st.engine.timeout — a stub
    # engine avoids constructing the full HTTP engine for this policy test.
    eng = SimpleNamespace(scope=ScopeRule(allowed_domains=["example.com"]),
                          timeout=6.0)
    st = _StStub(eng)
    ep = Endpoint(url=f"http://127.0.0.1:{port}/x")
    before = len(HITS)
    t_c, st_c, t_p, st_p, why = _smug_pair(st, ep, "canary-x")
    assert why == "target host outside the scan scope"
    assert t_c is None
    assert len(HITS) == before, "the carve-out must be gone: no raw connection"


class _StStub:
    def __init__(self, engine):
        self.engine = engine
        self.requests = 0
        self.counts = {"http_request_smuggling": {"sent": 0}}
