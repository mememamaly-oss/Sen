"""ORD-001-REMAND — the discriminating battery (M1 RED -> post-fix GREEN).

Coverage is appended per fix, in the supervisor's ordered sequence:
  item 1 (RT-03/RT-04)  seed entropy + HKDF derivation   [this revision]
  item 2 (RT-01 TOCTOU)  DNS-rebinding pin               [appended later]
  item 3                 request-body sanitization        [appended later]

Every test here FAILS on the audit-rb-1 vulnerable tree (that is the M1
RED record) and PASSES on the fixed tree. The suite contract
(run_tests.py 227 x 19 = 4313) is untouched by this file.
"""
import base64
import hashlib
import hmac

import pytest

from sentinel import audit
from sentinel.audit import audit_block, derive_keypair, enrich_report
from sentinel.core import EventBus, ScopeRule, new_run_id

try:
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    _CRYPTO = True
except ImportError:            # pragma: no cover — stdlib fallback path
    _CRYPTO = False


# ---------------------------------------------------------------- helpers
def _hkdf_stdlib(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256, stdlib hmac only (independent of sentinel.audit)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _rep(seed, n_findings=2, run_id="run-battery-remand"):
    return {"run_id": run_id, "seed": seed, "scanner": "sentinel-core/4.3.0",
            "target": "http://fixture.test/", "stats": {"requests": 3},
            "findings": [
                {"id": f"F{i}", "type": "xss_reflected", "severity": "high",
                 "status": "verified", "url": f"http://fixture.test/v{i}?q=x",
                 "parameter": "q", "method": "GET", "confidence": 0.9,
                 "risk": 8, "evidence": [{"kind": "marker_in_body",
                                          "detail": "m"}],
                 "verification": {"method": "replay_marker", "passed": True}}
                for i in range(1, n_findings + 1)],
            "rejected_candidates": []}


# ================================================================ item 1
def test_rt03_seed_entropy():
    """The default run seed must be unguessable — 64 hex chars from
    os.urandom(32) (256-bit); date-shaped seeds must be REJECTED before any
    key material exists (fail-closed), so a date dictionary can never even
    produce a candidate key."""
    s1 = new_run_id(None)[1]
    s2 = new_run_id(None)[1]
    assert len(s1) == 64 and len(s2) == 64, \
        f"default run seeds must be 64 hex chars (got {len(s1)}, {len(s2)})"
    assert all(c in "0123456789abcdef" for c in s1 + s2), \
        "default run seeds must be hex"
    assert s1 != s2, "two default runs must never share a seed"
    # date/timestamp/serial shapes and anything under 32 bytes: REJECTED
    for weak in ("20261021", "2026-10-21", "1760000000", "run-1",
                 "unseeded", "x" * 31, "benchmark-fixed-seed"):
        with pytest.raises(Exception) as ei:
            derive_keypair(weak)
        assert "32" in str(ei.value) or "seed" in str(ei.value).lower(), \
            f"weak seed {weak!r} must be rejected with a fail-closed error"
    # a date-seeded report cannot be signed AT ALL (rejected at the source)
    with pytest.raises(Exception):
        audit_block(_rep("20261021"), seed="20261021")


def test_rt04_hkdf_derivation():
    """The Ed25519 key must come from HKDF-SHA256 (RFC 5869) over the
    high-entropy seed — not from a plain hash, not from the legacy
    sha256[:8] -> PRNG stream."""
    seed_hex = "b7f3a9e1c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8"
    ikm = bytes.fromhex(seed_hex)
    priv, pub = derive_keypair(seed_hex)
    salt = audit._HKDF_SALT
    info = audit._HKDF_INFO
    expect_std = _hkdf_stdlib(ikm, salt, info, 32)
    assert priv == expect_std, \
        "the private key must equal the independent stdlib HMAC HKDF-SHA256"
    if _CRYPTO:
        expect_lib = HKDF(algorithm=_hashes.SHA256(), length=32,
                           salt=salt, info=info).derive(ikm)
        assert priv == expect_lib, \
            "the private key must equal the cryptography-library HKDF"
    # and it is NOT any of the plain-hash shapes
    assert priv != hashlib.sha256(ikm).digest()
    assert priv != hashlib.sha256(seed_hex.encode()).digest()[:32]
    assert priv != hashlib.sha256(seed_hex.encode()).digest()[:8], \
        "the legacy 64-bit sha256[:8] intermediate must be gone"


def test_rt04_replay_determinism():
    """Axis 14 preserved: the SAME manually-passed seed (>=32 bytes) must
    reproduce the byte-identical public key + signature; a different seed
    must give a different signature."""
    seed_a = "d1" * 32            # 64 hex chars -> 32 bytes
    seed_b = "e2" * 32
    b1 = audit_block(_rep(seed_a), seed=seed_a)
    b2 = audit_block(_rep(seed_a), seed=seed_a)
    assert b1["signature_b64"] == b2["signature_b64"], \
        "same seed must reproduce the byte-identical signature"
    assert b1["public_key_b64"] == b2["public_key_b64"]
    b3 = audit_block(_rep(seed_b), seed=seed_b)
    assert b1["signature_b64"] != b3["signature_b64"], \
        "a different seed must give a different signature"
    # full-report reproducibility through enrich_report (the operator path)
    r1 = enrich_report(_rep(seed_a), seed=seed_a)
    r2 = enrich_report(_rep(seed_a), seed=seed_a)
    assert r1["audit"]["signature_b64"] == r2["audit"]["signature_b64"]


# ================================================================ item 2 (RT-01 TOCTOU)
def test_rt01_dns_rebinding_blocked():
    """DNS-rebinding simulation: the name resolves to a PUBLIC address on
    the first lookup (the guard passes) and to 127.0.0.1 on every later
    lookup (the rebinding flip). The connection to the SECOND (unsafe) IP
    must be BLOCKED — the engine resolves once, validates every answer,
    and pins the transport to the validated address."""
    import socket as _socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from sentinel.core import Endpoint
    from sentinel.http_engine import RequestEngine, RequestMutation

    rebind_name = "rebind.sentinel-proof.test"
    safe_ip = "93.184.216.34"

    class _Evil(BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self):
            type(self).hits += 1
            body = b"EVIL-REBOUND-CONTENT"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Evil)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    real_getaddrinfo = _socket.getaddrinfo
    state = {"n": 0}

    def fake(host, *args, **kwargs):
        if host == rebind_name:
            state["n"] += 1
            answer = safe_ip if state["n"] == 1 else "127.0.0.1"
            return real_getaddrinfo(answer, *args, **kwargs)
        return real_getaddrinfo(host, *args, **kwargs)

    try:
        _socket.getaddrinfo = fake
        eng = RequestEngine(
            ScopeRule(allowed_hosts=[rebind_name], allow_private=False),
            EventBus("rt01-rebind"), timeout=6)
        ep = Endpoint(url=f"http://{rebind_name}:{port}/rebind", method="GET")
        resp = eng.send(RequestMutation(endpoint=ep))
    finally:
        _socket.getaddrinfo = real_getaddrinfo

    assert _Evil.hits == 0, \
        f"RED: the engine connected to the rebound (unsafe) IP — evil " \
        f"listener hit {_Evil.hits} time(s) with status {resp.status}"
    assert resp.status == 0, f"the blocked request must return status=0 (got {resp.status})"
    assert "pin" in (resp.error or ""), \
        f"the block must carry the pin reason (got {resp.error!r})"


def test_rt01_pin_host_header():
    """Option A semantics preserved: the pinned transport carries the
    ORIGINAL authority in the Host header — never the pinned IP."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from sentinel.core import Endpoint
    from sentinel.http_engine import RequestEngine, RequestMutation

    class _EchoHost(BaseHTTPRequestHandler):
        seen_host = ""

        def do_GET(self):
            type(self).seen_host = self.headers.get("Host", "")
            body = f"HOST={type(self).seen_host}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHost)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    eng = RequestEngine(
        ScopeRule(allowed_hosts=["localhost"], allow_private=True),
        EventBus("rt01-host"), timeout=6)
    ep = Endpoint(url=f"http://localhost:{port}/pin", method="GET")
    r = eng.send(RequestMutation(endpoint=ep))
    assert r.status == 200, f"the pinned request must still succeed (got {r.status})"
    assert _EchoHost.seen_host == f"localhost:{port}", \
        f"the server must observe the ORIGINAL authority in Host " \
        f"(got {_EchoHost.seen_host!r})"
