"""REPLAY FIDELITY TESTS (2026-10-31, replay-gap closure campaign).

These pin the EXACT production defects recorded in
evidence/full-reverify/*/replay_results.json (2026-10-31): on the fixture,
the three REPRODUCTION_FAILED classes were

    F-032bdac7bf command_injection  /vuln/ping        (param host)
    F-e462d9cbcb csrf               /vuln/csrf-action (param email, FORM body)
    F-04eeda1891 jwt_security       /vuln/jwt-login   (JSON body, parameter "-")

and on the authorized remote target five path_traversal findings produced by
the header-NAME channel detector (trav_hname) were replayed through the
VALUE-channel detector because the proof never recorded WHICH detector
produced the finding. Root causes, all in the replay path (the detectors
themselves are correct):

    RP-1  the proof recorded only {method, url, parameter} — no param
          locations, no request shape — so a clean replay rebuilt the request
          as GET-style QUERY params: the csrf FORM body and the jwt JSON body
          were never reconstructed (fixture answered 400 both times).
    RP-2  the replay constructed every detector as det_cls(engine, bus, None)
          — no OAST channel — so the OOB-dependent classes (cmdi et al.) were
          INERT on replay ("no longer produces a candidate" was a lie by
          omission: the detector could not even try).
    RP-3  one vuln_type can be produced by several detectors
          (path_traversal: traversal / trav_hname / trav_pname;
          command_injection: cmdi / cmdi_echo) — the replay routed by
          type-name only and probed the wrong channel.

Fix under test: build_proof records the endpoint's full request shape
(param locations) + the producing detector's name; replay_finding
reconstructs the shape, routes by the recorded detector, and wires an armed
OAST channel into OOB-dependent detectors — or reports NOT_REPLAYABLE
honestly when no channel is provided. Legacy proofs (no shape recorded)
keep their exact historical behavior.
"""
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULNAPP = os.path.join(ROOT, "fixtures", "vulnapp.py")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def vulnapp():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, VULNAPP],
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        if proc.poll() is not None:
            pytest.fail("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            yield f"http://127.0.0.1:{port}"
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("vulnapp never became reachable")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _mk(base):
    """Shared construction: scope, bus, engine, verifier — loopback only."""
    from burhan.core import ScopeRule, EventBus
    from burhan.http_engine import RequestEngine
    from burhan.intel import VerificationEngine

    scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
    bus = EventBus("replay-fidelity-test")
    engine = RequestEngine(scope, bus, timeout=8.0)
    return scope, bus, engine, VerificationEngine(engine, bus)


# --------------------------------------------------------------------------
# RP-1: request-shape reconstruction (csrf FORM / jwt JSON)
# --------------------------------------------------------------------------

def test_rp1_csrf_form_body_replay_verifies(vulnapp):
    """The recorded csrf proof must replay with the email param in the FORM
    body (RP-1). Historical defect: replay probed ?email=... (QUERY) on the
    POST endpoint -> fixture 400 'email required' -> detector silent ->
    REPRODUCTION_FAILED."""
    from burhan.core import Endpoint, Parameter, ParamLocation
    from burhan.detect import CsrfDetector
    from burhan.evidence import build_proof, replay_finding

    scope, bus, engine, ver = _mk(vulnapp)
    ep = Endpoint(url=vulnapp + "/vuln/csrf-action", method="POST",
                  parameters=[Parameter("email", ParamLocation.BODY,
                                        "reader@example.com").classify()])
    det = CsrfDetector(engine, bus)
    cand = det.run(ep)
    assert cand is not None, "detector itself must fire on the live fixture"
    verified = ver.verify(cand, ep)
    assert verified.status and verified.status.value == "verified"

    proof = build_proof(verified, endpoint=ep)
    shape = proof["requests"][0]
    assert shape.get("request_params"), "proof must record the request shape (RP-1)"
    assert any(p["location"] == "body" and p["name"] == "email"
               for p in shape["request_params"])

    out = replay_finding(proof, scope, bus, timeout=8.0)
    assert out["replay"] == "REPRODUCTION_VERIFIED", \
        f"csrf replay must verify via the reconstructed FORM body: {out}"


def test_rp1_jwt_json_body_replay_verifies(vulnapp):
    """The recorded jwt proof must replay with the JSON body (content type
    application/json) the endpoint actually consumes (RP-1). Historical
    defect: the jwt finding's parameter is '-' (class-level finding), so the
    replay sent a bodyless POST -> fixture 400 'expected application/json'
    -> no token in the response -> REPRODUCTION_FAILED."""
    from burhan.core import Endpoint, Parameter, ParamLocation
    from burhan.detect import JwtDetector
    from burhan.evidence import build_proof, replay_finding

    scope, bus, engine, ver = _mk(vulnapp)
    ep = Endpoint(url=vulnapp + "/vuln/jwt-login", method="POST",
                  parameters=[Parameter("user", ParamLocation.JSON, "demo").classify()])
    det = JwtDetector(engine, bus)
    cand = det.run(ep)
    assert cand is not None, "detector itself must fire on the live fixture"
    verified = ver.verify(cand, ep)
    assert verified.status and verified.status.value == "verified"

    proof = build_proof(verified, endpoint=ep)
    assert proof["requests"][0].get("request_params"), "RP-1 shape missing"
    assert any(p["location"] == "json" for p in proof["requests"][0]["request_params"])

    out = replay_finding(proof, scope, bus, timeout=8.0)
    assert out["replay"] == "REPRODUCTION_VERIFIED", \
        f"jwt replay must verify via the reconstructed JSON body: {out}"


# --------------------------------------------------------------------------
# RP-2: OOB classes need an armed channel on replay
# --------------------------------------------------------------------------

def _drive_cmdi(vulnapp, engine, ver, oast):
    """Drive the real cmdi detector the way the orchestrator does (the
    verifier needs the armed channel too — a blind class verifies THROUGH
    the OOB confirmation)."""
    from burhan.core import Endpoint, Parameter, ParamLocation
    from burhan.detect import CommandInjectionDetector
    from burhan.intel import VerificationEngine

    ep = Endpoint(url=vulnapp + "/vuln/ping", method="GET",
                  parameters=[Parameter("host", ParamLocation.QUERY,
                                        "localhost").classify()])
    det = CommandInjectionDetector(engine, bus=None, strategy_store=None, oast=oast)
    cand = None
    for m in det.candidates(ep):
        r = engine.send(m)
        if r is None or r.error:
            continue
        p = next((p for p in ep.parameters if p.name == m.param_name), None)
        cand = det.analyze((ep, p), r)
        if cand:
            break
    assert cand is not None, "cmdi detector must fire (OOB callback on local channel)"
    assert cand.detector == "cmdi", "the cmdi Finding must carry its detector name"
    from burhan.core import EventBus as _EB
    _event_bus = lambda: _EB("cmdi-verify")
    ver_oob = VerificationEngine(engine, _event_bus(), oast=oast)
    return ver_oob.verify(cand, ep), ep


def test_rp2_cmdi_oob_replay_verifies_with_channel(vulnapp):
    """F-032bdac7bf: the cmdi proof must replay VERIFIED when the replay
    wires an armed OAST channel (RP-2). Historical defect: replay built the
    detector with no oast -> candidates() returned [] -> 'no longer produces
    a candidate'."""
    from burhan.evidence import build_proof, replay_finding
    from burhan.oast import OastServer

    scope, bus, engine, ver = _mk(vulnapp)
    with OastServer() as scan_oast:                       # scan-time channel
        verified, ep = _drive_cmdi(vulnapp, engine, ver, scan_oast)
        assert verified.status and verified.status.value == "verified"
        proof = build_proof(verified, endpoint=ep)

    with OastServer() as replay_oast:                     # CLEAN replay channel
        out = replay_finding(proof, scope, bus, timeout=10.0, oast=replay_oast)
    assert out["replay"] == "REPRODUCTION_VERIFIED", \
        f"cmdi replay must verify with a fresh armed channel: {out}"


def test_rp2_cmdi_replay_without_channel_is_not_replayable(vulnapp):
    """Without an armed OAST channel the honest verdict is NOT_REPLAYABLE
    (the class's own recorded precondition), never the misleading 'no longer
    produces a candidate' (RP-2)."""
    from burhan.evidence import build_proof, replay_finding
    from burhan.oast import OastServer

    scope, bus, engine, ver = _mk(vulnapp)
    with OastServer() as scan_oast:
        verified, ep = _drive_cmdi(vulnapp, engine, ver, scan_oast)
        proof = build_proof(verified, endpoint=ep)

    out = replay_finding(proof, scope, bus, timeout=5.0, oast=None)
    assert out["replay"] == "NOT_REPLAYABLE", \
        f"OOB class without a channel must say NOT_REPLAYABLE, got: {out}"
    assert "OOB" in out["reason"] or "OAST" in out["reason"] or \
        "oast" in out["reason"], f"reason must name the missing channel: {out}"


# --------------------------------------------------------------------------
# RP-3: detector-name routing (one type, several detectors)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def hname_sink():
    """A minimal header-NAME path sink: a header literally named '..' (the
    sink base's parent) resolves; any burhan-random control name does not.
    Mirrors the OWASP-Benchmark oracle the real detector was built on."""
    class HNSink(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parent = any(k == ".." for k in self.headers.keys())
            body = (b"And file already exists." if parent
                    else b"But file doesn't exist yet.")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HNSink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_rp3_header_name_traversal_replays_via_recorded_detector(hname_sink):
    """The five remote-target path_traversal REPRODUCTION_FAILEDs: the proof
    must record WHICH detector produced the finding and the replay must
    route to it (RP-3). Historical defect: type-name routing sent a
    header-NAME finding to the VALUE-channel traversal detector."""
    from burhan.core import Endpoint
    from burhan.detect import HeaderNameTraversalDetector
    from burhan.evidence import build_proof, replay_finding

    scope, bus, engine, ver = _mk(hname_sink)
    ep = Endpoint(url=hname_sink + "/download", method="GET")
    det = HeaderNameTraversalDetector(engine, bus)
    cand = det.run(ep)
    assert cand is not None, "trav_hname must fire on the header-name sink"
    assert cand.parameter.startswith("header:"), \
        "the finding is a header-NAME channel finding"
    assert getattr(cand, "detector", "") == "trav_hname", \
        "the Finding must carry its producing detector's name (RP-3)"
    verified = ver.verify(cand, ep)
    assert verified.status and verified.status.value == "verified"

    proof = build_proof(verified, endpoint=ep)
    assert proof.get("detector") == "trav_hname", \
        "the proof must carry the producing detector's name (RP-3)"

    out = replay_finding(proof, scope, bus, timeout=8.0)
    assert out["replay"] == "REPRODUCTION_VERIFIED", \
        f"replay must route by the recorded detector (trav_hname): {out}"


# --------------------------------------------------------------------------
# Legacy proofs: exact historical behavior, unchanged
# --------------------------------------------------------------------------

def test_legacy_proof_without_shape_keeps_historical_verdict(vulnapp):
    """Proofs recorded before the fix (no request shape, no detector name)
    must keep behaving EXACTLY as they did in the recorded evidence: the
    csrf replay against the FORM endpoint fails with 'no longer produces a
    candidate'. No history rewriting, no retroactive upgrades."""
    from burhan.core import Endpoint, Parameter, ParamLocation
    from burhan.detect import CsrfDetector
    from burhan.evidence import build_proof, replay_finding

    scope, bus, engine, ver = _mk(vulnapp)
    ep = Endpoint(url=vulnapp + "/vuln/csrf-action", method="POST",
                  parameters=[Parameter("email", ParamLocation.BODY,
                                        "reader@example.com").classify()])
    det = CsrfDetector(engine, bus)
    cand = det.run(ep)
    assert cand is not None
    verified = ver.verify(cand, ep)

    legacy = build_proof(verified)                      # NO endpoint -> legacy shape
    assert not legacy["requests"][0].get("request_params")
    out = replay_finding(legacy, scope, bus, timeout=8.0)
    assert out["replay"] == "REPRODUCTION_FAILED"
    assert "no longer produces a candidate" in out["reason"]


def test_rp3_legacy_header_signature_routes_to_trav_hname(hname_sink):
    """Legacy proofs (recorded BEFORE the detector stamp) whose parameter
    carries the trav_hname channel signature ('header:') must route to
    trav_hname via the signature fallback — this is the exact shape of the
    five remote path_traversal findings in the committed evidence."""
    from burhan.core import Endpoint
    from burhan.detect import HeaderNameTraversalDetector
    from burhan.evidence import build_proof, replay_finding

    scope, bus, engine, ver = _mk(hname_sink)
    ep = Endpoint(url=hname_sink + "/download", method="GET")
    det = HeaderNameTraversalDetector(engine, bus)
    cand = det.run(ep)
    assert cand is not None
    verified = ver.verify(cand, ep)

    legacy = build_proof(verified)                      # NO endpoint -> legacy
    legacy["detector"] = ""                             # and no stamp, as committed
    assert legacy["requests"][0]["parameter"].startswith("header:")

    out = replay_finding(legacy, scope, bus, timeout=8.0)
    assert out["replay"] == "REPRODUCTION_VERIFIED", \
        f"legacy header: signature must route to trav_hname: {out}"
