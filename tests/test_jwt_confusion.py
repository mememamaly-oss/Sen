"""AUTH-06 + fam1 (jwt_algorithm_confusion) end-to-end red/blue proof.

Root cause of this suite (owner-order follow-up 2026-11-01): the live
validation vs crAPI recorded fam1 NOT_DISCOVERED with 0/12 probes sent —
the scan ran unauthenticated, so no auth-shaped endpoint was ever in
flight; and the battery had ZERO fam1 test coverage (every existing JWT
fixture exercises alg=none, not the RS/HS confusion differential).

Proven here on a crAPI-shaped JSON login (fixtures/vulnapp.py AUTH-06
surface — strict Content-Type, RS256 issuance, /.well-known/jwks.json,
a protected dashboard):

  necessity = a form-mode login (the pre-AUTH-06 engine) against the
         same JSON API cannot authenticate (415) — the chain is
         impossible without json_login.
  chain  = a json_login scan authenticates AND contributes the
         credentialed endpoint to the map (source auth:login).
  RED    = the confusion twin (CONFUSION=1: HS256 signed with the public
         key as the HMAC secret is accepted — the challenge-15
         mechanism) PRODUCES the finding, and the VR-29 fresh
         differential re-verifies it.
  BLUE   = the strict twin produces ZERO fam1 findings and an honest
         TESTED_NEGATIVE boundary with both probes sent.

The fam1 differential runs at BATTERY level (the test_modernsec2
pattern): a full vulnapp scan burns its whole request budget on the
general detectors before axis 13 ever runs — live-caught while writing
this suite (BUDGET_REACHED on the harvest itself), which is exactly the
bounded-scan behavior RT-07 mandates.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.auth import AuthProfile                               # noqa: E402
from burhan.core import Endpoint, EventBus, Parameter, \
    ParamLocation, ScopeRule                                      # noqa: E402
from burhan.http_engine import RequestEngine                      # noqa: E402
from burhan.modernsec import replay_confusion, \
    run_modern_battery                                            # noqa: E402
from burhan.orchestrator import BurhanScanner, ScanConfig         # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn_vulnapp(confusion: bool):
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    if confusion:
        env["CONFUSION"] = "1"
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if proc.poll() is not None:
            pytest.fail("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("vulnapp never became reachable")
    return port, proc


@pytest.fixture(scope="module")
def confusion_base():
    port, proc = _spawn_vulnapp(confusion=True)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()


@pytest.fixture(scope="module")
def strict_base():
    port, proc = _spawn_vulnapp(confusion=False)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()


def _profile(base: str) -> AuthProfile:
    return AuthProfile(
        login_url=f"{base}/auth/api/login",
        username="user@fixture.test", password="fixture-pass-123",
        user_field="email", pass_field="password",
        json_login=True, success_marker='"token"',
        validate_url=f"{base}/api/account/dashboard")


# ------------------------------------------------ necessity: the old path
def test_form_mode_login_fails_against_json_api(strict_base):
    """The pre-AUTH-06 engine posts x-www-form-urlencoded; a strict JSON
    login answers 415 — the chain is impossible without json_login."""
    data = BurhanScanner(strict_base, ScanConfig(
        allow_private=True, max_pages=4, timeout=8.0, browser=False,
        auth=AuthProfile(
            login_url=f"{strict_base}/auth/api/login",
            username="user@fixture.test", password="fixture-pass-123",
            user_field="email", pass_field="password",
            success_marker='"token"'))).run()        # json_login=False (default)
    auth = data["stats"]["auth"]
    assert auth["authenticated"] is False, auth
    # fam1 lands on an honest skip kind — NOT_DISCOVERED (no auth-shaped
    # endpoint in flight) or UNTESTABLE (the crawled /login page matched
    # AUTHISH but its harvest is clean). Either way: ZERO probes sent.
    mod = data["stats"]["modern"]
    fam1 = [b for b in mod["boundaries"] if b["family"] == "jwt_algorithm_confusion"]
    assert fam1 and fam1[0]["kind"] in ("NOT_DISCOVERED", "UNTESTABLE"), fam1
    assert mod["probe_counts"]["jwt_algorithm_confusion"]["sent"] == 0


# ------------------------------------------- the json_login chain (scanner)
def test_json_login_contributes_the_credentialed_endpoint(confusion_base):
    data = BurhanScanner(confusion_base, ScanConfig(
        allow_private=True, max_pages=4, timeout=8.0, browser=False,
        auth=_profile(confusion_base), max_requests=6000)).run()
    auth = data["stats"]["auth"]
    assert auth["authenticated"] is True, auth
    assert auth["logins"] == 1, auth
    # the credentialed login endpoint entered the endpoint map (harvest source)
    apis = data["stats"]["api_inventory"]["apis"]
    login_api = [a for a in apis if a["path"] == "/auth/api/login"]
    assert login_api, "the json_login endpoint never entered the endpoint map"
    assert login_api[0].get("method") == "POST", login_api[0]
    assert "auth:login" in login_api[0]["sources"], login_api[0]["sources"]


# ----------------------------------------------------- RED/BLUE at battery
def _battery(base: str):
    """fam1's exact production inputs: the contributed login endpoint
    (POST, JSON credential params) + a crawled protected dashboard."""
    engine = RequestEngine(ScopeRule(allow_private=True,
                                     allowed_hosts=["127.0.0.1"]),
                           EventBus("jwt-confusion-test"), timeout=8.0)
    login_ep = Endpoint(
        url=f"{base}/auth/api/login", method="POST",
        parameters=[Parameter("email", ParamLocation.JSON, "user@fixture.test"),
                    Parameter("password", ParamLocation.JSON,
                              "fixture-pass-123")])
    dash_ep = Endpoint(url=f"{base}/api/account/dashboard", method="GET")
    # the orchestrator stashes this after a successful json_login — the
    # VR-29 fresh harvest replays it (a bare GET can never re-obtain the token)
    engine.auth_harvest_endpoint = login_ep
    return engine, run_modern_battery(engine, [dash_ep, login_ep]), login_ep


def test_confusion_twin_fires_and_reverifies(confusion_base):
    engine, mres, _ = _battery(confusion_base)
    fam1 = [f for f in mres.findings if f.type == "jwt_algorithm_confusion"]
    assert fam1, [(b["family"], b["kind"]) for b in mres.boundaries]
    assert mres.probe_counts["jwt_algorithm_confusion"]["sent"] == 2, \
        mres.probe_counts["jwt_algorithm_confusion"]
    # VR-29: a FRESH end-to-end differential — fresh harvest (through the
    # stashed credentialed endpoint), fresh key discovery, fresh forged pair
    ok, notes = replay_confusion(engine, fam1[0])
    assert ok, notes


def test_strict_twin_is_tested_negative(strict_base):
    engine, mres, _ = _battery(strict_base)
    fam1 = [f for f in mres.findings if f.type == "jwt_algorithm_confusion"]
    assert not fam1, [f.type for f in mres.findings]
    kinds = [(b["family"], b["kind"]) for b in mres.boundaries
             if b["family"] == "jwt_algorithm_confusion"]
    assert kinds == [("jwt_algorithm_confusion", "TESTED_NEGATIVE")], \
        [(b["family"], b["kind"], b["detail"]) for b in mres.boundaries]
    assert mres.probe_counts["jwt_algorithm_confusion"]["sent"] == 2, \
        mres.probe_counts["jwt_algorithm_confusion"]
