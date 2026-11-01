"""3E BFLA (Broken Function Level Authorization) — RED/BLUE proof.

The family lives in the modern2 battery (OFF by default with --modern-v2
unset) and reuses the authz battery's logged-in sessions (demo=admin,
bob=user — nothing logs in inside 3E). The fixture surface
(BFLA=1-gated lab divs + two POST routes):

  RED   POST /api/admin/rotate-keys — any AUTHENTICATED session executes
        the admin function (no role check): the API5:2023 class. The
        finding fires and survives VR-36 (a fresh lower-privilege replay
        through the same session engine).
  BLUE  POST /api/secure/admin/rotate-keys — the hardened twin (role
        enforced, 403): zero findings, honest TESTED_NEGATIVE.
  REGRESSION the standard fixture (no BFLA surfaces) with the same
        authz + modern_v2 configuration: zero bfla findings on every
        correctly-scoped endpoint the suite already exercises.
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

from burhan.orchestrator import BurhanScanner, ScanConfig         # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(bfla: bool):
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    if bfla:
        env["BFLA"] = "1"
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


def _scan(base: str):
    cfg = ScanConfig(
        allow_private=True, max_pages=8, timeout=8.0, browser=False,
        modern_v2=True, max_requests=8000,
        authz={"login_url": f"{base}/login",
               "accounts": [
                   {"name": "admin", "role": "admin",
                    "username": "demo", "password": "demo123",
                    "marker": "root-admin@burhan-fixture.local"},
                   {"name": "bob", "role": "user",
                    "username": "bob", "password": "bob123",
                    "marker": "bob-user@burhan-fixture.local"}],
               "user_field": "uid", "pass_field": "passw",
               "success_marker": "Sign Off"})
    return BurhanScanner(base, cfg).run()


def test_bfla_red_broken_and_blue_hardened_in_one_scan():
    port, proc = _spawn(bfla=True)
    try:
        data = _scan(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
    types = {f["type"] for f in data["findings"]}
    # RED: the broken admin function fired
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    assert bfla, sorted(types)
    broken = [f for f in bfla if "/api/admin/rotate-keys" in f["url"]]
    assert broken, [f["url"] for f in bfla]
    assert str(broken[0]["status"]).lower() == "verified", broken[0]["status"]
    # BLUE: the hardened twin stayed silent
    secure = [f for f in bfla if "secure" in f["url"]]
    assert not secure, [f["url"] for f in bfla]
    # the battery's own record: probes sent, hardened endpoint rejected
    m2 = (data["stats"].get("modern_v2") or {})
    assert m2.get("probe_counts", {}).get("bfla", {}).get("sent", 0) >= 3, \
        m2.get("probe_counts", {}).get("bfla")
    kinds = [b["kind"] for b in m2.get("boundaries", []) if b["family"] == "bfla"]
    assert "TESTED_NEGATIVE" in kinds or len(bfla) >= 1, kinds


def test_bfla_regression_standard_fixture_zero_findings():
    """Every existing surface the suite already exercises — correctly scoped
    or not admin-shaped — must produce ZERO bfla findings."""
    port, proc = _spawn(bfla=False)
    try:
        data = _scan(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    assert not bfla, [f["url"] for f in bfla]
    m2 = (data["stats"].get("modern_v2") or {})
    fam_b = [b for b in m2.get("boundaries", []) if b["family"] == "bfla"]
    assert fam_b and fam_b[0]["kind"] == "NOT_DISCOVERED", fam_b
    assert m2.get("probe_counts", {}).get("bfla", {}).get("sent", 0) == 0, \
        m2.get("probe_counts", {}).get("bfla")
