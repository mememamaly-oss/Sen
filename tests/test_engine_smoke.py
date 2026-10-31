"""ENGINE SMOKE TESTS — fixtures boot, live scan, doctor (audit 2026-10-23).

Proves the restored fixture actually serves, the engine scans it end-to-end
with allow_private (the lab/demo path), and the engine doctor reports no
FAIL. All traffic is loopback-only inside the test process.
"""
import json
import os
import subprocess
import sys
import socket
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
    ready = False
    for _ in range(60):
        if proc.poll() is not None:
            pytest.fail("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            ready = True
            break
        except OSError:
            time.sleep(0.25)
    if not ready:
        proc.terminate()
        pytest.fail("vulnapp never became reachable")
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_vulnapp_serves_index(vulnapp):
    import urllib.request
    with urllib.request.urlopen(vulnapp + "/", timeout=5) as r:
        assert r.status == 200
        body = r.read().decode("utf-8", "replace")
        assert len(body) > 100  # a real page, not an error stub


def test_engine_scan_smoke_on_fixture(vulnapp, tmp_path):
    """End-to-end: the SaaS bridge invokes the engine with exactly this
    policy shape (allow_private for the loopback demo target). A short scan
    must complete, return a result dict, and find the fixture's known
    vulnerable surface."""
    from burhan.orchestrator import BurhanScanner, ScanConfig

    cfg = ScanConfig(
        allow_private=True,   # loopback fixture = the demo-target policy
        max_pages=6,          # quick smoke, not the full 40-page benchmark
        timeout=8.0,
    )
    scanner = BurhanScanner(vulnapp, cfg)
    data = scanner.run()
    assert isinstance(data, dict)
    findings = data.get("findings", [])
    types = {f.get("type") for f in findings}
    assert data.get("run_id"), "engine must produce a run id"
    # the fixture's front page alone guarantees these passive findings
    assert "missing_security_headers" in types
    assert len(findings) >= 3, f"expected a meaningful smoke yield, got {len(findings)}"
    # store the result like the SaaS layer does (result.json contract)
    (tmp_path / "result.json").write_text(json.dumps(data))


def test_doctor_no_failures():
    """The engine doctor must report zero FAIL (WARN allowed: browser env)."""
    from burhan.orchestrator import doctor
    report = doctor()
    checks = report["checks"] if isinstance(report, dict) and "checks" in report else report
    fails = [c for c in checks if c.get("status") == "FAIL"]
    assert not fails, f"doctor reported FAIL: {json.dumps(fails, ensure_ascii=False)[:400]}"
    assert len(checks) >= 17, f"expected >=17 doctor checks, got {len(checks)}"
