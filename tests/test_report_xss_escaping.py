"""ENGINE REPORT XSS ESCAPING (owner order 2026-10-31, part 2.3).

Findings carry data produced by the SCANNED TARGET (a malicious target can
plant arbitrary strings in reflected evidence, URLs, parameters). The
engine's HTML and GLASS reports embed those strings — this test proves they
are ALWAYS HTML-escaped, never raw. The SaaS report viewer additionally
renders them inside a sandbox="" iframe (covered by the browser proof), so
this is defense in depth layer 2 of 3 (React auto-escaping is layer 3).
"""
import re

import pytest

from burhan.report import build_html, build_glass_html
from burhan.store import Store

PAYLOAD = "<script>window.__engineReportPwned=1</script>"
ATTR_PAYLOAD = "<img src=x onerror='window.__attrPwned=1'>"


@pytest.fixture()
def poisoned_store(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    store.save_run({
        "run_id": "run-xss-proof",
        "scanner": "burhan-test",
        "target": "https://target.invalid/?q=" + PAYLOAD,
        "stats": {"duration": 1.0, "requests": 3, "verified": 2,
                  "coverage": {"discovered": 2, "tested": 2, "untested": 0,
                               "skip_reasons": {PAYLOAD: 1}}},
        "findings": [
            {
                "id": "F-xss0000001",
                "type": "xss_reflected",
                "severity": "high",
                "status": "verified",
                "url": "https://target.invalid/search?q=" + PAYLOAD,
                "parameter": PAYLOAD,
                "method": "GET",
                "confidence": 0.9,
                "risk": 70,
                "evidence": [{"kind": PAYLOAD, "detail": "reflection: " + PAYLOAD + " " + ATTR_PAYLOAD}],
                "verification": {"method": PAYLOAD, "passed": True},
            },
            {
                "id": "F-xss0000002",
                "type": PAYLOAD,
                "severity": "medium",
                "status": "verified",
                "url": PAYLOAD,
                "parameter": ATTR_PAYLOAD,
                "method": "POST",
                "confidence": 0.8,
                "risk": 50,
                "evidence": [{"kind": "body", "detail": ATTR_PAYLOAD}],
                "verification": {"method": "replay", "passed": True},
            },
        ],
        "rejected_candidates": [],
    })
    return store


def _raw_payload_present(html: str) -> bool:
    # a RAW payload means the <script> tag itself (or the onerror attribute)
    # appears unescaped in the document — escaped forms appear as &lt;script&gt;
    return bool(re.search(r"<script>window\.__engineReportPwned", html)) or bool(
        re.search(r"onerror='window\.__attrPwned", html))


def test_html_report_escapes_every_target_controlled_string(poisoned_store):
    html = build_html(poisoned_store, "run-xss-proof")
    assert _raw_payload_present(html) is False, "raw <script>/onerror survived into the HTML report"
    # and the escaped form IS present (the data is shown, safely)
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=" in html


def test_glass_report_escapes_every_target_controlled_string(poisoned_store):
    glass = build_glass_html(poisoned_store, "run-xss-proof")
    assert _raw_payload_present(glass) is False, "raw <script>/onerror survived into the GLASS report"
    assert "&lt;script&gt;" in glass
