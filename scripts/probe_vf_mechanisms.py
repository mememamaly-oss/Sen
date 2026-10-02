#!/usr/bin/env python3
"""VF mechanism probes (Task 7-e, 2026-10-03): direct code-level discrimination
between the FROZEN v4.1.1 engine and the v4.2.0 engine, on the three fixes the
bench-adv fixture CANNOT reach (and one it can, for cross-checking):

  probe          | what it calls                      | v4.1.1 expected | v4.2.0 expected
  ---------------+------------------------------------+-----------------+-----------------
  VF-01a         | verify(Finding(type=<UNLISTED>))   | VERIFIED  0.98  | CANDIDATE 0.30 (unverified:no-branch)
  VF-01b         | verify(Finding(type=ssrf), no OOB) | VERIFIED  0.98  | CANDIDATE 0.30 (unverified:blind-class-no-oob)
  VF-01c         | verify(Finding(type=missing_sec..))| VERIFIED  0.98  | VERIFIED   0.70 (conf honesty)
  VF-03          | verify(sql_injection) w/ stubbed   | VERIFIED  0.95  | REJECTED   0.15 (500B diff < 25%)
                 | replays: 200/4500B vs 200/4000B    |  (old: >200B)  |  (new: needs >max(200,25%))
  VF-04-no-proof | WorkflowEngine._finding(...)       | Finding with    | ValueError (proof REQUIRED)
                 |                                    | passed=True     |
  VF-04-bad-rule | _finding(proof={"rule":"bogus"})   | n/a (no proof   | ValueError (unknown rule)
                 |                                    |  protocol)      |

Usage:  python3 probe_vf_mechanisms.py v411|v420
Prints one JSON line per probe (machine-mergeable), exits 0.
The bench-level discrimination (VF-02 csrf/nosql) is proven separately by
scripts/bench_adv_v411_driver.py + the extended official bench.
"""
import json
import sys

BUILD = sys.argv[1] if len(sys.argv) > 1 else "v420"
ROOT = {"v411": "/home/z/my-project/build-v411",
        "v420": "/home/z/my-project/build-v420"}[BUILD]
sys.path.insert(0, ROOT)

from sentinel.core import (Evidence, Finding, FindingStatus, Severity,  # noqa: E402
                           Verification, EventBus)
from sentinel.intel import VerificationEngine                            # noqa: E402


class FakeBus:
    def emit(self, *a, **k):
        return {}


class FakeResp:
    def __init__(self, status, body):
        self.status, self.body, self.error = status, body, False

    @property
    def ok(self):
        return 200 <= self.status < 300

    def hop_location(self):
        return ""


def probe_vf01_unlisted():
    ve = VerificationEngine(engine=None, bus=FakeBus(), oast=None, browser=None)
    f = Finding(type="future_widget_scan", severity=Severity.MEDIUM,
                endpoint_url="http://t.local/x", parameter="p",
                evidence=[Evidence("presence", "some future detector fired", "req-1")])
    ve.verify(f, ep=None)
    return {"probe": "VF-01a-unlisted-type", "type": "future_widget_scan",
            "status": str(f.status), "confidence": f.confidence,
            "method": f.verification.method if f.verification else None,
            "passed": f.verification.passed if f.verification else None}


def probe_vf01_ssrf_no_oob():
    ve = VerificationEngine(engine=None, bus=FakeBus(), oast=None, browser=None)
    f = Finding(type="ssrf", severity=Severity.HIGH,
                endpoint_url="http://t.local/fetch", parameter="url",
                evidence=[Evidence("param_shape", "url param observed", "req-1")])
    ve.verify(f, ep=None)
    return {"probe": "VF-01b-ssrf-no-oob", "type": "ssrf",
            "status": str(f.status), "confidence": f.confidence,
            "method": f.verification.method if f.verification else None,
            "passed": f.verification.passed if f.verification else None}


def probe_vf01_passive_conf():
    ve = VerificationEngine(engine=None, bus=FakeBus(), oast=None, browser=None)
    f = Finding(type="missing_security_headers", severity=Severity.LOW,
                endpoint_url="http://t.local/", parameter="",
                evidence=[Evidence("header_absence", "no CSP", "req-1")])
    ve.verify(f, ep=None)
    return {"probe": "VF-01c-passive-confidence", "type": "missing_security_headers",
            "status": str(f.status), "confidence": f.confidence,
            "method": f.verification.method if f.verification else None}


def probe_vf03_path_a():
    ve = VerificationEngine(engine=None, bus=FakeBus(), oast=None, browser=None)

    def fake_replay(ep, p, value):
        # volatile-content page: TRUE probe 4500B, FALSE probe 4000B — a 500B
        # swing (11%) of dynamic content, same status, no errors, no redirects.
        if "1=1" in value and "1=2" not in value:
            return FakeResp(200, "A" * 4500)
        return FakeResp(200, "B" * 4000)

    ve._replay = fake_replay
    f = Finding(type="sql_injection", severity=Severity.CRITICAL,
                endpoint_url="http://t.local/items", parameter="id",
                evidence=[Evidence("param_shape", "numeric id", "req-1")])
    ve.verify(f, ep=None)
    return {"probe": "VF-03-path-a-mild-diff", "type": "sql_injection",
            "status": str(f.status), "confidence": f.confidence,
            "method": f.verification.method if f.verification else None,
            "passed": f.verification.passed if f.verification else None}


def probe_vf04_no_proof():
    from sentinel.workflow import WorkflowEngine
    try:
        f = WorkflowEngine._finding(
            "business_logic_duplicate_execution", "http://t.local/wf", "tid",
            Evidence("state_delta", "raw obs", "req-1"), "notes-here")
        return {"probe": "VF-04-no-proof", "outcome": "returned-finding",
                "stamped_passed": f.verification.passed if f.verification else None,
                "status": str(f.status)}
    except (ValueError, TypeError) as e:
        return {"probe": "VF-04-no-proof", "outcome": "raised",
                "error_type": type(e).__name__, "error": str(e)[:160]}


def probe_vf04_bad_rule():
    from sentinel.workflow import WorkflowEngine
    try:
        WorkflowEngine._finding(
            "business_logic_duplicate_execution", "http://t.local/wf", "tid",
            Evidence("state_delta", "raw obs", "req-1"), "notes-here",
            proof={"rule": "bogus-rule", "obs": {"ok": True}})
        return {"probe": "VF-04-bad-rule", "outcome": "returned-finding"}
    except (ValueError, TypeError) as e:
        return {"probe": "VF-04-bad-rule", "outcome": "raised",
                "error_type": type(e).__name__, "error": str(e)[:160]}


if __name__ == "__main__":
    for fn in (probe_vf01_unlisted, probe_vf01_ssrf_no_oob, probe_vf01_passive_conf,
               probe_vf03_path_a, probe_vf04_no_proof, probe_vf04_bad_rule):
        try:
            print(json.dumps({"engine": BUILD, **fn()}, ensure_ascii=False))
        except Exception as e:                                  # noqa: BLE001
            print(json.dumps({"engine": BUILD, "probe": fn.__name__,
                              "outcome": "exception", "error": f"{type(e).__name__}: {e}"}))
