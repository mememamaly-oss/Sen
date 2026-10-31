"""Transparency-log gate (public-readiness order PART 4A.3, 2026-10-31).

Permanent CI version of the tamper battery:
  1. an untampered signed bundle + log verifies TRUE through the
     INDEPENDENT verifier (subprocess — zero shared code);
  2. a single-character tamper of the evidence is REJECTED;
  3. a single-character tamper of the signature is REJECTED;
  4. a single-character tamper of the Merkle path is REJECTED;
  5. an entry signed with a DIFFERENT keypair is REJECTED under the
     pinned public key;
  6. the independent verifier provably never imports the signer's code;
  7. a real committed scan report verifies through the independent
     verifier's report mode (dogfoods the audit recipe on a real
     artifact every run).
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from transparency_selftest import run_battery  # noqa: E402


def test_tamper_battery(tmp_path):
    results = run_battery(tmp_path / "battery")
    cases = results["cases"]
    assert cases["case_1_untampered"]["pass"], \
        "untampered bundle must verify: " + cases["case_1_untampered"]["verifier_output"]
    for name in ("case_2_tamper_evidence", "case_3_tamper_signature",
                 "case_4_tamper_merkle_path", "case_5_different_keypair"):
        assert cases[name]["pass"], \
            f"{name} must be rejected: " + cases[name]["verifier_output"]
    assert results["all_pass"]


def test_independent_verifier_never_imports_burhan():
    """The whole point of the independent verifier is that it shares NO
    code with the signer. Guard that property forever."""
    src = (ROOT / "tools" / "independent_verify.py").read_text(encoding="utf-8")
    for forbidden in ("import burhan", "from burhan", "import append_transparency",
                      "from append_transparency", "import transparency_selftest",
                      "from transparency_selftest"):
        assert forbidden not in src, \
            f"independent_verify.py must never contain {forbidden!r}"


def test_committed_real_report_verifies_independently():
    """The committed canonical fixture report is a REAL signed artifact;
    the independent verifier must confirm its audit block every run."""
    report = ROOT / "evidence" / "full-reverify" / "fixtures-vulnapp" / "scan.json"
    assert report.is_file(), "committed evidence report is missing"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "independent_verify.py"),
         "verify-report", str(report)],
        capture_output=True, text=True, cwd=str(ROOT))
    assert proc.returncode == 0, \
        "independent verification of the committed report failed:\n" + proc.stdout
    assert "PASSED" in proc.stdout
