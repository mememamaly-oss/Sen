#!/usr/bin/env python3
"""The transparency-log tamper battery (format v1).

Five REAL checks, each producing checkable artifacts:

  case 1  an untampered signed bundle + log verifies TRUE through the
          independent verifier (tools/independent_verify.py, subprocess —
          zero code shared with the signer);
  case 2  a single-character tamper of the EVIDENCE (one byte of a
          finding's non-volatile field) is REJECTED;
  case 3  a single-character tamper of the SIGNATURE (one hex digit) is
          REJECTED;
  case 4  a single-character tamper of the MERKLE PATH (one hex digit of
          one sibling hash) is REJECTED;
  case 5  an entry signed with a DIFFERENT keypair — otherwise well-formed,
          correctly hashed, correctly chained — is REJECTED because the
          verifier pins the project's published public key.

Run directly to produce the evidence artifacts:
  python3 tools/transparency_selftest.py --out evidence/transparency-log/selftest

The pytest wrapper (tests/test_transparency_log.py) runs the same battery
into a temp directory on every CI run — the gate is permanent.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from append_transparency import (  # noqa: E402
    GENESIS_PREV, build_entry, write_bundle)

VERIFIER = ROOT / "tools" / "independent_verify.py"


def _synthetic_report() -> dict:
    """Three findings; one carries nested volatile keys (duration/notes)
    to prove the declared volatile set is stripped before hashing on both
    sides."""
    return {
        "run_id": "run-selftest0001",
        "seed": "selftest-seed-" + "0" * 32,
        "scanner": "burhan-selftest/1",
        "target": "synthetic://selftest",
        "findings": [
            {"id": "F-syn000001", "type": "sql_injection", "severity": "critical",
             "status": "verified", "confidence": 0.99, "method": "GET",
             "url": "http://synthetic.test/items?sort=name", "parameter": "sort",
             "duration": 0.123, "notes": "volatile — must not move the root"},
            {"id": "F-syn000002", "type": "xss_reflected", "severity": "high",
             "status": "verified", "confidence": 0.95, "method": "GET",
             "url": "http://synthetic.test/search?q=a", "parameter": "q",
             "evidence": ["<script>alert(1)</script>"]},
            {"id": "F-syn000003", "type": "open_redirect", "severity": "medium",
             "status": "verified", "confidence": 0.9, "method": "GET",
             "url": "http://synthetic.test/go?next=/home", "parameter": "next"},
        ],
        "audit": None,
    }


def _sign_into(out_dir: Path, seed_hex: str, pubkey_file: Path,
               log_file: Path) -> Path:
    """Sign the synthetic report with the given key; write bundle + a
    one-entry log; write the pinned pubkey file."""
    report = _synthetic_report()
    entry = build_entry(report, "selftest:synthetic", seed_hex, GENESIS_PREV,
                        evidence_path="evidence/transparency-log/selftest/case-1")
    bundle = write_bundle(out_dir, report, entry)
    log_file.write_text(json.dumps(entry, sort_keys=True) + "\n",
                        encoding="utf-8")
    pubkey_file.parent.mkdir(parents=True, exist_ok=True)
    pubkey_file.write_text(entry["public_key"] + "\n", encoding="utf-8")
    return bundle


def _run_verifier(*args) -> dict:
    cmd = [sys.executable, str(VERIFIER), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    return {"rc": proc.returncode, "output": (proc.stdout + proc.stderr).strip()}


def _flip_one_char(s: str, position: int) -> str:
    """Replace the character at `position` with a DIFFERENT hex digit —
    a single-character tamper that keeps the string well-formed."""
    replacement = "1" if s[position] != "1" else "2"
    return s[:position] + replacement + s[position + 1:]


def run_battery(out_dir: Path) -> dict:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    # ephemeral keys — the battery never touches the real project key
    seed_a = "11" * 32
    seed_b = "22" * 32

    results: dict = {"tool": str(VERIFIER), "cases": {}}

    # ---- case 1: untampered verifies TRUE
    case1 = out_dir / "case-1-untampered"
    bundle1 = _sign_into(case1, seed_a, case1 / "pubkey.hex",
                         case1 / "log.jsonl")
    v_log = _run_verifier("verify-log", str(case1 / "log.jsonl"),
                          "--pubkey", str(case1 / "pubkey.hex"))
    v_bun = _run_verifier("verify-bundle", str(bundle1),
                          "--pubkey", str(case1 / "pubkey.hex"),
                          "--log", str(case1 / "log.jsonl"))
    results["cases"]["case_1_untampered"] = {
        "expectation": "verify-log rc==0 AND verify-bundle rc==0",
        "rc_log": v_log["rc"], "rc_bundle": v_bun["rc"],
        "verifier_output": v_bun["output"],
        "pass": v_log["rc"] == 0 and v_bun["rc"] == 0,
    }

    def tampered_case(name: str, mutate) -> dict:
        case_dir = out_dir / name
        case_dir.mkdir(parents=True)
        shutil.copytree(bundle1, case_dir / "bundle")
        shutil.copy2(case1 / "log.jsonl", case_dir / "log.jsonl")
        shutil.copy2(case1 / "pubkey.hex", case_dir / "pubkey.hex")
        mutate(case_dir / "bundle")
        r = _run_verifier("verify-bundle", str(case_dir / "bundle"),
                          "--pubkey", str(case_dir / "pubkey.hex"),
                          "--log", str(case_dir / "log.jsonl"))
        return {"expectation": "verify-bundle rc==1 (tamper rejected)",
                "rc": r["rc"], "verifier_output": r["output"],
                "pass": r["rc"] == 1}

    # ---- case 2: single-character tamper of the EVIDENCE
    def tamper_evidence(bundle: Path) -> None:
        f = json.loads((bundle / "findings.json").read_text(encoding="utf-8"))
        url = f["findings"][0]["url"]
        f["findings"][0]["url"] = _flip_one_char(url, len(url) - 1)
        (bundle / "findings.json").write_text(json.dumps(f), encoding="utf-8")
    results["cases"]["case_2_tamper_evidence"] = \
        tampered_case("case-2-tamper-evidence", tamper_evidence)

    # ---- case 3: single-character tamper of the SIGNATURE
    def tamper_signature(bundle: Path) -> None:
        e = json.loads((bundle / "entry.json").read_text(encoding="utf-8"))
        e["signature"] = _flip_one_char(e["signature"], 0)
        (bundle / "entry.json").write_text(json.dumps(e), encoding="utf-8")
        # the log still carries the original entry — the mismatch must be caught
    results["cases"]["case_3_tamper_signature"] = \
        tampered_case("case-3-tamper-signature", tamper_signature)

    # ---- case 4: single-character tamper of the MERKLE PATH
    def tamper_path(bundle: Path) -> None:
        p = json.loads((bundle / "inclusion_proofs.json").read_text(encoding="utf-8"))
        p["proofs"][0]["path"][0]["sibling"] = \
            _flip_one_char(p["proofs"][0]["path"][0]["sibling"], 0)
        (bundle / "inclusion_proofs.json").write_text(json.dumps(p), encoding="utf-8")
    results["cases"]["case_4_tamper_merkle_path"] = \
        tampered_case("case-4-tamper-merkle-path", tamper_path)

    # ---- case 5: DIFFERENT keypair, otherwise well-formed
    case5 = out_dir / "case-5-different-key"
    bundle5 = _sign_into(case5, seed_b, case5 / "pubkey-B.hex",
                         case5 / "log-with-B.jsonl")
    # pin key A (the published key) while the entry was signed with key B
    shutil.copy2(case1 / "pubkey.hex", case5 / "pubkey.hex")
    r5 = _run_verifier("verify-bundle", str(bundle5),
                       "--pubkey", str(case5 / "pubkey.hex"),
                       "--log", str(case5 / "log-with-B.jsonl"))
    results["cases"]["case_5_different_keypair"] = {
        "expectation": ("verify-bundle rc==1 (entry signed with a different "
                        "keypair is rejected under the pinned key)"),
        "rc": r5["rc"], "verifier_output": r5["output"], "pass": r5["rc"] == 1,
    }

    results["all_pass"] = all(c["pass"] for c in results["cases"].values())
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, required=True,
                    help="evidence output directory")
    args = ap.parse_args()
    results = run_battery(args.out)

    (args.out / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = [
        "# Transparency-log tamper battery — results",
        "",
        f"Independent verifier: `tools/independent_verify.py` (subprocess; "
        f"zero code shared with the signer).",
        "",
        "| case | expectation | result |",
        "|---|---|---|",
    ]
    for name, case in results["cases"].items():
        rc = case.get("rc", case.get("rc_bundle"))
        lines.append(f"| {name} | {case['expectation']} | "
                     f"{'PASS' if case['pass'] else 'FAIL'} (rc={rc}) |")
    lines += ["", f"**All checks passed: {results['all_pass']}**", "",
              "Reproduce: `python3 tools/transparency_selftest.py --out <dir>`"]
    (args.out / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    for name, case in results["cases"].items():
        print(f"{'PASS' if case['pass'] else 'FAIL'}  {name} (rc="
              f"{case.get('rc', case.get('rc_bundle'))})")
    print(f"ALL PASS: {results['all_pass']}")
    return 0 if results["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
