#!/usr/bin/env python3
"""Signer side of the Sen transparency log (format v1).

Appends a signed entry for a completed scan run to
`transparency-log/log.jsonl` and writes the matching evidence bundle
under `evidence/transparency-log/<run_id>/`.

The signer is ALLOWED to use the engine's own primitives (sentinel.audit
+ sentinel.proof) — independence is the VERIFIER's job, and the verifier
(tools/independent_verify.py) deliberately shares no code with this file.
After every append this tool re-verifies its own output THROUGH the
independent verifier as a subprocess and rolls the append back if that
check fails.

Key management: the project signing seed (32 bytes, hex) is read from
--seed-hex or --seed-file (default: .transparency-seed at the repo root,
gitignored). The matching public key is committed at
transparency-log/pubkey.hex. Rotation procedure: docs/transparency-log-format.md.

Usage:
  # full append (writes bundle + appends to the log + independent re-check)
  python3 tools/append_transparency.py --report result.json \
      --label "fixture:vulnapp" --log transparency-log/log.jsonl \
      --bundle-root evidence/transparency-log

  # CI mode: produce the bundle + a standalone entry.json artifact,
  # do NOT touch the committed log (the entry is adopted later)
  python3 tools/append_transparency.py --report result.json \
      --label "fixture:vulnapp (CI)" --no-append \
      --seed-hex "$TRANSPARENCY_SEED" --out-entry entry.json \
      --bundle-root "$RUNNER_TEMP/t-bundle"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.audit import merkle_root_of_records  # noqa: E402
from sentinel.proof import ed25519_public_key, ed25519_sign, merkle_prove  # noqa: E402

FORMAT_VERSION = 1
GENESIS_PREV = "0" * 64
DEFAULT_SEED_FILE = ROOT / ".transparency-seed"
INDEPENDENT_VERIFIER = ROOT / "tools" / "independent_verify.py"


def _canonical(obj) -> str:
    """Canonical JSON — identical rules to the published format spec."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def load_log(path: Path) -> list[dict]:
    entries = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def build_entry(report: dict, label: str, seed_hex: str,
                prev_entry_hash: str, evidence_path: str,
                timestamp_ms: int | None = None) -> dict:
    """Build + sign one log entry for a finished scan run."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise SystemExit("report has no findings list — nothing to log")
    root = merkle_root_of_records(findings)
    audit = report.get("audit")
    if isinstance(audit, dict) and audit.get("merkle_root") not in (None, root):
        raise SystemExit(
            "report audit merkle_root does not match the recomputed root — "
            "the report's findings changed after signing; refusing to log")
    core = {
        "version": FORMAT_VERSION,
        "kind": "scan-run",
        "run_id": str(report.get("run_id", "")),
        "scanner": str(report.get("scanner", "")),
        "target": str(report.get("target", "")),
        "label": str(label),
        "seed": str(report.get("seed", "")),
        "findings_count": len(findings),
        "merkle_root": root,
        "timestamp_ms": int(time.time() * 1000) if timestamp_ms is None
                        else int(timestamp_ms),
        "evidence": evidence_path,
        "prev_entry_hash": prev_entry_hash,
    }
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise SystemExit("signing seed must be 32 bytes (64 hex chars)")
    entry_hash = hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()
    entry = dict(core)
    entry["entry_hash"] = entry_hash
    entry["signature"] = ed25519_sign(seed, bytes.fromhex(entry_hash)).hex()
    entry["public_key"] = ed25519_public_key(seed).hex()
    return entry


def build_proofs(findings) -> list[dict]:
    """One inclusion proof per finding, leaf order = findings order."""
    from sentinel.audit import canonical_finding
    leaves = [canonical_finding(f).encode("utf-8") for f in findings]
    proofs = []
    for i, finding in enumerate(findings):
        path = merkle_prove(leaves, i)
        proofs.append({
            "index": i,
            "finding_id": finding.get("id", ""),
            "leaf_hash": hashlib.sha256(leaves[i]).hexdigest(),
            "path": [{"side": side, "sibling": sib.hex()}
                     for side, sib in path],
        })
    return proofs


def write_bundle(bundle_dir: Path, report: dict, entry: dict) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    findings = report["findings"]
    (bundle_dir / "findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    (bundle_dir / "entry.json").write_text(
        json.dumps(entry, ensure_ascii=False, sort_keys=True, indent=1),
        encoding="utf-8")
    (bundle_dir / "inclusion_proofs.json").write_text(
        json.dumps({"proofs": build_proofs(findings)}, ensure_ascii=False),
        encoding="utf-8")
    (bundle_dir / "report_meta.json").write_text(
        json.dumps({
            "run_id": entry["run_id"], "seed": entry["seed"],
            "scanner": entry["scanner"], "target": entry["target"],
            "findings_count": entry["findings_count"],
            "merkle_root": entry["merkle_root"],
            "audit": report.get("audit"),
        }, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return bundle_dir


def verify_with_independent_tool(bundle_dir: Path, log_path: Path,
                                 pubkey_file: Path) -> tuple[int, str]:
    """Run the INDEPENDENT verifier (subprocess — zero shared code)."""
    cmd = [sys.executable, str(INDEPENDENT_VERIFIER), "verify-bundle",
           str(bundle_dir), "--pubkey", str(pubkey_file), "--log", str(log_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", required=True, type=Path,
                    help="the run's result.json (enriched report)")
    ap.add_argument("--label", required=True,
                    help="human tag, e.g. 'fixture:vulnapp' or 'juice-shop:20.3.0'")
    ap.add_argument("--log", type=Path, default=ROOT / "transparency-log/log.jsonl")
    ap.add_argument("--bundle-root", type=Path,
                    default=ROOT / "evidence/transparency-log")
    ap.add_argument("--seed-hex", default="",
                    help="64-hex signing seed (prefer --seed-file / CI secret)")
    ap.add_argument("--seed-file", type=Path, default=DEFAULT_SEED_FILE)
    ap.add_argument("--no-append", action="store_true",
                    help="write the bundle + entry only; do not touch the log")
    ap.add_argument("--out-entry", type=Path, default=None,
                    help="also write the entry JSON here (CI artifact)")
    args = ap.parse_args()

    seed_hex = args.seed_hex.strip() or (
        args.seed_file.read_text(encoding="utf-8").strip()
        if args.seed_file.is_file() else "")
    if not seed_hex:
        raise SystemExit("no signing seed: pass --seed-hex or create "
                         f"{DEFAULT_SEED_FILE} (see docs/transparency-log-format.md)")

    report = json.loads(args.report.read_text(encoding="utf-8"))
    run_id = str(report.get("run_id", ""))
    if not run_id:
        raise SystemExit("report has no run_id")

    existing = load_log(args.log)
    if any(e.get("run_id") == run_id for e in existing):
        raise SystemExit(f"run_id {run_id!r} is already in the log — "
                         "the log is append-only; refusing duplicates")

    prev = existing[-1]["entry_hash"] if existing else GENESIS_PREV
    bundle_dir = args.bundle_root / run_id
    try:
        evidence_path = f"{args.bundle_root.relative_to(ROOT)}/{run_id}"
    except ValueError:
        # bundle root outside the repository (CI artifact dir): the entry
        # still records the canonical in-repo location it will be adopted at
        evidence_path = f"evidence/transparency-log/{run_id}"

    entry = build_entry(report, args.label, seed_hex, prev, evidence_path)
    write_bundle(bundle_dir, report, entry)
    if args.out_entry:
        args.out_entry.parent.mkdir(parents=True, exist_ok=True)
        args.out_entry.write_text(
            json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8")

    if args.no_append:
        print(f"bundle written: {bundle_dir}")
        print(f"entry written: {args.out_entry or '(bundle/entry.json only)'}")
        print("log untouched (--no-append)")
        return 0

    # append (atomically: write temp + rename)
    tmp = args.log.with_suffix(".jsonl.tmp")
    tmp.write_text("".join(
        json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n"
        for e in existing + [entry]), encoding="utf-8")
    tmp.replace(args.log)

    # independent re-verification — roll back on any failure
    rc, out = verify_with_independent_tool(
        bundle_dir, args.log, ROOT / "transparency-log/pubkey.hex")
    if rc != 0:
        tmp = args.log.with_suffix(".jsonl.rollback")
        tmp.write_text("".join(
            json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n"
            for e in existing), encoding="utf-8")
        tmp.replace(args.log)
        print(f"ROLLBACK — independent verifier rejected the append:\n{out}")
        return 1
    print(f"OK: entry appended for {run_id} "
          f"(root={entry['merkle_root'][:16]}…, {entry['findings_count']} findings)")
    print(out.splitlines()[-2] if len(out.splitlines()) > 1 else out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
