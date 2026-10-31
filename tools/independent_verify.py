#!/usr/bin/env python3
"""Independent verifier for the Sen transparency log and signed reports.

WHY THIS FILE EXISTS, AND WHY IT IMPORTS NOTHING FROM `sentinel`
----------------------------------------------------------------
The point of a transparency log is that a third party can verify Sen's
signed scan results while trusting NOTHING about this project — not its
maintainers, and deliberately not its own code. A verifier that imports
the signer's modules would share any bug the signer has: if the signer
hashes the wrong bytes, a same-code verifier would happily confirm the
wrong bytes. This file therefore reimplements the published wire format
from scratch (docs/transparency-log-format.md) using only the Python
standard library and the `cryptography` package (the same audited
library the signer uses for the Ed25519 primitive itself — the primitive
is not what we are trying to be independent of; the hashing, the
canonical form, the Merkle construction and the chain ARE).

It verifies, with zero code shared with the signer:

  1. every transparency-log entry: content hash, chain linkage, and the
     Ed25519 signature under the project's PUBLISHED public key;
  2. every evidence bundle: each finding hashes to the leaf it claims,
     every inclusion proof folds to the entry's Merkle root, counts
     match, and the entry itself is the one in the log;
  3. any enriched scan report (`audit` block): the Merkle root over the
     canonical findings and the per-run Ed25519 signature derived from
     the public run seed (the recipe embedded in every report).

Exit codes: 0 = everything verified; 1 = verification failure (reasons
printed); 2 = usage / IO error.

Usage:
  python3 tools/independent_verify.py verify-log  <log.jsonl> --pubkey <pubkey.hex> [--json]
  python3 tools/independent_verify.py verify-bundle <bundle-dir> --pubkey <pubkey.hex> [--log <log.jsonl>] [--json]
  python3 tools/independent_verify.py verify-report <result.json> [--json]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

# ============================================================ format constants
# Source of truth: docs/transparency-log-format.md (format v1). The values
# below are transcribed from that specification — NOT imported from the
# signing code.
FORMAT_VERSION = 1
GENESIS_PREV = "0" * 64

# The declared volatile key set: removed recursively at every depth before
# any hashing (timing-bearing data must never move a Merkle root).
VOLATILE_KEYS = frozenset({
    "notes", "duration", "duration_s", "wall_time", "wall", "elapsed",
    "timestamp", "dur_s", "latency", "latency_ms", "time_ms", "time",
    "generated_at", "date", "stats", "requests", "started_at",
    "finished_at", "verified_at",
})

# sha256(b"") — the declared empty-set Merkle root.
EMPTY_ROOT_HEX = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca"
                  "495991b7852b855")

# Report-level audit key derivation (the recipe embedded in every report):
# HKDF-SHA256 over the run seed with a versioned, domain-separated salt.
AUDIT_HKDF_SALT = b"SENTINEL-axis14-ed25519-HKDF-SHA256-v1"
AUDIT_HKDF_INFO = b"axis14-ed25519-keypair"

ENTRY_CORE_FIELDS = (
    "version", "kind", "run_id", "scanner", "target", "label", "seed",
    "findings_count", "merkle_root", "timestamp_ms", "evidence",
    "prev_entry_hash",
)


class VerificationFailure(Exception):
    """A check did not pass — the message is safe to print (no secret data)."""


# ============================================================ primitives
def canonical_json(obj) -> str:
    """Canonical JSON: sorted keys, compact separators, UTF-8, no escapes
    of non-ASCII (the exact form the spec hashes)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def strip_volatile(obj):
    """Remove the declared volatile keys recursively at every depth."""
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items()
                if k not in VOLATILE_KEYS}
    if isinstance(obj, (list, tuple)):
        return [strip_volatile(x) for x in obj]
    return obj


def canonical_finding(finding: dict) -> str:
    return canonical_json(strip_volatile(finding))


def finding_leaf(finding: dict) -> bytes:
    return hashlib.sha256(canonical_finding(finding).encode("utf-8")).digest()


def merkle_root_from_findings(findings) -> str:
    """Leaf(i)=sha256(canonical(finding_i)); node=sha256(L||R); when a
    level has an ODD count its last hash is duplicated once. The empty
    set has the declared constant root sha256(b'')."""
    findings = list(findings or [])
    if not findings:
        return EMPTY_ROOT_HEX
    level = [finding_leaf(f) for f in findings]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def fold_proof(leaf_hash: bytes, path) -> str:
    """Fold an inclusion proof ([{"side","sibling"}...] leaf->root) and
    return the resulting root as hex."""
    cur = leaf_hash
    for step in path:
        side = step.get("side")
        sib = bytes.fromhex(step.get("sibling", ""))
        if len(sib) != 32:
            raise VerificationFailure(
                f"sibling hash is not 32 bytes (got {len(sib)})")
        if side == "L":        # sibling is the LEFT operand
            cur = hashlib.sha256(sib + cur).digest()
        elif side == "R":      # sibling is the RIGHT operand
            cur = hashlib.sha256(cur + sib).digest()
        else:
            raise VerificationFailure(f"unknown proof side {side!r}")
    return cur.hex()


def ed25519_verify(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
        return True
    except Exception:
        return False


def entry_core(entry: dict) -> dict:
    try:
        return {k: entry[k] for k in ENTRY_CORE_FIELDS}
    except KeyError as exc:
        raise VerificationFailure(f"entry missing field {exc}") from None


def entry_hash_of(entry: dict) -> str:
    return hashlib.sha256(
        canonical_json(entry_core(entry)).encode("utf-8")).hexdigest()


def _is_hex(s, length=None) -> bool:
    if not isinstance(s, str):
        return False
    if length is not None and len(s) != length:
        return False
    return all(c in "0123456789abcdef" for c in s)


# ============================================================ log verification
def verify_log(log_path: Path, pubkey: bytes) -> dict:
    """Verify the whole log: per-entry structure, chain linkage, pinned
    public key, and Ed25519 signature over each entry hash."""
    entries = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VerificationFailure(
                    f"line {lineno}: not valid JSON ({exc})") from None
            if not isinstance(entry, dict):
                raise VerificationFailure(f"line {lineno}: entry is not an object")
            entries.append((lineno, entry))
    if not entries:
        return {"entries": 0, "message": "log is empty (nothing to verify)"}

    prev_hash = GENESIS_PREV
    for lineno, entry in entries:
        where = f"line {lineno} (run_id={entry.get('run_id', '?')})"
        if entry.get("version") != FORMAT_VERSION:
            raise VerificationFailure(
                f"{where}: unsupported version {entry.get('version')!r}")
        if entry.get("kind") != "scan-run":
            raise VerificationFailure(f"{where}: unknown kind")
        if not _is_hex(entry.get("merkle_root"), 64):
            raise VerificationFailure(f"{where}: merkle_root not 64-hex")
        if not isinstance(entry.get("findings_count"), int) \
                or entry["findings_count"] < 0:
            raise VerificationFailure(f"{where}: bad findings_count")
        if not isinstance(entry.get("timestamp_ms"), int):
            raise VerificationFailure(f"{where}: bad timestamp_ms")
        if entry.get("prev_entry_hash") != prev_hash:
            raise VerificationFailure(
                f"{where}: chain broken — prev_entry_hash does not match "
                f"the previous entry's hash")
        recomputed = entry_hash_of(entry)
        if entry.get("entry_hash") != recomputed:
            raise VerificationFailure(
                f"{where}: entry_hash mismatch — content was modified")
        if entry.get("public_key") != pubkey.hex():
            raise VerificationFailure(
                f"{where}: public_key is not the pinned project key")
        if not _is_hex(entry.get("signature"), 128):
            raise VerificationFailure(f"{where}: signature not 128-hex")
        ok = ed25519_verify(pubkey, bytes.fromhex(entry["signature"]),
                            bytes.fromhex(recomputed))
        if not ok:
            raise VerificationFailure(
                f"{where}: Ed25519 signature does not verify under the "
                f"pinned public key")
        prev_hash = recomputed

    return {"entries": len(entries), "head": prev_hash,
            "message": (f"chain + signatures verified for "
                        f"{len(entries)} entries")}


# ============================================================ bundle verification
def verify_bundle(bundle_dir: Path, pubkey: bytes,
                  log_path: Path | None = None) -> dict:
    """Verify an evidence bundle end-to-end against its log entry."""
    def load(name):
        p = bundle_dir / name
        if not p.is_file():
            raise VerificationFailure(f"missing bundle file: {name}")
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    findings_doc = load("findings.json")
    entry = load("entry.json")
    proofs_doc = load("inclusion_proofs.json")
    meta = load("report_meta.json")

    findings = findings_doc.get("findings")
    if not isinstance(findings, list):
        raise VerificationFailure("findings.json: 'findings' must be a list")
    proofs = proofs_doc.get("proofs")
    if not isinstance(proofs, list):
        raise VerificationFailure("inclusion_proofs.json: 'proofs' must be a list")

    # -- entry structure, pinned key, signature
    if entry.get("version") != FORMAT_VERSION:
        raise VerificationFailure("entry version unsupported")
    recomputed = entry_hash_of(entry)
    if entry.get("entry_hash") != recomputed:
        raise VerificationFailure("entry_hash mismatch — entry content modified")
    if entry.get("public_key") != pubkey.hex():
        raise VerificationFailure("entry public_key is not the pinned project key")
    if not ed25519_verify(pubkey, bytes.fromhex(entry["signature"]),
                          bytes.fromhex(recomputed)):
        raise VerificationFailure("entry signature invalid under pinned key")

    # -- count consistency
    if entry.get("findings_count") != len(findings):
        raise VerificationFailure(
            f"findings_count mismatch: entry says {entry.get('findings_count')}, "
            f"bundle has {len(findings)}")

    # -- leaves + inclusion proofs
    if len(proofs) != len(findings):
        raise VerificationFailure(
            f"proof count {len(proofs)} != findings count {len(findings)}")
    root = entry["merkle_root"]
    for i, (finding, proof) in enumerate(zip(findings, proofs)):
        if not isinstance(finding, dict):
            raise VerificationFailure(f"finding[{i}] is not an object")
        if proof.get("index") != i:
            raise VerificationFailure(
                f"proof[{i}]: index field is {proof.get('index')!r}")
        fid = finding.get("id")
        if "finding_id" in proof and proof["finding_id"] != fid:
            raise VerificationFailure(
                f"proof[{i}]: finding_id {proof['finding_id']!r} != finding "
                f"id {fid!r}")
        leaf = finding_leaf(finding)
        if proof.get("leaf_hash") != leaf.hex():
            raise VerificationFailure(
                f"proof[{i}]: leaf hash mismatch — finding content does not "
                f"hash to the claimed leaf")
        folded = fold_proof(leaf, proof.get("path", []))
        if folded != root:
            raise VerificationFailure(
                f"proof[{i}]: inclusion path folds to {folded[:16]}… not the "
                f"entry's merkle_root")

    # -- meta consistency
    for field in ("run_id", "seed", "scanner", "target", "findings_count",
                  "merkle_root"):
        if str(meta.get(field)) != str(entry.get(field)):
            raise VerificationFailure(
                f"report_meta.{field} ({meta.get(field)!r}) != entry "
                f"({entry.get(field)!r})")

    # -- the report's own audit block (independent re-verification)
    audit = meta.get("audit")
    if audit is not None:
        verify_audit_block(meta, findings, audit)

    # -- log cross-check
    log_msg = "no log given — entry verified standalone"
    if log_path is not None:
        log_result = verify_log(log_path, pubkey)
        if log_result.get("entries", 0) == 0:
            raise VerificationFailure("the transparency log is empty — "
                                      "the bundle's entry is not in it")
        with open(log_path, "r", encoding="utf-8") as fh:
            log_entries = [json.loads(l) for l in fh if l.strip()]
        match = [e for e in log_entries
                 if e.get("run_id") == entry.get("run_id")]
        if not match:
            raise VerificationFailure(
                f"run_id {entry.get('run_id')!r} is not present in the log")
        if match[0].get("entry_hash") != entry.get("entry_hash"):
            raise VerificationFailure(
                "the log's entry for this run_id is NOT the bundle's entry "
                "(different entry_hash)")
        log_msg = (f"entry found and chain-verified in the log "
                   f"({log_result['entries']} entries)")

    return {
        "run_id": entry.get("run_id"),
        "findings": len(findings),
        "merkle_root": root,
        "message": (f"{len(findings)} findings: leaves + inclusion proofs + "
                    f"entry signature verified; {log_msg}"),
    }


# ============================================================ report verification
def _seed_material(seed) -> bytes:
    """The published seed-to-key-material rule (audit recipe): a >=64-char
    even-length ASCII hex string decodes as hex; any other string uses its
    UTF-8 bytes when >=32 bytes; anything shorter is rejected."""
    if seed is None:
        raise VerificationFailure("report has no seed (unseeded reports make "
                                  "no reproducibility claim)")
    s = str(seed).strip()
    if (len(s) >= 64 and len(s) % 2 == 0 and s.isascii()
            and all(c in "0123456789abcdefABCDEF" for c in s)):
        return bytes.fromhex(s)
    raw = s.encode("utf-8")
    if len(raw) >= 32:
        return raw
    raise VerificationFailure(
        f"seed too short ({len(raw)} bytes < 32) — not valid key material")


def _audit_header(report: dict) -> str:
    header = {"run_id": str(report.get("run_id", "")),
              "seed": str(report.get("seed", "")),
              "scanner": str(report.get("scanner", "")),
              "target": str(report.get("target", ""))}
    return canonical_json(header)


def derive_audit_public_key(seed) -> bytes:
    """The per-run Ed25519 public key: HKDF-SHA256 over the public run
    seed (versioned, domain-separated), per the recipe in every report."""
    ikm = _seed_material(seed)
    priv = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=AUDIT_HKDF_SALT, info=AUDIT_HKDF_INFO).derive(ikm)
    return Ed25519PrivateKey.from_private_bytes(priv).public_key() \
        .public_bytes(serialization.Encoding.Raw,
                      serialization.PublicFormat.Raw)


def verify_audit_block(report: dict, findings, audit: dict) -> None:
    """The per-run audit block: root over canonical findings + Ed25519 over
    sha256(run_id \\0 root \\0 count \\0 header_canonical) with the keypair
    HKDF-derived from the PUBLIC run seed."""
    root = merkle_root_from_findings(findings)
    if root != audit.get("merkle_root"):
        raise VerificationFailure(
            f"recomputed Merkle root {root[:16]}… != audit.merkle_root "
            f"{str(audit.get('merkle_root'))[:16]}… — findings were modified")
    count = audit.get("findings_count")
    if count != len(findings):
        raise VerificationFailure(
            f"audit.findings_count {count} != actual {len(findings)}")
    header = _audit_header(report)
    for part in (str(report.get("run_id", "")), root, str(int(count)),
                 header):
        if "\x00" in part:
            raise VerificationFailure("NUL byte in a signed field")
    digest = hashlib.sha256(b"\x00".join(
        p.encode("utf-8") for p in
        [str(report.get("run_id", "")), root, str(int(count)),
         header])).digest()
    pub = derive_audit_public_key(report.get("seed"))
    embedded = base64.b64decode(audit.get("public_key_b64", ""))
    if pub != embedded:
        raise VerificationFailure(
            "derived public key != embedded public_key_b64 — seed does not "
            "match the signing key")
    sig = base64.b64decode(audit.get("signature_b64", ""))
    if not ed25519_verify(embedded, sig, digest):
        raise VerificationFailure("audit signature does not verify")


def verify_report(report_path: Path) -> dict:
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    audit = report.get("audit")
    if not isinstance(audit, dict):
        raise VerificationFailure("report has no audit block "
                                  "(not an enriched report)")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise VerificationFailure("report.findings must be a list")
    verify_audit_block(report, findings, audit)
    return {"run_id": report.get("run_id"),
            "findings": len(findings),
            "merkle_root": audit.get("merkle_root"),
            "message": (f"report audit block verified: Merkle root over "
                        f"{len(findings)} canonical findings + per-run "
                        f"Ed25519 signature")}


# ============================================================ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Independent verifier for Sen transparency log, "
                    "evidence bundles, and signed reports")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_log = sub.add_parser("verify-log", help="verify a transparency log")
    p_log.add_argument("log", type=Path)
    p_log.add_argument("--pubkey", type=Path, required=True,
                       help="file with the pinned project public key (64 hex)")
    p_log.add_argument("--json", action="store_true")

    p_bun = sub.add_parser("verify-bundle", help="verify an evidence bundle")
    p_bun.add_argument("bundle", type=Path)
    p_bun.add_argument("--pubkey", type=Path, required=True)
    p_bun.add_argument("--log", type=Path, default=None)
    p_bun.add_argument("--json", action="store_true")

    p_rep = sub.add_parser("verify-report", help="verify a report's audit block")
    p_rep.add_argument("report", type=Path)
    p_rep.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    def load_pubkey(p: Path) -> bytes:
        text = p.read_text(encoding="utf-8").strip()
        if not _is_hex(text, 64):
            raise VerificationFailure(
                f"{p}: expected 64 hex chars (Ed25519 public key), got "
                f"{len(text)} chars")
        return bytes.fromhex(text)

    try:
        if args.cmd == "verify-log":
            result = verify_log(args.log, load_pubkey(args.pubkey))
        elif args.cmd == "verify-bundle":
            result = verify_bundle(args.bundle, load_pubkey(args.pubkey),
                                   args.log)
        else:
            result = verify_report(args.report)
    except VerificationFailure as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"FAIL: {exc}")
            print(f"verification FAILED ({args.cmd})")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    payload = {"ok": True, **result}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=1))
    else:
        print(f"OK: {result['message']}")
        print(f"verification PASSED ({args.cmd})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
