"""AXIS-18 models — Constraint / Solution / Path / SymbolicResult + the
evidence chain signer (Merkle-SHA256 root + Ed25519, RFC 8032 via
the audited cryptography library since 2026-10-30 — no hand-rolled
point arithmetic, no pre-hash prefix).

Design invariants (supervisor-visible):
  * Pure data classes; no global mutable state; every field serializable.
  * The signature is EXTERNALLY verifiable: the public key rides in the
    result, the signed message is the canonical JSON of everything except
    the signature itself, and the Merkle root is recomputed from the
    evidence chain before the Ed25519 check — tampering any signed field,
    any evidence item, or the root itself fails verification.
  * Honest-boundary vocabulary is CLOSED and machine-readable (never free
    prose): unsatisfiable | contradiction | tautology |
    complex_solver_unavailable | untestable | blocked_by_planner_gate |
    untested_no_sender | verification_transport_error | no_constraints |
    unresolvable_reference.
"""
from __future__ import annotations
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

# ---------------------------------------------------------------- boundaries
BOUNDARY_UNSATISFIABLE = "unsatisfiable"          # a constraint SET has an empty interval
BOUNDARY_CONTRADICTION = "contradiction"          # ONE compound declaration defeats itself
BOUNDARY_TAUTOLOGY = "tautology"                  # x == x — any value satisfies
BOUNDARY_COMPLEX = "complex_solver_unavailable"   # non-linear / out of solver scope
BOUNDARY_UNTESTABLE = "untestable"                # declared but not machine-checkable
BOUNDARY_BLOCKED_PLANNER = "blocked_by_planner_gate"
BOUNDARY_NO_SENDER = "untested_no_sender"
BOUNDARY_TRANSPORT = "verification_transport_error"
BOUNDARY_NO_CONSTRAINTS = "no_constraints"
BOUNDARY_UNRESOLVABLE_REF = "unresolvable_reference"
HONEST_BOUNDARIES = (BOUNDARY_UNSATISFIABLE, BOUNDARY_CONTRADICTION, BOUNDARY_TAUTOLOGY,
                     BOUNDARY_COMPLEX, BOUNDARY_UNTESTABLE, BOUNDARY_BLOCKED_PLANNER,
                     BOUNDARY_NO_SENDER, BOUNDARY_TRANSPORT, BOUNDARY_NO_CONSTRAINTS,
                     BOUNDARY_UNRESOLVABLE_REF)


class Constraint:
    """One machine-checkable condition guarding an application path."""

    def __init__(self, var: str, op: str, value, kind: str, expr: str,
                 source: str = "declared", origin: str = "single", context: dict | None = None):
        self.var, self.op, self.value = var, op, value
        self.kind, self.expr = kind, expr          # kind: numeric|length|string|enum|tautology|complex|numeric_ref
        self.source = source                       # where it came from (error_message|status_differential|expression|declared)
        self.origin = origin                       # "single" | "compound:<full expr>" | "status_differential"
        self.context = context or {}               # {url, method, status, text} — Phase-4 verification anchor

    def to_dict(self) -> dict:
        return {"var": self.var, "op": self.op, "value": self.value, "kind": self.kind,
                "expr": self.expr, "source": self.source, "origin": self.origin}


class Solution:
    """A concrete value computed to satisfy one variable's constraints."""

    def __init__(self, var: str, value, method: str = "computed", note: str = ""):
        self.var, self.value, self.method, self.note = var, value, method, note

    def to_dict(self) -> dict:
        return {"var": self.var, "value": self.value, "method": self.method, "note": self.note}


class Path:
    """The application path a solution is computed to activate."""

    def __init__(self, description: str, expected_effect: str, constraints: list | None = None):
        self.description, self.expected_effect = description, expected_effect
        self.constraints = list(constraints or [])

    def to_dict(self) -> dict:
        return {"description": self.description, "expected_effect": self.expected_effect,
                "constraints": list(self.constraints)}


class SymbolicResult:
    """The signed unit of AXIS-18 output — constraint(s), computed solution,
    gated payload, verification verdict, evidence chain, honest boundary."""

    def __init__(self, constraints: list | None = None, solution: Solution | None = None,
                 payload: dict | None = None, path: Path | None = None, source: dict | None = None):
        self.constraints = list(constraints or [])
        self.solution, self.payload, self.path = solution, payload, path
        self.source = source or {}
        self.blocked: str | None = None            # gate reason (destructive value, planner class)
        self.verified: str | None = None           # activated | not_activated | transport_error | None
        self.evidence_chain: list[str] = []
        self.honest_boundary: str | None = None
        self.signature: dict | None = None

    def to_dict(self) -> dict:
        return {
            "constraint": [c.expr for c in self.constraints],      # the order-mandated key
            "solution": self.solution.to_dict() if self.solution else None,
            "payload": dict(self.payload) if self.payload else None,
            "path": self.path.to_dict() if self.path else None,
            "blocked": self.blocked,
            "verified": self.verified,
            "evidence_chain": list(self.evidence_chain),
            "honest_boundary": self.honest_boundary,
            "signature": dict(self.signature) if self.signature else None,
            "source": {"url": self.source.get("url", ""), "method": self.source.get("method", "GET"),
                       "status": self.source.get("status", 0), "note": self.source.get("note", "")},
        }


# ---------------------------------------------------------------- canonical
def canonical_json(obj) -> str:
    """Stable JSON for signing: sorted keys, tight separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    """Pairwise SHA-256 tree over hex digests; an odd level duplicates its
    last node (documented, deterministic, standard certificate-style rule)."""
    if not hashes:
        return _sha256_hex("")
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])).hexdigest()
                 for i in range(0, len(level), 2)]
    return level[0]


def _evidence_items(d: dict) -> list[str]:
    """The ordered evidence digests of one result dict — the Merkle leaves."""
    src = d.get("source") or {}
    return [
        _sha256_hex(canonical_json(d.get("constraint") or [])),
        _sha256_hex(canonical_json(d.get("solution"))),
        _sha256_hex(canonical_json(d.get("payload"))),
        _sha256_hex(canonical_json(d.get("path"))),
        _sha256_hex(canonical_json({"url": src.get("url", ""), "method": src.get("method", "GET"),
                                    "status": src.get("status", 0), "note": src.get("note", "")})),
        _sha256_hex(canonical_json({"blocked": d.get("blocked"), "verified": d.get("verified"),
                                    "honest_boundary": d.get("honest_boundary")})),
    ]


_SIGNED_FIELDS = ("constraint", "solution", "payload", "path", "blocked", "verified",
                  "honest_boundary", "evidence_chain", "source")


def _signing_message(d: dict) -> bytes:
    return canonical_json({k: d.get(k) for k in _SIGNED_FIELDS}).encode("utf-8")


# ---------------------------------------------------------------- Ed25519
# FORMAT CHANGE (2026-10-30): signing now goes through the audited
# `cryptography` library (pyca) per standard RFC 8032 — the actual payload
# is signed directly, exactly as sentinel/proof.py has since the
# 2026-10-30 integrity pass. The deleted "axis-18" variant derived keys
# via sha512(b"sentinel-axis18/" + seed) with hand-rolled point arithmetic;
# because of that prefix, the SAME seed now yields a DIFFERENT key, and
# keys never mix across the two eras. Old axis-18 artifacts still verify
# against their embedded public key (the signature equation was already
# standard then) — but they can no longer be re-derived from their seed.
# No production artifact needed to remain verifiable under the old scheme
# (owner-confirmed 2026-10-30).

_DEFAULT_SEED = hashlib.sha256(b"sentinel-axis18-default-seed").digest()
# 32-byte deterministic default (RFC 8032 keying). The pre-2026-10-30
# default was a 28-byte literal that only worked because the hand-rolled
# expansion absorbed any length; it is derived here once, and documented.


def _seed32(seed: bytes) -> bytes:
    """RFC 8032 keys a signature from a 32-byte seed. Legacy callers pass
    other lengths (engine run ids, the doctor selftest); those are
    normalized by a single SHA-256 — an input rule, not a signature-format
    rule. The ed25519_* layer below accepts nothing but 32 bytes, exactly
    like sentinel/proof.py."""
    if len(seed) == 32:
        return seed
    return hashlib.sha256(seed).digest()


def ed25519_sign(msg: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """Returns (public_key, signature) — standard RFC 8032 via the
    cryptography library. seed must be exactly 32 bytes; sign_result
    normalizes legacy lengths before calling in."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes (RFC 8032)")
    if not isinstance(msg, (bytes, bytearray)):
        raise ValueError("message must be bytes")
    priv = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub, priv.sign(bytes(msg))


def ed25519_verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- sign/verify
def sign_result(result: SymbolicResult, seed: bytes = b"") -> SymbolicResult:
    """Build the evidence chain + Merkle root, then Ed25519-sign the result
    in place. Deterministic for the same content and seed. Seeds that are
    not 32 bytes are normalized by a single SHA-256 (_seed32); an empty
    seed uses the module default. Signature format changed 2026-10-30."""
    d = result.to_dict()
    result.evidence_chain = _evidence_items(d)
    d["evidence_chain"] = list(result.evidence_chain)
    pub, sig = ed25519_sign(_signing_message(d), _seed32(seed or _DEFAULT_SEED))
    result.signature = {"algo": "ed25519-sha512-merkle", "public_key": pub.hex(),
                        "ed25519": sig.hex(), "merkle_root": merkle_root(result.evidence_chain),
                        "signed_fields": list(_SIGNED_FIELDS)}
    return result


def verify_result_signature(d: dict) -> bool:
    """External verification: recompute the Merkle root from the evidence
    chain, rebuild the canonical message, check the Ed25519 signature with
    the EMBEDDED public key. Any tampering anywhere fails."""
    try:
        sig = d.get("signature") or {}
        chain = d.get("evidence_chain") or []
        if sig.get("merkle_root") != merkle_root(chain):
            return False
        if _evidence_items(d) != list(chain):
            return False
        return ed25519_verify(_signing_message(d), bytes.fromhex(sig["public_key"]),
                              bytes.fromhex(sig["ed25519"]))
    except Exception:
        return False
