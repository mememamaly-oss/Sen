"""AXIS-18 models — Constraint / Solution / Path / SymbolicResult + the
evidence chain signer (Merkle-SHA256 root + Ed25519, RFC 8032, stdlib only).

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
# Compact RFC 8032 Ed25519 (the classic reference formulation), pure stdlib
# arithmetic. Sign/verify round-trips are covered by tests + doctor check.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("not a quadratic residue — point not on curve")
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)
_IDENT = (0, 1, 1, 0)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * _D * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalarmult(P, e: int):
    Q = _IDENT
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _encodepoint(P) -> bytes:
    x, y, z, _ = P
    zi = pow(z, _P - 2, _P)
    x, y = (x * zi) % _P, (y * zi) % _P
    return bytes([sum(((y >> (8 * i + j)) & 1) << j for j in range(8)) for i in range(31)]
                 + [sum(((y >> (248 + j)) & 1) << j for j in range(7)) | ((x & 1) << 7)])


def _decodepoint(s: bytes):
    y = int.from_bytes(s[:32], "little") & ((1 << 255) - 1)   # sign bit excluded
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _P - x
    P = (x, y, 1, (x * y) % _P)
    xs, ys, zs, ts = P
    # RFC 8032 curve: -x^2 + y^2 = 1 + d*x^2*y^2  ->  -x^2 + y^2 - z^2 - d*t^2 = 0
    if (-xs * xs + ys * ys - zs * zs - _D * ts * ts) % _P != 0:
        raise ValueError("decoded point not on curve")
    return P


def _affine(P):
    x, y, z, _ = P
    zi = pow(z, _P - 2, _P)
    return ((x * zi) % _P, (y * zi) % _P)


def _expanded_key(seed: bytes):
    h = hashlib.sha512(b"sentinel-axis18/" + seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    return a, h


def ed25519_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Deterministic (pub, priv32) from a seed — priv32 is the clamped scalar."""
    a, _ = _expanded_key(seed)
    return _encodepoint(_scalarmult(_B, a)), a.to_bytes(32, "little")


def ed25519_sign(msg: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """Returns (public_key, signature) — signature = R (32B) || s (32B)."""
    a, h = _expanded_key(seed)
    pub = _encodepoint(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(h[32:64] + msg).digest(), "little") % _L
    R = _encodepoint(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return pub, R + s.to_bytes(32, "little")


def ed25519_verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R, A = _decodepoint(sig[:32]), _decodepoint(pub)
    except Exception:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _affine(_scalarmult(_B, s)) == _affine(_edwards_add(R, _scalarmult(A, k)))


# ---------------------------------------------------------------- sign/verify
def sign_result(result: SymbolicResult, seed: bytes = b"") -> SymbolicResult:
    """Build the evidence chain + Merkle root, then Ed25519-sign the result
    in place. Deterministic for the same content and seed."""
    d = result.to_dict()
    result.evidence_chain = _evidence_items(d)
    d["evidence_chain"] = list(result.evidence_chain)
    pub, sig = ed25519_sign(_signing_message(d), seed or b"sentinel-axis18-default-seed")
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
