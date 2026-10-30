"""TARGET 3 — sentinel/audit.py: replace the second, independent
hand-rolled HKDF-SHA256 loop (_hkdf_sha256, feeding derive_keypair) with
cryptography's HKDF class. Interface unchanged; output byte-identical
(both constructions are RFC 5869 — pinned by tests + pre-swap snapshot).
"""
import sys

PATH = "sentinel/audit.py"

s = open(PATH, encoding="utf-8").read()

# ---- 1. the hand-rolled loop --------------------------------------------------
OLD_FN = '''def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract-then-expand), stdlib hmac only."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()           # Extract
    t, okm, counter = b"", b"", 1                              # Expand
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]'''
NEW_FN = '''def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract-then-expand) via cryptography's HKDF
    class since 2026-10-30 (was an independent stdlib-hmac loop — the
    second hand-rolled HKDF in the tree). Output is byte-identical to the
    previous implementation: verified against RFC 5869 A.1-A.3 and the
    pre-swap keypair snapshot in tests/test_audit_hkdf_rfc5869.py, so the
    same seed still derives the same Ed25519 keypair."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)'''
if s.count(OLD_FN) != 1:
    print("ABORT: hand-rolled _hkdf_sha256 not found exactly once")
    sys.exit(1)
s = s.replace(OLD_FN, NEW_FN)

# ---- 2. imports ----------------------------------------------------------------
import re
if re.search(r"\bhmac\.(new|compare_digest|digest)\b", s):
    print("ABORT: stdlib hmac still called in audit.py — check before removing")
    sys.exit(1)

OLD_IMP = '''import base64
import hashlib
import hmac
import json
import os

from .proof import (ValidationError as _VE, ed25519_public_key,
                     ed25519_sign, merkle_root)'''
NEW_IMP = '''import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .proof import (ValidationError as _VE, ed25519_public_key,
                     ed25519_sign, merkle_root)'''
if s.count(OLD_IMP) != 1:
    print("ABORT: audit.py import block not found exactly once")
    sys.exit(1)
s = s.replace(OLD_IMP, NEW_IMP)

# ---- 3. docstrings / comments ----------------------------------------------------
OLD_C1 = '''  - the deterministic keypair derivation is HKDF-SHA256 (RFC 5869, stdlib
    hmac) over the full >=32-byte seed material (ORD-001-REMAND RT-03/RT-04).'''
NEW_C1 = '''  - the deterministic keypair derivation is HKDF-SHA256 (RFC 5869,
    cryptography's HKDF class since 2026-10-30, byte-identical output) over
    the full >=32-byte seed material (ORD-001-REMAND RT-03/RT-04).'''
if s.count(OLD_C1) != 1:
    print("ABORT: module docstring HKDF line not found exactly once")
    sys.exit(1)
s = s.replace(OLD_C1, NEW_C1)

OLD_C2 = '''#   * the KEYPAIR is derived by HKDF-SHA256 (RFC 5869, stdlib hmac) over the
#     FULL seed material + a domain-separated versioned salt — the legacy'''
NEW_C2 = '''#   * the KEYPAIR is derived by HKDF-SHA256 (RFC 5869, via cryptography's
#     HKDF class — output byte-identical to the stdlib-hmac loop it
#     replaced on 2026-10-30) over the FULL seed material + a
#     domain-separated versioned salt — the legacy'''
if s.count(OLD_C2) != 1:
    print("ABORT: §3 comment HKDF line not found exactly once")
    sys.exit(1)
s = s.replace(OLD_C2, NEW_C2)

# ---- post-conditions -----------------------------------------------------------
for gone in ("while len(okm)", "import hmac", "hmac.new"):
    if gone in s:
        print(f"ABORT: residual hand-rolled reference {gone!r} still present")
        sys.exit(1)
if "HKDF(algorithm=hashes.SHA256()" not in s:
    print("ABORT: library HKDF call missing")
    sys.exit(1)

open(PATH, "w", encoding="utf-8").write(s)
print("TARGET 3 edit applied: _hkdf_sha256 -> cryptography HKDF; "
      "imports + 2 doc lines updated; stdlib hmac import removed")
