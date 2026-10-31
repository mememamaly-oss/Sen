#!/usr/bin/env python3
"""Apply the AXIS-18 Ed25519 replacement order (STRICT FOLLOW-UP).

Replaces the hand-rolled point arithmetic and the "burhan-axis18/"
pre-hash prefix in burhan/symbolic/models.py with the audited
cryptography library, per RFC 8032, mirroring burhan/proof.py.

Idempotent: exits 0 without touching anything if already applied.
Generates the old-scheme fixture from the live pre-change module BEFORE
rewriting it, so the format change is pinned by a real artifact.
"""
import re
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "burhan" / "symbolic" / "models.py"
INIT = ROOT / "burhan" / "symbolic" / "__init__.py"
ORCH = ROOT / "burhan" / "orchestrator.py"
TEST = ROOT / "tests" / "test_symbolic_rfc8032.py"


def die(msg):
    print("FATAL: " + msg)
    sys.exit(1)


def replace_once(text, old, new, what):
    if old not in text:
        die("anchor not found for: " + what)
    return text.replace(old, new, 1)


# ------------------------------------------------------------------ 0. base
src = MODELS.read_text()
if "FORMAT CHANGE (2026-10-30)" in src:
    print("already applied — nothing to do")
    sys.exit(0)
if 'sha512(b"burhan-axis18/"' not in src:
    die("old axis-18 anchor missing — wrong base?")

# ------------------------------------------------- 1. old-scheme live fixture
OLD_SEED = b"doctor-selftest"
OLD_MSG = b"axis18-format-change-fixture-2026-10-30"
old_mod = types.ModuleType("old_axis18_models")
old_mod.__file__ = str(MODELS)
exec(compile(src, str(MODELS), "exec"), old_mod.__dict__)
old_pub, old_sig = old_mod.ed25519_sign(OLD_MSG, OLD_SEED)
if not old_mod.ed25519_verify(OLD_MSG, old_pub, old_sig):
    die("old-scheme fixture failed self-verify — refusing to proceed")
print("[fixture] old-scheme pub:", old_pub.hex())
print("[fixture] old-scheme sig:", old_sig.hex())

# ------------------------------------------------------------- 2. new section
NEW_SECTION = '''# ---------------------------------------------------------------- Ed25519
# FORMAT CHANGE (2026-10-30): signing now goes through the audited
# `cryptography` library (pyca) per standard RFC 8032 — the actual payload
# is signed directly, exactly as burhan/proof.py has since the
# 2026-10-30 integrity pass. The deleted "axis-18" variant derived keys
# via sha512(b"burhan-axis18/" + seed) with hand-rolled point arithmetic;
# because of that prefix, the SAME seed now yields a DIFFERENT key, and
# keys never mix across the two eras. Old axis-18 artifacts still verify
# against their embedded public key (the signature equation was already
# standard then) — but they can no longer be re-derived from their seed.
# No production artifact needed to remain verifiable under the old scheme
# (owner-confirmed 2026-10-30).

_DEFAULT_SEED = hashlib.sha256(b"burhan-axis18-default-seed").digest()
# 32-byte deterministic default (RFC 8032 keying). The pre-2026-10-30
# default was a 28-byte literal that only worked because the hand-rolled
# expansion absorbed any length; it is derived here once, and documented.


def _seed32(seed: bytes) -> bytes:
    """RFC 8032 keys a signature from a 32-byte seed. Legacy callers pass
    other lengths (engine run ids, the doctor selftest); those are
    normalized by a single SHA-256 — an input rule, not a signature-format
    rule. The ed25519_* layer below accepts nothing but 32 bytes, exactly
    like burhan/proof.py."""
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


'''

m_ed = re.search(r"(?m)^# -+ Ed25519\s*$", src)
m_sv = re.search(r"(?m)^# -+ sign/verify\s*$", src)
if not m_ed or not m_sv or not m_ed.start() < m_sv.start():
    die("section markers not found in models.py")
new_src = src[:m_ed.start()] + NEW_SECTION + src[m_sv.start():]

new_src = replace_once(
    new_src,
    "from __future__ import annotations\nimport hashlib\nimport json\n",
    "from __future__ import annotations\nimport hashlib\nimport json\n\n"
    "from cryptography.exceptions import InvalidSignature\n"
    "from cryptography.hazmat.primitives import serialization\n"
    "from cryptography.hazmat.primitives.asymmetric.ed25519 import (\n"
    "    Ed25519PrivateKey, Ed25519PublicKey)\n",
    "top-of-file cryptography imports")

new_src = replace_once(
    new_src,
    "evidence chain signer (Merkle-SHA256 root + Ed25519, RFC 8032, stdlib only).",
    "evidence chain signer (Merkle-SHA256 root + Ed25519, RFC 8032 via\n"
    "the audited cryptography library since 2026-10-30 — no hand-rolled\n"
    "point arithmetic, no pre-hash prefix).",
    "module docstring")

new_src = replace_once(
    new_src,
    '"""Build the evidence chain + Merkle root, then Ed25519-sign the result\n'
    '    in place. Deterministic for the same content and seed."""',
    '"""Build the evidence chain + Merkle root, then Ed25519-sign the result\n'
    '    in place. Deterministic for the same content and seed. Seeds that are\n'
    '    not 32 bytes are normalized by a single SHA-256 (_seed32); an empty\n'
    '    seed uses the module default. Signature format changed 2026-10-30."""',
    "sign_result docstring")

new_src = replace_once(
    new_src,
    'pub, sig = ed25519_sign(_signing_message(d), seed or b"burhan-axis18-default-seed")',
    'pub, sig = ed25519_sign(_signing_message(d), _seed32(seed or _DEFAULT_SEED))',
    "sign_result seed handling")

MODELS.write_text(new_src)
print("[edited] burhan/symbolic/models.py")

# ------------------------------------------------------------- 3. __init__.py
init = INIT.read_text()
init = replace_once(
    init,
    "from .models import (Constraint, Solution, Path, SymbolicResult,\n"
    "                     sign_result, verify_result_signature, merkle_root,\n"
    "                     ed25519_keypair, ed25519_sign, ed25519_verify,\n"
    "                     HONEST_BOUNDARIES)",
    "from .models import (Constraint, Solution, Path, SymbolicResult,\n"
    "                     sign_result, verify_result_signature, merkle_root,\n"
    "                     ed25519_sign, ed25519_verify,\n"
    "                     HONEST_BOUNDARIES)",
    "__init__ import list (ed25519_keypair removed — zero callers in tree)")
INIT.write_text(init)
print("[edited] burhan/symbolic/__init__.py (ed25519_keypair export dropped)")

# ----------------------------------------------------------- 4. orchestrator
orch = ORCH.read_text()
orch = replace_once(
    orch,
    "        # ---- AXIS-18 (ORD-003): symbolic execution analysis. OFF by default —\n"
    "        # without --symbolic the burhan/symbolic/ package is never imported,\n"
    "        # never invoked, sends nothing, and no section appears (bomb-tested in\n"
    "        # tests/test_axis18_symbolic.py; bench x3 zero-drift at the gate).",
    "        # ---- AXIS-18 (ORD-003): symbolic execution analysis. OFF by default —\n"
    "        # without --symbolic the burhan/symbolic/ package is never imported,\n"
    "        # never invoked, sends nothing, and no section appears (the historical\n"
    "        # bomb-test file tests/test_axis18_symbolic.py is not part of the\n"
    "        # current tree; the signing path is covered by\n"
    "        # tests/test_symbolic_rfc8032.py).",
    "orchestrator symbolic comment (stale test reference)")
orch = replace_once(
    orch,
    "    # AXIS-18 evidence signing: Merkle root + Ed25519 sign/verify round trip\n"
    "    # (RFC 8032 arithmetic, stdlib-only; externally verifiable signatures).",
    "    # AXIS-18 evidence signing: Merkle root + Ed25519 sign/verify round trip\n"
    "    # (RFC 8032 via the audited cryptography library; externally verifiable).",
    "doctor selftest comment (stdlib-only claim was stale)")
ORCH.write_text(orch)
print("[edited] burhan/orchestrator.py (2 stale comments)")

# --------------------------------------------------------------- 5. the test
TEST_TEMPLATE = '''"""RFC 8032 §7.1 official test vectors for the AXIS-18 signing path
(burhan/symbolic/models.py).

Parallel to tests/test_proof_rfc8032.py — the same three §7.1 vectors,
copied verbatim — for the second Ed25519 consumer, whose hand-rolled
point arithmetic and "burhan-axis18/" pre-hash prefix were removed on
2026-10-30 in favor of the audited cryptography library. Byte-for-byte
agreement with RFC 8032 is the pass bar.

OLD_SEED/OLD_MSG/OLD_PUB/OLD_SIG pin REAL output of the deleted scheme
(generated from the pre-2026-10-30 code before its removal): they
document the format change — the same seed now derives a different key,
while the old pair remains internally consistent.
"""
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey)

from burhan.symbolic.models import (
    Constraint, Solution, SymbolicResult, canonical_json, ed25519_sign,
    ed25519_verify, sign_result, verify_result_signature)

# ---- RFC 8032 §7.1: TEST 1 (empty message) — identical to test_proof_rfc8032
V1 = {
    "seed": ("9d61b19deffd5a60ba844af492ec2cc4"
             "4449c5697b326919703bac031cae7f60"),
    "pub": ("d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"),
    "msg": "",
    "sig": ("e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"),
}

# ---- RFC 8032 §7.1: TEST 2 (1-byte message 0x72) ---------------------------
V2 = {
    "seed": ("4ccd089b28ff96da9db6c346ec114e0f"
             "5b8a319f35aba624da8cf6ed4fb8a6fb"),
    "pub": ("3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c"),
    "msg": "72",
    "sig": ("92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"),
}

# ---- RFC 8032 §7.1: TEST 3 (2-byte message 0xaf82) -------------------------
V3 = {
    "seed": ("c5aa8df43f9f837bedb7442f31dcb7b1"
             "66d38535076f094b85ce3a2e0b4458f7"),
    "pub": ("fc51cd8e6218a1a38da47ed00230f058"
            "0816ed13ba3303ac5deb911548908025"),
    "msg": "af82",
    "sig": ("6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"),
}

VECTORS = [V1, V2, V3]

# ---- real output of the deleted axis-18 scheme (pre-2026-10-30 code) --------
OLD_SEED = b"doctor-selftest"
OLD_MSG = b"axis18-format-change-fixture-2026-10-30"
OLD_PUB = bytes.fromhex("__OLD_PUB__")
OLD_SIG = bytes.fromhex("__OLD_SIG__")


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_sign(v):
    seed, msg = bytes.fromhex(v["seed"]), bytes.fromhex(v["msg"])
    assert ed25519_sign(msg, seed) == (bytes.fromhex(v["pub"]),
                                       bytes.fromhex(v["sig"]))


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_verify_accepts(v):
    msg, pub = bytes.fromhex(v["msg"]), bytes.fromhex(v["pub"])
    assert ed25519_verify(msg, pub, bytes.fromhex(v["sig"])) is True


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_verify_rejects_tampered_message(v):
    pub = bytes.fromhex(v["pub"])
    msg = bytearray(bytes.fromhex(v["msg"]))
    sig = bytes.fromhex(v["sig"])
    if len(msg) == 0:
        tampered = b"x"
    else:
        msg[0] ^= 0x01
        tampered = bytes(msg)
    assert ed25519_verify(tampered, pub, sig) is False


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_verify_rejects_tampered_signature(v):
    msg, pub = bytes.fromhex(v["msg"]), bytes.fromhex(v["pub"])
    sig = bytearray(bytes.fromhex(v["sig"]))
    sig[0] ^= 0x01
    assert ed25519_verify(msg, pub, bytes(sig)) is False


def test_contract_rejects_non_32_byte_seed():
    with pytest.raises(ValueError):
        ed25519_sign(b"payload", b"not-thirty-two-bytes")


def test_sign_result_roundtrip_tamper_rejected():
    # mirrors the doctor selftest exactly (same 16-byte legacy seed)
    r = SymbolicResult(constraints=[Constraint("password", ">=", 8, "length",
                                               "len(password) >= 8")],
                       solution=Solution("password", "password123", "doctor"),
                       payload={"password": "password123"})
    sign_result(r, b"doctor-selftest")
    d = r.to_dict()
    assert verify_result_signature(d) is True
    d["payload"]["password"] = "tampered"
    assert verify_result_signature(d) is False
    d2 = r.to_dict()
    d2["evidence_chain"][0] = "00" * 32
    assert verify_result_signature(d2) is False


def test_sign_result_default_seed_is_deterministic():
    a = SymbolicResult(payload={"x": 1})
    sign_result(a)
    b = SymbolicResult(payload={"x": 1})
    sign_result(b)
    assert a.signature == b.signature


def test_sign_result_externally_verifiable_via_library_directly():
    r = SymbolicResult(payload={"password": "password123"})
    sign_result(r, b"doctor-selftest")
    d = r.to_dict()
    msg = canonical_json({k: d[k]
                           for k in d["signature"]["signed_fields"]}).encode("utf-8")
    pub = bytes.fromhex(d["signature"]["public_key"])
    sig = bytes.fromhex(d["signature"]["ed25519"])
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)  # raises on bad


def test_format_change_2026_10_30_same_seed_new_key():
    new_seed = hashlib.sha256(OLD_SEED).digest()  # what _seed32 derives
    new_pub, new_sig = ed25519_sign(OLD_MSG, new_seed)
    assert new_pub != OLD_PUB                        # same seed, different key
    assert ed25519_verify(OLD_MSG, OLD_PUB, OLD_SIG) is True   # old pair consistent
    assert ed25519_verify(OLD_MSG, new_pub, new_sig) is True   # new pair valid
    # cross-era: an old signature under the new key must fail, and vice versa
    assert ed25519_verify(OLD_MSG, new_pub, OLD_SIG) is False
    assert ed25519_verify(OLD_MSG, OLD_PUB, new_sig) is False
'''

TEST.write_text(TEST_TEMPLATE
                .replace("__OLD_PUB__", old_pub.hex())
                .replace("__OLD_SIG__", old_sig.hex()))
print("[created] tests/test_symbolic_rfc8032.py")

# ------------------------------------------------------------------ 6. proof
import ast
for f in (MODELS, INIT, ORCH, TEST):
    ast.parse(f.read_text())  # syntax gate
print("[verified] all four files parse")
print("APPLY OK")
