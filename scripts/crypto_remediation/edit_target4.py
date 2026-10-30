"""TARGET 4 — sentinel/vault.py: replace the hand-rolled ChaCha20 stream
cipher + separate HMAC-SHA256 MAC/KDF (encrypt-then-MAC) with the
cryptography library's ChaCha20Poly1305 AEAD primitive. Chosen over
"ChaCha20 primitive + separate HMAC" because the {nonce, ct, tag}
envelope shape maps 1:1 onto the AEAD output with no caller changes.
Also updates sentinel/orchestrator.py's doctor self-test, which imported
the hand-rolled _quarter_round (must go with it).
"""
import sys

PATH = "sentinel/vault.py"
ORCH = "sentinel/orchestrator.py"

s = open(PATH, encoding="utf-8").read()

HDR_CHA = "# ============================================================ ChaCha20 (RFC 8439)"
END_MARK = "def _b64e(b: bytes) -> str:"

if s.count(HDR_CHA) != 1 or s.count(END_MARK) != 1:
    print("ABORT: vault.py section markers not found exactly once")
    sys.exit(1)
for probe in ("_chacha20_block", "_quarter_round", "def chacha20_xor"):
    if probe not in s:
        print(f"ABORT: expected hand-rolled piece {probe!r} missing")
        sys.exit(1)

NEW_BLOCK = '''# ============================================================ authenticated AEAD
# 2026-10-30: the hand-rolled ChaCha20 stream cipher + separate
# HMAC-SHA256 MAC (encrypt-then-MAC) were replaced by the ChaCha20Poly1305
# AEAD primitive from the cryptography library (pyca) — one audited call
# instead of hand-assembled parts. The storage envelope keeps the
# {nonce, ct, tag} shape, but the tag is now the 16-byte Poly1305 tag
# (was a 32-byte HMAC tag), so vault files written by the previous
# implementation fail authentication explicitly and can no longer be
# decrypted. The RFC 8439 §2.8.2 known-answer vector for this AEAD is
# pinned in crypto_selftest() (called by the doctor) and in
# tests/test_vault_aead_rfc8439.py. The domain-separated subkey
# derivation (_derive, stdlib hmac) is unchanged — it is not a
# hand-rolled primitive.


def _derive(master: bytes, label: str) -> bytes:
    """Domain-separated subkey derivation from the 256-bit blob key."""
    return hmac.new(master, f"sentinel-vault/1/{label}".encode(),
                    hashlib.sha256).digest()


def aead_encrypt(master: bytes, aad: str, plaintext: bytes) -> dict:
    """AEAD under the enc subkey of `master`. Returns {nonce, ct, tag}."""
    nonce = os.urandom(12)
    ct_tag = ChaCha20Poly1305(_derive(master, "enc")).encrypt(
        nonce, plaintext, aad.encode())
    return {"nonce": nonce, "ct": ct_tag[:-16], "tag": ct_tag[-16:]}


def aead_decrypt(master: bytes, aad: str, envelope: dict) -> bytes:
    """Verify-then-decrypt. ANY tamper (ct, tag, aad, truncation) -> VaultError."""
    try:
        nonce, ct, tag = envelope["nonce"], envelope["ct"], envelope["tag"]
    except (KeyError, TypeError):
        raise VaultError("malformed envelope")
    if not (isinstance(nonce, bytes) and isinstance(ct, bytes)
            and isinstance(tag, bytes)):
        raise VaultError("malformed envelope")
    try:
        return ChaCha20Poly1305(_derive(master, "enc")).decrypt(
            nonce, ct + tag, aad.encode())
    except InvalidTag:
        raise VaultError("authentication failed: wrong key or tampered data")


# RFC 8439 §2.8.2 — the official AEAD known-answer vector, verbatim.
_KAT_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f")
_KAT_NONCE = bytes.fromhex("070000004041424344454647")
_KAT_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_KAT_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer "
           b"you only one tip for the future, sunscreen would be it.")
_KAT_EXPECTED = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "61161ae10b594f09e26a7e902ecbd0600691")


def crypto_selftest() -> None:
    """Known-answer test: RFC 8439 §2.8.2 through the very AEAD primitive
    used for storage — any drift raises VaultError (the doctor calls this)."""
    aead = ChaCha20Poly1305(_KAT_KEY)
    got = aead.encrypt(_KAT_NONCE, _KAT_PT, _KAT_AAD)
    if got != _KAT_EXPECTED:
        raise VaultError("RFC 8439 2.8.2 AEAD known-answer mismatch")
    if aead.decrypt(_KAT_NONCE, got, _KAT_AAD) != _KAT_PT:
        raise VaultError("RFC 8439 2.8.2 AEAD roundtrip failed")


'''

start = s.index(HDR_CHA)
end = s.index(END_MARK)
old_len = end - start
s = s[:start] + NEW_BLOCK + s[end:]

# ---- imports ----------------------------------------------------------------
OLD_IMP = '''from typing import Any, Callable
'''
NEW_IMP = '''from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
'''
if s.count(OLD_IMP) != 1:
    print("ABORT: vault.py import anchor not found exactly once")
    sys.exit(1)
s = s.replace(OLD_IMP, NEW_IMP)

# ---- module docstring (the wrap/blob description) -----------------------------
OLD_DS = '''where each wrap = ChaCha20(wrap_key(keyfile, salt), nonce) over the 32-byte
blob key K, and blob = ChaCha20(enc_key(K), nonce) over the JSON payload
{records: [...], audit: [...]}.'''
NEW_DS = '''where each wrap = ChaCha20-Poly1305 AEAD under wrap_key(keyfile, salt) over
the 32-byte blob key K, and blob = ChaCha20-Poly1305 AEAD under enc_key(K)
over the JSON payload {records: [...], audit: [...]} (library AEAD since
2026-10-30; tags are 16-byte Poly1305 — files written by the previous
hand-rolled ChaCha20+HMAC scheme no longer decrypt).'''
if s.count(OLD_DS) != 1:
    print("ABORT: vault.py module docstring anchor not found exactly once")
    sys.exit(1)
s = s.replace(OLD_DS, NEW_DS)

# ---- post-conditions on vault.py ----------------------------------------------
for gone in ("_chacha20_block", "_quarter_round", "chacha20_xor", "_rotl",
             "_CHACHA_CONSTANTS", "def _mac(", "_mac("):
    if gone in s:
        print(f"ABORT: residual hand-rolled reference {gone!r} still in vault.py")
        sys.exit(1)
for needed in ("ChaCha20Poly1305(", "InvalidTag", "crypto_selftest"):
    if needed not in s:
        print(f"ABORT: expected library reference {needed!r} missing from vault.py")
        sys.exit(1)

open(PATH, "w", encoding="utf-8").write(s)
print(f"TARGET 4 vault.py: hand-rolled ChaCha20+MAC block ({old_len} chars) "
      f"-> library AEAD block ({len(NEW_BLOCK)} chars)")

# ================= orchestrator.py: doctor self-test ============================
o = open(ORCH, encoding="utf-8").read()

OLD_DOC = '''    # Credential Vault (Phase 57): crypto self-test — RFC 8439 quarter-round
    # vector, AEAD roundtrip, tamper rejection, purge leaves no plaintext.
    try:
        import tempfile as _tf, os as _os2
        from .vault import Vault, VaultError, keygen, _quarter_round
        w = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
        _quarter_round(w, 0, 1, 2, 3)
        assert w == [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb], \\
            "ChaCha20 quarter-round vector mismatch"'''
NEW_DOC = '''    # Credential Vault (Phase 57): crypto self-test — RFC 8439 §2.8.2 AEAD
    # known-answer vector through the library primitive, vault roundtrip,
    # purge leaves no plaintext.
    try:
        import tempfile as _tf, os as _os2
        from .vault import Vault, VaultError, keygen, crypto_selftest
        crypto_selftest()   # RFC 8439 §2.8.2 KAT via the storage AEAD'''
if o.count(OLD_DOC) != 1:
    print("ABORT: orchestrator.py doctor block not found exactly once")
    sys.exit(1)
o = o.replace(OLD_DOC, NEW_DOC)

OLD_MSG = '"ChaCha20+HMAC encrypt-then-MAC OK; audit + purge leave no plaintext"'
NEW_MSG = ('"ChaCha20-Poly1305 AEAD (cryptography) OK; '
           'audit + purge leave no plaintext"')
if o.count(OLD_MSG) != 1:
    print("ABORT: orchestrator.py doctor success message not found exactly once")
    sys.exit(1)
o = o.replace(OLD_MSG, NEW_MSG)

if "_quarter_round" in o:
    print("ABORT: _quarter_round still referenced in orchestrator.py")
    sys.exit(1)

open(ORCH, "w", encoding="utf-8").write(o)
print("TARGET 4 orchestrator.py: doctor self-test now calls crypto_selftest() "
      "(RFC 8439 §2.8.2 KAT); hand-rolled quarter-round import removed")
