"""RFC 5869 A.1-A.3 vectors + keypair continuity for audit._hkdf_sha256.

The 2026-10-30 swap (an independent hand-rolled stdlib-hmac loop ->
cryptography's HKDF class) must be byte-identical: the RFC vectors pin
the construction, and the pinned keypairs below were captured from the
OLD implementation immediately before the swap — the same seeds must
keep deriving the same Ed25519 keypairs (nothing becomes unreproducible
from old seeds).
"""
import pytest

from burhan.audit import (SeedPolicyError, _hkdf_sha256, derive_keypair)

# ---- RFC 5869 Appendix A (SHA-256), verbatim --------------------------------
A1 = {
    "ikm": b"\x0b" * 22,
    "salt": bytes.fromhex("000102030405060708090a0b0c"),
    "info": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    "l": 42,
    "okm": bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"),
}
A2 = {
    "ikm": bytes(range(0x00, 0x50)),
    "salt": bytes(range(0x60, 0xB0)),
    "info": bytes(range(0xB0, 0x100)),
    "l": 82,
    "okm": bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
}
A3 = {
    "ikm": b"\x0b" * 22,
    "salt": b"",
    "info": b"",
    "l": 42,
    "okm": bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"),
}


class TestRfc5869OfficialVectors:
    def test_a1_basic(self):
        assert _hkdf_sha256(A1["ikm"], A1["salt"], A1["info"], A1["l"]) == A1["okm"]

    def test_a2_longer_inputs_outputs(self):
        assert _hkdf_sha256(A2["ikm"], A2["salt"], A2["info"], A2["l"]) == A2["okm"]

    def test_a3_zero_length_salt_info(self):
        assert _hkdf_sha256(A3["ikm"], A3["salt"], A3["info"], A3["l"]) == A3["okm"]


class TestKeypairContinuity:
    """Pinned from the pre-swap implementation (2026-10-30): the swap must
    not move a single byte of any derived keypair."""

    def test_seed_bytes_range_32(self):
        priv, pub = derive_keypair(bytes(range(32)))
        assert priv.hex() == (
            "95cee817c132da65ee228144ee6da2add31424ef4c5e1ed7420d4f54db37e268")
        assert pub.hex() == (
            "3cfa9d7f4901a94ec605c19ab57993b8b90eb83ec118bf5eea28fd413eec7164")

    def test_seed_hex_string(self):
        priv, pub = derive_keypair("ab" * 32)
        assert priv.hex() == (
            "f271ccc677e62f3a239a2d072221287e78f485e4310a1ff7f2056cbaf4896280")
        assert pub.hex() == (
            "8dc0202d78ad5199faf623b82ad19e1699738b4928918005cb6df09c3639b43c")

    def test_seed_policy_still_fail_closed(self):
        with pytest.raises(SeedPolicyError):
            derive_keypair(b"short-seed")
        with pytest.raises(SeedPolicyError):
            derive_keypair("2026-10-30")
