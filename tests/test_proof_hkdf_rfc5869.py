"""RFC 5869 Appendix A official test vectors for the proof-layer HKDF.

External correctness anchor for the pyca/cryptography HKDF / HKDFExpand
classes (and the library HMAC used for the standalone extract step) that
replaced the hand-rolled extract/expand loop on 2026-10-30. A.1-A.3 are
copied verbatim from RFC 5869 Appendix A. Byte-for-byte agreement is the
pass bar; the declared length bounds (1..255*32, ValidationError) are
pinned unchanged.
"""
import pytest

from sentinel.proof import (ValidationError, hkdf_sha256, hkdf_sha256_expand,
                            hkdf_sha256_extract)

# ---- RFC 5869 A.1: basic test case (SHA-256) --------------------------------
A1 = {
    "ikm": b"\x0b" * 22,
    "salt": bytes.fromhex("000102030405060708090a0b0c"),
    "info": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    "l": 42,
    "prk": bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    "okm": bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"),
}

# ---- RFC 5869 A.2: longer inputs/outputs (SHA-256) ---------------------------
A2 = {
    "ikm": bytes(range(0x00, 0x50)),
    "salt": bytes(range(0x60, 0xB0)),
    "info": bytes(range(0xB0, 0x100)),
    "l": 82,
    "prk": bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
    "okm": bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
}

# ---- RFC 5869 A.3: zero-length salt/info (SHA-256) ---------------------------
A3 = {
    "ikm": b"\x0b" * 22,
    "salt": b"",
    "info": b"",
    "l": 42,
    "prk": bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
    "okm": bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"),
}


class TestRfc5869OfficialVectors:
    @pytest.mark.parametrize("v", [A1, A2, A3], ids=["A.1", "A.2", "A.3"])
    def test_extract(self, v):
        assert hkdf_sha256_extract(v["salt"], v["ikm"]) == v["prk"]

    @pytest.mark.parametrize("v", [A1, A2, A3], ids=["A.1", "A.2", "A.3"])
    def test_expand_from_official_prk(self, v):
        assert hkdf_sha256_expand(v["prk"], v["info"], v["l"]) == v["okm"]

    @pytest.mark.parametrize("v", [A1, A2, A3], ids=["A.1", "A.2", "A.3"])
    def test_full_extract_then_expand(self, v):
        assert hkdf_sha256(v["ikm"], v["salt"], v["info"], v["l"]) == v["okm"]


class TestDeclaredBoundsUnchanged:
    def test_zero_length_rejected(self):
        with pytest.raises(ValidationError):
            hkdf_sha256(A1["ikm"], A1["salt"], A1["info"], 0)

    def test_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            hkdf_sha256(A1["ikm"], A1["salt"], A1["info"], 255 * 32 + 1)

    def test_expand_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            hkdf_sha256_expand(A1["prk"], b"", 255 * 32 + 1)

    def test_max_length_accepted(self):
        okm = hkdf_sha256(A1["ikm"], A1["salt"], b"", 255 * 32)
        assert len(okm) == 255 * 32

    def test_non_int_length_rejected(self):
        with pytest.raises(ValidationError):
            hkdf_sha256(A1["ikm"], A1["salt"], A1["info"], "42")
