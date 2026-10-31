"""RFC 8439 §2.8.2 official test vector for the proof-layer AEAD.

External correctness anchor for the pyca/cryptography ChaCha20Poly1305
primitive that replaced the hand-rolled ChaCha20 block function +
Poly1305 MAC on 2026-10-30. The vector below is copied verbatim from
RFC 8439 §2.8.2 (the "sunscreen" message). Byte-for-byte agreement is
the pass bar; rejection behavior (IntegrityError on tamper, structural
ValidationError on bad key/nonce lengths) is pinned as-is.
"""
import pytest

from burhan.proof import (IntegrityError, ValidationError,
                            chacha20poly1305_decrypt,
                            chacha20poly1305_encrypt)

# ---- RFC 8439 §2.8.2: the official AEAD test vector ------------------------
KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f")
NONCE = bytes.fromhex("070000004041424344454647")
AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
PLAINTEXT = (b"Ladies and Gentlemen of the class of '99: If I could "
             b"offer you only one tip for the future, sunscreen would "
             b"be it.")
CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116")
TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
EXPECTED = CIPHERTEXT + TAG


class TestRfc8439OfficialVector:
    def test_encrypt_official_vector(self):
        assert chacha20poly1305_encrypt(KEY, NONCE, PLAINTEXT, AAD) == EXPECTED

    def test_decrypt_official_vector(self):
        assert chacha20poly1305_decrypt(KEY, NONCE, EXPECTED, AAD) == PLAINTEXT

    def test_roundtrip_arbitrary_input(self):
        pt = bytes(range(256)) * 3
        ct = chacha20poly1305_encrypt(KEY, NONCE, pt, b"")
        assert chacha20poly1305_decrypt(KEY, NONCE, ct, b"") == pt

    def test_output_shape_ct_plus_16_byte_tag(self):
        ct = chacha20poly1305_encrypt(KEY, NONCE, PLAINTEXT, AAD)
        assert len(ct) == len(PLAINTEXT) + 16
        assert ct[-16:] == TAG


class TestRejectionBehavior:
    def test_tag_tamper_rejected_integrity_error(self):
        tampered = EXPECTED[:-1] + bytes([EXPECTED[-1] ^ 1])
        with pytest.raises(IntegrityError):
            chacha20poly1305_decrypt(KEY, NONCE, tampered, AAD)

    def test_ciphertext_tamper_rejected(self):
        tampered = bytes([EXPECTED[0] ^ 1]) + EXPECTED[1:]
        with pytest.raises(IntegrityError):
            chacha20poly1305_decrypt(KEY, NONCE, tampered, AAD)

    def test_wrong_aad_rejected(self):
        with pytest.raises(IntegrityError):
            chacha20poly1305_decrypt(KEY, NONCE, EXPECTED, AAD + b"x")

    def test_wrong_key_rejected(self):
        with pytest.raises(IntegrityError):
            chacha20poly1305_decrypt(bytes(32), NONCE, EXPECTED, AAD)

    def test_short_ciphertext_rejected(self):
        with pytest.raises(IntegrityError):
            chacha20poly1305_decrypt(KEY, NONCE, b"tooshort", AAD)

    def test_structural_rejection_unchanged(self):
        with pytest.raises(ValidationError):
            chacha20poly1305_encrypt(b"short", NONCE, b"x", b"")
        with pytest.raises(ValidationError):
            chacha20poly1305_encrypt(KEY, b"shortnonce", b"x", b"")
        with pytest.raises(ValidationError):
            chacha20poly1305_encrypt(KEY, NONCE, b"x", "not-bytes")
