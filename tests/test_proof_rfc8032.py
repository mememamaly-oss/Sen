"""RFC 8032 §7.1 official test vectors for burhan.proof Ed25519.

The three vectors below are copied verbatim from RFC 8032 (Edwards-Curve
Digital Signature Algorithm), section 7.1 "Test Vectors for Ed25519".
They are the external correctness anchor for the library-backed
implementation (pyca/cryptography) that replaced the former hand-rolled
point arithmetic. Byte-for-byte agreement with RFC 8032 is the pass bar.
"""
import pytest

from burhan.proof import (ValidationError, ed25519_public_key,
                            ed25519_sign, ed25519_verify)

# ---- RFC 8032 §7.1: TEST 1 (empty message) ---------------------------------
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


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_public_key(v):
    seed = bytes.fromhex(v["seed"])
    assert ed25519_public_key(seed) == bytes.fromhex(v["pub"])


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_sign(v):
    seed = bytes.fromhex(v["seed"])
    msg = bytes.fromhex(v["msg"])
    assert ed25519_sign(seed, msg) == bytes.fromhex(v["sig"])


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_verify_accepts(v):
    pub = bytes.fromhex(v["pub"])
    msg = bytes.fromhex(v["msg"])
    sig = bytes.fromhex(v["sig"])
    assert ed25519_verify(sig, msg, pub) is True


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
    assert ed25519_verify(sig, tampered, pub) is False


@pytest.mark.parametrize("v", VECTORS, ids=["rfc8032-test1", "rfc8032-test2",
                                            "rfc8032-test3"])
def test_rfc8032_verify_rejects_tampered_signature(v):
    pub = bytes.fromhex(v["pub"])
    msg = bytes.fromhex(v["msg"])
    sig = bytearray(bytes.fromhex(v["sig"]))
    sig[0] ^= 0x01
    assert ed25519_verify(bytes(sig), msg, pub) is False


def test_contract_rejects_short_seed():
    with pytest.raises(ValidationError):
        ed25519_public_key(b"short")


def test_contract_rejects_bad_signature_length():
    pub = bytes.fromhex(V1["pub"])
    with pytest.raises(ValidationError):
        ed25519_verify(b"tooshort", b"", pub)
