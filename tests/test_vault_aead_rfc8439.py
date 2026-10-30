"""RFC 8439 §2.8.2 anchor + storage-path checks for the vault AEAD.

2026-10-30: the hand-rolled ChaCha20 stream cipher + separate HMAC-SHA256
MAC were replaced by the cryptography library's ChaCha20Poly1305 AEAD.
crypto_selftest() runs the official §2.8.2 vector through the same
primitive used for storage; the other tests pin the storage path: shape,
tamper rejection, legacy-envelope rejection (old 32-byte-HMAC-tag files
must fail authentication explicitly), and a forced-nonce cross-check
proving aead_encrypt is exactly the library AEAD under _derive.
"""
import os

import pytest

import sentinel.vault as vault
from sentinel.vault import Vault, VaultError, _derive, crypto_selftest


def test_rfc8439_official_vector_selftest():
    crypto_selftest()   # raises VaultError on any drift from §2.8.2


def test_aead_roundtrip_and_envelope_shape():
    master = os.urandom(32)
    env = vault.aead_encrypt(master, "blob|test-org|7", b"payload" * 9)
    assert set(env) == {"nonce", "ct", "tag"}
    assert len(env["nonce"]) == 12
    assert len(env["tag"]) == 16          # Poly1305 tag (was 32-byte HMAC)
    assert vault.aead_decrypt(master, "blob|test-org|7", env) == b"payload" * 9


def test_tamper_rejected_every_field():
    master = os.urandom(32)
    env = vault.aead_encrypt(master, "aad", b"secret-value")
    for field in ("ct", "tag", "nonce"):
        bad = dict(env)
        bad[field] = bytes(b ^ 1 for b in bad[field])
        with pytest.raises(VaultError):
            vault.aead_decrypt(master, "aad", bad)


def test_wrong_aad_rejected():
    master = os.urandom(32)
    env = vault.aead_encrypt(master, "aad", b"secret-value")
    with pytest.raises(VaultError):
        vault.aead_decrypt(master, "other-aad", env)


def test_wrong_master_rejected():
    env = vault.aead_encrypt(os.urandom(32), "aad", b"secret-value")
    with pytest.raises(VaultError):
        vault.aead_decrypt(os.urandom(32), "aad", env)


def test_malformed_envelope_rejected():
    master = os.urandom(32)
    with pytest.raises(VaultError):
        vault.aead_decrypt(master, "aad", {})
    with pytest.raises(VaultError):
        vault.aead_decrypt(master, "aad",
                           {"nonce": "not-bytes", "ct": b"", "tag": b""})


def test_legacy_hmac_envelope_fails_authentication():
    """Files written by the old scheme (32-byte HMAC tag) must fail
    explicitly — never decrypt, never crash."""
    master = os.urandom(32)
    legacy = {"nonce": os.urandom(12), "ct": os.urandom(48),
              "tag": os.urandom(32)}      # old-format 32-byte tag
    with pytest.raises(VaultError):
        vault.aead_decrypt(master, "aad", legacy)


def test_storage_path_is_exactly_the_library_aead(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    master = os.urandom(32)
    forced = bytes(range(12))
    monkeypatch.setattr(
        vault.os, "urandom",
        lambda n, _f=forced: (_f + bytes(max(0, n - len(_f))))[:n])
    env = vault.aead_encrypt(master, "aad-x", b"probe")
    expect = ChaCha20Poly1305(_derive(master, "enc")).encrypt(
        forced, b"probe", b"aad-x")
    assert env["ct"] + env["tag"] == expect


def test_vault_end_to_end(tmp_path):
    kf = tmp_path / "k.json"
    vp = tmp_path / "v.vault"
    vault.keygen(str(kf), "test")
    v = Vault.init(str(vp), str(kf), "test-org")
    probe = "AKIA" + "D" * 16
    rid = v.store("aws_access_key", probe, {"url": "http://x/cfg"}, "critical")
    assert v.export(rid)["raw"] == probe
    v.purge(all_records=True)
    assert open(vp, "rb").read().count(probe.encode()) == 0
