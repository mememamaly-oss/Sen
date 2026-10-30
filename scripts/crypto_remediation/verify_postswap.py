"""POST-SWAP VERIFY (2026-10-30) — re-runs the exact pre-swap probes on the
swapped tree and enforces the declared continuity contract:

  byte-identical : audit keypairs, proof HKDF, proof AEAD, repro pipeline
  must-fail      : the captured OLD-scheme vault envelope (format change)
  fresh-ok       : a new-scheme vault envelope roundtrips (16-byte tag)

Exit code 0 = contract holds. Any drift prints the offending field.
"""
import hashlib
import json
import sys
from pathlib import Path

CAP = json.loads(
    Path(__file__).with_name("preswap_capture.json").read_text(
        encoding="utf-8"))
fail = []

# ---- audit keypairs ---------------------------------------------------------
from sentinel.audit import derive_keypair

SEEDS = [bytes(range(32)), b"ab" * 32, bytes(64),
         hashlib.sha256(b"seed-C").digest(), b"\x00" * 32]
for sd, want in zip(SEEDS, CAP["audit_keypairs"]):
    priv, pub = derive_keypair(sd)
    if (priv.hex(), pub.hex()) != (want["priv_hex"], want["pub_hex"]):
        fail.append(f"audit keypair drift for seed {want['seed_sha256'][:12]}")
print(f"audit keypairs: {len(SEEDS)} checked")

# ---- proof HKDF -------------------------------------------------------------
from sentinel.proof import (hkdf_sha256, hkdf_sha256_expand,
                            hkdf_sha256_extract)

A1_IKM = b"\x0b" * 22
A1_SALT = bytes.fromhex("000102030405060708090a0b0c")
A1_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
got = {
    "a1_prk": hkdf_sha256_extract(A1_SALT, A1_IKM).hex(),
    "a1_okm42": hkdf_sha256(A1_IKM, A1_SALT, A1_INFO, 42).hex(),
    "a3_okm42": hkdf_sha256(b"\x0b" * 22, b"", b"", 42).hex(),
    "p1_okm77": hkdf_sha256(b"probe-ikm-1", b"probe-salt-1",
                            b"probe-info-1", 77).hex(),
    "p1_expand": hkdf_sha256_expand(bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        b"probe-info-2", 100).hex(),
}
for k, v in CAP["hkdf"].items():
    if got[k] != v:
        fail.append(f"hkdf drift: {k}")
print("hkdf probes:", len(got), "checked")

# ---- proof AEAD -------------------------------------------------------------
from sentinel.proof import chacha20poly1305_encrypt

KAT_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                        "909192939495969798999a9b9c9d9e9f")
KAT_NONCE = bytes.fromhex("070000004041424344454647")
KAT_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
KAT_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer "
          b"you only one tip for the future, sunscreen would be it.")
got = {
    "rfc8439_2_8_2": chacha20poly1305_encrypt(KAT_KEY, KAT_NONCE,
                                              KAT_PT, KAT_AAD).hex(),
    "probe1": chacha20poly1305_encrypt(
        hashlib.sha256(b"key-1").digest(),
        hashlib.sha256(b"nonce-1").digest()[:12],
        b"x" * 1000 + b"!", b"aad-1").hex(),
    "probe2_empty_pt": chacha20poly1305_encrypt(
        hashlib.sha256(b"key-2").digest(),
        hashlib.sha256(b"nonce-2").digest()[:12],
        b"", b"").hex(),
}
for k, v in CAP["aead"].items():
    if got[k] != v:
        fail.append(f"aead drift: {k}")
print("aead probes:", len(got), "checked")

# ---- repro pipeline ---------------------------------------------------------
from sentinel.repro import (DeterministicExecutor, default_pipeline,
                            require_determinism)

ex = DeterministicExecutor(default_pipeline(), name="crypto-swap-check")
runs = [ex.execute({"probe": "env1-crypto-remediation"}, seed=20261030)
        for _ in range(3)]
require_determinism(runs)
if runs[0]["flow_digest"] != CAP["repro"]["flow_digest"]:
    fail.append("repro flow_digest drift")
if runs[0]["flow_merkle_hex"] != CAP["repro"]["flow_merkle_hex"]:
    fail.append("repro flow_merkle drift")
if hashlib.sha256(runs[0]["final_payload"]).hexdigest() != \
        CAP["repro"]["final_payload_sha256"]:
    fail.append("repro final_payload drift")
print("repro pipeline: flow_digest",
      runs[0]["flow_digest"][:16], "...")

# ---- vault: old envelope must FAIL, new envelope must roundtrip -------------
import sentinel.vault as vault

MASTER = hashlib.sha256(b"vault-capture-master").digest()
old = CAP["vault_old_scheme"]
old_env = {"nonce": bytes.fromhex(old["nonce_hex"]),
           "ct": bytes.fromhex(old["ct_hex"]),
           "tag": bytes.fromhex(old["tag_hex"])}
try:
    vault.aead_decrypt(MASTER, old["aad"], old_env)
    fail.append("vault: OLD-scheme envelope still decrypts "
                "(format change not effective)")
except vault.VaultError:
    print("vault old-scheme envelope: rejected as declared (OK)")
new_env = vault.aead_encrypt(MASTER, "postswap|check", b"postswap-probe")
if len(new_env["tag"]) != 16:
    fail.append(f"vault: new tag length {len(new_env['tag'])} != 16")
if vault.aead_decrypt(MASTER, "postswap|check", new_env) != \
        b"postswap-probe":
    fail.append("vault: new-scheme roundtrip failed")
print("vault new-scheme roundtrip: OK (16-byte Poly1305 tag)")

# ---- verdict ----------------------------------------------------------------
if fail:
    print("\nPOSTSWAP VERIFY FAILED:")
    for f in fail:
        print("  -", f)
    sys.exit(1)
print("\nPOSTSWAP VERIFY OK: all byte-identity anchors hold; "
      "declared vault format change verified (old rejected, new roundtrips)")
