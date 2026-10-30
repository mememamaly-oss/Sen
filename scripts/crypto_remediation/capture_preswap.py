"""PRE-SWAP CAPTURE (2026-10-30) — byte-level anchors from the four
hand-rolled implementations immediately BEFORE their replacement with the
cryptography library (targets 1-4 of the crypto-library-primitives order).

Run from repo root on the PRE-swap tree (cleanup/crypto-library-primitives
at the cleanup/symbolic-ed25519 base). Writes preswap_capture.json next to
this script. verify_postswap.py re-runs the exact same probes after the
swap and demands:

  * audit.derive_keypair      — byte-identical (keypair continuity)
  * proof HKDF (RFC 5869)     — byte-identical
  * proof AEAD (RFC 8439 2.8.2 + fixed probes) — byte-identical
  * repro default_pipeline    — identical flow_digest + final payload
  * vault OLD-scheme envelope — must FAIL authentication after the swap
    (declared format change: 32-byte HMAC tag -> 16-byte Poly1305 tag)
"""
import hashlib
import json
from pathlib import Path

out = {}

# ---- audit: deterministic keypairs on fixed seeds ---------------------------
from sentinel.audit import derive_keypair

SEEDS = [bytes(range(32)), b"ab" * 32, bytes(64),
         hashlib.sha256(b"seed-C").digest(), b"\x00" * 32]
kps = []
for sd in SEEDS:
    priv, pub = derive_keypair(sd)
    kps.append({"seed_sha256": hashlib.sha256(sd).hexdigest(),
                "priv_hex": priv.hex(), "pub_hex": pub.hex()})
out["audit_keypairs"] = kps

# ---- proof: HKDF-SHA256 probes (RFC 5869 A.1 + arbitrary fixed inputs) ------
from sentinel.proof import (hkdf_sha256, hkdf_sha256_expand,
                            hkdf_sha256_extract)

A1_IKM = b"\x0b" * 22
A1_SALT = bytes.fromhex("000102030405060708090a0b0c")
A1_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
out["hkdf"] = {
    "a1_prk": hkdf_sha256_extract(A1_SALT, A1_IKM).hex(),
    "a1_okm42": hkdf_sha256(A1_IKM, A1_SALT, A1_INFO, 42).hex(),
    "a3_okm42": hkdf_sha256(b"\x0b" * 22, b"", b"", 42).hex(),
    "p1_okm77": hkdf_sha256(b"probe-ikm-1", b"probe-salt-1",
                            b"probe-info-1", 77).hex(),
    "p1_expand": hkdf_sha256_expand(bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        b"probe-info-2", 100).hex(),
}

# ---- proof: AEAD probes (RFC 8439 2.8.2 + fixed arbitrary inputs) -----------
from sentinel.proof import chacha20poly1305_encrypt

KAT_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                        "909192939495969798999a9b9c9d9e9f")
KAT_NONCE = bytes.fromhex("070000004041424344454647")
KAT_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
KAT_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer "
          b"you only one tip for the future, sunscreen would be it.")
out["aead"] = {
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

# ---- repro: default_pipeline determinism anchor -----------------------------
from sentinel.repro import (DeterministicExecutor, default_pipeline,
                            require_determinism)

ex = DeterministicExecutor(default_pipeline(), name="crypto-swap-check")
runs = [ex.execute({"probe": "env1-crypto-remediation"}, seed=20261030)
        for _ in range(3)]
require_determinism(runs)
out["repro"] = {
    "flow_digest": runs[0]["flow_digest"],
    "final_payload_sha256": hashlib.sha256(runs[0]["final_payload"])
    .hexdigest(),
    "flow_merkle_hex": runs[0]["flow_merkle_hex"],
}

# ---- vault: OLD-scheme envelope (format-change evidence) --------------------
import sentinel.vault as vault

MASTER = hashlib.sha256(b"vault-capture-master").digest()
AAD = "capture|2026-10-30"
env = vault.aead_encrypt(MASTER, AAD, b"preswap-probe-payload")
assert vault.aead_decrypt(MASTER, AAD, env) == b"preswap-probe-payload"
out["vault_old_scheme"] = {
    "nonce_hex": env["nonce"].hex(), "ct_hex": env["ct"].hex(),
    "tag_hex": env["tag"].hex(), "tag_len": len(env["tag"]),
    "aad": AAD, "master_sha256": hashlib.sha256(MASTER).hexdigest(),
}
out["vault_probe_master_b64note"] = (
    "MASTER = sha256('vault-capture-master'); reconstruct in the verifier "
    "for the must-fail check — the envelope below is OLD-scheme "
    "(32-byte HMAC tag) and must FAIL authentication after target 4.")

dest = Path(__file__).with_name("preswap_capture.json")
dest.write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
print("PRESWAP CAPTURE OK — sections:",
      ", ".join(out.keys()))
print("  audit keypairs:", len(kps), "| tag_len(old vault):",
      out["vault_old_scheme"]["tag_len"])
print("  repro flow_digest:", out["repro"]["flow_digest"][:16], "...")
