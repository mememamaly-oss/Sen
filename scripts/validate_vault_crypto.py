#!/usr/bin/env python3
"""Dev-time cross-validation of sentinel.vault crypto against the independent
`cryptography` library oracle (TEST-ONLY — SENTINEL itself stays pure stdlib),
plus a full vault lifecycle smoke test with byte-level no-plaintext assertions."""
import json, os, sys, tempfile, shutil

sys.path.insert(0, "/home/z/my-project/verify-live")

# ---------- 1. ChaCha20 cross-validation vs cryptography lib ----------
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sentinel.vault import chacha20_xor, _quarter_round, VaultError

ok = 0
for trial in range(6):
    import secrets as ps
    key, nonce = ps.token_bytes(32), ps.token_bytes(12)
    data = ps.token_bytes(64 * 4 + 37)              # multi-block + partial
    ctr = trial + 1
    # reference: cryptography's ChaCha20 with 16-byte nonce = counter||nonce
    ref = Cipher(algorithms.ChaCha20(key, ctr.to_bytes(4, "little") + nonce),
                 mode=None).encryptor()
    expect = ref.update(data)
    got = chacha20_xor(key, nonce, data, counter=ctr)
    assert got == expect, f"chacha20 mismatch at trial {trial}"
    ok += 1
print(f"chacha20 cross-validation: {ok}/6 random trials MATCH the oracle")

# RFC 8439 §2.1.1 quarter-round vector
w = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
_quarter_round(w, 0, 1, 2, 3)
assert w == [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb], [hex(x) for x in w]
print("quarter-round RFC 8439 2.1.1 vector: MATCH")

# ---------- 2. full lifecycle ----------
from sentinel.vault import Vault, keygen

tmp = tempfile.mkdtemp(prefix="vault-dev-")
try:
    kf, kf2, vp = f"{tmp}/designer.json", f"{tmp}/owner.json", f"{tmp}/org.vault"
    keygen(kf, "designer"); keygen(kf2, "owner")
    assert oct(os.stat(kf).st_mode & 0o777) == "0o600"

    v = Vault.init(vp, kf, "demo.testfire.net")
    RAW1 = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"                  # aws-shaped
    RAW2 = "gh" + "p_" + "SENTINELFIXTURE" + "GHPTOKEN" + "1234567890"
    rid1 = v.store("aws_access_key", RAW1, {"run_id": "run-x", "url": "http://t/vuln/leak-config",
                                            "location": "body", "request_id": "r1"}, "critical")
    rid2 = v.store("github_token", RAW2, {"run_id": "run-x", "url": "http://t/vuln/leak-config",
                                          "location": "body", "request_id": "r1"}, "high")
    rid1b = v.store("aws_access_key", RAW1, {"run_id": "run-x", "url": "http://t/vuln/leak-config",
                                             "location": "body", "request_id": "r2"}, "critical")
    assert rid1 == rid1b, "upsert should reuse the record id"
    # masked list: raws never appear
    listing = v.list()
    assert all("raw" not in r for r in listing) and len(listing) == 2
    # byte-level no-plaintext guarantee on the vault FILE
    blob_bytes = open(vp, "rb").read()
    assert blob_bytes.count(RAW1.encode()) == 0 and blob_bytes.count(RAW2.encode()) == 0
    print("vault file contains NO plaintext secrets (byte-level): OK")

    # reopen with the same key
    v2 = Vault.open(vp, kf)
    rec = v2.export(rid2)
    assert rec["raw"] == RAW2, "export must reveal the original value"
    # unauthorized key rejected
    try:
        Vault.open(vp, kf2); raise SystemExit("FAIL: owner key opened without authorization")
    except VaultError as e:
        assert "not authorized" in str(e)
    # authorize owner key, then it works
    v2.authorize(kf2, "org-owner")
    v3 = Vault.open(vp, kf2)
    assert v3.export(rid1)["raw"] == RAW1
    # audit chain
    actions = [a["action"] for a in v3.audit()]
    for expected in ("INIT", "STORE", "LIST", "EXPORT", "AUTHORIZE", "EXPORT"):
        assert expected in actions, f"missing {expected} in {actions}"
    # tamper: flip a byte in the blob ct
    env = json.load(open(vp))
    import base64
    ct = bytearray(base64.b64decode(env["blob"]["ct"])); ct[5] ^= 0xFF
    env["blob"]["ct"] = base64.b64encode(bytes(ct)).decode()
    json.dump(env, open(f"{tmp}/tampered.vault", "w"))
    try:
        Vault.open(f"{tmp}/tampered.vault", kf); raise SystemExit("FAIL: tamper accepted")
    except VaultError:
        pass
    # org transplant: swap org field -> AAD mismatch
    env2 = json.load(open(vp)); env2["org"] = "other-org"
    json.dump(env2, open(f"{tmp}/transplant.vault", "w"))
    try:
        Vault.open(f"{tmp}/transplant.vault", kf); raise SystemExit("FAIL: transplant accepted")
    except VaultError:
        pass
    print("tamper + org-transplant rejection: OK")

    # revoke: 2-key case (designer + owner) — removing owner is allowed and
    # rotates the blob key so the old owner copy/file can no longer open it
    owner_key_id = v3.key_id
    v4 = Vault.open(vp, kf)
    v4.revoke(owner_key_id)
    try:
        Vault.open(vp, kf2); raise SystemExit("FAIL: revoked key still opens")
    except VaultError:
        pass
    print("revoke + rotation: OK (revoked key rejected)")

    # 3-key case: with another authorized key present, revoke must refuse
    # honestly (re-wrapping the rotated blob key needs that key's material)
    kf3 = f"{tmp}/auditor.json"; keygen(kf3, "auditor")
    v5 = Vault.open(vp, kf)
    v5.authorize(kf2, "org-owner"); v5.authorize(kf3, "auditor")
    v6 = Vault.open(vp, kf)
    auditor_id = next(k["key_id"] for k in v6.status()["authorized_keys"]
                      if k["label"] == "auditor")
    try:
        v6.revoke(owner_key_id)
        raise SystemExit("FAIL: revoke with a third key present should refuse")
    except VaultError as e:
        assert "re-wrap" in str(e)
    # removing BOTH other keys one at a time is impossible without their
    # material — but revoking auditor while owner present also refuses:
    try:
        v6.revoke(auditor_id)
        raise SystemExit("FAIL: revoke with owner present should refuse")
    except VaultError:
        pass
    # clean up for the purge test: reopen with owner, revoke nobody, proceed
    print("3-key honest refusal: OK")

    # purge: shred one record, then all; audit survives; no raws in file
    v6 = Vault.open(vp, kf)
    v6.purge(rid1)
    v6.purge(all_records=True)
    data = open(vp, "rb").read()
    assert data.count(RAW1.encode()) == 0 and data.count(RAW2.encode()) == 0
    assert any(a["action"] == "PURGE" for a in v6.audit())
    print("purge semantics + audit survival: OK")

    # scrub defense-in-depth
    v7 = Vault.open(vp, kf)
    v7.store("generic", "supersecretvalue12345", {"url": "http://x"})
    scrubbed = v7.scrub({"note": "leak supersecretvalue12345 here",
                         "list": ["supersecretvalue12345"], "n": 5})
    assert scrubbed["note"] == "leak ******** here" and scrubbed["list"][0] == "********"
    print("scrub defense-in-depth: OK")
    print("\nALL VAULT VALIDATIONS PASSED")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
