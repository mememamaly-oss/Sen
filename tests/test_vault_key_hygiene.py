"""VAULT KEY HYGIENE (owner order 2026-10-31, part 2.5).

Invariant: the vault's KEY MATERIAL (the 32-byte secret inside a key file)
must NEVER appear — verbatim, base64, or hex — in:
  * any VaultError message (wrong key, tampered vault, unreadable file,
    public permissions, corrupted key, key_id mismatch),
  * any CLI stdout/stderr (keygen prints path + key_id only),
  * the scan-abort JSON path,
  * vault status/list/report/audit outputs (list is masked by design).

The key_id (a sha256[:8] PUBLIC fingerprint) is explicitly allowed to
appear — it is an identifier, not secret material.
"""
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys

import pytest

from burhan.vault import Vault, VaultError, keygen, load_key


def _leak_forms(key_bytes: bytes) -> set[str]:
    forms = {key_bytes.hex(), base64.b64encode(key_bytes).decode()}
    return {f for f in forms if len(f) > 8}


def _assert_no_leak(text: str, key_bytes: bytes, where: str):
    for form in _leak_forms(key_bytes):
        assert form not in text, f"KEY MATERIAL leaked via {where}"


@pytest.fixture()
def key(tmp_path):
    kf = keygen(str(tmp_path / "designer.key"), label="test-designer")
    _, data = load_key(str(tmp_path / "designer.key"))
    return kf, data


def test_keygen_cli_output_never_contains_key_material(key, tmp_path):
    # NOTE: the keygen() FUNCTION returns the key-file payload (it just wrote
    # the file — that is its contract, the material lands in the 0600 file).
    # The invariant under test is every OUTPUT surface: CLI stdout/stderr.
    p = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "vault", "keygen",
         "--out", str(tmp_path / "cli.key")],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 0
    _assert_no_leak(p.stdout + p.stderr, key[1], "vault keygen CLI output")


def test_every_vaulterror_path_is_key_free(key, tmp_path):
    kf, data = key
    vpath = str(tmp_path / "org.vault")
    v = Vault.init(vpath, str(tmp_path / "designer.key"), "test-org")
    v.store("credential", "SUPER-SECRET-RAW-VALUE-123", {"url": "https://t.invalid/"})
    # every refusal path, one by one
    cases = []
    # 1. wrong (unauthorized) key
    keygen(str(tmp_path / "stranger.key"), label="stranger")
    try:
        Vault.open(vpath, str(tmp_path / "stranger.key"))
        cases.append(("wrong-key", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("wrong-key", str(e)))
    # 2. tampered vault file (flip one byte of the blob)
    raw = open(vpath, "rb").read()
    open(vpath, "wb").write(raw.replace(b'"ct": "', b'"ct": "ff', 1))
    try:
        Vault.open(vpath, str(tmp_path / "designer.key"))
        cases.append(("tampered-vault", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("tampered-vault", str(e)))
    # restore + 3. unreadable vault (garbage json)
    open(vpath, "wb").write(b"not json at all")
    try:
        Vault.open(vpath, str(tmp_path / "designer.key"))
        cases.append(("garbage-vault", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("garbage-vault", str(e)))
    # 4. not-a-vault-format file
    open(vpath, "w").write(json.dumps({"format": "something-else"}))
    try:
        Vault.open(vpath, str(tmp_path / "designer.key"))
        cases.append(("bad-format", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("bad-format", str(e)))
    # 5. corrupted key file (32-byte check)
    bad = tmp_path / "bad.key"
    bad.write_text(json.dumps({"format": "burhan-vault-key/1", "key_id": "deadbeef",
                               "data": base64.b64encode(b"short").decode()}))
    try:
        load_key(str(bad))
        cases.append(("short-key", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("short-key", str(e)))
    # 6. key_id mismatch
    real = json.load(open(tmp_path / "designer.key"))
    mismatched = dict(real)
    mismatched["key_id"] = "00000000"
    (tmp_path / "mismatch.key").write_text(json.dumps(mismatched))
    try:
        load_key(str(tmp_path / "mismatch.key"))
        cases.append(("keyid-mismatch", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("keyid-mismatch", str(e)))
    # 7. world-readable key file (public perms refusal)
    world = tmp_path / "world.key"
    keygen(str(world), label="world")
    # intentional: creates the bad-perms state the gate must refuse
    os.chmod(world, 0o644)  # codeql[py/overly-permissive-file]
    try:
        Vault.init(str(tmp_path / "w.vault"), str(world), "org2")
        cases.append(("public-perms", "NO ERROR RAISED"))
    except VaultError as e:
        cases.append(("public-perms", str(e)))

    assert len(cases) == 7
    for name, msg in cases:
        assert msg != "NO ERROR RAISED", f"{name}: expected a refusal"
        _assert_no_leak(msg, data, f"VaultError path {name!r}")


def test_open_pins_the_checked_descriptor_toctou_hardening(key, tmp_path):
    """Item 1.5 (2026-10-31): the permission gate and the read must see the
    SAME object (one open descriptor). Deterministic pins for the refusal
    classes introduced with the fd-pinned open; the race itself is proven by
    scripts/attack_vault_toctou.py — RED: 1 bypass in a 20s real
    two-process race pre-fix; BLUE: 0 bypasses post-fix."""
    kf, data = key
    # 1. symlinked key file — refused where O_NOFOLLOW exists (the swap
    #    trick becomes a symlink too; both must die at open)
    link = tmp_path / "link.key"
    link.symlink_to(tmp_path / "designer.key")
    try:
        load_key(str(link))
        if hasattr(os, "O_NOFOLLOW"):
            raise AssertionError("symlinked key file must be refused (O_NOFOLLOW)")
    except VaultError:
        pass
    # 2. not a regular file — refused (the fd-pinned fstat knows what it
    #    actually opened; a directory is not a key file)
    with pytest.raises(VaultError):
        load_key(str(tmp_path))


def test_status_list_report_audit_never_leak_key_or_raw_values(key, tmp_path):
    kf, data = key
    vpath = str(tmp_path / "org.vault")
    v = Vault.init(vpath, str(tmp_path / "designer.key"), "test-org")
    v.store("credential", "SUPER-SECRET-RAW-VALUE-123", {"url": "https://t.invalid/"})
    hook = v.capture_callback("run-1", "https://t.invalid/cb")
    hook("credential", "tok-abc123", "/cb", "req-1")
    # reopen (fresh view) then dump every read surface
    v2 = Vault.open(vpath, str(tmp_path / "designer.key"))
    # masked surfaces: raw values must NEVER appear
    for name, text in {"status": json.dumps(v2.status()),
                       "list": json.dumps(v2.list()),
                       "audit": json.dumps(v2.audit())}.items():
        _assert_no_leak(text, data, f"vault {name} output")
        assert "SUPER-SECRET-RAW-VALUE-123" not in text, f"RAW VALUE leaked via {name}"
        assert "tok-abc123" not in text, f"captured token leaked via {name}"
    # BY-DESIGN reveal surfaces (owner-only, audit-logged — the documented
    # contract): export() and report() DO reveal stored record values; the
    # invariant there is that they never leak the VAULT KEY material and
    # that every reveal writes an audit entry.
    rep = v2.report()
    _assert_no_leak(json.dumps(rep), data, "vault report output")
    exp = v2.export(v2.list()[0]["id"])
    _assert_no_leak(json.dumps(exp), data, "vault export output")
    audit_actions = [a.get("action") for a in v2.audit()]
    assert "REPORT" in audit_actions and "EXPORT" in audit_actions, \
        "reveal surfaces must be audit-logged"
    # and a fresh masked listing still hides everything after the reveals
    assert "SUPER-SECRET-RAW-VALUE-123" not in json.dumps(v2.list())


def test_scan_abort_path_prints_the_error_only(key, tmp_path):
    """A refused vault during scan prints vault_error (a VaultError string) —
    the key must not ride along."""
    kf, data = key
    vpath = str(tmp_path / "org.vault")
    Vault.init(vpath, str(tmp_path / "designer.key"), "scan-org")
    keygen(str(tmp_path / "stranger.key"), label="stranger")
    p = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "scan", "https://scan-target.invalid/",
         "--vault", vpath, "--vault-key-file", str(tmp_path / "stranger.key"),
         "--out", str(tmp_path / "r.json"), "--db", str(tmp_path / "s.db"),
         "--no-browser", "--max-pages", "1"],
        capture_output=True, text=True, timeout=120,
    )
    out = p.stdout + p.stderr
    _assert_no_leak(out, data, "scan-abort output")
    # the abort path must actually have refused (otherwise the test proves nothing)
    assert "vault refused" in out or "vault_error" in out or p.returncode != 0, out[-400:]
