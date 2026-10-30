"""TARGET 1 — sentinel/proof.py §6: replace hand-rolled ChaCha20-Poly1305
(block function + Poly1305 MAC) with cryptography's ChaCha20Poly1305 AEAD.
External interface preserved exactly (names, arg order, return shapes,
rejection behavior). Run from repo root after checking out the branch.
"""
import sys

PATH = "sentinel/proof.py"

s = open(PATH, encoding="utf-8").read()

HDR6 = "# ============================================================ §6 ChaCha20-Poly1305"
HDR7 = "# ============================================================ §7 HKDF-SHA256"

# ---- sanity guards --------------------------------------------------------
if s.count(HDR6) != 1 or s.count(HDR7) != 1:
    print("ABORT: section headers not found exactly once")
    sys.exit(1)
if "_chacha20_block" not in s or "_poly1305" not in s:
    print("ABORT: hand-rolled §6 internals not present (already replaced?)")
    sys.exit(1)

NEW_SECTION = '''# ============================================================ §6 ChaCha20-Poly1305
# منذ 2026-10-30: AEAD وفق RFC 8439 §2.8 عبر بدائي ChaCha20Poly1305 في
# مكتبة cryptography (pyca) — لا دالة كتلة ChaCha20 يدوية ولا Poly1305
# يدوي في هذا الملف بعد الآن. الناتج بايت-لبايت مطابق للتنفيذ اليدوي
# السابق (متحقق بمتجه RFC 8439 §2.8.2 الرسمي في
# tests/test_proof_aead_rfc8439.py) فكل أثر قديم يظل قابلاً للتحقق وفك
# التشفير دون أي تغيير.
# FORMAT MARKER 2026-10-30: §6 implementation switched (hand-rolled ->
# cryptography AEAD); wire format unchanged (ct || 16-byte tag).


def chacha20poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                             aad: bytes) -> bytes:
    """AEAD RFC 8439 §2.8 — يعيد ct||وسم (16 بايتاً). حتمي بالكامل
    لنفس المدخلات؛ مطابق حرفياً لمتجه §2.8.2 الرسمي."""
    key = _require_bytes(key, 32, "key")
    nonce = _require_bytes(nonce, 12, "nonce")
    plaintext = _require_bytes(plaintext, None, "plaintext")
    aad = _require_bytes(aad, None, "aad")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def chacha20poly1305_decrypt(key: bytes, nonce: bytes, ct_tag: bytes,
                             aad: bytes) -> bytes:
    """التحقق قبل فك أي بايت — العبث يُرفض بـ IntegrityError (صفر
    تسريب نصيح: الاستثناء يُرفع قبل إرجاع أي نص)."""
    key = _require_bytes(key, 32, "key")
    nonce = _require_bytes(nonce, 12, "nonce")
    ct_tag = _require_bytes(ct_tag, None, "ciphertext_with_tag")
    aad = _require_bytes(aad, None, "aad")
    if len(ct_tag) < 16:
        raise IntegrityError("aead: ciphertext shorter than the 16-byte tag")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct_tag, aad)
    except InvalidTag:
        raise IntegrityError("aead: authentication failed")


'''

start = s.index(HDR6)
end = s.index(HDR7)
old_len = end - start
s = s[:start] + NEW_SECTION + s[end:]

# ---- import updates --------------------------------------------------------
OLD_IMP = '''import json
import os
import struct
import time'''
NEW_IMP = '''import json
import os
import time'''
if s.count(OLD_IMP) != 1:
    print("ABORT: stdlib import block not found exactly once")
    sys.exit(1)
s = s.replace(OLD_IMP, NEW_IMP)

OLD_CRYPT = '''from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization'''
NEW_CRYPT = '''from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305'''
if s.count(OLD_CRYPT) != 1:
    print("ABORT: cryptography import block not found exactly once")
    sys.exit(1)
s = s.replace(OLD_CRYPT, NEW_CRYPT)

# ---- docstring updates ------------------------------------------------------
OLD_DS1 = '''- الاعتماديات: hashlib + hmac + os + struct من stdlib، وEd25519 عبر
  مكتبة cryptography (pyca) منذ استبدال التنفيذ اليدوي — لا حساب
  نقاطي يدوي. ChaCha20-Poly1305 وHKDF لا يزالان stdlib.'''
NEW_DS1 = '''- الاعتماديات: hashlib + hmac + os من stdlib؛ وEd25519 وChaCha20-Poly1305
  عبر مكتبة cryptography (pyca) — لا حساب نقاطي يدوي ولا دالة كتلة
  ChaCha20/Poly1305 يدوية منذ 2026-10-30. HKDF لا يزال stdlib.'''
if s.count(OLD_DS1) != 1:
    print("ABORT: provenance docstring not found exactly once")
    sys.exit(1)
s = s.replace(OLD_DS1, NEW_DS1)

OLD_DS2 = '''  §6  ChaCha20-Poly1305   RFC 8439 §2-§8 (كتلة ChaCha20 + Poly1305
                          أعداد كبيرة + AEAD بالترتيب القياسي)'''
NEW_DS2 = '''  §6  ChaCha20-Poly1305   RFC 8439 §2.8 AEAD عبر مكتبة cryptography
                          (pyca) منذ 2026-10-30 — ناتج مطابق بايت-لبايت'''
if s.count(OLD_DS2) != 1:
    print("ABORT: §6 contents docstring not found exactly once")
    sys.exit(1)
s = s.replace(OLD_DS2, NEW_DS2)

# ---- post-conditions --------------------------------------------------------
for gone in ("_chacha20_block", "_chacha20_xor", "_poly1305", "_rotl32",
             "_quarter", "_pad16", "struct.", "import struct",
             "_CHACHA_CONSTANTS"):
    if gone in s:
        print(f"ABORT: residual hand-rolled reference {gone!r} still present")
        sys.exit(1)
if "hmac." not in s:
    print("ABORT: unexpected — hmac usage vanished before §7 replacement")
    sys.exit(1)

open(PATH, "w", encoding="utf-8").write(s)
print(f"TARGET 1 edit applied: §6 section {old_len} -> {len(NEW_SECTION)} chars; "
      "imports + docstrings updated; struct import removed")
