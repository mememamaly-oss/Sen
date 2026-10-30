"""TARGET 2 — sentinel/proof.py §7: replace hand-rolled HKDF-SHA256
(extract/expand loops) with cryptography's HKDF / HKDFExpand classes.
hkdf_sha256_extract has no HKDF-class equivalent in pyca, so it uses the
library's own HMAC primitive (cryptography.hazmat.primitives.hmac.HMAC).
Interface (names, signatures, return shapes, rejection behavior) unchanged.
"""
import sys

PATH = "sentinel/proof.py"

s = open(PATH, encoding="utf-8").read()

HDR7 = "# ============================================================ §7 HKDF-SHA256"
HDR8 = "# ============================================================ §8 نموذج الإثبات"

if s.count(HDR7) != 1 or s.count(HDR8) != 1:
    print("ABORT: §7/§8 headers not found exactly once")
    sys.exit(1)
if "while len(okm) < length" not in s:
    print("ABORT: hand-rolled expand loop not present (already replaced?)")
    sys.exit(1)

NEW_SECTION = '''# ============================================================ §7 HKDF-SHA256
# منذ 2026-10-30: RFC 5869 عبر صنفي HKDF وHKDFExpand في مكتبة
# cryptography (pyca) — لا حلقة expand يدوية ولا تركيب HMAC يدوي هنا.
# الناتج بايت-لبايت مطابق للتنفيذ اليدوي السابق (متحقق بمتجهات
# RFC 5869 A.1-A.3 الرسمية في tests/test_proof_hkdf_rfc5869.py).
# ملاحظة تنفيذية: صنف HKDF لا يعرض استخراج PRK منفرداً، لذا تُنفَّذ
# hkdf_sha256_extract ببدائي HMAC من المكتبة نفسها
# (cryptography.hazmat.primitives.hmac.HMAC) — لا شيء يدوي.


def hkdf_sha256_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2: PRK = HMAC-SHA256(salt, IKM) — عبر بدائي HMAC
    في مكتبة cryptography (الملح الفارغ => 32 صفراً كما في RFC)."""
    salt = _require_bytes(salt, None, "salt")
    ikm = _require_bytes(ikm, None, "ikm")
    if len(salt) == 0:
        salt = b"\\x00" * 32  # RFC 5869: الافتراضي أصفار بطول الهاش
    mac = HMAC(salt, hashes.SHA256())
    mac.update(ikm)
    return mac.finalize()


def hkdf_sha256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 عبر صنف HKDFExpand — الحد 255·32 كما كان."""
    prk = _require_bytes(prk, None, "prk")
    info = _require_bytes(info, None, "info")
    length = _require_int(length, "length")
    if not 1 <= length <= 255 * 32:
        raise ValidationError(
            f"hkdf: length must be in [1, {255 * 32}], got {length}")
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(prk)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 (extract ثم expand) عبر صنف HKDF في مكتبة cryptography
    — الملح الفارغ يُعامل داخلياً كأصفار بطول الهاش (A.3 متحقق)."""
    ikm = _require_bytes(ikm, None, "ikm")
    salt = _require_bytes(salt, None, "salt")
    info = _require_bytes(info, None, "info")
    length = _require_int(length, "length")
    if not 1 <= length <= 255 * 32:
        raise ValidationError(
            f"hkdf: length must be in [1, {255 * 32}], got {length}")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


'''

start = s.index(HDR7)
end = s.index(HDR8)
old_len = end - start
s = s[:start] + NEW_SECTION + s[end:]

# ---- imports ----------------------------------------------------------------
OLD_CRYPT = '''from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization'''
NEW_CRYPT = '''from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand'''
if s.count(OLD_CRYPT) != 1:
    print("ABORT: cryptography import block not found exactly once")
    sys.exit(1)
s = s.replace(OLD_CRYPT, NEW_CRYPT)

# stdlib hmac no longer used anywhere in proof.py -> drop the import
# (match actual calls only — the §7 comment legitimately mentions
# "primitives.hmac.HMAC", which is library, not stdlib usage)
import re
if re.search(r"\bhmac\.(new|compare_digest|digest|new_digest)\b", s):
    print("ABORT: stdlib hmac still called in proof.py — check before removing")
    sys.exit(1)
OLD_STD = '''import hashlib
import hmac
import json'''
NEW_STD = '''import hashlib
import json'''
if s.count(OLD_STD) != 1:
    print("ABORT: stdlib import block not found exactly once")
    sys.exit(1)
s = s.replace(OLD_STD, NEW_STD)

# ---- docstrings ---------------------------------------------------------------
OLD_DS1 = '''- الاعتماديات: hashlib + hmac + os من stdlib؛ وEd25519 وChaCha20-Poly1305
  عبر مكتبة cryptography (pyca) — لا حساب نقاطي يدوي ولا دالة كتلة
  ChaCha20/Poly1305 يدوية منذ 2026-10-30. HKDF لا يزال stdlib.'''
NEW_DS1 = '''- الاعتماديات: hashlib + os من stdlib؛ وEd25519 وChaCha20-Poly1305 وHKDF
  عبر مكتبة cryptography (pyca) — لا حساب نقاطي ولا حلقة expand ولا
  دالة كتلة يدوية منذ 2026-10-30.'''
if s.count(OLD_DS1) != 1:
    print("ABORT: provenance docstring (T1 version) not found exactly once")
    sys.exit(1)
s = s.replace(OLD_DS1, NEW_DS1)

OLD_DS2 = "  §7  HKDF-SHA256         RFC 5869 (extract + expand)"
NEW_DS2 = ("  §7  HKDF-SHA256         RFC 5869 عبر صنفي HKDF/HKDFExpand في\n"
           "                          مكتبة cryptography (منذ 2026-10-30)")
if s.count(OLD_DS2) != 1:
    print("ABORT: §7 contents docstring not found exactly once")
    sys.exit(1)
s = s.replace(OLD_DS2, NEW_DS2)

# ---- post-conditions -----------------------------------------------------------
for gone in ("while len(okm)", "okm = bytearray", "t + info + bytes([",
             "import hmac", "hmac.new"):
    if gone in s:
        print(f"ABORT: residual hand-rolled HKDF reference {gone!r} still present")
        sys.exit(1)
for needed in ("HKDF(", "HKDFExpand(", "HMAC(salt", "hashes.SHA256()"):
    if needed not in s:
        print(f"ABORT: expected library reference {needed!r} missing")
        sys.exit(1)

open(PATH, "w", encoding="utf-8").write(s)
print(f"TARGET 2 edit applied: §7 section {old_len} -> {len(NEW_SECTION)} chars; "
      "HKDF/HKDFExpand/HMAC imports added; stdlib hmac import removed")
