"""SENTINEL Axis-8 — طبقة الإثبات التشفيري (Military-Grade Cryptographic
Proof Layer).

PROVENANCE (عقد M1 المُسجَّل — tests/test_axis8_proof.py):
- العقد مُشتق من المواصفة المرجعية المؤرشفة §8 (D1) + قائمة نطاق أمر
  البناء (D2)، مُعلن وقابل للإحلال عند أي حد محطة (سابقة المحور-4).
- المحرك نقي stdlib حصراً: hashlib + hmac + os + struct. لا pyca، لا
  scipy، لا أي استيراد خارجي. المراجع الخارجية في الاختبارات فقط.
- انضباط المحور-11: كل الأزمنة معاملات صريحة (when_ms=None → ساعة
  النظام؛ البطاريات تمرر أزمنة مثبتة). لا زمن حائطي في أي هاضم.
- validation-before-mutation: العقود البنيوية (أنواع/أطوال/حدود)
  تُرفض بـ ValidationError قبل أي أثر؛ فشل التحقق الدلالي (توقيع/وسم/
  سلسلة) يُعاد False أو IntegrityError — الفصل معلن.

المحتويات:
  §1  أخطاء               ProofError → ValidationError / IntegrityError
  §2  Ed25519             RFC 8032 خالص (إحداثيات ممتدة، حتمي)
  §3  Merkle              §8.2 من المواصفة (Leaf=SHA-256(data),
                          Node=SHA-256(L||R)، مضاعفة الأخيرة للفرد —
                          اصطلاح CT معلن، إثبات O(log n))
  §4  سلسلة الأدلة        §8.5 (H(Pᵢ)=H(Pᵢ₋₁||dataᵢ)، genesis أصفار)
  §5  طابع RFC 3161       §8.4 (TST=Sign(TSA, Hash(data)||Time) محلياً)
  §6  ChaCha20-Poly1305   RFC 8439 §2-§8 (كتلة ChaCha20 + Poly1305
                          أعداد كبيرة + AEAD بالترتيب القياسي)
  §7  HKDF-SHA256         RFC 5869 (extract + expand)
  §8  نموذج الإثبات       §8.1/§8.6 (P الستّي، تمثيل JSON قياسي حتمي)
  §9  سلسلة الحيازة       تسجيل/تنازل موقّع بسلسلة روابط — التنازل
                          من غير الحائز الحالي مرفوض ذرياً (ضد التزوير
                          البنيوي)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import time

__all__ = [
    "ProofError", "ValidationError", "IntegrityError",
    "ed25519_generate_seed", "ed25519_public_key", "ed25519_sign",
    "ed25519_verify",
    "merkle_root", "merkle_prove", "merkle_verify",
    "chain_build", "chain_verify",
    "timestamp_token", "timestamp_verify",
    "chacha20poly1305_encrypt", "chacha20poly1305_decrypt",
    "hkdf_sha256_extract", "hkdf_sha256_expand", "hkdf_sha256",
    "create_claim", "sign_claim", "verify_claim",
    "custody_open", "custody_transfer", "custody_verify",
]


# ============================================================ §1 الأخطاء
class ProofError(ValueError):
    """قاعدة أخطاء طبقة الإثبات (ValueError عمداً — عقد M1)."""


class ValidationError(ProofError):
    """رفض ذري لعقد بنيوي فاسد (نوع/طول/حدود) قبل أي أثر حالة."""


class IntegrityError(ProofError):
    """فشل تحقق سلامة (وسم AEAD/توقيع/سلسلة) — لا تسريب نصيح."""


def _require_bytes(value, length, name):
    """عقد bytes صارم — bytearray يُقبل ويوحَّد؛ str/int/bool تُرفض."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
    else:
        raise ValidationError(
            f"{name}: expected bytes, got {type(value).__name__}")
    if length is not None and len(value) != length:
        raise ValidationError(
            f"{name}: expected {length} bytes, got {len(value)}")
    return value


def _require_int(value, name):
    """int صارم — bool مرفوض (صنو int في بايثون لكنه ليس زمناً)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"{name}: expected int, got {type(value).__name__}")
    return value


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(obj) -> bytes:
    """تمثيل JSON قياسي حتمي (فرز مفاتيح، بلا فراغات) — أساس كل هاش."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ============================================================ §2 Ed25519
# منحنى edwards25519 — RFC 8032. تنفيذ خالص بأعداد بايثون الكبيرة
# (إحداثيات ممتدة X:Y:Z:T بالتكافؤ x=X/Z, y=Y/Z, T=XY/Z).
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _inv_q(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _recover_x(y: int, sign: int):
    """فك ضغط النقطة: حل x²=(y²-1)/(d·y²+1) وضبط إشارة البِت الأعلى."""
    if y >= _Q:
        return None
    x2 = ((y * y - 1) * _inv_q(_D * y * y + 1)) % _Q
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_Q + 3) // 8, _Q)
    if (x * x - x2) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - x2) % _Q != 0:
        return None
    if x % 2 != sign:
        x = _Q - x
    return x


def _pt_add(P, Q):
    """جمع نقطتين بإحداثيات ممتدة (RFC 8032 §5.1.4)."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (2 * t1 * t2 * _D) % _Q
    d = (2 * z1 * z2) % _Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q)


def _pt_mult(P, e: int):
    """ضرب سكّالي مزدوج-وجمع (حتمي — لا نوافذ عشوائية)."""
    Q = _IDENTITY
    while e:
        if e & 1:
            Q = _pt_add(Q, P)
        P = _pt_add(P, P)
        e >>= 1
    return Q


def _pt_compress(P) -> bytes:
    x, y, z, _t = P
    zi = _inv_q(z)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _pt_decompress(s: bytes):
    if len(s) != 32:
        raise ValidationError("point encoding must be 32 bytes")
    val = int.from_bytes(s, "little")
    sign = val >> 255
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        raise ValidationError("invalid point encoding (not on curve)")
    return (x, y, 1, (x * y) % _Q)


def _secret_expansion(seed: bytes):
    """توسيع البذرة: a مقيدّة (clamp) + بادئة عشوائية RFC 8032 §5.1.5."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def _sha512_mod_l(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _L


def ed25519_generate_seed() -> bytes:
    """بذرة 32 بايت من os.urandom (مصدر النظام وحده — معلن)."""
    return os.urandom(32)


def ed25519_public_key(seed: bytes) -> bytes:
    seed = _require_bytes(seed, 32, "seed")
    a, _prefix = _secret_expansion(seed)
    return _pt_compress(_pt_mult(_B, a))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    seed = _require_bytes(seed, 32, "seed")
    message = _require_bytes(message, None, "message")
    a, prefix = _secret_expansion(seed)
    a_enc = _pt_compress(_pt_mult(_B, a))
    r = _sha512_mod_l(prefix + message)
    r_enc = _pt_compress(_pt_mult(_B, r))
    k = _sha512_mod_l(r_enc + a_enc + message)
    s = (r + k * a) % _L
    return r_enc + int.to_bytes(s, 32, "little")


def ed25519_verify(signature: bytes, message: bytes,
                   public_key: bytes) -> bool:
    signature = _require_bytes(signature, 64, "signature")
    message = _require_bytes(message, None, "message")
    public_key = _require_bytes(public_key, 32, "public key")
    try:
        a_pt = _pt_decompress(public_key)
        r_pt = _pt_decompress(signature[:32])
    except ValidationError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_mod_l(signature[:32] + public_key + message)
    # معادلة RFC 8032: s·B = R + k·A (بلا عامل مساعد — يكفي للعقد)
    lhs = _pt_mult(_B, s)
    rhs = _pt_add(r_pt, _pt_mult(a_pt, k))
    return _pt_compress(lhs) == _pt_compress(rhs)


# ============================================================ §3 Merkle
def _leaf_hashes(leaves):
    if not isinstance(leaves, (list, tuple)) or len(leaves) == 0:
        raise ValidationError("merkle: leaves must be a non-empty list")
    return [hashlib.sha256(_require_bytes(x, None, "leaf")).digest()
            for x in leaves]


def merkle_root(leaves) -> bytes:
    """§8.2: Leaf(i)=SHA-256(data_i)، Node=SHA-256(L||R).
    الاصطلاح المعلن للعدد الفردي: مضاعفة الورقة الأخيرة (نمط CT)."""
    level = _leaf_hashes(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0]


def merkle_prove(leaves, index: int):
    """إثبات انتماء O(log n): قائمة (side, sibling_hash) بالترتيب من
    الورقة إلى الجذر. side="L" يعني الأخ شقيق على اليسار."""
    level = _leaf_hashes(leaves)
    index = _require_int(index, "index")
    if not 0 <= index < len(level):
        raise ValidationError(
            f"merkle: index {index} out of range [0, {len(level)})")
    proof = []
    idx = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        if idx % 2 == 0:
            proof.append(("R", level[idx + 1]))
        else:
            proof.append(("L", level[idx - 1]))
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def merkle_verify(leaf_hash: bytes, proof, root: bytes) -> bool:
    leaf_hash = _require_bytes(leaf_hash, 32, "leaf hash")
    root = _require_bytes(root, 32, "root")
    cur = leaf_hash
    for step in proof:
        try:
            side, sib = step
        except (TypeError, ValueError):
            return False
        sib = _require_bytes(sib, 32, "sibling hash")
        if side == "L":
            cur = hashlib.sha256(sib + cur).digest()
        elif side == "R":
            cur = hashlib.sha256(cur + sib).digest()
        else:
            return False
    return cur == root


# ============================================================ §4 سلسلة الأدلة
_GENESIS_PREV = bytes(32)  # معلن: prev_hash للسجل الأول = 32 بايت صفر


def chain_build(items) -> list:
    """§8.5: H(Pᵢ) = H(Pᵢ₋₁ || dataᵢ) — الصيغة الحرفية."""
    if not isinstance(items, (list, tuple)) or len(items) == 0:
        raise ValidationError("chain: items must be a non-empty list")
    chain = []
    prev = _GENESIS_PREV
    for i, data in enumerate(items):
        data = _require_bytes(data, None, "chain data")
        h = hashlib.sha256(prev + data).digest()
        chain.append({"index": i, "data": data,
                      "prev_hash": prev.hex(), "hash": h.hex()})
        prev = h
    return chain


def chain_verify(chain) -> bool:
    """«أي تعديل يكسر السلسلة»: كل رابط يُعاد حسابه من الصفر.
    الفشل الدلالي False (لا رفع) — عقد M1."""
    if not isinstance(chain, (list, tuple)) or len(chain) == 0:
        return False
    prev = _GENESIS_PREV
    for i, rec in enumerate(chain):
        try:
            if rec["index"] != i:
                return False
            data = rec["data"]
            if not isinstance(data, (bytes, bytearray)):
                return False
            data = bytes(data)
            if rec["prev_hash"] != prev.hex():
                return False
            if hashlib.sha256(prev + data).hexdigest() != rec["hash"]:
                return False
        except (KeyError, TypeError, ValueError):
            return False
        prev = bytes.fromhex(rec["hash"])
    return True


# ============================================================ §5 طابع RFC 3161
def timestamp_token(data: bytes, tsa_seed: bytes,
                    when_ms: int | None = None) -> dict:
    """§8.4: TST = Sign(TSA_key, Hash(data) || Time).
    Time = مللي-ثانية UTC (int). TSA محلية — لا اتصال خارجي إطلاقاً
    (قائمة الأهداف المغلقة قائمة). when_ms صريح في البطاريات."""
    data = _require_bytes(data, None, "data")
    tsa_seed = _require_bytes(tsa_seed, 32, "tsa_seed")
    when = _now_ms() if when_ms is None else _require_int(when_ms, "when_ms")
    hmsg = hashlib.sha256(data).digest()
    payload = hmsg + int.to_bytes(when, 8, "little")  # Hash(data) || Time
    sig = ed25519_sign(tsa_seed, payload)
    return {"hash_alg": "sha256", "hashed_msg": hmsg.hex(),
            "time_ms": when, "signature": sig.hex()}


def timestamp_verify(token: dict, data: bytes, tsa_pub: bytes) -> bool:
    tsa_pub = _require_bytes(tsa_pub, 32, "tsa_pub")
    if not isinstance(token, dict):
        return False
    try:
        hmsg = bytes.fromhex(token["hashed_msg"])
        sig = bytes.fromhex(token["signature"])
        when = token["time_ms"]
    except (KeyError, ValueError, TypeError):
        return False
    if not isinstance(when, int) or isinstance(when, bool):
        return False
    if len(hmsg) != 32 or len(sig) != 64:
        return False
    if hmsg != hashlib.sha256(data).digest():
        return False
    payload = hmsg + int.to_bytes(when, 8, "little")
    return ed25519_verify(sig, payload, tsa_pub)


# ============================================================ §6 ChaCha20-Poly1305
_CHACHA_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """كتلة ChaCha20 واحدة (RFC 8439 §2.3) — بايثون خالص."""
    k = struct.unpack("<8L", key)
    n = struct.unpack("<3L", nonce)
    state = list(_CHACHA_CONSTANTS) + list(k) + [counter & 0xFFFFFFFF] \
        + list(n)
    working = list(state)
    for _ in range(10):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    return struct.pack("<16L", *[(a + b) & 0xFFFFFFFF
                                 for a, b in zip(working, state)])


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes,
                  counter: int = 1) -> bytes:
    out = bytearray()
    for off in range(0, len(data), 64):
        ks = _chacha20_block(key, counter + off // 64, nonce)
        chunk = data[off:off + 64]
        out.extend(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - (len(data) % 16)) % 16)


_POLY_P = (1 << 130) - 5
_POLY_R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def _poly1305(key: bytes, msg: bytes) -> bytes:
    """Poly1305 (RFC 8439 §2.5) بأعداد بايثون الكبيرة — حتمي خالص."""
    r = int.from_bytes(key[:16], "little") & _POLY_R_MASK
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % _POLY_P
    acc = (acc + s) & ((1 << 128) - 1)
    return int.to_bytes(acc, 16, "little")


def chacha20poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                             aad: bytes) -> bytes:
    """AEAD RFC 8439 §2.8: مفتاح Poly من كتلة counter=0، التشفير من 1،
    الوسم على (ct||pad||aad||pad||len(aad)||len(ct)). حتمي بالكامل."""
    key = _require_bytes(key, 32, "key")
    nonce = _require_bytes(nonce, 12, "nonce")
    plaintext = _require_bytes(plaintext, None, "plaintext")
    aad = _require_bytes(aad, None, "aad")
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, nonce, plaintext, counter=1)
    # RFC 8439 §2.8: AAD ثم ciphertext (كلٌّ محشو) ثم الطولان —
    # الترتيب aad-first هو الحرفي (أُصيب مرتَّتُه الأولى في GREEN
    # بيد متجه §2.8.2 الثابت — ملاحظة التكرار الصادقة مُسجَّلة).
    mac_data = (aad + _pad16(aad) + ct + _pad16(ct)
                + struct.pack("<QQ", len(aad), len(ct)))
    tag = _poly1305(poly_key, mac_data)
    return ct + tag


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
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    mac_data = (aad + _pad16(aad) + ct + _pad16(ct)
                + struct.pack("<QQ", len(aad), len(ct)))
    expected = _poly1305(poly_key, mac_data)
    if not hmac.compare_digest(expected, tag):
        raise IntegrityError("aead: authentication failed")
    return _chacha20_xor(key, nonce, ct, counter=1)


# ============================================================ §7 HKDF-SHA256
def hkdf_sha256_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2: PRK = HMAC-SHA256(salt, IKM)."""
    salt = _require_bytes(salt, None, "salt")
    ikm = _require_bytes(ikm, None, "ikm")
    if len(salt) == 0:
        salt = b"\x00" * 32  # RFC 5869: الافتراضي أصفار بطول الهاش
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_sha256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3: T(i)=HMAC(PRK, T(i-1)||info||i) — الحد 255·32."""
    prk = _require_bytes(prk, None, "prk")
    info = _require_bytes(info, None, "info")
    length = _require_int(length, "length")
    if not 1 <= length <= 255 * 32:
        raise ValidationError(
            f"hkdf: length must be in [1, {255 * 32}], got {length}")
    okm = bytearray()
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]),
                     hashlib.sha256).digest()
        okm.extend(t)
        i += 1
    return bytes(okm[:length])


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_sha256_expand(hkdf_sha256_extract(salt, ikm), info, length)


# ============================================================ §8 نموذج الإثبات
_CLAIM_CORE_FIELDS = ("claim", "evidence_sha256", "witness", "timestamp_ms")


def create_claim(statement: str, evidence: bytes, witness: dict,
                 when_ms: int | None = None) -> dict:
    """§8.1/§8.6: Claim غير موقّع — الحقول الأربعة الأساسية + Hash =
    SHA-256(تمثيل قياسي للنواة). Evidence يُلزق بهاشه (لا يُنسخ خاماً)."""
    if not isinstance(statement, str) or not statement:
        raise ValidationError("claim statement must be a non-empty str")
    evidence = _require_bytes(evidence, None, "evidence")
    if not isinstance(witness, dict):
        raise ValidationError("witness must be a dict")
    when = _now_ms() if when_ms is None else _require_int(when_ms,
                                                          "when_ms")
    core = {"claim": statement,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "witness": witness,
            "timestamp_ms": when}
    core["hash"] = hashlib.sha256(_canonical(
        {k: core[k] for k in _CLAIM_CORE_FIELDS})).hexdigest()
    return core


def sign_claim(claim: dict, seed: bytes) -> dict:
    """§8.6: SignedClaim = Claim + Signature (Ed25519 على بايتات Hash)
    + مفتاح الموقّع العام (للتحقق الذاتي المضمّن)."""
    if not isinstance(claim, dict):
        raise ValidationError("claim must be a dict")
    try:
        core = {k: claim[k] for k in _CLAIM_CORE_FIELDS}
        core["hash"] = claim["hash"]
    except KeyError as exc:
        raise ValidationError(f"claim missing field: {exc}") from None
    recomputed = hashlib.sha256(
        _canonical({k: core[k] for k in _CLAIM_CORE_FIELDS})).hexdigest()
    if recomputed != claim["hash"]:
        raise ValidationError("claim hash mismatch (tampered claim)")
    seed = _require_bytes(seed, 32, "seed")
    signed = dict(claim)
    signed["signature"] = ed25519_sign(
        seed, bytes.fromhex(claim["hash"])).hex()
    signed["signer_pubkey"] = ed25519_public_key(seed).hex()
    return signed


def verify_claim(signed: dict, pub: bytes | None = None) -> bool:
    """§8.6: إعادة حساب الهاش + التحقق من التوقيع. الفشل الدلالي False."""
    if not isinstance(signed, dict):
        return False
    try:
        core = {k: signed[k] for k in _CLAIM_CORE_FIELDS}
        if hashlib.sha256(_canonical(core)).hexdigest() != signed["hash"]:
            return False
        sig = bytes.fromhex(signed["signature"])
        spk = bytes.fromhex(signed["signer_pubkey"])
    except (KeyError, ValueError, TypeError):
        return False
    if pub is not None:
        pub = _require_bytes(pub, 32, "pub")
        if spk != pub:
            return False
    return ed25519_verify(sig, bytes.fromhex(signed["hash"]), spk)


# ============================================================ §9 سلسلة الحيازة
_CUSTODY_CORE_FIELDS = ("seq", "action", "prev_custodian", "custodian",
                        "payload_sha256", "prev_hash", "timestamp_ms")
_CUSTODY_GENESIS = bytes(32)  # prev_hash لسجل الفتح = 32 صفراً (معلن)


def _custody_record_hash(rec: dict) -> str:
    return hashlib.sha256(_canonical(
        {k: rec[k] for k in _CUSTODY_CORE_FIELDS})).hexdigest()


def custody_open(payload: bytes, custodian_seed: bytes,
                 when_ms: int | None = None) -> dict:
    """فتح سلسلة حيازة: السجل 0 (action=open) موقّع من الفاتح."""
    payload = _require_bytes(payload, None, "payload")
    custodian_seed = _require_bytes(custodian_seed, 32, "custodian_seed")
    when = _now_ms() if when_ms is None else _require_int(when_ms,
                                                          "when_ms")
    rec = {"seq": 0, "action": "open", "prev_custodian": None,
           "custodian": ed25519_public_key(custodian_seed).hex(),
           "payload_sha256": hashlib.sha256(payload).hexdigest(),
           "prev_hash": _CUSTODY_GENESIS.hex(),
           "timestamp_ms": when}
    rec["record_hash"] = _custody_record_hash(rec)
    rec["signature"] = ed25519_sign(
        custodian_seed, bytes.fromhex(rec["record_hash"])).hex()
    return rec


def custody_transfer(prev_rec: dict, from_seed: bytes, to_seed: bytes,
                     when_ms: int | None = None) -> dict:
    """تنازل موقّع من الحائز الحالي حصراً — مفتاح المسلِّم يجب أن يطابق
    حائز السجل السابق، وإلا رفض ذري (التزوير البنيوي مستحيل بالبناء)."""
    if not isinstance(prev_rec, dict):
        raise ValidationError("prev_rec must be a dict")
    from_seed = _require_bytes(from_seed, 32, "from_seed")
    to_seed = _require_bytes(to_seed, 32, "to_seed")
    when = _now_ms() if when_ms is None else _require_int(when_ms,
                                                          "when_ms")
    from_pub_hex = ed25519_public_key(from_seed).hex()
    try:
        if prev_rec["custodian"] != from_pub_hex:
            raise ValidationError(
                "custody: transferor key does not match the current "
                "holder (structural anti-forgery)")
        prev_seq = prev_rec["seq"]
        prev_hash = prev_rec["record_hash"]
        payload_sha = prev_rec["payload_sha256"]
    except KeyError as exc:
        raise ValidationError(f"prev_rec missing field: {exc}") from None
    rec = {"seq": prev_seq + 1, "action": "transfer",
           "prev_custodian": from_pub_hex,
           "custodian": ed25519_public_key(to_seed).hex(),
           "payload_sha256": payload_sha,
           "prev_hash": prev_hash,
           "timestamp_ms": when}
    rec["record_hash"] = _custody_record_hash(rec)
    rec["signature"] = ed25519_sign(
        from_seed, bytes.fromhex(rec["record_hash"])).hex()
    return rec


def custody_verify(records, payload: bytes,
                   expected_final_pub=None) -> dict:
    """تحقق شامل مع تقرير صادق: {valid, length, final_custodian, breaks}.
    فشل التحقق الدلالي = valid False مع تعداد الكسور — لا صمت."""
    payload = _require_bytes(payload, None, "payload")
    if not isinstance(records, (list, tuple)) or len(records) == 0:
        raise ValidationError("custody: records must be a non-empty list")
    breaks = []
    payload_sha = hashlib.sha256(payload).hexdigest()
    prev_hash = _CUSTODY_GENESIS.hex()
    holder = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            breaks.append(f"record@{i}: not a dict")
            continue
        try:
            if rec["seq"] != i:
                breaks.append(f"seq@{i}")
            if rec["action"] != ("open" if i == 0 else "transfer"):
                breaks.append(f"action@{i}")
            if i > 0 and rec["prev_custodian"] != holder:
                breaks.append(f"prev_custodian@{i}")
            if rec["payload_sha256"] != payload_sha:
                breaks.append(f"payload_sha@{i}")
            if rec["prev_hash"] != prev_hash:
                breaks.append(f"prev_hash@{i}")
            if _custody_record_hash(rec) != rec["record_hash"]:
                breaks.append(f"record_hash@{i}")
            # الموقّع: الفاتح للتسجيل الأول؛ المسلِّم (prev_custodian)
            # لكل تنازل — إثبات أن الحائز الحالي أذن بالنقل.
            signer = (rec["custodian"] if i == 0
                      else rec["prev_custodian"])
            if not ed25519_verify(bytes.fromhex(rec["signature"]),
                                  bytes.fromhex(rec["record_hash"]),
                                  bytes.fromhex(signer)):
                breaks.append(f"signature@{i}")
            holder = rec["custodian"]
            prev_hash = rec["record_hash"]
        except (KeyError, ValueError, TypeError):
            breaks.append(f"malformed@{i}")
    final_pub_hex = None
    if holder is not None:
        final_pub_hex = holder
    if expected_final_pub is not None:
        if isinstance(expected_final_pub, (bytes, bytearray)):
            exp = bytes(expected_final_pub).hex()
        elif isinstance(expected_final_pub, str):
            exp = expected_final_pub
        else:
            raise ValidationError(
                "expected_final_pub must be 32-byte key or hex str")
        if final_pub_hex != exp:
            breaks.append("final_custodian")
    return {"valid": len(breaks) == 0, "length": len(records),
            "final_custodian": final_pub_hex, "breaks": breaks}
