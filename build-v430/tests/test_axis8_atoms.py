#!/usr/bin/env python3
"""SENTINEL Axis-8 — M3 ATOMS: البطاريات الإجبارية الثلاث.

PROVENANCE والعقد (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-7):
- جدول بطاريات أمر البناء الحرفي غير مسترد من أي سجل ملتزم (ضاع مع
  قطع الجلسة)؛ البطاريات الثلاث أدناه مُشتقة من عقد M1 المُسجَّل
  (tests/test_axis8_proof.py — D1 المواصفة §8 + D2 قائمة النطاق)
  ومن نمط البطاريات المعتمد في المحاور 4/7/10 (عشوائية مزروعة ×
  مرجع خارجي × سيناريوهات عدائية بالضبط-عدد) — قابلة للإحلال عند أي
  حد محطة.
- تُنفَّذ فوق sentinel/proof.py (M2 GREEN عند 4a0f4d1) — لا تعديل
  في المحرك ولا لمس للنواة 227×19=4313 (جناح مستقل، غير مُسجَّل في
  @case، كل بطارية تستورد sentinel.proof داخل جسمها).
- انضباط الهضم: التيار المنطقي فقط (battery, what, ok) — أزمنة
  الحائط في detail ولا تدخل الهضم أبداً (انضباط المحور-11). كل
  العشوائية ببذور ثابتة معلَنة — لا عشوائية حرة.
- خط الإيقاف الحرفي: أي فشل يُلصق خاماً — لا إصلاح بلا إذن.

البطاريات الثلاث (مُشتقة من عقد M1 — مُعلنة):
  8a — 500 دورة Ed25519+Merkle مزروعة:
       sign→verify صحيح، عبث→False، إثبات انتماء عضو/غير عضو،
       جذر حتمي → صفر انهيار، هضم قابل للتكرار (مروران)
  8b — 200 مطابقة مع مرجع خارجي:
       Ed25519 (100) وChaCha20-Poly1305 (60) مقابل pyca بايت-ببايت
       (الحتمية تجعلها قاطعة)، وHKDF-SHA256 (40) مقابل إعادة تنفيذ
       RFC 5869 مستقلة بـ hmac/hashlib داخل البطارية → 200/200
  8c — بالضبط 50 سيناريو عدائي:
       أطوال/أنواع فاسدة، حدود HKDF، عبث سلاسل/طوابع/وسوم، تزوير
       حيازة → رفض ذري بالاستثناء المعلَن أو False المعلن،
       صفر أنواع غير معلنة، لا تسمم حالة (فحص حي)

ملاحظات الصدق (الفروقات المُعلنة — لا مخفية):
  N1 (8a) — «عشوائية» = مولَّدة ببذور ثابتة معلَنة (seed=200000+i
      للمفاتيح والرسائل؛ بذرة مستقلة لأشجار Merkle): عشوائية التوليد
      حتمية الإعادة — هذا ما يجعل «هضم قابل للتكرار» برهاناً لا
      ادعاءً. سجل كل دورة يحمل بادئات hex (16 حرفاً) للمفتاح العام
      والتوقيع والجذر — كافية للهضم الحتمي دون تضخيم الدليل.
  N2 (8b) — pyca مرجع خارجي (يُستورد داخل البطارية لا المحرك):
      Ed25519 حتمي (RFC 8032) وAEAD حتمي — فالمطابقة بايت-ببايت
      ممكنة وقاطعة (ليست ضمن تسامح). مرجع HKDF إعادة تنفيذ مستقلة
      للـRFC داخل البطارية (hmac/hashlib مباشرة — لا تستدعي المحرك).
  N3 (8c) — التصنيف: كل الهجمات إما خرق عقد بنيوي (ValidationError
      المعلَن) أو فشل دلالي معلَن (False / IntegrityError / سلسلة
      حيازة valid=False مع كسر معدود). «صفر انهيار» يعني: لا
      استثناء من نوع غير معلَن، لا TypeError/AttributeError متسرب،
      ولا تسمم حالة (فحص حي: بعد الخمسين هجوماً، دورة صالحة كاملة
      تُنتج القيم نفسها المحسوبة قبل البطارية).

Usage:
  python3 -m pytest tests/test_axis8_atoms.py --tb=short -q
  python3 tests/test_axis8_atoms.py --out results/axis8/axis8_ATOMS.json
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _proof():
    import sentinel.proof as proof
    return proof


# ============================================================ البطارية 8a
def _cycle_pass(p, sid: int) -> dict:
    """دورة واحدة: مفتاح/رسالة مزروعة → توقيع+تحقق+عبث+Merkle.

    أي استثناء غير متوقع = انهيار (يُلتقط عند المستدعي خاماً)."""
    rng = random.Random(200000 + sid)
    seed = bytes(rng.randrange(256) for _ in range(32))
    msg = bytes(rng.randrange(256) for _ in range(rng.randint(1, 96)))

    pub = p.ed25519_public_key(seed)
    sig = p.ed25519_sign(seed, msg)
    assert len(pub) == 32 and len(sig) == 64
    assert p.ed25519_verify(sig, msg, pub) is True, f"[8a s{sid}] verify"

    # عبث رسالة (بت واحد) → False
    bad_msg = bytearray(msg)
    bad_msg[len(msg) // 2] ^= 0x40
    assert p.ed25519_verify(sig, bytes(bad_msg), pub) is False, \
        f"[8a s{sid}] tampered msg accepted"

    # مفتاح عام آخر → False
    other_pub = p.ed25519_public_key(bytes(rng.randrange(256)
                                           for _ in range(32)))
    assert p.ed25519_verify(sig, msg, other_pub) is False, \
        f"[8a s{sid}] wrong pub accepted"

    # Merkle: شجرة مزروعة بحجم 1..64، فهرس هدف، عضو/غير عضو + حتمية
    n = 1 + (sid * 7) % 64
    leaves = [bytes(rng.randrange(256) for _ in range(rng.randint(1, 48)))
              for _ in range(n)]
    root1 = p.merkle_root(leaves)
    root2 = p.merkle_root(list(leaves))
    assert root1 == root2, f"[8a s{sid}] merkle root non-deterministic"
    idx = rng.randrange(n)
    proof = p.merkle_prove(leaves, idx)
    assert p.merkle_verify(hashlib.sha256(leaves[idx]).digest(),
                           proof, root1) is True, f"[8a s{sid}] inclusion"
    non = hashlib.sha256(b"not-in-tree-%d" % sid).digest()
    assert p.merkle_verify(non, proof, root1) is False, \
        f"[8a s{sid}] non-member accepted"

    return {"sid": sid, "pub": pub.hex()[:16], "sig": sig.hex()[:16],
            "root": root1.hex()[:16]}


def battery_8a(p) -> dict:
    """8a — 500 دورة Ed25519+Merkle مزروعة → صفر انهيار، هضم قابل
    للتكرار (مروران مستقلان في نفس العملية → هضم سجلات متطابق)."""
    t0 = time.perf_counter()
    crashes = []
    records1 = []
    for sid in range(500):
        try:
            records1.append(_cycle_pass(p, sid))
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
            crashes.append({"sid": sid, "error": repr(exc)})
    # المرور الثاني — نفس البذور → نفس السجلات (حتمية الإعادة)
    records2 = []
    for sid in range(500):
        try:
            records2.append(_cycle_pass(p, sid))
        except BaseException as exc:  # noqa: BLE001
            crashes.append({"sid": sid, "pass": 2, "error": repr(exc)})
            break
    d1 = hashlib.sha256(json.dumps(records1, sort_keys=True)
                        .encode()).hexdigest()
    d2 = hashlib.sha256(json.dumps(records2, sort_keys=True)
                        .encode()).hexdigest()
    ok = (len(crashes) == 0 and d1 == d2 and len(records1) == 500)
    return {
        "battery": "8a", "what": "500 seeded Ed25519+Merkle cycles",
        "ok": ok,
        "detail": {
            "cycles": 500, "crashes": crashes[:5], "crash_count":
                len(crashes), "records_digest_1": d1,
            "records_digest_2": d2, "repeatable": d1 == d2,
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ البطارية 8b
def _hkdf_reference(ikm: bytes, salt: bytes, info: bytes,
                    length: int) -> bytes:
    """مرجع RFC 5869 مستقل — hmac/hashlib مباشرة، لا يستدعي المحرك."""
    if len(salt) == 0:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]),
                     hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def battery_8b(p) -> dict:
    """8b — 200 مطابقة مع مرجع خارجي: pyca (Ed25519×100، AEAD×60
    بايت-ببايت — الحتمية قاطعة) + مرجع RFC 5869 مستقل (HKDF×40)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import \
        ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)

    t0 = time.perf_counter()
    mismatches = []
    counts = {"ed25519": 0, "aead": 0, "hkdf": 0}

    for i in range(100):
        rng = random.Random(300000 + i)
        seed = bytes(rng.randrange(256) for _ in range(32))
        msg = bytes(rng.randrange(256) for _ in range(rng.randint(0, 128)))
        try:
            ref = Ed25519PrivateKey.from_private_bytes(seed)
            ref_pub = ref.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)
            ref_sig = ref.sign(msg)
            ours_pub = p.ed25519_public_key(seed)
            ours_sig = p.ed25519_sign(seed, msg)
            if ours_pub != ref_pub or ours_sig != ref_sig:
                mismatches.append({"i": i, "kind": "ed25519",
                                   "pub_eq": ours_pub == ref_pub,
                                   "sig_eq": ours_sig == ref_sig})
            else:
                counts["ed25519"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"i": i, "kind": "ed25519-crash",
                               "error": repr(exc)})

    for i in range(60):
        rng = random.Random(400000 + i)
        key = bytes(rng.randrange(256) for _ in range(32))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        pt = bytes(rng.randrange(256)
                   for _ in range(rng.randint(0, 200)))
        aad = bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
        try:
            ref_ct = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
            ours_ct = p.chacha20poly1305_encrypt(key, nonce, pt, aad)
            if ours_ct != ref_ct:
                mismatches.append({"i": i, "kind": "aead",
                                   "ct_eq": ours_ct == ref_ct})
            else:
                counts["aead"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"i": i, "kind": "aead-crash",
                               "error": repr(exc)})

    for i in range(40):
        rng = random.Random(500000 + i)
        ikm = bytes(rng.randrange(256) for _ in range(rng.randint(16, 64)))
        salt = bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))
        info = bytes(rng.randrange(256) for _ in range(rng.randint(0, 24)))
        length = rng.randint(1, 128)
        try:
            ref = _hkdf_reference(ikm, salt, info, length)
            ours = p.hkdf_sha256(ikm, salt, info, length)
            if ours != ref:
                mismatches.append({"i": i, "kind": "hkdf",
                                   "eq": ours == ref})
            else:
                counts["hkdf"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"i": i, "kind": "hkdf-crash",
                               "error": repr(exc)})

    ok = (len(mismatches) == 0 and counts["ed25519"] == 100
          and counts["aead"] == 60 and counts["hkdf"] == 40)
    return {
        "battery": "8b",
        "what": "200 cross-checks vs external reference (pyca + RFC5869)",
        "ok": ok,
        "detail": {
            "matched": counts, "mismatches": mismatches[:10],
            "mismatch_total": len(mismatches),
            "reference": "pyca-cryptography 44.0.3 (external; engine "
                         "never imports it) + independent RFC 5869 "
                         "re-implementation",
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ البطارية 8c
def battery_8c(p) -> dict:
    """8c — بالضبط 50 سيناريو عدائي: رفض ذري بالاستثناء المعلَن أو
    False المعلن، صفر أنواع غير معلنة، لا تسمم حالة (فحص حي).

    كل هجوم: (اسم، استدعاء، النتيجة المعلَنة). النجاح = النتيجة
    المعلَنة بالضبط؛ أي استثناء آخر أو عودة طبيعية = انهيار خام.
    """
    t0 = time.perf_counter()
    seed32 = bytes(range(32))
    pub32 = p.ed25519_public_key(seed32)
    other_seed = bytes(range(77, 109))
    key32, nonce12 = bytes(range(40, 72)), bytes(range(12))
    prk = p.hkdf_sha256_extract(b"salt", b"ikm")
    ev, witness = b"evidence", {"w": "sentinel"}
    claim = p.create_claim("stmt", ev, witness, when_ms=1760000000000)
    signed = p.sign_claim(claim, seed32)
    chain = p.chain_build([b"a", b"b", b"c"])
    tok = p.timestamp_token(b"ts-data", seed32, when_ms=1760000000000)
    payload = b"custody-payload"
    r0 = p.custody_open(payload, seed32, when_ms=1760000000000)
    ct = p.chacha20poly1305_encrypt(key32, nonce12, b"pt", b"aad")
    leaves = [b"l0", b"l1", b"l2", b"l3"]
    root = p.merkle_root(leaves)
    proof0 = p.merkle_prove(leaves, 0)

    # فحص حي — القيم المرجعية قبل الهجمات (لاسمم حالة)
    ref_sig = p.ed25519_sign(seed32, b"state-canary")
    ref_root = p.merkle_root([b"canary-a", b"canary-b"])

    V, I = p.ValidationError, p.IntegrityError  # المعلَنان

    attacks: list[tuple[str, object, object]] = [
        # --- Ed25519 بنيوي (8)
        ("ed_pub_seed31", lambda: p.ed25519_public_key(bytes(31)), V),
        ("ed_pub_seed33", lambda: p.ed25519_public_key(bytes(33)), V),
        ("ed_pub_str", lambda: p.ed25519_public_key("hex"), V),
        ("ed_sign_seed0", lambda: p.ed25519_sign(bytes(0), b"m"), V),
        ("ed_sign_seed64", lambda: p.ed25519_sign(bytes(64), b"m"), V),
        ("ed_verify_sig63", lambda: p.ed25519_verify(bytes(63), b"m", pub32), V),
        ("ed_verify_pub31", lambda: p.ed25519_verify(bytes(64), b"m", bytes(31)), V),
        ("ed_sign_msg_int", lambda: p.ed25519_sign(seed32, 123), V),
        # --- Merkle بنيوي (6) — [تكرار عددي أُصلح: القائمة كانت 51
        #     هجوماً؛ أُزيل mk_root_none (ذات فئة mk_root_empty) —
        #     عدّي أنا، المحرك بريء: كل الـ51 رُفضت بالاستثناء المعلَن]
        ("mk_root_empty", lambda: p.merkle_root([]), V),
        ("mk_root_str_leaf", lambda: p.merkle_root([b"a", "s", b"c"]), V),
        ("mk_root_int_leaf", lambda: p.merkle_root([b"a", 5, b"c"]), V),
        ("mk_prove_neg", lambda: p.merkle_prove([b"a"], -1), V),
        ("mk_prove_oob", lambda: p.merkle_prove([b"a", b"b"], 2), V),
        ("mk_prove_empty", lambda: p.merkle_prove([], 0), V),
        # --- Merkle دلالي (3)
        ("mk_bad_side", lambda: p.merkle_verify(
            hashlib.sha256(b"l0").digest(), [("X", bytes(32))], root),
         False),
        ("mk_sib_31b", lambda: p.merkle_verify(
            hashlib.sha256(b"l0").digest(), [("R", bytes(31))], root), V),
        ("mk_non_member", lambda: p.merkle_verify(
            hashlib.sha256(b"XX").digest(), proof0, root), False),
        # --- سلسلة الأدلة (6)
        ("ch_build_empty", lambda: p.chain_build([]), V),
        ("ch_build_none_item", lambda: p.chain_build([b"a", None]), V),
        ("ch_verify_str", lambda: p.chain_verify("not-a-list"), False),
        ("ch_str_data", lambda: p.chain_verify(
            [dict(r, data="str") for r in chain]), False),
        ("ch_mid_flip", lambda: p.chain_verify(
            [dict(r) for r in chain[:1]]
            + [dict(chain[1], data=b"X" + chain[1]["data"][1:])]
            + [dict(r) for r in chain[2:]]), False),
        ("ch_forged_hash", lambda: p.chain_verify(
            [dict(r) for r in chain[:2]]
            + [dict(chain[2], hash="ab" * 32)]), False),
        # --- الطابع الزمني (6)
        ("ts_seed16", lambda: p.timestamp_token(b"d", bytes(16), when_ms=1), V),
        ("ts_when_bool", lambda: p.timestamp_token(b"d", seed32, when_ms=True), V),
        ("ts_when_str", lambda: p.timestamp_token(b"d", seed32, when_ms="17"), V),
        ("ts_verify_empty_dict", lambda: p.timestamp_verify({}, b"d", pub32), False),
        ("ts_bad_hex", lambda: p.timestamp_verify(
            dict(tok, signature="zz"), b"ts-data", pub32), False),
        ("ts_shifted_1ms", lambda: p.timestamp_verify(
            dict(tok, time_ms=tok["time_ms"] + 1), b"ts-data", pub32), False),
        # --- AEAD (8)
        ("ae_key16", lambda: p.chacha20poly1305_encrypt(
            bytes(16), nonce12, b"x", b""), V),
        ("ae_nonce8", lambda: p.chacha20poly1305_encrypt(
            key32, bytes(8), b"x", b""), V),
        ("ae_pt_str", lambda: p.chacha20poly1305_encrypt(
            key32, nonce12, "pt", b""), V),
        ("ae_aad_int", lambda: p.chacha20poly1305_encrypt(
            key32, nonce12, b"x", 42), V),
        ("ae_ct_short", lambda: p.chacha20poly1305_decrypt(
            key32, nonce12, b"short", b"aad"), I),
        ("ae_ct_flip", lambda: p.chacha20poly1305_decrypt(
            key32, nonce12, ct[:5] + bytes([ct[5] ^ 1]) + ct[6:], b"aad"), I),
        ("ae_wrong_aad", lambda: p.chacha20poly1305_decrypt(
            key32, nonce12, ct, b"other"), I),
        ("ae_wrong_nonce", lambda: p.chacha20poly1305_decrypt(
            key32, bytes(12), ct, b"aad"), I),
        # --- HKDF (5)
        ("hk_len0", lambda: p.hkdf_sha256_expand(prk, b"i", 0), V),
        ("hk_len_8161", lambda: p.hkdf_sha256_expand(prk, b"i", 255 * 32 + 1), V),
        ("hk_info_str", lambda: p.hkdf_sha256_expand(prk, "i", 32), V),
        ("hk_len_bool", lambda: p.hkdf_sha256_expand(prk, b"i", True), V),
        ("hk_ikm_int", lambda: p.hkdf_sha256_extract(b"s", 123), V),
        # --- نموذج الإثبات (7)
        ("cl_empty_stmt", lambda: p.create_claim("", ev, witness), V),
        ("cl_stmt_int", lambda: p.create_claim(5, ev, witness), V),
        ("cl_ev_str", lambda: p.create_claim("s", "str", witness), V),
        ("cl_witness_list", lambda: p.create_claim("s", ev, [1, 2]), V),
        ("cl_sign_tampered", lambda: p.sign_claim(
            dict(claim, hash="cd" * 32), seed32), V),
        ("cl_verify_tampered", lambda: p.verify_claim(
            dict(signed, claim="other")), False),
        ("cl_verify_bad_hex", lambda: p.verify_claim(
            dict(signed, signature="zz")), False),
        # --- الحيازة ( بالضبط الإغلاق على 50 )
        ("cu_nonholder", lambda: p.custody_transfer(
            r0, other_seed, other_seed, when_ms=1), V),
    ]

    crashes = []
    rejected_atomically = 0
    for name, call, expected in attacks:
        try:
            result = call()
            if expected is False:
                if result is not False:
                    crashes.append({"attack": name,
                                    "error": f"expected False, got {result!r}"})
                else:
                    rejected_atomically += 1
            else:
                crashes.append({"attack": name,
                                "error": f"expected {expected.__name__}, "
                                         f"returned {result!r}"})
        except BaseException as exc:  # noqa: BLE001
            if expected is not False and isinstance(exc, expected):
                rejected_atomically += 1
            else:
                crashes.append({"attack": name, "error": repr(exc)})

    # فحص حي — لا تسمم حالة: الكناري بعد الخمسين هجوماً مطابق لما قبلها
    post_sig = p.ed25519_sign(seed32, b"state-canary")
    post_root = p.merkle_root([b"canary-a", b"canary-b"])
    state_clean = (post_sig == ref_sig and post_root == ref_root)

    ok = (len(crashes) == 0 and rejected_atomically == 50
          and len(attacks) == 50 and state_clean)
    return {
        "battery": "8c",
        "what": "exactly 50 adversarial scenarios — atomic reject",
        "ok": ok,
        "detail": {
            "attacks": 50, "rejected_atomically": rejected_atomically,
            "crashes": crashes[:10], "crash_count": len(crashes),
            "state_poisoning_check": state_clean,
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ pytest
def test_battery_8a():
    """8a — 500 دورة مزروعة: صفر انهيار، هضم قابل للتكرار."""
    assert battery_8a(_proof())["ok"]


def test_battery_8b():
    """8b — 200 مطابقة مع مرجع خارجي: 200/200، صفر عدم مطابقة."""
    assert battery_8b(_proof())["ok"]


def test_battery_8c():
    """8c — 50 سيناريو عدائي: رفض ذري، صفر انهيار، لا تسمم حالة."""
    assert battery_8c(_proof())["ok"]


# ============================================================ وضع الدليل
_BATTERIES = [("8a", battery_8a), ("8b", battery_8b), ("8c", battery_8c)]


def _overall_digest(bats: list[dict]) -> str:
    """هضم التيار المنطقي الكلي: (بطارية، ماذا، نجحت) فقط (انضباط 11)."""
    h = hashlib.sha256()
    for b in bats:
        h.update(f"{b['battery']}:{b['what']}:{int(b['ok'])}"
                 .encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-8 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    p = _proof()
    bats = [fn(p) for _, fn in _BATTERIES]
    total = len(bats)
    passed = sum(1 for b in bats if b["ok"])
    doc = {
        "suite": "axis8-atoms",
        "station": "M3-ATOMS",
        "total": total,
        "passed_count": passed,
        "failed": total - passed,
        "passed": passed == total,
        "overall_digest": _overall_digest(bats),
        "batteries": bats,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis8-atoms: {passed}/{total} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        extra = ""
        if b["battery"] == "8a":
            extra = (f" | crashes={b['detail']['crash_count']}"
                     f" repeatable={b['detail']['repeatable']}")
        elif b["battery"] == "8b":
            extra = (f" | matched={sum(b['detail']['matched'].values())}"
                     f" mismatches={b['detail']['mismatch_total']}")
        elif b["battery"] == "8c":
            extra = (f" | rejected={b['detail']['rejected_atomically']}/50"
                     f" crashes={b['detail']['crash_count']}"
                     f" state_clean={b['detail']['state_poisoning_check']}")
        print(f"  [{mark}] battery {b['battery']}: {b['what']}{extra}")
        if not b["ok"]:
            print(f"      raw: "
                  f"{json.dumps(b['detail'], ensure_ascii=False)[:600]}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
