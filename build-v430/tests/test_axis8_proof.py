#!/usr/bin/env python3
"""SENTINEL Axis-8 suite — طبقة الإثبات التشفيري العسكرية (Military-Grade
Cryptographic Proof).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-4):
- جدول الحالات أدناه ليس نقلًا حرفياً: جدول-H08 الحرفي من أمر البناء
  2026-10-19 («أمر بناء المحاور 7 و8 و11 و12») ضاع مع قطع الجلسة ولا
  يُسترد من أي سجل ملتزم (فُحص: docs/SPEC_12_AXES_ORIGINAL.md لا يحوي
  جداول H، وworklog المهمة 80 لا يقتبس H08، ولا التزام يحمله).
- العقد أدناه مُشتق من مصدرين ملتزمين، مُعلنين وقابلين للإحلال عند أي
  حد محطة (المشرف يملك الإحلال في أي وقت):
  D1 — المواصفة المرجعية المؤرشفة docs/SPEC_12_AXES_ORIGINAL.md §8
       (طبقة الإثبات): نموذج P=(Claim,Evidence,Witness,Timestamp,Hash,
       Signature) بـ Hash=SHA-256 وSignature=Ed25519 (§8.1)؛ شجرة Merkle
       بـ Leaf=SHA-256(data) وNode=SHA-256(L||R) وإثبات انتماء O(log n)
       (§8.2)؛ الطابع الزمني RFC 3161: TST=Sign(TSA_key, Hash(data)||Time)
       (§8.4)؛ سلسلة الأدلة H(Pᵢ)=H(Pᵢ₋₁||dataᵢ) و«أي تعديل يكسر
       السلسلة» (§8.5)؛ واجهة ProofEngine (§8.6).
  D2 — قائمة نطاق المحور-8 كما وردت في أمر البناء (محفوظة في سياق
       الاستمرار): توقيعات Ed25519، أشجار Merkle، سلاسل هاش SHA-256،
       طوابع RFC 3161، تشفير ChaCha20-Poly1305، اشتقاق مفاتيح
       HKDF-SHA256، سلسلة حيازة (custody chain) — 15 حالة H08_01..H08_15.
- حد معلن (boundary، لا نقص مخفي): zk-SNARK (§8.3 من المواصفة) خارج
  نطاق هذا المحور — قائمة نطاق أمر البناء (D2) لم تشمل ZK، وتنفيذ
  zk-SNARK حقيقي (trusted setup + pairing) خارج عقد المحرك النقي
  stdlib. إن أراده المشرف فهو محطة مستقلة بأمر صريح.

- كل حالة تستورد sentinel.proof داخل جسمها (وليس على مستوى الوحدة)
  حتى تكون المحطة الحمراء 0/15 بنمط فشل واحد حرفياً:
  ModuleNotFoundError: No module named 'sentinel.proof'.
- جناح مستقل، غير مُسجَّل في @case — عقد النواة 227×19=4313 لا يُمس
  بالبناء (نمط المحاور 1/2/3/4/7/10 المعاد).
- انضباط الهضم: التيار المنطقي فقط (اسم الحالة، نجحت؟) — أزمنة الحائط
  تُسجَّل في dur_s ولا تدخل الهضم أبداً (انضباط المحور-11).
- المرجع الخارجي: مكتبة cryptography (pyca) في الاختبارات حصراً —
  الحتمية المقطوعة تتيح مطابقة بايت-ببايت (توقيع Ed25519 حتمي وفق
  RFC 8032، وتشفير AEAD حتمي) — نظير scipy في المحور-7. المحرك نفسه
  نقي stdlib (hashlib/hmac/os فقط) ولا يستورد pyca أبداً.

جدول الحالات (العقد المُشتق — كل حالة بعقدها):
  H08_01 — نموذج الإثبات الستّي P=(Claim,Evidence,Witness,Timestamp,
             Hash,Signature):
             assert all six fields present in signed claim
             assert signed.evidence_sha256 == sha256(evidence)
  H08_02 — دورة Ed25519 توقيع/تحقق:
             assert ed25519_verify(sig, msg, pub) is True
  H08_03 — Ed25519 تزوير/عبث → False:
             assert verify(tampered_msg) is False
             assert verify(wrong_pub) is False
             assert verify(corrupted_sig) is False
  H08_04 — Ed25519 حتمية + متجه RFC 8032 الاختبار 1 (بايت-ببايت):
             assert pub(seed1) == RFC vector
             assert sign(seed1, b'') == RFC vector
             assert sign(s, m) == sign(s, m)
             assert engine sig == pyca sig (مرجع خارجي)
  H08_05 — جذر Merkle لأربع أوراق بإجابة يدوية مستقلة (hashlib في
             الاختبار نفسه):
             assert root == sha256(sha256(h0||h1) || sha256(h2||h3))
  H08_06 — إثبات انتماء Merkle: عضو True / غير عضو False:
             assert merkle_verify(h2, proof, root) is True
             assert merkle_verify(hX, proofX, root) is False
  H08_07 — Merkle أعداد فردية (الاصطلاح المعلن: مضاعفة الأخيرة) وحجم
             الإثبات O(log n):
             assert proof_len <= ceil(log2(n)) + 1 لكل n في 1..9
             assert root(n) حتمي (مروران متطابقان)
  H08_08 — طابع RFC 3161: TST = Sign(TSA, Hash(data)||Time):
             assert timestamp_verify(tok, data, tsa_pub) is True
             assert tok.time_ms == FIXED (زمن مُمرَّر صريحاً)
  H08_09 — طابع زمني مزوّر → False:
             assert verify(tok, tampered_data) is False
             assert verify(tok_with_shifted_time, data) is False
  H08_10 — سلسلة الأدلة H(Pᵢ)=H(Pᵢ₋₁||dataᵢ) (الصيغة الحرفية):
             assert chain[i].hash == sha256(chain[i-1].hash || data_i)
             assert chain_verify(chain) is True
  H08_11 — «أي تعديل يكسر السلسلة» (الخاصية الحرفية §8.5) — كل المواضع:
             flip بايت في الرأس/الوسط/الذيل + حذف سجل + تبديل سجلين
             → chain_verify False في كل صيغة
  H08_12 — ChaCha20-Poly1305 دورة + متجه RFC 8439 §2.8.2 (بايت-ببايت):
             assert ct||tag == RFC vector
             assert decrypt(key, nonce, ct, aad) == plaintext
             assert engine AEAD == pyca AEAD (مرجع خارجي)
  H08_13 — AEAD عبث بت واحد → IntegrityError (صفر تسريب نصيح):
             flip في ciphertext/tag/aad/nonce → raises IntegrityError
  H08_14 — HKDF-SHA256 متجه RFC 5869 الاختبار 1 (بايت-ببايت) + حتمية:
             assert extract/expand/full == RFC PRK/OKM
             assert same inputs → same output; different info → different
  H08_15 — سلسلة الحيازة + الرفض الذري:
             open → transfer → transfer → custody_verify valid=True
             forged transfer (توقيع خارجي) → valid=False
             payload مبذول → valid=False
             atomic rejections (أطوال خاطئة/أنواع فاسدة/حدود HKDF)
             → ValidationError قبل أي حالة

ملاحظات الصدق (العقود المفسَّرة — مُعلنة لا مخفية):
  N1 (عام) — المحرك نقي stdlib: hashlib+hmac+os فقط. pyca مرجع خارجي
      في الاختبارات حصراً (نمط scipy/المحور-7)؛ الطمأنة القصوى:
      التوقيع والتشفير حتميان فالمطابقة بايت-ببايت ممكنة وقاطعة.
  N2 (H08_07) — اصطلاح العقد الفردي المعلن: مضاعفة الورقة الأخيرة
      (نمط Certificate Transparency). الإثبات طوله ≤ ceil(log2(n))+1
      (العقدة المضاعفة قد تضيف مستوى واحداً على الأكثر).
  N3 (H08_08) — «Time» في صيغة المواصفة = مللي-ثانية UTC (int).
      when_ms معامل صريح في كل واجهات المحرك (الافتراضي ساعة النظام)
      — البطاريات تمرر أزمنة مثبتة حصراً (انضباط المحور-11: لا زمن
      حائطي في أي هضم). الطابع موقّع محلياً بـ TSA-key محلية (لا
      اتصال خارجي — قائمة الأهداف المغلقة قائمة).
  N4 (H08_10) — سلسلة الأدلة: prev_hash للسجل الأول = 32 بايت صفر
      (genesis معلن). hash كل سجل يغطي (prev_hash || data) — الصيغة
      الحرفية للمواصفة §8.5.
  N5 (H08_15) — سلسلة الحيازة: كل سجل يحمل record_hash = SHA-256(تمثيل
      قياسي JSON للسجلwithout التوقيع) + توقيع Ed25519 من الحائز
      الحالي (الفاتح للتسجيل الأول؛ المسلِّم للتنازلات). التنازل يُرفض
      ذرياً إن لم يطابق مفتاح المسلِّم الحائز الحالي (التزوير البنيوي
      مستحيل بالبناء). payload_sha ثابت عبر السلسلة كلها.
  N6 (عام) — validation-before-mutation في كل مدخل: أطوال المفاتيح
      (seed=32B, key=32B, nonce=12B)، حدود طول HKDF (≤ 255×32)،
      الأنواع (bytes حصراً — str/bool/int مرفوضة حيث يشترط bytes)،
      الفهارس السالبة/الخارجة، سلاسل فارغة → ValidationError/ValueError
      المعلن قبل أي أثر حالة.

عقد الواجهة المطلوب من sentinel.proof في M2 (ما تستورده هذه البطارية):
  Errors    : ProofError(ValueError) قاعدة؛ ValidationError(ProofError)،
              IntegrityError(ProofError)
  Ed25519   : ed25519_public_key(seed)->bytes32, ed25519_sign(seed, msg)
              ->bytes64, ed25519_verify(sig, msg, pub)->bool
  Merkle    : merkle_root(leaves)->bytes32, merkle_prove(leaves, index)
              ->list[(side,bytes32)], merkle_verify(leaf_hash, proof, root)
              ->bool
  Chain     : chain_build(items)->list[dict], chain_verify(chain)->bool
  Timestamp : timestamp_token(data, tsa_seed, when_ms=None)->dict,
              timestamp_verify(tok, data, tsa_pub)->bool
  AEAD      : chacha20poly1305_encrypt(key, nonce, pt, aad)->bytes(ct||tag),
              chacha20poly1305_decrypt(key, nonce, ct_tag, aad)->bytes
  HKDF      : hkdf_sha256_extract(salt, ikm)->bytes32,
              hkdf_sha256_expand(prk, info, length)->bytes,
              hkdf_sha256(ikm, salt, info, length)->bytes
  Claims    : create_claim(statement, evidence, witness, when_ms=None)
              ->dict, sign_claim(claim, seed)->dict,
              verify_claim(signed, pub=None)->bool
  Custody   : custody_open(payload, custodian_seed, when_ms=None)->dict,
              custody_transfer(prev_rec, from_seed, to_seed,
              when_ms=None)->dict, custody_verify(records, payload,
              expected_final_pub=None)->dict

Usage:
  python3 -m pytest tests/test_axis8_proof.py --tb=short -q
  python3 tests/test_axis8_proof.py --out results/axis8/axis8_RED.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# متجهات RFC العامة الثابتة (تحققت حياً مقابل pyca قبل التثبيت):
RFC8032_T1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_T1_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC8032_T1_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
RFC8439_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PT = (b"Ladies and Gentlemen of the class of '99: If I could "
              b"offer you only one tip for the future, sunscreen would "
              b"be it.")
RFC8439_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116")
RFC8439_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
RFC5869_IKM = b"\x0b" * 22
RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
RFC5869_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
RFC5869_PRK = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
RFC5869_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865")

# أزمنة مثبتة حصراً (انضباط المحور-11 — لا زمن حائطي في أي دليل):
FIXED_WHEN = 1760000000000
FIXED_WHEN_2 = 1760000001000
FIXED_WHEN_3 = 1760000002000


def _proof():
    """هدف M2. حتى وجود sentinel/proof.py كل حالة تفشل RED بالنمط
    الواحد: ModuleNotFoundError: No module named 'sentinel.proof'."""
    import sentinel.proof as proof
    return proof


def _pyca_ed25519():
    """المرجع الخارجي (اختبارات فقط — المحرك لا يستورده أبداً)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PrivateKey
    return Ed25519PrivateKey


def _pyca_aead():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305


# ============================================================ H08_01
def test_H08_01():
    """H08_01 — نموذج الإثبات الستّي: الحقول الستة حاضرة وHash مربوط
    بالأدلة."""
    p = _proof()
    ev = b"raw-evidence-bytes-01"
    witness = {"executor": "sentinel-core", "env": "build-v430"}
    claim = p.create_claim("finding verified", ev, witness,
                           when_ms=FIXED_WHEN)
    signed = p.sign_claim(claim, RFC8032_T1_SEED)
    for field in ("claim", "evidence_sha256", "witness", "timestamp_ms",
                  "hash", "signature", "signer_pubkey"):
        assert field in signed, f"missing field {field}"
    assert signed["evidence_sha256"] == hashlib.sha256(ev).hexdigest()
    assert signed["timestamp_ms"] == FIXED_WHEN
    # الحقل الرابع من الصيغة (Timestamp) + الرابط الحرفي Evidence→Hash


# ============================================================ H08_02
def test_H08_02():
    """H08_02 — دورة Ed25519: توقيع يُتحقق منه بالمفتاح العام."""
    p = _proof()
    seed = bytes(range(32))
    msg = b"axis8 roundtrip message"
    pub = p.ed25519_public_key(seed)
    sig = p.ed25519_sign(seed, msg)
    assert isinstance(sig, bytes) and len(sig) == 64
    assert p.ed25519_verify(sig, msg, pub) is True


# ============================================================ H08_03
def test_H08_03():
    """H08_03 — Ed25519 تزوير/عبث → False (كل صيغة)."""
    p = _proof()
    seed = bytes(range(32))
    other_seed = bytes(range(1, 33))
    msg = b"axis8 forgery message"
    pub = p.ed25519_public_key(seed)
    sig = p.ed25519_sign(seed, msg)
    bad = bytearray(sig)
    bad[0] ^= 0x01
    assert p.ed25519_verify(bytes(bad), msg, pub) is False
    assert p.ed25519_verify(sig, msg + b"x", pub) is False
    assert p.ed25519_verify(sig, msg, p.ed25519_public_key(other_seed)) \
        is False


# ============================================================ H08_04
def test_H08_04():
    """H08_04 — Ed25519 حتمية + متجه RFC 8032 الاختبار 1 بايت-ببايت
    + مطابقة المرجع الخارجي pyca."""
    p = _proof()
    assert p.ed25519_public_key(RFC8032_T1_SEED) == RFC8032_T1_PUB
    assert p.ed25519_sign(RFC8032_T1_SEED, b"") == RFC8032_T1_SIG
    seed = bytes(range(5, 37))
    msg = b"determinism probe"
    s1 = p.ed25519_sign(seed, msg)
    s2 = p.ed25519_sign(seed, msg)
    assert s1 == s2  # حتمية RFC 8032
    k = _pyca_ed25519().from_private_bytes(seed)
    assert k.sign(msg) == s1  # مرجع خارجي: تطابق بايت-ببايت
    assert k.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["Encoding"]).Encoding.RAW,
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["PublicFormat"]).PublicFormat.Raw) \
        == p.ed25519_public_key(seed)


# ============================================================ H08_05
def test_H08_05():
    """H08_05 — جذر Merkle لأربع أوراق: إجابة يدوية مستقلة (hashlib
    داخل الاختبار — لا تستورد المحرك)."""
    p = _proof()
    leaves = [b"a", b"b", b"c", b"d"]
    h = [hashlib.sha256(x).digest() for x in leaves]
    hand_root = hashlib.sha256(
        hashlib.sha256(h[0] + h[1]).digest()
        + hashlib.sha256(h[2] + h[3]).digest()).digest()
    assert p.merkle_root(leaves) == hand_root
    assert p.merkle_root(leaves) == p.merkle_root(leaves)  # حتمية


# ============================================================ H08_06
def test_H08_06():
    """H08_06 — إثبات انتماء Merkle: عضو True / غير عضو False."""
    p = _proof()
    leaves = [b"leaf-%d" % i for i in range(8)]
    root = p.merkle_root(leaves)
    h2 = hashlib.sha256(leaves[2]).digest()
    proof = p.merkle_prove(leaves, 2)
    assert p.merkle_verify(h2, proof, root) is True
    hx = hashlib.sha256(b"leaf-not-in-tree").digest()
    px = p.merkle_prove(leaves, 0)
    assert p.merkle_verify(hx, px, root) is False


# ============================================================ H08_07
def test_H08_07():
    """H08_07 — Merkle أعداد فردية (اصطلاح مضاعفة الأخيرة) + حجم
    الإثبات O(log n) + حتمية الجذر."""
    p = _proof()
    for n in range(1, 10):
        leaves = [b"n%d-i%d" % (n, i) for i in range(n)]
        r1 = p.merkle_root(leaves)
        r2 = p.merkle_root(list(leaves))
        assert r1 == r2  # حتمية الجذر لكل n
        for i in range(n):
            proof = p.merkle_prove(leaves, i)
            assert len(proof) <= math.ceil(math.log2(n)) + 1, \
                f"proof too long at n={n} i={i}: {len(proof)}"
            assert p.merkle_verify(
                hashlib.sha256(leaves[i]).digest(), proof, r1) is True
    # الاصطلاح المعلن: 3 أوراق = مضاعفة الأخيرة (اليدوية المستقلة)
    l3 = [b"x", b"y", b"z"]
    hh = [hashlib.sha256(x).digest() for x in l3]
    hand = hashlib.sha256(
        hashlib.sha256(hh[0] + hh[1]).digest()
        + hashlib.sha256(hh[2] + hh[2]).digest()).digest()
    assert p.merkle_root(l3) == hand


# ============================================================ H08_08
def test_H08_08():
    """H08_08 — طابع RFC 3161: TST = Sign(TSA_key, Hash(data)||Time)
    ويتحقق بالمفتاح العام للسلطة."""
    p = _proof()
    data = b"evidence-to-stamp"
    tsa_pub = p.ed25519_public_key(RFC8032_T1_SEED)
    tok = p.timestamp_token(data, RFC8032_T1_SEED, when_ms=FIXED_WHEN)
    assert tok["time_ms"] == FIXED_WHEN
    assert tok["hash_alg"] == "sha256"
    assert tok["hashed_msg"] == hashlib.sha256(data).hexdigest()
    assert p.timestamp_verify(tok, data, tsa_pub) is True


# ============================================================ H08_09
def test_H08_09():
    """H08_09 — طابع زمني مزوّر: بيانات مغايرة أو زمن مزحزح → False."""
    p = _proof()
    data = b"evidence-to-stamp"
    tsa_pub = p.ed25519_public_key(RFC8032_T1_SEED)
    tok = p.timestamp_token(data, RFC8032_T1_SEED, when_ms=FIXED_WHEN)
    assert p.timestamp_verify(tok, b"other-evidence", tsa_pub) is False
    shifted = dict(tok)
    shifted["time_ms"] = FIXED_WHEN + 1
    assert p.timestamp_verify(shifted, data, tsa_pub) is False


# ============================================================ H08_10
def test_H08_10():
    """H08_10 — سلسلة الأدلة: الصيغة الحرفية H(Pᵢ)=H(Pᵢ₋₁||dataᵢ)."""
    p = _proof()
    items = [b"record-one", b"record-two", b"record-three"]
    chain = p.chain_build(items)
    assert len(chain) == 3
    # الصيغة الحرفية تُفحص يدوياً (hashlib في الاختبار — مستقلة):
    prev = bytes(32)
    for rec, data in zip(chain, items):
        assert rec["prev_hash"] == prev.hex()
        manual = hashlib.sha256(prev + data).hexdigest()
        assert rec["hash"] == manual
        prev = bytes.fromhex(rec["hash"])
    assert p.chain_verify(chain) is True


# ============================================================ H08_11
def test_H08_11():
    """H08_11 — «أي تعديل يكسر السلسلة»: كل المواضع وكل الصيغ."""
    p = _proof()
    items = [b"r%d" % i for i in range(6)]
    chain = p.chain_build(items)

    def _clone(c):
        return [dict(r) for r in c]

    # عبث بايت واحد في data: الرأس/الوسط/الذيل
    for pos in (0, 2, 5):
        bad = _clone(chain)
        bad[pos]["data"] = (b"X" + bad[pos]["data"][1:]).decode()
        assert p.chain_verify(bad) is False, f"head/mid/tail pos={pos}"
    # حذف سجل من المنتصف
    dropped = _clone(chain)
    del dropped[3]
    assert p.chain_verify(dropped) is False
    # تبديل سجلين
    swapped = _clone(chain)
    swapped[1], swapped[4] = swapped[4], swapped[1]
    assert p.chain_verify(swapped) is False
    # تزوير هاش وسيط
    forged = _clone(chain)
    forged[2]["hash"] = "ab" * 32
    assert p.chain_verify(forged) is False


# ============================================================ H08_12
def test_H08_12():
    """H08_12 — ChaCha20-Poly1305: متجه RFC 8439 §2.8.2 بايت-ببايت +
    دورة كاملة + مطابقة المرجع الخارجي pyca."""
    p = _proof()
    ct_tag = p.chacha20poly1305_encrypt(
        RFC8439_KEY, RFC8439_NONCE, RFC8439_PT, RFC8439_AAD)
    assert ct_tag[:len(RFC8439_CT)] == RFC8439_CT
    assert ct_tag[len(RFC8439_CT):] == RFC8439_TAG
    out = p.chacha20poly1305_decrypt(
        RFC8439_KEY, RFC8439_NONCE, ct_tag, RFC8439_AAD)
    assert out == RFC8439_PT
    # مرجع خارجي: تطابق بايت-ببايت (AEAD حتمي)
    ref = _pyca_aead()(RFC8439_KEY).encrypt(
        RFC8439_NONCE, RFC8439_PT, RFC8439_AAD)
    assert ref == ct_tag


# ============================================================ H08_13
def test_H08_13():
    """H08_13 — AEAD عبث بت واحد → IntegrityError (صفر تسريب نصيح)."""
    p = _proof()
    key, nonce, pt, aad = RFC8439_KEY, RFC8439_NONCE, b"secret-pt", b"aad"
    ct_tag = p.chacha20poly1305_encrypt(key, nonce, pt, aad)
    for bit in range(8):
        bad_ct = bytearray(ct_tag)
        bad_ct[3] ^= (1 << bit)
        try:
            p.chacha20poly1305_decrypt(key, nonce, bytes(bad_ct), aad)
            raise AssertionError("tampered ct accepted at bit %d" % bit)
        except p.IntegrityError:
            pass
    for pos in (len(ct_tag) - 1, len(ct_tag) - 16):  # tag + حدّه
        bad = bytearray(ct_tag)
        bad[pos] ^= 0x80
        try:
            p.chacha20poly1305_decrypt(key, nonce, bytes(bad), aad)
            raise AssertionError("tampered tag accepted")
        except p.IntegrityError:
            pass
    try:  # aad مغاير
        p.chacha20poly1305_decrypt(key, nonce, ct_tag, b"other")
        raise AssertionError("wrong aad accepted")
    except p.IntegrityError:
        pass
    try:  # nonce مغاير
        p.chacha20poly1305_decrypt(key, RFC8439_NONCE, ct_tag, aad)
        p.chacha20poly1305_decrypt(key, bytes(12), ct_tag, aad)
        raise AssertionError("wrong nonce accepted")
    except p.IntegrityError:
        pass


# ============================================================ H08_14
def test_H08_14():
    """H08_14 — HKDF-SHA256: متجه RFC 5869 الاختبار 1 بايت-ببايت +
    حتمية + حساسية المعلومات."""
    p = _proof()
    prk = p.hkdf_sha256_extract(RFC5869_SALT, RFC5869_IKM)
    assert prk == RFC5869_PRK
    okm = p.hkdf_sha256(RFC5869_IKM, RFC5869_SALT, RFC5869_INFO, 42)
    assert okm == RFC5869_OKM
    assert p.hkdf_sha256_expand(prk, RFC5869_INFO, 42) == RFC5869_OKM
    assert okm == p.hkdf_sha256(RFC5869_IKM, RFC5869_SALT,
                                RFC5869_INFO, 42)  # حتمية
    other = p.hkdf_sha256(RFC5869_IKM, RFC5869_SALT, b"other-info", 42)
    assert other != okm  # حساسية info


# ============================================================ H08_15
def test_H08_15():
    """H08_15 — سلسلة الحيازة: صلاحية كاملة + تزوير + بذر مبذولة +
    رفض ذري شامل."""
    p = _proof()
    opener = bytes(range(10, 42))
    alice = bytes(range(50, 82))
    bob = bytes(range(90, 122))
    payload = b"exhibit-payload-1957"
    r0 = p.custody_open(payload, opener, when_ms=FIXED_WHEN)
    r1 = p.custody_transfer(r0, opener, alice, when_ms=FIXED_WHEN_2)
    r2 = p.custody_transfer(r1, alice, bob, when_ms=FIXED_WHEN_3)
    chain = [r0, r1, r2]
    v = p.custody_verify(chain, payload,
                         expected_final_pub=p.ed25519_public_key(bob))
    assert v["valid"] is True and v["length"] == 3
    # تسليم من غير الحائز الحالي → رفض ذري (التزوير البنيوي)
    try:
        p.custody_transfer(r0, alice, bob, when_ms=FIXED_WHEN_2)
        raise AssertionError("non-holder transfer accepted")
    except p.ValidationError:
        pass
    # توقيع خارجي مزوّر على سجل تنازل → السلسلة غير صالحة
    forged = dict(r1)
    forged["signature"] = p.ed25519_sign(bob, bytes.fromhex(forged[
        "record_hash"]))
    assert p.custody_verify([r0, forged, r2], payload)["valid"] is False
    # payload مبذول → غير صالحة
    assert p.custody_verify(chain, b"swapped-payload")["valid"] is False
    # رفض ذري: أطوال خاطئة وأنواع فاسدة وحدود HKDF — قبل أي أثر
    for bad_call in (
        lambda: p.ed25519_public_key(bytes(31)),
        lambda: p.ed25519_sign(bytes(33), b"m"),
        lambda: p.ed25519_verify(bytes(63), b"m", bytes(32)),
        lambda: p.chacha20poly1305_encrypt(bytes(16), bytes(12), b"x",
                                           b""),
        lambda: p.chacha20poly1305_encrypt(bytes(32), bytes(8), b"x",
                                           b""),
        lambda: p.hkdf_sha256_expand(RFC5869_PRK, b"", 255 * 32 + 1),
        lambda: p.merkle_root([]),
        lambda: p.merkle_prove([b"a"], 1),
        lambda: p.merkle_prove([b"a"], -1),
        lambda: p.chain_build([]),
        lambda: p.custody_verify([], payload),
        lambda: p.chacha20poly1305_encrypt("str-key", bytes(12), b"x",
                                           b""),  # str حيث bytes يشترط
    ):
        try:
            bad_call()
            raise AssertionError("invalid input accepted: %r"
                                 % (bad_call,))
        except (p.ValidationError, ValueError):
            pass


# ============================================================ وضع السكربت
def _run_all() -> list[dict]:
    """تشغيل كل الحالات بترتيبها مع التقاط النتائج — التيار المنطقي
    فقط."""
    names = [n for n in sorted(globals())
             if n.startswith("test_H08_") and callable(globals()[n])]
    results = []
    for name in names:
        fn = globals()[name]
        t0 = time.perf_counter()
        try:
            fn()
            results.append({"name": name, "ok": True, "error": None,
                            "dur_s": round(time.perf_counter() - t0, 6)})
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
            results.append({"name": name, "ok": False, "error": repr(exc),
                            "dur_s": round(time.perf_counter() - t0, 6)})
    return results


def _digest(results: list[dict]) -> str:
    """هضم التيار المنطقي: (اسم الحالة، نجحت؟) فقط — الأزمنة والرسائل
    خارج الهضم (انضباط المحور-11)."""
    h = hashlib.sha256()
    for r in results:
        h.update(f"{r['name']}:{int(r['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-8 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    doc = {
        "suite": "axis8-proof",
        "station": "M1-RED" if passed == 0 else "run",
        "total": total,
        "passed_count": passed,
        "failed": total - passed,
        "passed": passed == total,
        "digest": _digest(results),
        "cases": results,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis8: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['name']}"
              + ("" if r["ok"] else f"  {r['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
