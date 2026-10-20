#!/usr/bin/env python3
"""SENTINEL Axis-14 suite — التقرير القابل للتدقيق المستقل (Independent
external audit: Merkle root + Ed25519).

PROVENANCE (معلنة، مقدَّمة — نمط سابقة 7/8/11/12/13):
- D1 = المواصفة المرجعية الملتزمة docs/SPEC_AXES_13_16.md §14 (المودعة
  5544f9a قبل أي عمل بناء؛ الأمر الحرفي للمشرف مودَع في ترويستها):
  (§14.1) الجذر فوق النتائج المؤكدة: الورقة = sha256(canonical JSON
  لسجل نتيجة واحدة VERIFIED) — مفاتيح مرتبة، فواصل ,/:، UTF-8؛ الحقول
  الطائرة (أزمنة الحائط/القيود المقاسة) خارج الـcanonical؛ الشجرة دمج
  زوجي sha256(L‖R) مع مضاعفة الأخيرة للفرد؛ المجموعة الفارغة → الثابت
  المعلن sha256(b"")؛ الترتيب = ترتيب النتائج في التقرير (بذرة واحدة
  → نفس الجذر)؛
  (§14.2) Ed25519 (RFC 8032) نقي stdlib — البناء فوق عناصر المحور-8
  الملتزمة (proof.py: ed25519_public_key/sign/verify + merkle_root
  بترتيب §8.2 نفسه) بلا إعادة تنفيذ؛ الزوج المفتاحي مشتق حتمياً من
  بذرة الجولة عبر SeededPRNG (المحور-11): 32 بايتاً → الخاص (RFC 8032
  يعرّف الخاص بأنه 32 بايتاً) → نفس البذرة = نفس الزوج = نفس التوقيع؛
  التقرير يحمل merkle_root + المفتاح العام (32B b64) + التوقيع (64B
  b64) فوق sha256(run_id ‖ merkle_root ‖ عدد النتائج ‖ رأس التقرير
  الـcanonical)؛
  (§14.3) عقد التدقيق الخارجي: أي محقق بأدوات مفتوحة بلا أي وصول
  للكود يتحقق من كل نتيجة: (1) إعادة حساب كل ورقة من سجلات التقرير
  نفسها، (2) بناء الشجرة → مطابقة الجذر، (3) التحقق من توقيع Ed25519
  بالمفتاح العام المضمّن (openssl/cryptography/أي تنفيذ RFC 8032)؛
  الوصفة الحرفية مضمّنة في التقرير وفي docs؛ البطارية: تحقق متقاطع
  ضد مرجع مستقل (cryptography في جانب الاختبار فقط) + openssl شرطياً.
- D2 = نطاق أمر البناء: «تقرير للعميل قابل للتدقيق المستقل ... هذه
  ميزة تنافسية حقيقية لا يملكها Burp Suite أو OWASP ZAP».

الإفصاحات (نمط N):
N1) الوحدة الجديدة sentinel/audit.py — النمط الأحمر المتوقع الموحد:
    ModuleNotFoundError (كالمحاور 11/12/13).
N2) البناء فوق الملتزم: عناصر التشفير من proof.py (المحور-8 المغلق
    ببواباته) والاشتقاق الحتمي من repro.SeededPRNG (المحور-11 المغلق)
    — لا إعادة تنفيذ لأي منهما؛ الإثبات أن جناحي 8/11 يعملان فوق
    الشجرة نفسها دون تغيير.
N3) الحقول الطائرة خارج الـcanonical: أي مفتاح من المجموعة المعلنة
    (notes وأزمنة/قيود) يُحذف عودياً — الحتمية عبر التوقيت محفوظة
    حتى لو حملت ملاحظات التحقق أرقاماً مقاسة.
N4) القائمة الفارغة: merkle_root الخاص بالمحور-8 يرفض القائمة الفارغة
    (عقده المعلن) — طبقة التدقيق تعلن الثابت e3b0c4... (sha256(b""))
    صراحة للحالة الفارغة (لا تمرر قائمة فارغة إلى البدائية).
N5) الإضافة فقط: enrich_report يضيف قسم audit وحسب — لا يغير نتائج
    ولا يضيف طلبات ولا يمس الإحصاءات (يُختبر).
N6) التوقيع فوق هضم SHA-256 للرسالة (مُعلن)؛ الفاصل b"\\x00" بين
    الحقول (مُعلن حرفياً في الوصفة — يستحيل التضارب مع محتوى الحقول).
N7) بلا بذرة (بذرة عشوائية): لا ادعاء قابلية تكرار — الزوج يظل صالحاً
    والتوقيع صادقاً لتلك التشغيلة وحدها (إفصاح، لا صمت).
N8)openssl: تحقق شرطي — الثنائي موجود (3.5.7، يدعم Ed25519) في
    هذه البيئة؛ غيابه في بيئة أخرى يُعلن حداً لا فشلاً صامتاً.

الوصفة: python3 tests/test_axis14_audit.py --out results/axis14/axis14_RED.json
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core import Endpoint  # noqa: E402 — موجودة قبل M2 لاستخدامها في الجناح

SUITE = "axis14-audit"
SEED_A = "axis14-fixed-seed"
SEED_B = "axis14-other-seed"
EMPTY_SHA_HEX = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca"
                 "495991b7852b855")            # sha256(b"") — الثابت المعلن


# ------------------------------------------------------------- عينات مزروعة
def _rec(i=1, **over):
    """سجل نتيجة مؤكدة مزروع — شكل to_dict في التقارير."""
    r = {
        "id": f"F-{i:04d}", "type": "xss_reflected", "severity": "high",
        "status": "verified", "confidence": 0.9, "method": "GET",
        "url": f"http://127.0.0.1:1/page{i}?q=x", "parameter": "q",
        "evidence": [{"kind": "reflection", "detail": f"canary-{i} reflected"}],
        "verification": {"method": "re-test:fresh-marker", "passed": True,
                          "confidence": 0.9, "rounds": 2,
                          "notes": f"fresh marker reproduced (control {12 + i}ms, "
                                   f"probe {34 + i}ms — timing note)"},
        "scanner": "sentinel-core/4.4.1", "run_id": "run-abc1234567",
        "risk": 7, "authz_context": "",
        "impact": {"grade": "proven", "statement": "deterministic statement",
                   "safe_proof": "non-destructive",
                   "evidence_chain": {"request": f"GET /page{i}", "parameter": "q",
                                      "evidence_kinds": ["reflection"],
                                      "out_of_band": False,
                                      "verification": "re-test:fresh-marker",
                                      "verification_passed": True}},
    }
    r.update(over)
    return r


def _report(records, seed=SEED_A, run_id="run-abc1234567"):
    return {"run_id": run_id, "seed": seed, "scanner": "sentinel-core/4.4.1",
            "target": "http://127.0.0.1:1/", "stats": {"requests": 10, "duration": 3.2},
            "findings": records, "rejected_candidates": []}


def _independent_merkle(leaf_hexes):
    """ميركل مستقل داخل الجناح — لا يستدعي audit.py إطلاقاً (محقق خارجي)."""
    level = [bytes.fromhex(h) for h in leaf_hexes]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _independent_leaf(canonical_str):
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


# ================================================================ الحالات
def test_H14_01():
    """الورقة: الـcanonical حرفي — مفاتيح مرتبة، فواصل ,/:، UTF-8،
    notes محذوفة، والورقة = sha256 له (مرجع مستقل داخل الجناح)."""
    from sentinel.audit import canonical_finding, finding_leaf
    rec = _rec(1)
    got = canonical_finding(rec)
    # المرجع المستقل: نفس القواعد مكتوبة يدوياً هنا (لا تستدعي الوحدة)
    stripped = {k: v for k, v in rec.items() if k != "verification"}
    stripped["verification"] = {k: v for k, v in rec["verification"].items()
                                if k != "notes"}
    ref = json.dumps(stripped, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    assert got == ref, f"canonical mismatch:\n got={got}\n ref={ref}"
    assert finding_leaf(rec).hex() == _independent_leaf(got)


def test_H14_02():
    """حصانة الحقول الطائرة: سجلان يختلفان فقط في notes/أزمنة → نفس الورقة
    (الحتمية عبر التوقيت محفوظة حتى لو حملت الملاحظات أرقاماً مقاسة)."""
    from sentinel.audit import finding_leaf
    a = _rec(2)
    b = _rec(2)
    b["verification"] = dict(b["verification"],
                             notes="completely different note with 999ms timing")
    b["duration"] = 88.8
    b["wall_time"] = 12.5
    b["stats"] = {"requests": 999}
    assert finding_leaf(a).hex() == finding_leaf(b).hex(), \
        "volatile-only changes must NOT move the leaf"


def test_H14_03():
    """حساسية الحقول المنطقية: تغيير parameter أو severity → ورقة مختلفة."""
    from sentinel.audit import finding_leaf
    a = _rec(3)
    assert finding_leaf(a).hex() != finding_leaf(_rec(3, parameter="other")).hex()
    assert finding_leaf(a).hex() != finding_leaf(_rec(3, severity="critical")).hex()


def test_H14_04():
    """المجموعة الفارغة: الجذر = الثابت المعلن sha256(b"") حرفياً."""
    from sentinel.audit import merkle_root_of_records
    assert merkle_root_of_records([]) == EMPTY_SHA_HEX, \
        "the empty set must yield the declared constant"


def test_H14_05():
    """العدد الفردي: مضاعفة الأخيرة — ثلاث سجلات، الجذر مشتق يدوياً
    بالجناح (sha256(sha256(L1‖L2) ‖ sha256(L3‖L3)))."""
    from sentinel.audit import finding_leaf, merkle_root_of_records
    recs = [_rec(1), _rec(2), _rec(3)]
    l1, l2, l3 = (finding_leaf(r) for r in recs)
    ref = hashlib.sha256(hashlib.sha256(l1 + l2).digest()
                         + hashlib.sha256(l3 + l3).digest()).hexdigest()
    assert merkle_root_of_records(recs) == ref


def test_H14_06():
    """الأعداد الزوجية: زوج واحد = sha256(L1‖L2)؛ أربعة = مستويان —
    كلها مشتقة يدوياً بالجناح."""
    from sentinel.audit import finding_leaf, merkle_root_of_records
    r2 = [_rec(1), _rec(2)]
    l1, l2 = (finding_leaf(r) for r in r2)
    assert merkle_root_of_records(r2) == hashlib.sha256(l1 + l2).hexdigest()
    r4 = [_rec(i) for i in (1, 2, 3, 4)]
    l1, l2, l3, l4 = (finding_leaf(r) for r in r4)
    lo = [hashlib.sha256(l1 + l2).digest(), hashlib.sha256(l3 + l4).digest()]
    ref = hashlib.sha256(lo[0] + lo[1]).hexdigest()
    assert merkle_root_of_records(r4) == ref


def test_H14_07():
    """حساسية الترتيب: نفس السجلات معكوسة → جذر مختلف (الترتيب = ترتيب
    التقرير؛ إعادة ترتيب التقرير تغيّر الجذر — لا تُخفى)."""
    from sentinel.audit import merkle_root_of_records
    recs = [_rec(1), _rec(2), _rec(3)]
    assert merkle_root_of_records(recs) != merkle_root_of_records(list(reversed(recs)))


def test_H14_08():
    """حتمية الجذر + حساسية قلب البت: قائمة مرتين → نفس الجذر؛ قلب بت
    في سجل واحد → جذر مختلف."""
    from sentinel.audit import finding_leaf, merkle_root_of_records
    recs = [_rec(i) for i in (1, 2, 3, 4)]
    assert merkle_root_of_records(recs) == merkle_root_of_records(recs)
    tampered = [_rec(1), _rec(2), _rec(3, parameter="bit-flipped"), _rec(4)]
    assert finding_leaf(recs[2]).hex() != finding_leaf(tampered[2]).hex()
    assert merkle_root_of_records(recs) != merkle_root_of_records(tampered)


def test_H14_09():
    """الزوج المفتاحي: نفس البذرة → نفس الزوج بالبايت؛ بذرة مختلفة →
    زوج مختلف؛ والزوج صالح (توقيع→تحقق بدائيات المحور-8 نفسها)."""
    from sentinel.audit import derive_keypair
    from sentinel.proof import ed25519_public_key, ed25519_sign, ed25519_verify
    p1a, u1a = derive_keypair(SEED_A)
    p1b, u1b = derive_keypair(SEED_A)
    p2, u2 = derive_keypair(SEED_B)
    assert p1a == p1b and u1a == u1b, "same seed must give the same keypair"
    assert p1a != p2 and u1a != u2, "different seeds must differ"
    assert len(p1a) == 32 and len(u1a) == 32
    assert u1a == ed25519_public_key(p1a), "pub must equal proof.ed25519_public_key(priv)"
    msg = b"axis14 keypair validity probe"
    sig = ed25519_sign(p1a, msg)
    assert ed25519_verify(sig, msg, u1a)
    assert not ed25519_verify(sig, b"other", u1a)


def test_H14_10():
    """التوقيع المضمّن: block.signature يتحقق فوق الرسالة المعاد حسابها
    بالبدائية النقية؛ وعبث الجذر/العدد/run_id/الرأس كلٌّ يكسر التحقق."""
    from sentinel.audit import audit_block, signed_message
    from sentinel.proof import ed25519_verify
    rep = _report([_rec(1), _rec(2), _rec(3)])
    blk = audit_block(rep, seed=SEED_A)
    pub = base64.b64decode(blk["public_key_b64"])
    sig = base64.b64decode(blk["signature_b64"])
    msg = signed_message(rep["run_id"], blk["merkle_root"],
                         blk["findings_count"], rep)
    assert len(pub) == 32 and len(sig) == 64
    assert ed25519_verify(sig, msg, pub), "the embedded signature must verify"
    assert not ed25519_verify(sig, signed_message(rep["run_id"], "00" * 32,
                                                  blk["findings_count"], rep), pub)
    assert not ed25519_verify(sig, signed_message(rep["run_id"], blk["merkle_root"],
                                                  blk["findings_count"] + 1, rep), pub)
    other = dict(rep)
    other["target"] = "http://elsewhere.test/"
    assert not ed25519_verify(sig, signed_message(rep["run_id"], blk["merkle_root"],
                                                 blk["findings_count"], other), pub)
    assert not ed25519_verify(sig, signed_message("run-zzzzzzzzzz", blk["merkle_root"],
                                                 blk["findings_count"], rep), pub)


def test_H14_11():
    """التحقق المتقاطع ضد مرجع مستقل (cryptography في جانب الاختبار فقط —
    المحرك يظل صفر تبعيات): بالاتجاهين وبرسائل متعددة."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PrivateKey, Ed25519PublicKey
    from sentinel.audit import derive_keypair
    from sentinel.proof import ed25519_sign, ed25519_verify
    priv, pub = derive_keypair(SEED_A)
    for i in range(5):
        msg = f"axis14 cross message {i}".encode()
        sig = ed25519_sign(priv, msg)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)   # المرجع يقبل
        k2 = Ed25519PrivateKey.generate_private_key()
        ref_sig = k2.sign(msg)
        ref_pub = k2.public_key().public_bytes_raw()
        assert ed25519_verify(ref_sig, msg, ref_pub), \
            "the pure implementation must verify the reference's signature"
        assert not ed25519_verify(ref_sig, b"tampered", ref_pub)


def test_H14_12():
    """openssl (أداة مفتوحة، بلا وصول للكود): التوقيع يُتحقق به عبر
    pkeyutl؛ والعبث يُعلن فشلاً — شرطي بوجود الثنائي (N8)."""
    import shutil
    if not shutil.which("openssl"):
        import pytest  # noqa: F401
        from sentinel.audit import AUDIT_RECIPE  # يجب أن يعلن الحالة الشرطية
        assert "openssl" in AUDIT_RECIPE.lower()
        return  # غياب openssl في بيئة أخرى: حدها الإفصاح في الوصفة (لا فشل)
    from sentinel.audit import audit_block, signed_message
    rep = _report([_rec(1), _rec(2)])
    blk = audit_block(rep, seed=SEED_A)
    pub = base64.b64decode(blk["public_key_b64"])
    sig = base64.b64decode(blk["signature_b64"])
    msg = signed_message(rep["run_id"], blk["merkle_root"],
                         blk["findings_count"], rep)
    spki = bytes.fromhex("302a300506032b6570032100") + pub
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + base64.encodebytes(spki).decode().strip()
           + "\n-----END PUBLIC KEY-----\n")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        pp, mp, sp, tp = (os.path.join(td, n) for n in
                           ("pub.pem", "msg.bin", "sig.bin", "tampered.bin"))
        open(pp, "w").write(pem)
        open(mp, "wb").write(msg)
        open(sp, "wb").write(sig)
        open(tp, "wb").write(b"tampered message")
        ok = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                              "-inkey", pp, "-rawin", "-in", mp, "-sig", sp],
                            capture_output=True)
        assert ok.returncode == 0 and b"Successful" in ok.stdout, \
            f"openssl must verify: {ok.stdout!r} {ok.stderr!r}"
        bad = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                              "-inkey", pp, "-rawin", "-in", tp, "-sig", sp],
                             capture_output=True)
        assert bad.returncode != 0, "openssl must reject the tampered message"


def test_H14_13():
    """enrich_report كاملاً: القسم موجود بكل الحقول؛ نفس البذرة → قسم
    مطابق بالبايت؛ بذرة مختلفة → نفس الجذر وتوقيع مختلف (الجذر من
    النتائج وحدها؛ الزوج من البذرة) — الخاصية المثبَّتة."""
    from sentinel.audit import enrich_report
    rep = _report([_rec(1), _rec(2), _rec(3)])
    r1 = enrich_report(dict(rep), seed=SEED_A)
    r2 = enrich_report(dict(rep), seed=SEED_A)
    r3 = enrich_report(dict(rep), seed=SEED_B)
    for key in ("merkle_root", "public_key_b64", "signature_b64",
                "findings_count", "algorithm", "leaf_spec", "signature_scheme",
                "signed_message_spec", "recipe"):
        assert key in r1["audit"], f"missing audit field {key}"
    assert r1["audit"] == r2["audit"], "same seed must reproduce the block byte-for-byte"
    assert r1["audit"]["merkle_root"] == r3["audit"]["merkle_root"], \
        "the root depends ONLY on the findings"
    assert r1["audit"]["signature_b64"] != r3["audit"]["signature_b64"], \
        "a different seed must give a different signature"
    # الإضافة فقط: لا نتائج تغيرت ولا إحصاءات
    assert r1["findings"] == rep["findings"] and r1["stats"] == rep["stats"]
    assert set(r1) == set(rep) | {"audit"}


def test_H14_14():
    """عقد التدقيق الخارجي (الميزة التنافسية المطلوبة بالأمر): محقق
    بلا أي وصول للكود — يعيد حساب الأوراق من التقرير نفسه بجدعة ميركل
    مستقلة داخل الجناح، يطابق الجذر، ويتحقق من التوقيع بأداة مفتوحة
    (cryptography)؛ ثم عبث سجل واحد يُكتشف بجذر غير مطابق."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from sentinel.audit import canonical_finding, enrich_report
    rep = enrich_report(_report([_rec(1), _rec(2), _rec(3), _rec(4)]), seed=SEED_A)
    blk = rep["audit"]
    # (1) أوراق من سجلات التقرير نفسها + (2) شجرة مستقلة بالجناح
    leaves = [_independent_leaf(canonical_finding(f)) for f in rep["findings"]]
    assert _independent_merkle(leaves) == blk["merkle_root"], \
        "the independent auditor's tree must match the signed root"
    # (3) التوقيع بأداة مفتوحة
    pub = base64.b64decode(blk["public_key_b64"])
    sig = base64.b64decode(blk["signature_b64"])
    # الرسالة: القاعدة المعلنة حرفياً في الوصفة (مكتوبة هنا يدوياً)
    hdr = {"run_id": rep["run_id"], "seed": rep["seed"],
           "scanner": rep["scanner"], "target": rep["target"]}
    hdr_canon = json.dumps(hdr, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    msg = hashlib.sha256(b"\x00".join([
        rep["run_id"].encode(), blk["merkle_root"].encode(),
        str(blk["findings_count"]).encode(), hdr_canon.encode()])).digest()
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    # العبث: تغيير سجل واحد بعد التوقيع → الجذر المعاد لا يطابق
    tampered = json.loads(json.dumps(rep))
    tampered["findings"][1]["parameter"] = "attacker-controlled"
    t_leaves = [_independent_leaf(canonical_finding(f)) for f in tampered["findings"]]
    assert _independent_merkle(t_leaves) != blk["merkle_root"], \
        "tampering a finding must be DETECTED (root mismatch)"


def test_H14_15():
    """e2e عبر الماسح الحقيقي: مسحان مستقلان بنفس البذرة على هدف محلي
    → نفس run_id + نفس الجذر + نفس التوقيع (قابلية تكرار التقرير كاملاً)."""
    from sentinel.core import FindingStatus
    from sentinel.orchestrator import ScanConfig, SentinelScanner
    from sentinel.audit import enrich_report

    pages = {"/": b"<html><body>home <a href='/p1'>p1</a> "
                  b"<a href='/p2'>p2</a></body></html>",
             "/p1": b"<html><body>page one</body></html>",
             "/p2": b"<html><body>page two</body></html>"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            p = urlsplit(self.path).path
            body = pages.get(p)
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # لا ترويسات أمنية + ترويستة خادم معلنة → نتائج presence مؤكدة
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Axis14Fixture/1.0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        def _scan():
            cfg = ScanConfig(allow_private=True, max_pages=5, crawl=True,
                             active=False, passive=True, timeout=6.0,
                             seed="axis14-e2e", browser=False, oast=None,
                             graphql=False, websocket=False, secrets=False,
                             modern=False)
            sc = SentinelScanner(base + "/", cfg)
            sc.run()
            return sc.report()

        rep1 = _scan()
        rep2 = _scan()
        n1 = sum(1 for f in rep1["findings"])
        assert n1 >= 3, f"expected deterministic findings, got {n1}"
        a1 = enrich_report(dict(rep1), seed="axis14-e2e")["audit"]
        a2 = enrich_report(dict(rep2), seed="axis14-e2e")["audit"]
        assert rep1["run_id"] == rep2["run_id"], "same seed must give the same run_id"
        assert a1["merkle_root"] == a2["merkle_root"], "same scan seed → same root"
        assert a1["signature_b64"] == a2["signature_b64"], \
            "same scan seed → same signature (the full-report reproducibility claim)"
        assert a1["findings_count"] == n1 == a2["findings_count"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_H14_16():
    """انضباط الوحدة: استيراد كسول (orchestrator لا يسحب audit على مستوى
    الوحدة — عملية فرعية نظيفة)، الوصفة مضمّنة في كل تقرير وفي docs،
    والوحدة بلا تبعيات خارجية (قراءة ثابتة للكود الملتزم)."""
    from sentinel.audit import AUDIT_RECIPE, RECIPE_DOC
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    probe = subprocess.run(
        [sys.executable, "-c",
         "import sys, sentinel.orchestrator; "
         "print('sentinel.audit' in sys.modules)"],
        cwd=here, capture_output=True, text=True, timeout=120)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "False", (
        "the orchestrator must import audit LAZILY; got: " + probe.stdout)
    # الوصفة الحرفية في التقرير وفي docs
    for needle in ("merkle", "Ed25519", "canonical"):
        assert needle.lower() in AUDIT_RECIPE.lower(), needle
    doc = os.path.join(here, "docs", RECIPE_DOC)
    assert os.path.exists(doc), f"missing docs/{RECIPE_DOC}"
    doc_text = open(doc, encoding="utf-8").read()
    for needle in ("openssl", "pkeyutl", "from_public_bytes", "sha256"):
        assert needle in doc_text, needle
    # بلا تبعيات خارجية: الكود الملتزم يستورد stdlib + sentinel فقط
    src = open(os.path.join(here, "sentinel", "audit.py"), encoding="utf-8").read()
    import re as _re
    imports = set(_re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)",
                              src, _re.M))
    allowed = {"json", "hashlib", "base64", "__future__",
               "sentinel", "sentinel.proof", "sentinel.repro"}
    bad = {i for i in imports if i.split(".")[0] not in
           {"json", "hashlib", "base64", "__future__", "sentinel"}}
    assert not bad, f"audit.py must stay stdlib+sentinel only; found {bad} ({imports})"


# ============================================================ وضع السكربت
def _run_all() -> list:
    names = [n for n in sorted(globals())
             if n.startswith("test_H14_") and callable(globals()[n])]
    results = []
    import time
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


def _digest(results: list) -> str:
    h = hashlib.sha256()
    for r_ in results:
        h.update(f"{r_['name']}:{int(r_['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SENTINEL Axis-14 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    total = len(results)
    doc = {
        "suite": SUITE,
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
    print(f"axis14: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
