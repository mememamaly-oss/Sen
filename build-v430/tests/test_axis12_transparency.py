#!/usr/bin/env python3
"""SENTINEL Axis-12 suite — الحدود والشفافية (Boundaries & Transparency).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-4/8/11):
- جدول الحالات الحرفي (H12) من أمر البناء الأصلي ضاع مع قطع الجلسات
  ولا يُسترد من أي سجل ملتزم (فُحص نمط H11: المواصفة المؤرشفة لا
  تحوي جداول H، وworklog لا يقتبس H12، ولا التزام يحمله).
- العقد أدناه مُشتق من مصدرين ملتزمين، مُعلنين وقابلين للإحلال عند
  أي حد محطة (المشرف يملك الإحلال في أي وقت):
  D1 — المواصفة المرجعية المؤرشفة docs/SPEC_12_AXES_ORIGINAL.md §12
       («المحور الثاني عشر: الحدود والشفافية» — الملف هو المرجع
       الحرفي للمشرف، مودَع 2026-10-17):
       (§12.1) BoundaryRecord = (Node, Reason, Category, Timestamp,
       Confidence) وجدول الفئات الأربع عشرة: OUT_OF_SCOPE،
       PRECONDITION_FAILED، RESOURCE_EXHAUSTED، DETECTION_AVOIDED،
       TIME_LIMIT، SAFETY_GUARD، UNKNOWN_PROTOCOL، AUTH_REQUIRED،
       ENCRYPTION_UNTRAVERSABLE، HARDWARE_LIMIT، NETWORK_ISOLATED،
       POLICY_RESTRICTED، CAPABILITY_MISSING، UNSUPPORTED_PLATFORM؛
       (§12.2) بوابة عدم الادعاء — القواعد الست: (R1) لا ادعاء تحقق
       بدون دليل، (R2) لا ادعاء تغطية بدون قياس، (R3) لا ادعاء
       حتمية بدون 3 تشغيلات، (R4) لا ادعاء أمانة بدون مقارنة بخط
       أساس، (R5) لا ادعاء قدرة بدون شرط مسبق مُتحقق، (R6) لا ادعاء
       اكتمال بدون جرد حدود؛ والتنفيذ: «إذا ادعاء ∉ {مدعوم بدليل}:
       أبلغ عن Hallucination»؛
       (§12.3) الواجهة: interface BoundaryEngine: record(node, reason,
       category) -> BoundaryRecord؛ query(category) -> List[BoundaryRecord]؛
       coverage() -> CoverageReport؛ verify_claim(claim) ->
       VerificationResult؛ detect_hallucination(claim) ->
       HallucinationReport؛ export() -> BoundaryExport؛
       وصف التعقيد: «12. الحدود | O(1) للتسجيل | O(|Records|)».
  D2 — نطاق المحور-12 في ترتيب البناء (محفوظ في سياق الاستمرار):
       «الحدود والشفافية» — المحور الأخير في ترتيب البناء الاثني عشر؛
       لا جدول H12 حرفي بعد فقدان الجلسة (نمط H11 نفسه).

- كل حالة تستورد sentinel.transparency داخل جسمها (وليس على مستوى
  الوحدة) حتى تكون المحطة الحمراء 0/15 بنمط فشل واحد حرفياً:
  ModuleNotFoundError: No module named 'sentinel.transparency'.
- جناح مستقل، غير مُسجَّل في @case — عقد النواة 227×19=4313 لا يُمس
  بالبناء (نمط المحاور 1/2/3/4/7/8/10/11 المعاد). sentinel/__init__.py
  يبقى فارغاً والمسار الساخن لا يستورد transparency أبداً.
- لماذا transparency.py لا boundary.py: المسار sentinel/boundary.py
  محجوز منذ v4.1.0 (Phase V41-05 — محرك ذكاء الحدود بحالةstates
  موحدة مختلفة) وهو مغطى بجناح النواة في tests/run_tests.py — لا
  يُمس (خطر على عقد 4313). محور-12 وحدة جديدة بمسار جديد تحمل
  الواجهة الحرفية §12.3 (فئة BoundaryEngine داخل transparency).
- انضباط الهضم (المحور-11 مطبَّقاً هنا): التيار المنطقي فقط (اسم
  الحالة، نجحت؟)؛ أزمنة الحائط في dur_s خارج الهضم؛ كل الأزمنة
  داخل الواجهات معاملات صريحة. الطابع الزمني في BoundaryRecord
  حقل طائر (VOLATILE_FIELDS) — خارج boundary_digest حصراً (خيار
  design معلن: السجل يحمله، الهضم يستثنيه — سابقة ts في v4.1.0).
- المحرك نقي stdlib حصراً (hashlib/json/time). لا scipy ولا pyca
  ولا أي استيراد خارجي في هذا الملف حصراً.

جدول الحالات (العقد المُشتق — كل حالة بعقدها):
  H12_01 — الفئات الأربع عشرة حرفياً §12.1: CATEGORIES == الجدول
             الحرفي (14 بلا زيادة ولا نقصان، بالترتيب) وكل فئة
             موثقة بدلالتها في CATEGORY_MEANINGS (لا فئة بلا دلالة —
             الشفافية تبدأ من مفردات موثقة).
  H12_02 — سجل الحدود §12.1: record(node, reason, category) →
             BoundaryRecord بالخمسة الحرفية (Node, Reason, Category,
             Timestamp, Confidence)؛ confidence ∈ [0,1] (والافتراضي
             1.0 معلن)؛ timestamp معامل صريح (تلقائي = الساعة —
             الموضع الوحيد الذي تُلمس فيه ساعة، معلن N3) وطارئ
             لاحق ≥ سابق؛ الرفض الذري: فئة مجهولة / عقدة فارغة /
             سبب فارغ / ثقة خارج النطاق / ثقة bool / طابع سالب →
             ValidationError قبل أي أثر (لا سجل ولا تسمم حالة).
  H12_03 — record محتوى-عنوان وقابل للتكرار (O(1) للتسجيل — إلحاق
             وفهرسة، لا مسح): نفس الثلاثة (node, reason, category)
             مرتين → نفس المعرّف (هاش المحتوى لا عدّاد) والسجل غير
             مكرر و«الأول يفوز» (الثقة لا تتغير بإعادة التسجيل)؛
             محتوى مختلف → معرّف مختلف؛ query(category) يعيد سجلات
             الفئة حصرها بترتيب الإدراج؛ الفئة القانونية الفارغة →
             قائمة فارغة (غياب معلن)؛ الفئة المجهولة → ValidationError.
  H12_04 — coverage() قياس لا ادعاء (R2 من الأساس): التقرير يُشتق
             من السجل الفعلي حصراً — عدّ لكل فئة من الأربع عشرة
             (الأصفار حاضرة) + total_records + distinct_nodes +
             empty_categories معلنة صراحة (الغياب يُقال لا يُسكَت)؛
             نفس السجل → نفس التقرير بالقيمة؛ السجل الفارغ → أصفار
             صادقة وempty_categories = الأربع عشرة كلها.
  H12_05 — R1 لا ادعاء تحقق بدون دليل: ادعاء verification بلا
             أدلة → غير مدعوم وdetect_hallucination يبلغ
             Hallucination بقاعدة R1 ويسمّي القاعدة والجملة؛ بدليل
             يحلّ (artifact ملاحظة observation مرفق) → مدعوم.
  H12_06 — R2 لا ادعاء تغطية بدون قياس: ادعاء coverage بلا artifact
             قياس → Hallucination بقاعدة R2؛ بقياس لكن القيمة
             المُدّعىة تخالف القيمة المقيسة → Hallucination؛
             والقيمة المطابقة → مدعوم.
  H12_07 — R3 لا ادعاء حتمية بدون 3 تشغيلات (تكامل مع المحور-11
             المغلق): artifact بتشغيلة واحدة أو اثنتين → Hallucination
             بقاعدة R3؛ بثلاث هضوم متطابقة (بنية triple_run) →
             مدعوم؛ وأربع متطابقة → مدعوم (العقد ≥3).
  H12_08 — R4 لا ادعاء أمانة بدون مقارنة بخط أساس: بلا artifact
             مقارنة → Hallucination بقاعدة R4؛ بمقارنة compare_rc=0
             (متطابق) → مدعوم؛ وبمقارنة compare_rc≠0 (انحراف مقيس)
             → Hallucination (الأمانة المزعومة تنقضها القياسات).
  H12_09 — R5 لا ادعاء قدرة بدون شرط مسبق مُتحقق: بلا artifact شرط
             مسبق → Hallucination بقاعدة R5؛ بشرط status=verified →
             مدعوم؛ بشرط status=failed → Hallucination؛ وبحد مسجل
             (PRECONDITION_FAILED) على موضوع الادعاء نفسه →
             Hallucination (الحد يسقط الادعاء).
  H12_10 — R6 لا ادعاء اكتمال بدون جرد حدود: بلا inventory →
             Hallucination بقاعدة R6؛ بجرد حي (هضم boundary_digest
             الحالي + العدد الحالي — يعاد حسابهما حياً) → مدعوم؛
             وبجرد قديم (سُجل حد جديد بعده) → Hallucination (الجرد
             يجب أن يكون حياً — الاكتمال لا يُدّعى على جرد متقادم).
  H12_11 — دقة البوابة (لا إيجابيات كاذبة): الستة أنواع بأدلة
             صالحة → ليست هلوسة جميعاً؛ والستة أشكال تخريب (واحد
             لكل قاعدة) → كل واحدة تُلتقط بقاعدتها نفسها؛ والتقرير
             يسمّي القاعدة والجملة وسبباً (الكشف لا الصمت).
  H12_12 — export() تصدير كامل حتمي: تصديران لنفس الحالة (طوابع
             صريحة) → متطابقان بالبايت؛ export JSON-safe وختمه
             boundary_digest (الطوابع الطائرة خارج الختم) — سجلان
             بطابع تلقائي → التصديران يختلفان في الحقل الطائر
             وختمهما متطابق؛ والاستيراد الدائري import_export يعيد
             بناء المحرك تماماً (سجلات + أدلة + سجل ادعاءات) →
             تصدير المطابق بالبايت.
  H12_13 — حتمية المحرك وحساسية الهضم: محركان يتغذيان نفس التسلسل →
             تصديران متطابقان بالبايت؛ سجل بمحتوى مختلف (سبب آخر) →
             boundary_digest مختلف (الختم حساس للمحتوى)؛ وتحريف سجل
             في التصدير دون إصلاح معرّفه → import_export يرفض
             ValidationError (سلامة المعرّف = هاش المحتوى).
  H12_14 — البوابة لا تُخدع: دليل لا يحل (معرّف غير موجود / بت
             مقلوب في معرّف) → هلوسة؛ دليل بنوع خاطئ (ادعاء حتمية
             بدليل قياس) → هلوسة؛ artifact تسمّيته تكذب بياناته
             (triple_run بـ all_identical=True وثلاثة هضوم مختلفة)
             → هلوسة (البوابة تعيد الحساب من المواد الخام ولا تثق
             بالتسميات — سابقة N-i للمحور-11)؛ ادعاء مشوه/فارغ →
             ValidationError قبل أي أثر؛ وبعد كل الرفض: فحص حي —
             سجل الادعاءات لم يُسمّم والمحرك يعمل كالأساس.
  H12_15 — التكامل مع سجل الحملة الصادق (الغرض الحرفي للمحور:
             المنصة لا تدّعي ما تنقضه حدودها): حدّان حقيقيان من
             جولتنا — X2 (NETWORK_ISOLATED: الهدف 2 محجوب من مسار
             الشبكة) وX3 (CAPABILITY_MISSING: لا ثنائي Docker) — ثم
             عشرة ادعاءات مزروعة: خمسة هلوسة ملتقطة (فحص الهدف 2
             بدليل مختلق — الحد يسقطه؛ فحص Juice Shop بحاوية؛ حتمية
             فحص الهدف 2 بثلاثية مختلقة؛ تغطية خارجية 100% بلا قياس؛
             اكتمال الجولة الخارجية بجرد متقادم) وخمسة مدعومة (بوابة
             X1 المحلية 4313 بقياسها؛ الملاحظة المحلية بدليلها؛
             حتمية bench الثلاثية؛ أمانة بلا انحراف بنيوي بمقارنتها؛
             قدرة البوابة المحلية بشرطها المُتحقق) — الحدود تعرف ما
             حدث وما لم يحدث.

ملاحظات الصدق (العقود المُفسَّرة — مُعلنة لا مخفية):
  N1 (الواجهة) — الواجهة الحرفية §12.3 (record/query/coverage/
      verify_claim/detect_hallucination/export) موجودة بتوقيعاتها
      الحرفية؛ المحرك يضيف آلية التغذية: attach(kind, content)
      لإيداع الأدلة (معرّفات محتوى-عنوان «E-» + sha256) وresolve(ref)
      لفكّها وmake_claim(kind, statement, evidence, subject) لبناء
      الادعاءات وimport_export(dump) للدورة الكاملة — هذه هي الآلية
      التي تجعل «مدعوم بدليل» قابلاً للفحص الآلي (بدونها لا حلّ
      للدليل)، معلنة كامتداد لا كإحلال.
  N2 (الحد يسقط الادعاء) — فحص تناقض كوني معلن: إذا كان على موضوع
      الادعاء (subject) حداً مسجلاً بعقدة مطابقة حرفياً فالادعاء
      الإيجابي عنها يسقط (هلوسة) أياً كان شكل أدلته — جرد الحدود
      هو حقيقة «ما لم يحدث». الادعاء عن القياس نفسه (موضوعه سجلُ
      الفحص لا العقدة المحجوبة) يمر عبر قواعد الأدلة كأي ادعاء.
  N3 (الساعة) — time.time() تُلمس في موضع واحد معلن: record()
      بطابع None. كل ما عدا ذلك معاملات صريحة. الطابع حقل طائر:
      يحمله السجل والتصدير، ويستثنيه boundary_digest حصراً.
  N4 (القواعد↔الأنواع) — تخطيط واحد-لواحد معلن: verification→R1،
      coverage→R2، determinism→R3، honesty→R4، capability→R5،
      completeness→R6. النصوص الست حرفية من §12.2 في RULES.
  N5 (إعادة الحساب) — البوابة تعيد الحساب من المواد الخام ولا تثق
      بتسميات الأدلة: triple_run تُفحص بيانات هضومها لا علم
      all_identical؛ inventory يُطابق هضمَه الحي وعددَه الحي؛
      measurement تُقارن قيمتها بالقيمة المُدّعاة حرفياً.
  N6 (O(1)) — «O(1) للتسجيل» منفذة بالإلحاق وفهرس قاموسي (لا مسح
      للسجل في record)؛ O(|Records|) لquery/coverage/export — عقد
      تصميم معلن، يُختبر وظيفياً (السلوك) لا بتوقيت.
  N7 (سجل الادعاءات) — سجل تدقيق إلحاقي: كل نداء verify_claim وكل
      نداء detect_hallucination يُسجَل بنتيجته (التدقيق الكامل — كشف
      الهلوسة نفسه دليل يُحفظ، لا صمت)؛ خارج boundary_digest (الختم
      لجرد الحدود حصراً — لا دائرية)؛ لا خصم بالمعرّف.
  N8 (موضوعية الدليل) — الدليل لا يدعم إلا ادعاءه: إذا حمل الartifact
      حقل subject فيجب أن يطابق موضوع الادعاء حرفياً (شرط مسبق عن X
      لا يثبت قدرة على Y). جرد الحدود (inventory) لا يحمل subject —
      يُفحص حيّاً بالهضم والعدد (N5).

عقد الواجهة المطلوب من sentinel.transparency في M2 (ما تستورده هذه البطارية):
  Errors    : TransparencyError(ValueError) قاعدة؛
              ValidationError(TransparencyError)
  Constants : CATEGORIES (tuple×14 بالترتيب الحرفي)؛ CATEGORY_MEANINGS؛
              أسماء الفئات كثوابت (OUT_OF_SCOPE ... UNSUPPORTED_PLATFORM)؛
              RULES = {"R1".."R6": {"kind","text"}}؛ CLAIM_KINDS؛
              EVIDENCE_KINDS؛ VOLATILE_FIELDS=("timestamp",)
  Record    : BoundaryRecord — node/reason/category/timestamp/confidence
              + id (B12-+sha256[:12] لهاش المحتوى) + seq ترتيبي؛
              to_dict/from_dict
  Engine    : BoundaryEngine() — سجلات + أدلة + سجل ادعاءات؛
              record(node, reason, category, *, confidence=1.0,
              timestamp=None)->BoundaryRecord؛
              query(category)->list؛ coverage()->dict؛
              attach(kind, content)->str معرّف؛ resolve(ref)->dict|None؛
              verify_claim(claim)->dict؛ detect_hallucination(claim)->dict؛
              export()->dict (ختم boundary_digest)؛
              records (السمة العامة)
  Claims    : make_claim(kind, statement, evidence=(), subject="")->dict
              (معرّف C-+sha256[:12])؛
              import_export(dump)->BoundaryEngine (دورة كاملة)

ثوابت مزروعة معلَنة (أرقام الحملة نفسها — لا عشوائية حرة):
  SEED_A=4313 (عقد النواة)؛ SEED_B=2740 (كوربس القياس)؛
  SEED_C=199 (الذهبية)؛ SEED_D=227 (المقطع)؛ طوابع صريحة 1000+i.

Usage:
  python3 -m pytest tests/test_axis12_transparency.py --tb=short -q
  python3 tests/test_axis12_transparency.py --out results/axis12/axis12_RED.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ثوابت مزروعة معلَنة (أرقام الحملة — عقد 227×19=4313، كوربس 2740،
# الحزمة الذهبية 199): لا عشوائية حرة في أي حالة.
SEED_A = 4313          # عقد النواة
SEED_B = 2740          # كوربس القياس
SEED_C = 199           # الحزمة الذهبية
SEED_D = 227           # المقطع الواحد

# جدول الفئات الحرفي §12.1 — نسخة الاختبار المستقلة (المحرك لا يخترع):
SPEC_CATEGORIES = (
    "OUT_OF_SCOPE", "PRECONDITION_FAILED", "RESOURCE_EXHAUSTED",
    "DETECTION_AVOIDED", "TIME_LIMIT", "SAETY_GUARD_PLACEHOLDER",
    "UNKNOWN_PROTOCOL", "AUTH_REQUIRED", "ENCRYPTION_UNTRAVERSABLE",
    "HARDWARE_LIMIT", "NETWORK_ISOLATED", "POLICY_RESTRICTED",
    "CAPABILITY_MISSING", "UNSUPPORTED_PLATFORM",
)
SPEC_CATEGORIES = tuple(
    c if c != "SAETY_GUARD_PLACEHOLDER" else "SAFETY_GUARD"
    for c in SPEC_CATEGORIES)
SPEC_MEANINGS = {
    "OUT_OF_SCOPE": "خارج النطاق",
    "PRECONDITION_FAILED": "شرط مسبق فشل",
    "RESOURCE_EXHAUSTED": "موارد مستنفدة",
    "DETECTION_AVOIDED": "تجنب كشف",
    "TIME_LIMIT": "حد زمني",
    "SAFETY_GUARD": "حارس أمان",
    "UNKNOWN_PROTOCOL": "بروتوكول غير معروف",
    "AUTH_REQUIRED": "مصادقة مطلوبة",
    "ENCRYPTION_UNTRAVERSABLE": "تشفير غير قابل للاجتياز",
    "HARDWARE_LIMIT": "حد عتادي",
    "NETWORK_ISOLATED": "شبكة معزولة",
    "POLICY_RESTRICTED": "سياسة مقيّدة",
    "CAPABILITY_MISSING": "قدرة مفقودة",
    "UNSUPPORTED_PLATFORM": "منصة غير مدعومة",
}
TS0 = 1000.0           # قاعدة الطوابع الصريحة


def _t12():
    """هدف M2. حتى وجود sentinel/transparency.py كل حالة تفشل RED
    بالنمط الواحد: ModuleNotFoundError: No module named
    'sentinel.transparency'."""
    import sentinel.transparency as t12
    return t12


def _sha_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ============================================================ H12_01
def test_H12_01():
    """H12_01 — الفئات الأربع عشرة حرفياً §12.1: المجموعة والترتيب
    والعدد، وكل فئة موثقة بدلالتها."""
    t12 = _t12()
    cats = t12.CATEGORIES
    assert isinstance(cats, tuple), "CATEGORIES tuple contract"
    assert len(cats) == 14, f"exactly 14 categories, got {len(cats)}"
    assert cats == SPEC_CATEGORIES, "the literal spec table, in order"
    assert len(set(cats)) == 14, "no duplicates"
    # الأسماء كثوابت وحدة مطابقة
    for name in SPEC_CATEGORIES:
        assert getattr(t12, name) == name, f"constant {name}"
    # لا فئة بلا دلالة — الشفافية تبدأ من مفردات موثقة
    meanings = t12.CATEGORY_MEANINGS
    assert set(meanings.keys()) == set(SPEC_CATEGORIES), \
        "meanings cover exactly the 14"
    for name in SPEC_CATEGORIES:
        assert isinstance(meanings[name], str) and meanings[name].strip(), \
            f"meaning of {name} is a non-empty string"
        assert meanings[name] == SPEC_MEANINGS[name], \
            f"meaning of {name} is the spec's own"


# ============================================================ H12_02
def test_H12_02():
    """H12_02 — سجل الحدود §12.1: الخمسة الحرفية + الثقة + الطابع
    الصريح/التلقائي + الرفض الذري قبل أي أثر."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    rec = eng.record("graph:n4313", "prerequisite probe never answered",
                     t12.AUTH_REQUIRED, confidence=0.875, timestamp=TS0)
    # الخمسة الحرفية (Node, Reason, Category, Timestamp, Confidence)
    assert rec.node == "graph:n4313"
    assert rec.reason == "prerequisite probe never answered"
    assert rec.category == t12.AUTH_REQUIRED
    assert rec.timestamp == TS0
    assert rec.confidence == 0.875
    assert rec.id.startswith("B12-") and len(rec.id) == 16, \
        "content-addressed id B12-+sha256[:12]"
    assert rec.seq == 0
    # الطابع التلقائي (N3 — الموضع الوحيد للساعة): عدد حقيقي غير
    # سالب، ولاحق ≥ سابق داخل المحرك
    r1 = eng.record("g:a", "why-a", t12.TIME_LIMIT)
    r2 = eng.record("g:b", "why-b", t12.TIME_LIMIT)
    assert isinstance(r1.timestamp, float) and r1.timestamp >= 0.0
    assert r2.timestamp >= r1.timestamp, "monotone within engine"
    # الافتراضي المعلن: الثقة 1.0
    assert r1.confidence == 1.0
    # الرفض الذري — قبل أي أثر (لا سجل ولا تسمم):
    before = len(eng.records)
    for bad in [
        lambda: eng.record("g:x", "why", "NOT_A_CATEGORY"),
        lambda: eng.record("g:x", "why", t12.OUT_OF_SCOPE,
                           confidence=1.5),
        lambda: eng.record("g:x", "why", t12.OUT_OF_SCOPE,
                           confidence=True),      # bool ليس رقماً هنا
        lambda: eng.record("g:x", "why", t12.OUT_OF_SCOPE,
                           timestamp=-1.0),
        lambda: eng.record("", "why", t12.OUT_OF_SCOPE),
        lambda: eng.record("g:x", "", t12.OUT_OF_SCOPE),
        lambda: eng.record(None, "why", t12.OUT_OF_SCOPE),
        lambda: eng.record("g:x", 42, t12.OUT_OF_SCOPE),
    ]:
        try:
            bad()
            raise AssertionError("atomic rejection expected")
        except t12.ValidationError:
            pass
    assert len(eng.records) == before, "no state change on rejection"


# ============================================================ H12_03
def test_H12_03():
    """H12_03 — record محتوى-عنوان: نفس الثلاثة → نفس المعرّف بلا
    تكرار والأول يفوز؛ محتوى مختلف → معرّف مختلف؛ query بترتيب
    الإدراج؛ الفئة الفارغة غياب معلن؛ المجهولة رفض."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    a1 = eng.record("g:alpha", "tls only, no http", t12.ENCRYPTION_UNTRAVERSABLE,
                    confidence=0.9, timestamp=TS0)
    a2 = eng.record("g:alpha", "tls only, no http", t12.ENCRYPTION_UNTRAVERSABLE,
                    confidence=0.1, timestamp=TS0 + 99)   # الأول يفوز
    assert a2.id == a1.id, "same (node,reason,category) -> same id"
    assert a2.confidence == 0.9, "first registration wins"
    assert len(eng.records) == 1, "no duplicate entry (O(1) dedup)"
    b = eng.record("g:beta", "tls only, no http", t12.ENCRYPTION_UNTRAVERSABLE,
                   timestamp=TS0 + 1)
    c = eng.record("g:alpha", "different reason", t12.TIME_LIMIT,
                   timestamp=TS0 + 2)
    assert len({a1.id, b.id, c.id}) == 3, "distinct content -> distinct ids"
    assert len(eng.records) == 3
    # query: فئة بعينها بترتيب الإدراج
    q = eng.query(t12.ENCRYPTION_UNTRAVERSABLE)
    assert [r.node for r in q] == ["g:alpha", "g:beta"]
    assert all(r.category == t12.ENCRYPTION_UNTRAVERSABLE for r in q)
    # فئة قانونية فارغة — غياب معلن لا صمت
    assert eng.query(t12.HARDWARE_LIMIT) == []
    # فئة مجهولة — رفض قبل أي أثر
    try:
        eng.query("NOT_A_CATEGORY")
        raise AssertionError("unknown category must be rejected")
    except t12.ValidationError:
        pass


# ============================================================ H12_04
def test_H12_04():
    """H12_04 — coverage() قياس لا ادعاء: مشتق من السجل الفعلي حصراً،
    الأصفار حاضرة والغياب معلن، حتمي بالقيمة."""
    t12 = _t12()
    # السجل الفارغ: أصفار صادقة
    eng0 = t12.BoundaryEngine()
    cov0 = eng0.coverage()
    assert cov0["total_records"] == 0
    assert cov0["distinct_nodes"] == 0
    assert cov0["empty_categories"] == list(t12.CATEGORIES), \
        "absence stated for all 14"
    assert set(cov0["per_category"].keys()) == set(t12.CATEGORIES)
    assert all(v == 0 for v in cov0["per_category"].values())
    # سجل مزروع: العدّ مشتق من السجل حصراً
    eng = t12.BoundaryEngine()
    eng.record("g:a", "r1", t12.NETWORK_ISOLATED, timestamp=TS0)
    eng.record("g:a", "r2", t12.TIME_LIMIT, timestamp=TS0 + 1)
    eng.record("g:b", "r3", t12.NETWORK_ISOLATED, timestamp=TS0 + 2)
    eng.record("g:c", "r4", t12.POLICY_RESTRICTED, timestamp=TS0 + 3)
    cov = eng.coverage()
    assert cov["total_records"] == 4
    assert cov["distinct_nodes"] == 3
    assert cov["per_category"][t12.NETWORK_ISOLATED] == 2
    assert cov["per_category"][t12.TIME_LIMIT] == 1
    assert cov["per_category"][t12.POLICY_RESTRICTED] == 1
    assert cov["empty_categories"] == [c for c in t12.CATEGORIES
                                        if cov["per_category"][c] == 0], \
        "absence stated in spec order"
    # حتمي بالقيمة: نفس السجل → نفس التقرير
    assert eng.coverage() == cov
    # لا ادعاء: التقرير قياس للسجل لا شهادة تغطية (measured_from معلن)
    assert cov["measured_from"] == "boundary-registry"


# ============================================================ H12_05
def test_H12_05():
    """H12_05 — R1 لا ادعاء تحقق بدون دليل: بلا دليل هلوسة تُبلَّغ
    بقاعدتها؛ بدليل يحلّ → مدعوم؛ التقرير يسمّي القاعدة والجملة."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    # بلا دليل
    claim = t12.make_claim("verification", "endpoint /api/x was tested",
                           evidence=[], subject="endpoint:/api/x")
    vr = eng.verify_claim(claim)
    assert vr["supported"] is False
    assert vr["rule"] == "R1"
    hr = eng.detect_hallucination(claim)
    assert hr["is_hallucination"] is True
    assert hr["rule"] == "R1"
    assert hr["statement"] == "endpoint /api/x was tested"
    assert hr["reasons"], "reasons named — detection not silence"
    # بدليل يحلّ (ملاحظة مرفقة)
    eid = eng.attach("observation", {
        "subject": "endpoint:/api/x", "what": "reflected payload observed",
        "request": 7, "finding": "F-101"})
    claim_ok = t12.make_claim("verification", "endpoint /api/x was tested",
                              evidence=[eid], subject="endpoint:/api/x")
    vr_ok = eng.verify_claim(claim_ok)
    assert vr_ok["supported"] is True
    assert vr_ok["rule"] == "R1"
    assert eng.detect_hallucination(claim_ok)["is_hallucination"] is False
    # النص الحرفي للقاعدة في RULES (§12.2)
    assert t12.RULES["R1"]["kind"] == "verification"
    assert "بدون دليل" in t12.RULES["R1"]["text"]


# ============================================================ H12_06
def test_H12_06():
    """H12_06 — R2 لا ادعاء تغطية بدون قياس: بلا قياس هلوسة؛ القيمة
    المخالفة للمقيس هلوسة؛ المطابقة مدعومة."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    # بلا قياس
    c1 = t12.make_claim("coverage", "category coverage is 87.5%",
                        evidence=[], subject="suite:core")
    assert eng.verify_claim(c1)["supported"] is False
    hr = eng.detect_hallucination(c1)
    assert hr["is_hallucination"] is True and hr["rule"] == "R2"
    # بقياس لكن القيمة المُدّعاة تخالف المقيسة
    mid = eng.attach("measurement", {"subject": "suite:core",
                                     "value": 87.5, "unit": "%",
                                     "source": "coverage()"})
    c2 = t12.make_claim("coverage", "category coverage is 100%",
                        evidence=[mid], subject="suite:core", value=100.0)
    assert eng.verify_claim(c2)["supported"] is False
    assert eng.detect_hallucination(c2)["is_hallucination"] is True
    # القيمة المطابقة → مدعوم
    c3 = t12.make_claim("coverage", "category coverage is 87.5%",
                        evidence=[mid], subject="suite:core", value=87.5)
    vr3 = eng.verify_claim(c3)
    assert vr3["supported"] is True and vr3["rule"] == "R2"
    # ادعاء تغطية بدليل من نوع خاطئ (ملاحظة ليست قياساً) → هلوسة
    oid = eng.attach("observation", {"subject": "suite:core",
                                     "what": "ran fine"})
    c4 = t12.make_claim("coverage", "category coverage is 87.5%",
                        evidence=[oid], subject="suite:core", value=87.5)
    assert eng.verify_claim(c4)["supported"] is False


# ============================================================ H12_07
def test_H12_07():
    """H12_07 — R3 لا ادعاء حتمية بدون 3 تشغيلات (تكامل المحور-11):
    واحدة أو اثنتين → هلوسة؛ ثلاث متطابقة → مدعوم؛ أربع → مدعوم."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    d = _sha_hex("run-deterministic")
    # تشغيلة واحدة
    a1 = eng.attach("triple_run", {"subject": "bench:run-3c0652b6be",
                                   "runs": [d], "all_identical": True})
    c1 = t12.make_claim("determinism", "bench output is deterministic",
                        evidence=[a1], subject="bench:run-3c0652b6be")
    assert eng.verify_claim(c1)["supported"] is False
    assert eng.detect_hallucination(c1)["rule"] == "R3"
    # اثنتان
    a2 = eng.attach("triple_run", {"subject": "bench:run-3c0652b6be",
                                   "runs": [d, d], "all_identical": True})
    c2 = t12.make_claim("determinism", "bench output is deterministic",
                        evidence=[a2], subject="bench:run-3c0652b6be")
    assert eng.verify_claim(c2)["supported"] is False
    # ثلاث متطابقة → مدعوم
    a3 = eng.attach("triple_run", {"subject": "bench:run-3c0652b6be",
                                   "runs": [d, d, d], "all_identical": True})
    c3 = t12.make_claim("determinism", "bench output is deterministic",
                        evidence=[a3], subject="bench:run-3c0652b6be")
    vr3 = eng.verify_claim(c3)
    assert vr3["supported"] is True and vr3["rule"] == "R3"
    # أربع متطابقة → مدعوم (العقد ≥3 معلن)
    a4 = eng.attach("triple_run", {"subject": "bench:run-3c0652b6be",
                                   "runs": [d, d, d, d],
                                   "all_identical": True})
    c4 = t12.make_claim("determinism", "bench output is deterministic",
                        evidence=[a4], subject="bench:run-3c0652b6be")
    assert eng.verify_claim(c4)["supported"] is True


# ============================================================ H12_08
def test_H12_08():
    """H12_08 — R4 لا ادعاء أمانة بدون مقارنة بخط أساس: بلا مقارنة
    هلوسة؛ compare_rc=0 مدعوم؛ انحراف مقيس (rc≠0) هلوسة."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    # بلا مقارنة بخط أساس
    c1 = t12.make_claim("honesty", "no structural drift vs record",
                        evidence=[], subject="bench:structural")
    assert eng.verify_claim(c1)["supported"] is False
    assert eng.detect_hallucination(c1)["rule"] == "R4"
    # مقارنة موجودة لكنها قاست انحرافاً → الأمانة المزعومة منقوضة
    bad = eng.attach("baseline_comparison", {
        "subject": "bench:structural", "baseline_ref": "record-4784",
        "fresh_ref": "fresh-7161", "compare_rc": 1,
        "diff": "path_tuples MISMATCH"})
    c2 = t12.make_claim("honesty", "no structural drift vs record",
                        evidence=[bad], subject="bench:structural")
    assert eng.verify_claim(c2)["supported"] is False
    assert eng.detect_hallucination(c2)["is_hallucination"] is True
    # مقارنة متطابقة → مدعوم
    good = eng.attach("baseline_comparison", {
        "subject": "bench:structural", "baseline_ref": "record-4784",
        "fresh_ref": "fresh-7161", "compare_rc": 0, "diff": None})
    c3 = t12.make_claim("honesty", "no structural drift vs record",
                        evidence=[good], subject="bench:structural")
    vr3 = eng.verify_claim(c3)
    assert vr3["supported"] is True and vr3["rule"] == "R4"


# ============================================================ H12_09
def test_H12_09():
    """H12_09 — R5 لا ادعاء قدرة بدون شرط مسبق مُتحقق: بلا شرط هلوسة؛
    verified مدعوم؛ failed هلوسة؛ وحد مسجل على الموضوع يسقط الادعاء."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    # بلا شرط مسبق
    c1 = t12.make_claim("capability", "SENTINEL can scan this WebSocket target",
                        evidence=[], subject="target:ws/live")
    assert eng.verify_claim(c1)["supported"] is False
    assert eng.detect_hallucination(c1)["rule"] == "R5"
    # شرط مُتحقق → مدعوم
    ok = eng.attach("precondition", {"subject": "target:ws/live",
                                     "check": "ws handshake reachable",
                                     "status": "verified"})
    c2 = t12.make_claim("capability", "SENTINEL can scan this WebSocket target",
                        evidence=[ok], subject="target:ws/live")
    vr2 = eng.verify_claim(c2)
    assert vr2["supported"] is True and vr2["rule"] == "R5"
    # شرط فاشل → هلوسة
    no = eng.attach("precondition", {"subject": "target:ws/dead",
                                     "check": "ws handshake reachable",
                                     "status": "failed"})
    c3 = t12.make_claim("capability", "SENTINEL can scan this WebSocket target",
                        evidence=[no], subject="target:ws/dead")
    assert eng.verify_claim(c3)["supported"] is False
    # حد مسجل (PRECONDITION_FAILED) على الموضوع نفسه يسقط الادعاء
    # حتى مع artifact شرط «verified» (N2: الحد يسقط الادعاء)
    eng.record("target:ws/guarded", "auth token never obtained",
               t12.PRECONDITION_FAILED, timestamp=TS0)
    yes = eng.attach("precondition", {"subject": "target:ws/guarded",
                                      "check": "ws handshake reachable",
                                      "status": "verified"})
    c4 = t12.make_claim("capability", "SENTINEL can scan this WebSocket target",
                        evidence=[yes], subject="target:ws/guarded")
    vr4 = eng.verify_claim(c4)
    assert vr4["supported"] is False
    assert eng.detect_hallucination(c4)["is_hallucination"] is True
    assert any("PRECONDITION_FAILED" in r_ for r_ in vr4["reasons"]), \
        "the contradicting boundary is named"


# ============================================================ H12_10
def test_H12_10():
    """H12_10 — R6 لا ادعاء اكتمال بدون جرد حدود حي: بلا جرد هلوسة؛
    الجرد الحي مدعوم؛ الجرد المتقادم (بعد سجل حد جديد) هلوسة."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    eng.record("g:a", "r-alpha", t12.NETWORK_ISOLATED, timestamp=TS0)
    eng.record("g:b", "r-beta", t12.CAPABILITY_MISSING, timestamp=TS0 + 1)
    # بلا جرد حدود
    c1 = t12.make_claim("completeness",
                        "external campaign complete, nothing left untested",
                        evidence=[], subject="campaign:external-2")
    assert eng.verify_claim(c1)["supported"] is False
    assert eng.detect_hallucination(c1)["rule"] == "R6"
    # جرد حي: من export الحالي (الهضم والعدد يعاد حسابهما حياً — N5)
    dump = eng.export()
    inv = eng.attach("inventory", {
        "digest": dump["boundary_digest"],
        "records": len(dump["records"]),
        "categories_covered": sum(1 for v in dump["coverage"]["per_category"].values() if v)})
    c2 = t12.make_claim("completeness",
                        "external campaign complete, nothing left untested",
                        evidence=[inv], subject="campaign:external-2")
    vr2 = eng.verify_claim(c2)
    assert vr2["supported"] is True and vr2["rule"] == "R6"
    # سجل حد جديد → الجرد متقادم → نفس الادعاء الآن هلوسة (حياً)
    eng.record("g:c", "r-gamma", t12.AUTH_REQUIRED, timestamp=TS0 + 2)
    vr3 = eng.verify_claim(c2)
    assert vr3["supported"] is False, "stale inventory detected live"
    assert eng.detect_hallucination(c2)["is_hallucination"] is True
    # جرد جديد من الحالة الحالية → مدعوم مجدداً
    dump2 = eng.export()
    inv2 = eng.attach("inventory", {
        "digest": dump2["boundary_digest"],
        "records": len(dump2["records"]),
        "categories_covered": sum(1 for v in dump2["coverage"]["per_category"].values() if v)})
    c4 = t12.make_claim("completeness",
                        "external campaign complete, nothing left untested",
                        evidence=[inv2], subject="campaign:external-2")
    assert eng.verify_claim(c4)["supported"] is True
    # جرد يكذب في العدد (هضم صحيح وعدد خاطئ) → هلوسة (إعادة الحساب)
    inv3 = eng.attach("inventory", {
        "digest": dump2["boundary_digest"],
        "records": len(dump2["records"]) + 5,
        "categories_covered": 3})
    c5 = t12.make_claim("completeness",
                        "external campaign complete, nothing left untested",
                        evidence=[inv3], subject="campaign:external-2")
    assert eng.verify_claim(c5)["supported"] is False, \
        "lying count caught by live recomputation"


# ============================================================ H12_11
def test_H12_11():
    """H12_11 — دقة البوابة: الستة أنواع بأدلة صالحة ليست هلوسة،
    والستة أشكال تخريب تُلتقط كلٌّ بقاعدتها، والتقارير تسمّي ولا تصمت."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    d = _sha_hex("axis12-precision-probe")
    # --- الستة أدلة الصالحة (واحد لكل نوع) → مدعومة جميعاً
    e_obs = eng.attach("observation", {"subject": "s:v", "what": "seen"})
    e_mea = eng.attach("measurement", {"subject": "s:c", "value": 91.0,
                                       "unit": "%", "source": "coverage()"})
    e_tri = eng.attach("triple_run", {"subject": "s:d", "runs": [d, d, d],
                                      "all_identical": True})
    e_bas = eng.attach("baseline_comparison", {"subject": "s:h",
                                               "baseline_ref": "b1",
                                               "fresh_ref": "f1",
                                               "compare_rc": 0, "diff": None})
    e_pre = eng.attach("precondition", {"subject": "s:p", "check": "c",
                                        "status": "verified"})
    # حد واحد معروف — جرد الحدود غير الفارغ شرط R6 المعلن (اكتمال بلا
    # أي حد معروف ادعاء فارغ)
    eng.record("g:limit", "precision battery scope limit",
               t12.OUT_OF_SCOPE, timestamp=TS0)
    inv_d = eng.export()
    e_inv = eng.attach("inventory", {"digest": inv_d["boundary_digest"],
                                     "records": len(inv_d["records"]),
                                     "categories_covered": 1})
    lawful = [
        t12.make_claim("verification", "v-ok", [e_obs], subject="s:v"),
        t12.make_claim("coverage", "c-ok", [e_mea], subject="s:c",
                       value=91.0),
        t12.make_claim("determinism", "d-ok", [e_tri], subject="s:d"),
        t12.make_claim("honesty", "h-ok", [e_bas], subject="s:h"),
        t12.make_claim("capability", "p-ok", [e_pre], subject="s:p"),
        t12.make_claim("completeness", "x-ok", [e_inv],
                       subject="campaign:precision"),
    ]
    for cl in lawful:
        vr = eng.verify_claim(cl)
        assert vr["supported"] is True, f"false positive on {cl['kind']}"
        assert vr["reasons"] == [], "no reasons when supported"
        assert eng.detect_hallucination(cl)["is_hallucination"] is False
    # --- الستة أشكال تخريب (واحد لكل قاعدة) → كلٌّ بقاعدته
    sab = [
        (t12.make_claim("verification", "v-sab", [], subject="s:v"), "R1"),
        (t12.make_claim("coverage", "c-sab", [], subject="s:c"), "R2"),
        (t12.make_claim("determinism", "d-sab", [], subject="s:d"), "R3"),
        (t12.make_claim("honesty", "h-sab", [], subject="s:h"), "R4"),
        (t12.make_claim("capability", "p-sab", [], subject="s:p"), "R5"),
        (t12.make_claim("completeness", "x-sab", [], subject="s:x"), "R6"),
    ]
    for cl, rule in sab:
        hr = eng.detect_hallucination(cl)
        assert hr["is_hallucination"] is True, f"missed {rule}"
        assert hr["rule"] == rule, f"{rule} must catch its own shape"
        assert hr["reasons"] and hr["statement"] == cl["statement"]
    # النصوص الست الحرفية §12.2 في RULES
    texts = " | ".join(t12.RULES[k]["text"] for k in
                       ("R1", "R2", "R3", "R4", "R5", "R6"))
    for frag in ("تحقق", "تغطية", "حتمية", "أمانة", "قدرة", "اكتمال"):
        assert frag in texts, f"rule text for {frag} must be literal"


# ============================================================ H12_12
def test_H12_12():
    """H12_12 — export() تصدير كامل حتمي: تطابق بالبايت للطوابع
    الصريحة؛ الطابع الطائر خارج الختم؛ والدورة الكاملة import_export."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    eng.record("g:a", "r-alpha", t12.NETWORK_ISOLATED, timestamp=TS0)
    eng.record("g:b", "r-beta", t12.CAPABILITY_MISSING, timestamp=TS0 + 1)
    eid = eng.attach("observation", {"subject": "probe:g:a",
                                     "what": "tcp rst"})
    cl = t12.make_claim("verification", "probe observed", [eid],
                        subject="probe:g:a")
    eng.verify_claim(cl)
    # تصديران لنفس الحالة (كل الطوابع صريحة) → متطابقان بالبايت
    j1 = json.dumps(eng.export(), sort_keys=True, ensure_ascii=False)
    j2 = json.dumps(eng.export(), sort_keys=True, ensure_ascii=False)
    assert j1 == j2, "export is byte-identical for the same state"
    # export JSON-safe وختم boundary_digest موجود
    dump = eng.export()
    assert isinstance(dump["boundary_digest"], str)
    assert len(dump["boundary_digest"]) == 64
    json.dumps(dump)  # JSON-safe كله
    # الطابع الطائر خارج الختم: سجلان بطابع تلقائي (ساعة) → التصديران
    # يختلفان في الحقل الطائر وختمهما متطابق (انضباط المحور-11: زمن
    # الحائط خارج كل هضم)
    eng2 = t12.BoundaryEngine()
    eng2.record("g:x", "r-x", t12.TIME_LIMIT)   # طابع تلقائي
    da = eng2.export()
    db = eng2.export()
    assert da["boundary_digest"] == db["boundary_digest"], \
        "volatile timestamp excluded from the digest"
    # الدورة الكاملة: import_export يعيد بناء المحرك تماماً
    reb = t12.import_export(dump)
    j3 = json.dumps(reb.export(), sort_keys=True, ensure_ascii=False)
    assert j3 == j1, "round-trip reproduces the export byte-identically"
    assert reb.records[0].id == eng.records[0].id
    assert len(reb.records) == len(eng.records)
    # والمحرك المُعاد يقبل عملاً جديداً (حي بعد الاستيراد)
    reb.record("g:c", "r-gamma", t12.AUTH_REQUIRED, timestamp=TS0 + 2)
    assert reb.query(t12.AUTH_REQUIRED)[0].node == "g:c"


# ============================================================ H12_13
def test_H12_13():
    """H12_13 — حتمية المحرك وحساسية الهضم وسلامة المعرّفات: محركان
    بنفس التغذية → تصديران متطابقان؛ محتوى مختلف → ختم مختلف؛
    وتحريف التصدير دون إصلاح المعرّف → رفض استيراد."""
    t12 = _t12()
    feed = [
        ("g:n1", "why-one", "NETWORK_ISOLATED", 0.9),
        ("g:n2", "why-two", "TIME_LIMIT", 1.0),
        ("g:n3", "why-three", "AUTH_REQUIRED", 0.5),
        ("g:n4", "why-four", "CAPABILITY_MISSING", 1.0),
    ]

    def build():
        e = t12.BoundaryEngine()
        for i, (n, r_, c, cf) in enumerate(feed):
            e.record(n, r_, getattr(t12, c), confidence=cf,
                     timestamp=TS0 + i)
        e.attach("observation", {"subject": "g:n1", "what": "w"})
        return e

    e_a, e_b = build(), build()
    ja = json.dumps(e_a.export(), sort_keys=True, ensure_ascii=False)
    jb = json.dumps(e_b.export(), sort_keys=True, ensure_ascii=False)
    assert ja == jb, "same feed -> identical exports"
    # محتوى مختلف → boundary_digest مختلف (الختم حساس للمحتوى)
    e_c = build()
    e_c.record("g:n1", "why-one-EDITED", t12.NETWORK_ISOLATED,
               confidence=0.9, timestamp=TS0)
    assert e_c.export()["boundary_digest"] != \
        e_a.export()["boundary_digest"], "digest is content-sensitive"
    # تحريف سجل داخل التصدير دون إصلاح المعرّف → رفض سلامة
    dump = e_a.export()
    tampered = json.loads(json.dumps(dump))
    tampered["records"][0]["reason"] = "tampered reason"
    try:
        t12.import_export(tampered)
        raise AssertionError("tampered record must be rejected")
    except t12.ValidationError:
        pass


# ============================================================ H12_14
def test_H12_14():
    """H12_14 — البوابة لا تُخدع: دليل لا يحل (بت مقلوب)؛ نوع خاطئ؛
    تسمية تكذب بياناتها؛ ادعاء مشوه → رفض ذري؛ وفحص حي بعد كل شيء."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    eid = eng.attach("observation", {"subject": "g:a", "what": "w"})
    # معرّف دليل ببت مقلوب → لا يحل → هلوسة
    flipped = ("E-" + ("0" if eid[2] != "0" else "1") + eid[3:])
    assert eng.resolve(flipped) is None
    c1 = t12.make_claim("verification", "v", [flipped], subject="g:a")
    vr1 = eng.verify_claim(c1)
    assert vr1["supported"] is False
    assert any("resolve" in r_.lower() or "unresolved" in r_.lower()
               for r_ in vr1["reasons"]), "unresolvable evidence named"
    # دليل بنوع خاطئ: قياس لا يثبت حتمية
    mid = eng.attach("measurement", {"subject": "g:a", "value": 50.0,
                                     "unit": "%", "source": "coverage()"})
    c2 = t12.make_claim("determinism", "d", [mid], subject="g:a")
    assert eng.verify_claim(c2)["supported"] is False
    # artifact تسميتها تكذب: all_identical=True وثلاثة هضوم مختلفة —
    # البوابة تعيد الحساب من المواد الخام (N5) ولا تثق بالتسميات
    d1, d2, d3 = (_sha_hex("a"), _sha_hex("b"), _sha_hex("c"))
    liar = eng.attach("triple_run", {"subject": "g:a",
                                     "runs": [d1, d2, d3],
                                     "all_identical": True})
    c3 = t12.make_claim("determinism", "d", [liar], subject="g:a")
    vr3 = eng.verify_claim(c3)
    assert vr3["supported"] is False, "recomputation catches the lying label"
    # ادعاء مشوه → ValidationError قبل أي أثر (لا يُسجَّل شيء)
    ledger_before = len(eng.export()["claims"])
    for bad in [
        {"kind": "not-a-kind", "statement": "s", "evidence": []},
        {"kind": "verification", "statement": "", "evidence": []},
        {"kind": "verification", "statement": "s", "evidence": "E-x"},
        {"kind": "verification", "statement": "s", "evidence": [7]},
        {"kind": "verification", "statement": "s", "evidence": [],
         "subject": 42},
    ]:
        try:
            eng.verify_claim(bad)
            raise AssertionError("malformed claim must be rejected")
        except t12.ValidationError:
            pass
    assert len(eng.export()["claims"]) == ledger_before, \
        "no ledger entry from rejected claims"
    # الفحص الحي بعد كل الرفض: المحرك غير مسمَّم — تنفيذ طازج يطابق
    # الأساس (نفس التغذية على محرك جديد == نفس التصدير)
    fresh = t12.BoundaryEngine()
    fresh.record("g:a", "w", t12.OUT_OF_SCOPE, timestamp=TS0)
    eng.record("g:a", "w", t12.OUT_OF_SCOPE, timestamp=TS0)
    assert fresh.export()["boundary_digest"] == \
        eng.export()["boundary_digest"], "engine healthy after rejections"


# ============================================================ H12_15
def test_H12_15():
    """H12_15 — التكامل مع سجل الحملة الصادق: الحدود تعرف ما حدث وما
    لم يحدث — خمسة ادعاءات هلوسة ملتقطة وخمسة مدعومة، بالحدود الحقيقية
    من جولتنا (X2 محجوب، X3 لا Docker) وقياساتها الحقيقية."""
    t12 = _t12()
    eng = t12.BoundaryEngine()
    # الحدود الحقيقية من external-round-2 (نمط السجل الصادق)
    eng.record("external2:X2:testphp.vulnweb.com",
               "TCP 80+443 timeouts x4 across two 45s-apart rounds; "
               "DNS resolves; egress controls open — block on target side",
               t12.NETWORK_ISOLATED, confidence=0.95, timestamp=TS0)
    eng.record("external2:X3:juice-shop",
               "docker binary absent (command -v rc=1) — containerized "
               "run impossible in this environment",
               t12.CAPABILITY_MISSING, confidence=1.0, timestamp=TS0 + 1)
    # الأدلة الحقيقية من الجولة
    e_gate_obs = eng.attach("observation", {
        "subject": "external2:X1:core-gate", "what": "local suite ran",
        "result": "4313/4313 AGG_RC=0"})
    e_gate_mea = eng.attach("measurement", {
        "subject": "external2:X1:core-gate", "value": 4313,
        "unit": "tests", "source": "phase0_suite_aggregate"})
    d_bench = _sha_hex("bench-run-3c0652b6be")
    e_bench_tri = eng.attach("triple_run", {
        "subject": "bench:run-3c0652b6be", "runs": [d_bench] * 3,
        "all_identical": True})
    e_struct = eng.attach("baseline_comparison", {
        "subject": "bench:structural", "baseline_ref": "record-4784",
        "fresh_ref": "fresh-7161", "compare_rc": 0, "diff": None})
    e_pre = eng.attach("precondition", {
        "subject": "external2:X1", "check": "python+deps present",
        "status": "verified"})
    # دليل مختلق (observation زائف عن فحص لم يحدث)
    e_fake_scan = eng.attach("observation", {
        "subject": "external2:X2:testphp.vulnweb.com",
        "what": "scan completed 65 requests 9 findings"})
    # --- الخمسة ادعاءات الهلوسة (تُلتقط جميعاً):
    hallucinations = [
        # 1) فحص الهدف 2 بدليل مختلق — الحد المسجل يسقطه (N2)
        t12.make_claim("verification",
                       "testphp.vulnweb.com was scanned in round-2",
                       [e_fake_scan],
                       subject="external2:X2:testphp.vulnweb.com"),
        # 2) قدرة فحص Juice Shop بحاوية — حد CAPABILITY_MISSING يسقطها
        t12.make_claim("capability",
                       "Juice Shop scanned in its Docker container",
                       [e_pre], subject="external2:X3:juice-shop"),
        # 3) حتمية «فحص» الهدف 2 بثلاثية مختلقة — الحد يسقطها
        t12.make_claim("determinism",
                       "target-2 scan is deterministic",
                       [e_bench_tri],
                       subject="external2:X2:testphp.vulnweb.com"),
        # 4) تغطية خارجية 100% بلا قياس (الجولة أوقفت بحدود معلنة)
        t12.make_claim("coverage",
                       "external campaign coverage is 100%",
                       [], subject="campaign:external-2", value=100.0),
        # 5) اكتمال الجولة الخارجية بجرد متقادم (سُجل حد بعده)
        t12.make_claim("completeness",
                       "external round-2 fully complete, no limits remain",
                       [eng.attach("inventory", {
                           "digest": _sha_hex("stale-not-live"),
                           "records": 1})],
                       subject="campaign:external-2"),
    ]
    for cl in hallucinations:
        hr = eng.detect_hallucination(cl)
        assert hr["is_hallucination"] is True, \
            f"must catch: {cl['statement']}"
        assert hr["reasons"], f"reason named for: {cl['statement']}"
    # --- الخمسة الادعاءات المدعومة (أدلة حقيقية ومواضيع بلا حدود):
    supported = [
        t12.make_claim("verification",
                       "X1 core gate ran locally 4313/4313",
                       [e_gate_obs], subject="external2:X1:core-gate"),
        t12.make_claim("coverage",
                       "X1 gate measured 4313/4313",
                       [e_gate_mea], subject="external2:X1:core-gate",
                       value=4313),
        t12.make_claim("determinism",
                       "bench triple-run identical",
                       [e_bench_tri], subject="bench:run-3c0652b6be"),
        t12.make_claim("honesty",
                       "no structural drift vs accepted record",
                       [e_struct], subject="bench:structural"),
        t12.make_claim("capability",
                       "local core gate runnable in this environment",
                       [e_pre], subject="external2:X1"),
    ]
    for cl in supported:
        vr = eng.verify_claim(cl)
        assert vr["supported"] is True, \
            f"false positive on: {cl['statement']}"
    # والتدقيق: سجل الادعاءات يحمل العشرة (لا خصم — N7)
    assert len(eng.export()["claims"]) == 10


# ============================================================ وضع السكربت
def _run_all() -> list[dict]:
    """تشغيل كل الحالات بترتيبها مع التقاط النتائج — التيار المنطقي
    فقط."""
    names = [n for n in sorted(globals())
             if n.startswith("test_H12_") and callable(globals()[n])]
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
    خارج الهضم (انضباط المحور-11 مطبَّقاً هنا)."""
    h = hashlib.sha256()
    for r_ in results:
        h.update(f"{r_['name']}:{int(r_['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-12 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    total = len(results)
    doc = {
        "suite": "axis12-transparency",
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
    print(f"axis12: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
