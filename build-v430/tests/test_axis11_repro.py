#!/usr/bin/env python3
"""SENTINEL Axis-11 suite — الحتمية والقابلية للتكرار (Determinism &
Reproducibility).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-4/8):
- جدول الحالات الحرفي (H11) من أمر البناء 2026-10-19 ضاع مع قطع
  الجلسات ولا يُسترد من أي سجل ملتزم (فُحص: المواصفة المؤرشفة لا
  تحوي جداول H، وworklog لا يقتبس H11، ولا التزام يحمله).
- العقد أدناه مُشتق من مصدرين ملتزمين، مُعلنين وقابلين للإحلال عند
  أي حد محطة (المشرف يملك الإحلال في أي وقت):
  D1 — المواصفة المرجعية المؤرشفة docs/SPEC_12_AXES_ORIGINAL.md §11:
       الضمانات (G1) Deterministic Seeding: seed → PRNG → نفس
       التسلسل؛ (G2) Reproducible Builds: نفس المدخلات = نفس
       المخرجات؛ (G3) Version Pinning: كل التبعيات مثبّتة بـhash؛
       (G4) Environment Isolation: كل تشغيل في حاوية معزولة؛
       (G5) Input Canonicalization: نفس المدخلات بشكل قانوني (§11.1)؛
       Triple-Run: Run1=Execute(input,seed) ×3 → assert متطابقة
       (§11.2)؛ تحليل الفروق: Diff(Run1,Run2)={MerkleRoot(Run1)==
       MerkleRoot(Run2)} وإذا Diff≠∅ → تحقيق آلي (§11.3)؛ الواجهة
       set_seed/execute/triple_run/diff/verify_determinism/
       freeze_environment/restore_environment (§11.4).
  D2 — قائمة نطاق المحور-11 كما وردت في أمر البناء (محفوظة في سياق
       الاستمرار): نفس البذرة → نفس المخرجات، Triple-Run، هضم التدفق
       المنطقي، حساسية انعكاس البت (bit-flip) — H11_01..H11_15.

- كل حالة تستورد sentinel.repro داخل جسمها (وليس على مستوى الوحدة)
  حتى تكون المحطة الحمراء 0/15 بنمط فشل واحد حرفياً:
  ModuleNotFoundError: No module named 'sentinel.repro'.
- جناح مستقل، غير مُسجَّل في @case — عقد النواة 227×19=4313 لا يُمس
  بالبناء (نمط المحاور 1/2/3/4/7/8/10 المعاد). sentinel/__init__.py
  يبقى فارغاً والمسار الساخن لا يستورد repro أبداً.
- انضباط الهضم (هذا محور الهضم نفسه — يطبَّق على نفسه): التيار
  المنطقي فقط (اسم الحالة، نجحت؟)؛ أزمنة الحائط تُسجَّل في dur_s
  ولا تدخل الهضم أبداً. كل الأزمنة داخل الواجهات معاملات صريحة
  (لا ساعة نظام في أي هضم)، وكل العشوائية ببذور معلَنة.
- المحرك نقي stdlib حصراً (hashlib/json/os/importlib.metadata).
  لا scipy ولا pyca في المحرك — وحدة 11b تختبر قياسية JSON فقط.

جدول الحالات (العقد المُشتق — كل حالة بعقدها):
  H11_01 — G1 البذر الحتمي: SeededPRNG(seed) مروران → نفس التسلسل
             بالقيمة (200 قيمة u64)؛ بذرة مختلفة → تسلسل مختلف؛
             derive_stream(seed,label) مروران متطابق، وlabels مختلفة
             → تيارات مختلفة.
  H11_02 — G2 نفس المدخلات = نفس المخرجات: execute(input, seed)
             مروران → RunRecord متطابقة تماماً (القاموس كله بالقيمة:
             steps/flow_digest/flow_merkle_hex/final_payload).
  H11_03 — Triple-Run (الصيغة الحرفية §11.2): triple_run(input)
             بنفس بذرة الحالة → ثلاث RunRecords متطابقة،
             verify_determinism True، require_determinism لا يرفع.
  H11_04 — هضم التدفق المنطقي + جذر Merkle بإجابة يدوية مستقلة
             (hashlib داخل الاختبار) وبمرجع وحدة مغلقة (proof.merkle_root
             — المحور-8): flow_merkle(steps) == اليدوي == المرجع.
  H11_05 — تحليل الفروق §11.3: diff(متطابقان) → كل المتساويات True
             وfirst_diff None؛ تحريف final_payload/steps → أوجه
             الفرق معلنة، وinvestigate «التحقيق الآلي» يحدد أول
             خطوة منحرفة (in_match/out_match).
  H11_06 — حساسية انعكاس البت — المدخل: قلب بت واحد في input
             (bytes) في مواقع معلنة (الرأس/الثلث/الوسط/الذيل) →
             flow_merkle وfinal_payload يختلفان عن الأساس في كل
             موقع؛ لا موضع صامت.
  H11_07 — حساسية انعكاس البت — البذرة: قلب بت واحد في seed
             (بتات معلنة) → التدفق مختلف (الجذر/الهضم/السجل)؛
             والوجه الوظيفي: plaintext المستعاد يظل المدخل القانوني
             نفسه (البذرة تغيّر الأدلة — المواد/التوقيع/التشفير/
             الجذر — لا الأصل)؛ ونفس البذرة مروراً → نفس المخرجات.
  H11_08 — G5 قياسية المدخلات: مدخلان متكافئان قانونياً (dict
             بترتيب إدراج معكوس) → canonical_input متطابق بالبايت →
             execute متطابقة تماماً؛ تمثيل مختلف قانونياً → مخرجات
             مختلفة (القياسية لا تبتلع المعنى).
  H11_09 — G3 التثبيت بالهاش: freeze_environment يضم لكل حزمة
             مثبتة معلنة (scipy/cryptography/pytest) version +
             record_sha256 (sha256 لملف RECORD في dist-info — التثبيت
             بالهاش حرفياً) + python/version + hash_seed + sys_flags؛
             المواصفة نفسها حتمية (مروران نفس البايت).
  H11_10 — G4 استعادة البيئة: restore_environment(spec صحيح) →
             قائمة اختلافات فارغة + البذرة أُعيدت (تحقق سلوكي:
             التنفيذ بعدها يطابق التنفيذ بنفس البذرة الصريحة) +
             PYTHONHASHSEED ضُبط في os.environ؛ spec محرَّف
             (python.version / record_sha256) → الاختلافات معلنة
             بالاسم — الكشف لا الصمت.
  H11_11 — الانحراف المفتعل (§11.3 «إذا Diff≠∅ → تحقيق آلي»):
             خطوة غير حتمية (عداد عام) → تشغيلان يختلفان؛
             require_determinism يرفع DriftError، وinvestigate يحدد
             الخطوة المنحرفة بأول فهرس (in_match=True/out_match=False).
  H11_12 — الرفض الذري: بلا بذرة، seed فاسد (0/سالب/bool/str)،
             input غير قابل للتمثيل، خطوات فارغة، fn غير callable،
             اسم خطوة فارغ، fn ترجع غير bytes، PRNG فاسد →
             ValidationError قبل أي أثر (لا تسمم حالة بعدها).
  H11_13 — عدم تسمم الحالة عبر التتابع: تنفيذات متداخلة بأمداخيل
             وبذور أخرى ثم العودة → نفس نتيجة الأساس بالبايت؛
             كائن Executor ثانٍ → نفس النتيجة (لا حالة كامنة).
  H11_14 — المتجه المرجعي المستقل: إعادة تنفيذ SplitMix64 مستقلة
             داخل الاختبار (ثوابت معلنة) مقابل SeededPRNG بايت-ببايت
             (بذور داخل عقد [1,2^64): 1/2/3/12345) + next_bytes
             big-endian + derive_stream
             والاشتقاق المستقل + randbelow ضمن [0,n) وحتمي.
  H11_15 — التكامل مع النواة الحتمية المغلقة: default_pipeline
             (ست خطوات فوق sentinel.proof — المحور-8): 20 زوجاً
             مزروعاً (input, seed) → تشغيلان متطابقان بالبايت +
             final_payload == canonical_input(input) (الدورة صالحة
             وظيفياً: verify فكّ وفكّ التشفير بنجاح) + أسماء الخطوات
             الست بالترتيب المعلن.

ملاحظات الصدق (العقود المُفسَّرة — مُعلنة لا مخفية):
  N1 (G4) — «حاوية معزولة» الحرفية (Docker) غير متاحة في هذه
      البيئة (أُثبتت في external-2 X3: لا ثنائي docker). العزل
      المُنفَّذ المُعلن: عمليات مستقلة كاملة في R3 (subprocess —
      ذاكرة/حالة معزولة) + بيئة محددة عبر restore_environment
      (PYTHONHASHSEED) — وهو نفس عزل R3 المعتمد للمحورين 7/8.
  N2 (PRNG) — SplitMix64 (ثوابت عيدرون المنشورة) اختير لأنه حتمي
      خالص قابل للتكرار عبر أي بايثون ومنصة (لا يعتمد على نسخة
      Mersenne الخاصة بCPython). randbelow عقد مبسط معلن: قيمة
      u64 % n (انحياز نظري أقصى 2^64/n — استعمالات المحور بأطوال
      صغيرة حيث الانحياز غير قابل للقياس عملياً).
  N3 (قياسية bytes) — canonical_input(bytes) يمرر البايتات كما
      هي (مدخل قانوني بذاته)؛ غير bytes يُمثَّل JSON قياسياً
      (sort_keys، بلا فراغات، ensure_ascii=False) — هذا عقد G5
      المُفسَّر المُعلن.
  N4 (11.3) — DiffReport يقارن على المستويين: الجذر (Merkle) —
      الحرفية «Diff(Run1,Run2)={MerkleRoot(Run1)==MerkleRoot(Run2)}»
      — والحمولة النهائية (أدق عملياً). first_diff يسمّي أول
      اختلاف (حقل أو خطوة).
  N5 (flow) — flow_merkle: أوراق = SHA-256(سطر الخطوة) لكل خطوة؛
      الجذر بقواعد §8.2 من المواصفة (Node=SHA-256(L||R)، مضاعفة
      الأخيرة للفرد) — نفس اصطلاح المحور-8 المُلتزم.
  N6 (Env/G3) — record_sha256 يُحتسب من ملف RECORD داخل dist-info
      للمثبت (importlib.metadata) — تثبيت التبعية بهاش ملفها
      الفعلي لا بمجرد رقم إصدار. القائمة المعلنة: scipy،
      cryptography، pytest (مراجع الحملة الخارجية الحصرية) —
      المحرك نفسه صفر تبعيات خارجية.
  N7 (الأزمنة) — لا ساعة نظام في أي هضم أو مسار حتمي داخل
      sentinel/repro.py (عقود when صريحة في proof عند الحاجة).
      أزمنة الحائط في dur_s خارج كل هضم — انضباط المحور-11
      المُعلن منذ المحور-7، مطبَّق على نفسه هنا.

عقد الواجهة المطلوب من sentinel.repro في M2 (ما تستورده هذه البطارية):
  Errors    : ReproError(ValueError) قاعدة؛ ValidationError(ReproError)،
              DriftError(ReproError)
  PRNG      : SeededPRNG(seed:int[1,2^64)) — SplitMix64 خالص؛
              .next_u64()->int، .next_bytes(n)->bytes (big-endian)،
              .randbelow(n)->int؛
              derive_stream(seed:int, label:str)->SeededPRNG
              (البذرة الأولية = أول 8 بايت من SHA-256(f"{seed}:{label}"))
  Canonical : canonical_input(obj)->bytes (bytes كما هي؛ غيرها JSON
              قياسي)؛ input_digest(obj)->bytes32
  Flow      : flow_lines(steps)->list[str] ("name:in_sha:out_sha")؛
              flow_digest(steps)->str (sha256 سداسي فوق الأسطر)؛
              flow_merkle(steps)->bytes32 (أوراق=SHA-256(سطر)؛ جذر §8.2)
  Executor  : DeterministicExecutor(steps=[(name, fn)])؛
              fn(payload:bytes, rng:SeededPRNG)->bytes نقية؛
              set_seed(seed)؛ execute(input, seed=None)->RunRecord dict؛
              triple_run(input)->(r,r,r)
  Diff      : diff(a,b)->DiffReport؛ investigate(a,b)->dict؛
              verify_determinism(runs)->bool؛ require_determinism(runs)
  Env       : PINNED_PACKAGES=("scipy","cryptography","pytest")؛
              freeze_environment()->spec dict (حتمي)؛
              restore_environment(spec)->list[str]
  Pipeline  : default_pipeline()->ست خطوات فوق sentinel.proof:
              canonical → derive → sign → aead → merkle → verify

ثوابت مزروعة معلَنة (أرقام الحملة نفسها — لا عشوائية حرة):
  SEED_A=4313 (عقد النواة)؛ SEED_B=2740 (كوربس القياس)؛
  SEED_C=199 (الذهبية)؛ SEED_D=227 (المقطع).

Usage:
  python3 -m pytest tests/test_axis11_repro.py --tb=short -q
  python3 tests/test_axis11_repro.py --out results/axis11/axis11_RED.json
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ثوابت مزروعة معلَنة (أرقام الحملة — عقد 227×19=4313، كوربس 2740،
# الذهبية 199): لا عشوائية حرة في أي حالة.
SEED_A = 4313          # عقد النواة
SEED_B = 2740          # كوربس القياس
SEED_C = 199           # الحزمة الذهبية
SEED_D = 227           # المقطع الواحد
INPUT_A = b"axis11-probe-payload-alpha-2026"
INPUT_B = {"scope": "axis11", "payload": [1, 2, {"deep": "tree"}],
           "meta": {"n": 4313, "tag": "determinism"}}
FLIP_POSITIONS = (0, 1, 7, 11, 17, 23)          # مواقع بت معلَنة في input
SEED_FLIP_BITS = (0, 1, 8, 12, 31)              # بتات معلَنة في seed
PIPELINE_NAMES = ["canonical", "derive", "sign", "aead", "merkle", "verify"]


def _repro():
    """هدف M2. حتى وجود sentinel/repro.py كل حالة تفشل RED بالنمط
    الواحد: ModuleNotFoundError: No module named 'sentinel.repro'."""
    import sentinel.repro as repro
    return repro


def _ref_splitmix_seq(state: int, count: int) -> list[int]:
    """مرجع مستقل — إعادة تنفيذ SplitMix64 بثوابتها المنشورة
    (عيدرون): داخل الاختبار حصراً، لا يستدعي المحرك أبداً."""
    out = []
    s = state
    for _ in range(count):
        s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        out.append(z ^ (z >> 31))
    return out


# ============================================================ H11_01
def test_H11_01():
    """H11_01 — G1 البذر الحتمي: نفس البذرة → نفس التسلسل."""
    r = _repro()
    a1 = [r.SeededPRNG(SEED_A).next_u64() for _ in range(1)]  # كائن 1
    seq1 = [r.SeededPRNG(SEED_A).next_u64() for _ in range(200)]
    seq2 = [r.SeededPRNG(SEED_A).next_u64() for _ in range(200)]
    assert len(seq1) == 200 and seq1 == seq2, "same seed, same sequence"
    del a1
    other = [r.SeededPRNG(SEED_A + 1).next_u64() for _ in range(200)]
    assert other != seq1, "different seed must differ"
    # تيار مشتق لكل خطوة: ثابت بالتكرار، مختلف بين التسميات
    s_sign_1 = r.derive_stream(SEED_A, "sign")
    s_sign_2 = r.derive_stream(SEED_A, "sign")
    s_aead = r.derive_stream(SEED_A, "aead")
    assert s_sign_1.next_u64() == s_sign_2.next_u64(), "stream stable"
    assert s_sign_1.next_u64() != s_aead.next_u64(), "streams must diverge"
    # seed داخل العقد [1, 2^64)
    assert r.SeededPRNG(1).next_u64() == _ref_splitmix_seq(1, 1)[0]


# ============================================================ H11_02
def test_H11_02():
    """H11_02 — G2 نفس المدخلات = نفس المخرجات (RunRecord كاملة)."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    r1 = ex.execute(INPUT_A, SEED_A)
    r2 = ex.execute(INPUT_A, SEED_A)
    assert r1 == r2, "identical (input, seed) must give identical record"
    for k in ("input_sha256", "flow_digest", "flow_merkle_hex",
              "final_payload", "steps", "seed"):
        assert k in r1, f"missing record field {k}"
    assert r1["seed"] == SEED_A
    assert r1["final_payload"] == r.canonical_input(INPUT_A)
    # وبذرة مختلفة نفس المدخل → سجل مختلف (الوجه الآخر)
    r3 = ex.execute(INPUT_A, SEED_B)
    assert r3["flow_merkle_hex"] != r1["flow_merkle_hex"], \
        "different seed must change the record"


# ============================================================ H11_03
def test_H11_03():
    """H11_03 — Triple-Run (الصيغة الحرفية §11.2)."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    ex.set_seed(SEED_B)
    t = ex.triple_run(INPUT_A)
    assert len(t) == 3
    assert t[0] == t[1] == t[2], "Run1==Run2==Run3"
    assert r.verify_determinism(list(t)) is True
    r.require_determinism(list(t))   # لا يرفع
    # Triple-Run بلا بذرة حالة → ValidationError (عقد الرفض الذري)
    ex2 = r.DeterministicExecutor(r.default_pipeline())
    try:
        ex2.triple_run(INPUT_A)
        raise AssertionError("triple_run without seed accepted")
    except r.ValidationError:
        pass


# ============================================================ H11_04
def test_H11_04():
    """H11_04 — هضم التدفق وجذر Merkle بإجابة يدوية مستقلة + مرجع
    وحدة مغلقة (المحور-8 proof.merkle_root)."""
    r = _repro()
    import sentinel.proof as proof   # وحدة مغلقة (المحور-8) — مرجع
    steps_spec = [
        ("pass", lambda p, rng: p),
        ("double", lambda p, rng: p + p),
        ("sha", lambda p, rng: hashlib.sha256(p).digest()),
    ]
    ex = r.DeterministicExecutor(steps_spec)
    rec = ex.execute(INPUT_A, SEED_C)
    lines = r.flow_lines(rec["steps"])
    # اليدوي: كل سطر ثم الجذر بقواعد §8.2 (فرد: مضاعفة الأخيرة)
    leaves = [hashlib.sha256(l.encode("utf-8")).digest() for l in lines]
    def _root(ls):
        if len(ls) == 1:
            return ls[0]
        while len(ls) > 1:
            nxt = []
            for i in range(0, len(ls) - 1, 2):
                nxt.append(hashlib.sha256(ls[i] + ls[i + 1]).digest())
            if len(ls) % 2:
                nxt.append(hashlib.sha256(ls[-1] + ls[-1]).digest())
            ls = nxt
        return ls[0]
    manual_root = _root(leaves[:])
    # مرجع المحور-8: merkle_root يتلقى البيانات الخام ويهضمها داخلياً
    # (Leaf=SHA-256(data)) — نمرر الأسطر نفسها فتكون أوراقه = هضوم
    # الأسطر = نفس أوراق flow_merkle (تصحيح تقني قبل أول تنفيذ)
    ref_root = proof.merkle_root([l.encode("utf-8") for l in lines])
    assert manual_root == ref_root == r.flow_merkle(rec["steps"]), \
        "flow merkle must equal hand answer AND closed-axis reference"
    assert rec["flow_merkle_hex"] == manual_root.hex()
    # هضم التدفق: sha256 فوق الأسطر — إجابة يدوية
    h = hashlib.sha256()
    for l in lines:
        h.update(l.encode("utf-8"))
        h.update(b"\n")
    assert r.flow_digest(rec["steps"]) == h.hexdigest(), \
        "flow digest hand mismatch"
    assert rec["flow_digest"] == h.hexdigest()


# ============================================================ H11_05
def test_H11_05():
    """H11_05 — تحليل الفروق §11.3: متطابقان → فارغ؛ محرَّف → معلن
    + investigate «التحقيق الآلي»."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    a = ex.execute(INPUT_A, SEED_A)
    b = ex.execute(INPUT_A, SEED_A)
    d0 = r.diff(a, b)
    assert d0["merkle_equal"] is True and d0["digest_equal"] is True
    assert d0["payload_equal"] is True and d0["first_diff"] is None
    # تحريف الحمولة النهائية فقط (نسخ عميق — RunRecord يحمل bytes:
    # التصحيح التقني قبل أول تنفيذ؛ JSON لا يمثل bytes)
    import copy
    tam = copy.deepcopy(b)
    tam["final_payload"] = bytes(tam["final_payload"][:-1]) + b"x"
    d1 = r.diff(a, tam)
    assert d1["merkle_equal"] is True        # الجذر لم يُمس
    assert d1["payload_equal"] is False
    assert d1["first_diff"] == "final_payload"
    # تحريب سجل خطوة → الجذر يكسر (الحرفية §11.3)
    import copy as _copy2
    tam2 = _copy2.deepcopy(b)
    tam2["steps"][2]["out_sha256"] = "00" * 32
    d2 = r.diff(a, tam2)
    assert d2["merkle_equal"] is False and d2["digest_equal"] is False
    inv = r.investigate(a, tam2)
    assert inv["first_divergent_step"]["index"] == 2
    assert inv["first_divergent_step"]["name"] == "sign"
    assert inv["first_divergent_step"]["out_match"] is False
    assert inv["first_divergent_step"]["in_match"] is True


# ============================================================ H11_06
def test_H11_06():
    """H11_06 — حساسية انعكاس البت — المدخل: بت واحد → مخرجات
    مختلفة في كل موقع معلن (لا موضع صامت)."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    base = ex.execute(INPUT_A, SEED_A)
    for pos in FLIP_POSITIONS:
        assert pos < len(INPUT_A) * 8, "flip position outside input"
        byte_i, bit_i = divmod(pos, 8)
        flipped = bytearray(INPUT_A)
        flipped[byte_i] ^= 1 << bit_i
        rec = ex.execute(bytes(flipped), SEED_A)
        assert rec["flow_merkle_hex"] != base["flow_merkle_hex"], \
            f"silent flip at input bit {pos}"
        assert rec["final_payload"] != base["final_payload"], \
            f"payload silent at input bit {pos}"


# ============================================================ H11_07
def test_H11_07():
    """H11_07 — حساسية انعكاس البت — البذرة: بت واحد → التدفق مختلف
    (الجذر/الهضم/السجل)؛ والدورة الوظيفية صامدة: plaintext المستعاد
    هو المدخل القانوني نفسه مهما كانت البذرة (البذرة تغيّر الأدلة
    لا الأصل) — الوجهان في الحالة نفسها."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    base = ex.execute(INPUT_A, SEED_A)
    same_again = ex.execute(INPUT_A, SEED_A)
    assert same_again == base, "same seed twice must match byte-for-byte"
    for bit in SEED_FLIP_BITS:
        seed2 = SEED_A ^ (1 << bit)
        assert seed2 != SEED_A
        rec = ex.execute(INPUT_A, seed2)
        assert rec["flow_merkle_hex"] != base["flow_merkle_hex"], \
            f"silent flip at seed bit {bit}"
        assert rec["flow_digest"] != base["flow_digest"], \
            f"digest silent at seed bit {bit}"
        assert rec["steps"] != base["steps"], \
            f"steps silent at seed bit {bit}"
        assert rec["input_sha256"] == base["input_sha256"], \
            "seed flip must not touch the input digest"
        # الوجه الوظيفي: فك التشفير يعيد الأصل نفسه مهما كانت البذرة
        assert rec["final_payload"] == base["final_payload"], \
            "verify cycle must restore the same plaintext"


# ============================================================ H11_08
def test_H11_08():
    """H11_08 — G5 قياسية المدخلات: التكافؤ القانوني → نفس المخرجات؛
    الاختلاف القانوني → مخرجات مختلفة."""
    r = _repro()
    d1 = {"alpha": 1, "beta": [1, 2, {"g": "x"}], "gamma": "v"}
    d2 = {"gamma": "v", "beta": [1, 2, {"g": "x"}], "alpha": 1}
    assert r.canonical_input(d1) == r.canonical_input(d2), \
        "lawfully-equivalent inputs must canonicalize identically"
    assert r.canonical_input(d1) != r.canonical_input({"alpha": 1}), \
        "different content must canonicalize differently"
    ex = r.DeterministicExecutor(r.default_pipeline())
    r1 = ex.execute(d1, SEED_D)
    r2 = ex.execute(d2, SEED_D)
    assert r1 == r2, "equivalent-by-law inputs, same outputs"
    # bytes تمر كما هي (عقد N3) — قلب بت فيها يعني مدخلاً مختلفاً
    r3 = ex.execute(INPUT_A, SEED_D)
    r4 = ex.execute(bytes(INPUT_A[:-1]) + b"z", SEED_D)
    assert r3["flow_merkle_hex"] != r4["flow_merkle_hex"]

# ============================================================ H11_09
def test_H11_09():
    """H11_09 — G3 التثبيت بالهاش: freeze_environment يحوي لكل
    حزمة معلنة version + record_sha256 (sha256 لملف RECORD الفعلي)،
    والمواصفة نفسها حتمية (مروران نفس البايت)."""
    r = _repro()
    import importlib.metadata as im
    env = r.freeze_environment()
    assert env["python"]["version"] == sys.version.split()[0]
    assert env["python"]["implementation"] == sys.implementation.name
    assert env["platform"]["system"] == sys.platform
    assert "machine" in env["platform"]
    assert "hash_seed" in env and "sys_flags" in env and "cwd" in env
    assert env["cwd"] == os.getcwd()
    assert set(env["pinned"]) == set(r.PINNED_PACKAGES)
    for pkg in r.PINNED_PACKAGES:
        ent = env["pinned"][pkg]
        assert ent["version"] == im.version(pkg), f"{pkg} version drift"
        sha = ent["record_sha256"]
        assert len(sha) == 64, f"{pkg} record sha must be hex64"
        assert all(c in "0123456789abcdef" for c in sha)
        # المرجع المستقل: importlib.metadata نفسه (مرجع stdlib الوحيد
        # المتاح — الإفصاح في N6): هاش RECORD من dist-info الفعلي
        dist = im.distribution(pkg)
        import hashlib as _h
        import pathlib as _pl
        rec = _pl.Path(dist._path) / "RECORD"     # معلَن N6
        ref_sha = _h.sha256(rec.read_bytes()).hexdigest()
        assert sha == ref_sha, f"{pkg} RECORD hash mismatch"
    # حتمية المواصفة: مروران → نفس التمثيل القياسي بالبايت
    env2 = r.freeze_environment()
    assert json.dumps(env, sort_keys=True).encode() == \
        json.dumps(env2, sort_keys=True).encode(), "env spec not deterministic"


# ============================================================ H11_10
def test_H11_10():
    """H11_10 — G4 استعادة البيئة: الكشف لا الصمت؛ الضبط لما
    يمكن ضبطه (PYTHONHASHSEEG من المواصفة، None→0 معلَن)."""
    r = _repro()
    env = r.freeze_environment()
    mm = r.restore_environment(env)
    assert mm == [], "matching environment must report zero mismatches"
    # الضبط الاستعادي: PYTHONHASHSEED من المواصفة (None→"0")
    expected_hs = str(env.get("hash_seed") or "0")
    assert os.environ.get("PYTHONHASHSEED") == expected_hs
    # spec محرَّف 1: python.version → mismatch بالاسم
    bad = json.loads(json.dumps(env))
    bad["python"]["version"] = "9.9.9"
    mm1 = r.restore_environment(bad)
    assert any("python.version" in m for m in mm1), \
        "python version drift must be NAMED, not silent"
    # spec محرَّف 2: record_sha256 لحزمة → mismatch باسمها
    bad2 = json.loads(json.dumps(env))
    bad2["pinned"]["scipy"]["record_sha256"] = "11" * 32
    mm2 = r.restore_environment(bad2)
    assert any("pinned.scipy.record_sha256" in m for m in mm2)
    # spec محرَّف 3: cwd مختلف → mismatch
    bad3 = json.loads(json.dumps(env))
    bad3["cwd"] = "/nonexistent/path"
    mm3 = r.restore_environment(bad3)
    assert any("cwd" in m for m in mm3)
    # spec فاسد بنيوياً → رفض ذري
    for broken in ({"python": "notadict"}, {"pinned": "x"}, "str"):
        try:
            r.restore_environment(broken)
            raise AssertionError("broken spec accepted")
        except r.ValidationError:
            pass


# ============================================================ H11_11
def test_H11_11():
    """H11_11 — الانحراف المفتعل (§11.3 «إذا Diff≠∅ → تحقيق آلي»):
    خطوة غير حتمية (عداد عام) → تشغيلان يختلفان؛ DriftError عند
    الطلب؛ investigate يحدد الخطوة المنحرفة بأول فهرس."""
    r = _repro()
    _C = itertools.count()
    steps = [
        ("canon", lambda p, rng: p),
        ("unstable", lambda p, rng: p + next(_C).to_bytes(8, "big")),
    ]
    ex = r.DeterministicExecutor(steps)
    a = ex.execute(INPUT_A, SEED_A)
    b = ex.execute(INPUT_A, SEED_A)
    assert a != b, "nondeterministic step must drift"
    d = r.diff(a, b)
    assert d["digest_equal"] is False or d["merkle_equal"] is False
    inv = r.investigate(a, b)
    fd = inv["first_divergent_step"]
    assert fd["index"] == 1 and fd["name"] == "unstable"
    assert fd["in_match"] is True and fd["out_match"] is False
    try:
        r.require_determinism([a, b])
        raise AssertionError("drift accepted silently")
    except r.DriftError:
        pass
    assert r.verify_determinism([a, b]) is False


# ============================================================ H11_12
def test_H11_12():
    """H11_12 — الرفض الذري: كل عقد فاسد → ValidationError قبل أي
    أثر (لا تسمم حالة بعدها)."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    base = ex.execute(INPUT_A, SEED_A)      # سليم قبل الرفض
    for bad in (
        lambda: ex.execute(INPUT_A),                       # بلا بذرة
        lambda: r.DeterministicExecutor([]),               # خطوات فارغة
        lambda: r.DeterministicExecutor([("x", "nc")]),    # غير callable
        lambda: r.DeterministicExecutor([("", lambda p, g: p)]),  # اسم فارغ
        lambda: r.DeterministicExecutor([("dup", lambda p, g: p),
                                         ("dup", lambda p, g: p)]),  # مكرر
        lambda: r.SeededPRNG(0),                           # خارج [1,2^64)
        lambda: r.SeededPRNG(-7),
        lambda: r.SeededPRNG(True),
        lambda: r.SeededPRNG("77"),
        lambda: r.derive_stream("x", "y"),
        lambda: r.derive_stream(5, ""),
        lambda: ex.set_seed(0),
        lambda: ex.set_seed(True),
        lambda: ex.set_seed("77"),
        lambda: ex.execute(object(), SEED_A),              # غير قابل للتمثيل
        lambda: ex.execute(lambda: 1, SEED_A),
    ):
        try:
            bad()
            raise AssertionError("invalid accepted: %r" % (bad,))
        except r.ValidationError:
            pass
    # fn ترجع غير bytes → رفض عند التنفيذ
    ex_bad = r.DeterministicExecutor([("x", lambda p, g: "str-not-bytes")])
    try:
        ex_bad.execute(INPUT_A, SEED_A)
        raise AssertionError("non-bytes step output accepted")
    except r.ValidationError:
        pass
    # لا تسمم: بعد كل الرفض، التنفيذ السليم يعطي نفس الأساس
    assert ex.execute(INPUT_A, SEED_A) == base


# ============================================================ H11_13
def test_H11_13():
    """H11_13 — عدم تسمم الحالة عبر التتابع: مداخيل وبذور أخرى
    بينهما ثم العودة → نفس نتيجة الأساس بالبايت؛ كائن ثانٍ → نفس
    النتيجة (لا حالة كامنة في الكائن)."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    base = ex.execute(INPUT_A, SEED_A)
    ex.execute(INPUT_A + b"-other", SEED_B)     # مدخل آخر
    ex.set_seed(SEED_C)
    ex.execute(INPUT_A, SEED_C)                 # بذرة أخرى
    ex.execute(INPUT_B, SEED_A)                 # قاموس كمدخل
    back = ex.execute(INPUT_A, SEED_A)
    assert back == base, "state poisoned by interleaved runs"
    ex2 = r.DeterministicExecutor(r.default_pipeline())
    assert ex2.execute(INPUT_A, SEED_A) == base, "second object differs"
    ex.set_seed(SEED_A)
    t = ex.triple_run(INPUT_A)
    assert t[0] == base


# ============================================================ H11_14
def test_H11_14():
    """H11_14 — المتجه المرجعي المستقل: إعادة تنفيذ SplitMix64 داخل
    الاختبار مقابل SeededPRNG بايت-ببايت + الاشتقاق المستقل
    + randbelow داخل النطاق وحتمي."""
    r = _repro()
    # 1) u64 عبر بذور معلنة داخل العقد [1,2^64) — مقابل المرجع
    #    المستقل (تصحيح GREEN: البذرة 0 كانت خارج العقد والرفض صحيح)
    for seed in (1, 2, 3, 12345):
        ref = _ref_splitmix_seq(seed, 64)
        pr = r.SeededPRNG(seed)
        got = [pr.next_u64() for _ in range(64)]
        assert got == ref, f"splitmix64 mismatch at seed {seed}"
    # 2) next_bytes = big-endian لقيم u64 المتتالية
    pr = r.SeededPRNG(12345)
    ref_seq = _ref_splitmix_seq(12345, 4)
    assert pr.next_bytes(32) == b"".join(v.to_bytes(8, "big")
                                         for v in ref_seq)
    assert pr.next_bytes(0) == b""
    # 3) derive_stream: المرجع المستقل للاشتقاق (SHA-256 seed:label)
    label, seed = "sign", 4313
    d0 = int.from_bytes(
        hashlib.sha256(f"{seed}:{label}".encode()).digest()[:8], "big")
    ref_stream = _ref_splitmix_seq(d0, 8)
    ds = r.derive_stream(seed, label)
    assert [ds.next_u64() for _ in range(8)] == ref_stream
    # 4) randbelow: داخل [0,n) وحتمي وrandbelow(1)==0
    p1, p2 = r.SeededPRNG(199), r.SeededPRNG(199)
    v1 = [p1.randbelow(7) for _ in range(1000)]
    v2 = [p2.randbelow(7) for _ in range(1000)]
    assert v1 == v2 and all(0 <= v < 7 for v in v1)
    assert r.SeededPRNG(199).randbelow(1) == 0


# ============================================================ H11_15
def test_H11_15():
    """H11_15 — التكامل مع النواة الحتمية المغلقة: default_pipeline
    (ست خطوات فوق sentinel.proof): 20 زوجاً مزروعاً → تشغيلان
    متطابقان + الدورة صالحة وظيفياً + لا تصادم بين الأزواج."""
    r = _repro()
    ex = r.DeterministicExecutor(r.default_pipeline())
    names = [n for n, _fn in r.default_pipeline()]
    assert names == PIPELINE_NAMES, "pipeline order contract"
    roots = set()
    for i in range(20):
        seed = 1000 + i
        inp = INPUT_A if i % 2 == 0 else \
            {"i": i, "load": [i, i + 1, {"s": str(i)}]}
        r1 = ex.execute(inp, seed)
        r2 = ex.execute(inp, seed)
        assert r1 == r2, f"pair {i} not reproducible"
        # الدورة صالحة وظيفياً: verify فكّ التشفير وحقّق التوقيع
        # وأرجع plaintext == التمثيل القانوني للمدخل
        assert r1["final_payload"] == r.canonical_input(inp), \
            f"pair {i} verify cycle broken"
        assert len(r1["steps"]) == 6
        assert len(r1["flow_merkle_hex"]) == 64
        roots.add(r1["flow_merkle_hex"])
    assert len(roots) == 20, "distinct (input,seed) pairs collapsed"


# ============================================================ وضع السكربت
def _run_all() -> list[dict]:
    """تشغيل كل الحالات بترتيبها مع التقاط النتائج — التيار المنطقي
    فقط."""
    names = [n for n in sorted(globals())
             if n.startswith("test_H11_") and callable(globals()[n])]
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
    خارج الهضم (انضباط المحور-11 على نفسه)."""
    h = hashlib.sha256()
    for r_ in results:
        h.update(f"{r_['name']}:{int(r_['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-11 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    total = len(results)
    doc = {
        "suite": "axis11-repro",
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
    print(f"axis11: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
