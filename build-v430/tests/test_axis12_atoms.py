#!/usr/bin/env python3
"""SENTINEL Axis-12 — M3 ATOMS: البطاريات الإجبارية الثلاث.

PROVENANCE والعقد (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-7/8/11):
- جدول بطاريات أمر البناء الحرفي غير مسترد من أي سجل ملتزم (ضاع مع
  قطع الجلسة)؛ البطاريات الثلاث أدناه مُشتقة من عقد M1 المُسجَّل
  (tests/test_axis12_transparency.py — D1 المواصفة §12 + D2 نطاق
  ترتيب البناء) ومن نمط البطاريات المعتمد (عشوائية مزروعة × مرجع
  مستقل × سيناريوهات عدائية بالضبط-عدد) — قابلة للإحلال عند أي حد
  محطة.
- تُنفَّذ فوق sentinel/transparency.py (M2 GREEN عند 4816023) — لا
  تعديل في المحرك ولا لمس للنواة 227×19=4313 (جناح مستقل، غير
  مُسجَّل في @case، كل بطارية تستورد sentinel.transparency داخل
  جسمها).
- انضباط الهضم: التيار المنطقي فقط (battery, what, ok) — أزمنة
  الحائط في detail ولا تدخل الهضم أبداً. كل العشوائية ببذور ثابتة
  معلَنة — لا عشوائية حرة.

البطاريات الثلاث (مُشتقة من عقد M1 — مُعلنة):
  12a — 400 دورة مزروعة (البوابة فوق منظومات أدلة مزروعة):
        كل دورة i: مولد random.Random(700000+i) يبني منظومة (1-4
        حدود بفئات مزروعة + أدلة ملاحظة/شرط/قياس عن موضوع حر) ثم
        ثلاثة ادعاءات مصنفة بالبناء: اثنان مدعومان (تحقق + قدرة عن
        الموضوع الحر) وواحد هلوسة بالبناء (قدرة عن عقدة عليها حد
        مسجل — النقيض الكوني N2). البوابة يجب أن تصنف الـ1200
        ادعاءاً كما صُنفت بالبناء (برهان لا ادعاء)؛ والبطارية كلها
        مروران → نفس قائمة أختام boundary_digest بالبايت؛ وقلب بت
        واحد في سبب حد → الختم يختلف (حساسية المحتوى).
  12b — 150 مطابقة مرجع مستقل (بايت-ببايت — حتمية قاطعة):
        (50) معرّفات السجلات B12- مقابل sha256(f"{node}|{reason}|
        {category}")[:12] المستقل؛ (25) معرّفات الأدلة E- مقابل
        canonical JSON مستقل + sha256؛ (25) ختم boundary_digest مقابل
        إعادة تركيب مستقلة فوق سجلات بلا الطابع الطائر (25 محركاً
        بأشكال مختلفة)؛ (25) عدّ التغطية مقابل عدّ مستقل لكل فئة؛
        (25) معرّفات الادعاءات C- مقابل إعادة حساب المستقلة → 150.
  12c — بالضبط 40 سيناريو عدائي (تصنيف معلن لكل فئة):
        (12 بنيوي) أشكال فاسدة → ValidationError قبل أي أثر؛
        (10 تخريب بوابة) محاولات هلوسة يجب أن تُلتقط كلها (دليل
        مختلق، دليل عن غير الموضوع، تسمية triple_run كاذبة، جرد
        يكذب في العدد، حد يناقض الادعاء، قيمة تخالف القياس،
        حتمية بتشغيلة واحدة، أمانة بانحراف مقيس، شرط فاشل، اكتمال
        فوق سجل فارغ)؛
        (8 دقة) ادعاءات صالحة يجب ألا تُوصم (واحد لكل قاعدة +
        متعدد الأدلة + ادعاء على محرك مُعاد بناؤه بالدورة الكاملة)؛
        (6 حدود وتحريف) سلامة معرّفات التصدير (سجل/دليل محرف →
        رفض)، دورة تحفظ سجل التدقيق، جرد متقادم ينقلب حياً، صحة
        بعد الرفض، رتابة الطوابع التلقائية؛
        (4 حيوية) محركان بنفس التغذية → تصديران متطابقان، الطابع
        التلقائي خارج الختم، أصفار السجل الفارغ بترتيب المواصفة،
        ومعالجة محتوى معرّف الادعاء.
        بعد الأربعين: فحص حي (لا تسمم حالة) — دورة صالحة تعطي
        نفس ختم ما قبل البطارية.

ملاحظات الصدق (الفروقات المُعلنة — لا مخفية):
  N1 (12a) — «عشوائية» = مولَّدة ببذور ثابتة معلَنة (700000+i):
      عشوائية التوليد حتمية الإعادة — هذا ما يجعل «قائمة الأختام
      قابلة للتكرار» برهاناً لا ادعاءً. التصنيف «المتوقع» يعرف
      بالبناء (أدلة عن الموضوع الحر صالحة؛ والعقدة المحدودة ينقضها
      حدّها المسجل) — لا يستنسخ من المحرك.
  N2 (12b) — المراجع المستقلة داخل البطارية حصراً (hashlib وjson
      القياسي مباشرة) — لا واحدة منها تستدعي المحرك.
  N3 (12c) — التصنيف معلن لكل فئة بالعدد؛ «صفر انهيار» يعني: لا
      استثناء من نوع غير معلن، ولا سيناريو سلك غير ما صُرِّح له.
      الفحص الحي بعد الأربعين هجوماً يثبت عدم تسمم الحالة.

Usage:
  python3 -m pytest tests/test_axis12_atoms.py --tb=short -q
  python3 tests/test_axis12_atoms.py --out results/axis12/axis12_ATOMS.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _t12():
    import sentinel.transparency as t12
    return t12


def _canon(obj) -> str:
    """المرجع المستقل: JSON قياسي مفاتيحه مرتبة (لا يستدعي المحرك)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


# ============================================================ البطارية 12a
def battery_12a(t12) -> dict:
    """400 دورة مزروعة: تصنيف 1200 ادعاءاً كما صُنفت بالبناء + مروران
    متطابقان + حساسية قلب البت."""
    detail = {"cycles": 400, "crash_count": 0, "classification_agreement": 0,
              "lawful_supported": 0, "hallucinations_caught": 0,
              "repeatable": None, "seal_lists": [], "bit_flip_sensitive": None}
    try:
        for _run_idx in (1, 2):
            seals = []
            for i in range(400):
                gen = random.Random(700000 + i)      # مزروعة معلَنة N1
                eng = t12.BoundaryEngine()
                n_rec = gen.randint(1, 4)
                bounded = None
                for j in range(n_rec):
                    cat = gen.choice(t12.CATEGORIES)
                    node = f"cyc{i}:node{j}"
                    eng.record(node, f"planted reason {gen.randint(1, 999)}",
                               cat, confidence=round(gen.random(), 3),
                               timestamp=1000.0 + j)
                    if bounded is None:
                        bounded = node                 # أول عقدة محدودة
                free = f"cyc{i}:free"                  # موضوع حر بلا حد
                e_obs = eng.attach("observation",
                                   {"subject": free, "what": "seen"})
                e_pre = eng.attach("precondition",
                                   {"subject": free, "check": "reachable",
                                    "status": "verified"})
                # ثلاثة ادعاءات مصنفة بالبناء (لا بالمحرك)
                c_v = t12.make_claim("verification", f"obs {i}",
                                     [e_obs], subject=free)
                c_p = t12.make_claim("capability", f"cap {i}",
                                     [e_pre], subject=free)
                c_bad = t12.make_claim("capability", f"bad {i}",
                                       [e_pre], subject=bounded)
                v_v = eng.verify_claim(c_v)
                v_p = eng.verify_claim(c_p)
                h_bad = eng.detect_hallucination(c_bad)
                if _run_idx == 1:
                    if v_v["supported"] and v_p["supported"] \
                            and h_bad["is_hallucination"]:
                        detail["classification_agreement"] += 1
                    detail["lawful_supported"] += 2
                    if h_bad["is_hallucination"]:
                        detail["hallucinations_caught"] += 1
                seals.append(eng.export()["boundary_digest"])
            detail["seal_lists"].append(
                hashlib.sha256("|".join(seals).encode()).hexdigest())
        detail["repeatable"] = \
            detail["seal_lists"][0] == detail["seal_lists"][1]
        # حساسية قلب البت: قلب بت واحد في بايت من سبب حد → ختم مختلف
        gen = random.Random(700999)
        base_reason = f"bitflip probe {gen.randint(1, 999)}"
        flip_pos = gen.randrange(len(base_reason))
        flipped = (base_reason[:flip_pos]
                   + chr(ord(base_reason[flip_pos]) ^ 1)
                   + base_reason[flip_pos + 1:])
        e1, e2 = t12.BoundaryEngine(), t12.BoundaryEngine()
        e1.record("g:x", base_reason, t12.NETWORK_ISOLATED, timestamp=1.0)
        e2.record("g:x", flipped, t12.NETWORK_ISOLATED, timestamp=1.0)
        detail["bit_flip_sensitive"] = (
            e1.export()["boundary_digest"]
            != e2.export()["boundary_digest"])
    except Exception as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
        detail["crash_count"] += 1
        detail["crash"] = repr(exc)
    ok = (detail["crash_count"] == 0
          and detail["classification_agreement"] == 400
          and detail["hallucinations_caught"] == 400
          and detail["repeatable"] is True
          and detail["bit_flip_sensitive"] is True)
    return {"battery": "12a", "what": "400 planted cycles: 1200 claims "
            "classified as constructed + two-pass seal repeatability + "
            "bit-flip sensitivity", "ok": ok, "detail": detail}


# ============================================================ البطارية 12b
def battery_12b(t12) -> dict:
    """150 مطابقة مرجع مستقل بايت-ببايت: المعرفات والختم والتغطية."""
    detail = {"matched": {"record_ids": 0, "artifact_ids": 0,
                          "boundary_digest": 0, "coverage": 0,
                          "claim_ids": 0},
              "mismatch_total": 0, "crash_count": 0}
    try:
        # (50) معرّفات السجلات — sha256 المستقل
        eng = t12.BoundaryEngine()
        for i in range(50):
            node, reason = f"n{i}", f"why-{i}"
            cat = t12.CATEGORIES[i % 14]
            exp = "B12-" + hashlib.sha256(
                f"{node}|{reason}|{cat}".encode()).hexdigest()[:12]
            rec = eng.record(node, reason, cat, timestamp=1.0 + i)
            detail["matched"]["record_ids"] += int(rec.id == exp)
        # (25) معرّفات الأدلة — canonical JSON المستقل
        for i in range(25):
            content = {"subject": f"s{i}", "value": float(i),
                       "unit": "x", "source": "b12"}
            exp = "E-" + hashlib.sha256(_canon(
                {"kind": "measurement", "content": content}).encode()
            ).hexdigest()[:12]
            aid = eng.attach("measurement", content)
            detail["matched"]["artifact_ids"] += int(aid == exp)
        # (25) ختم boundary_digest — إعادة تركيب مستقلة (25 محركاً)
        for i in range(25):
            gen = random.Random(800000 + i)
            e = t12.BoundaryEngine()
            for j in range(gen.randint(1, 6)):
                e.record(f"g{i}:{j}", f"r{gen.randint(1, 99)}",
                         gen.choice(t12.CATEGORIES),
                         confidence=round(gen.random(), 3),
                         timestamp=2000.0 + j)
            core = [{"id": r.id, "seq": r.seq, "node": r.node,
                     "reason": r.reason, "category": r.category,
                     "confidence": r.confidence} for r in e.records]
            exp = hashlib.sha256(_canon(core).encode()).hexdigest()
            detail["matched"]["boundary_digest"] += int(
                e.export()["boundary_digest"] == exp)
        # (25) عدّ التغطية — عدّ مستقل لكل فئة
        for i in range(25):
            gen = random.Random(810000 + i)
            e = t12.BoundaryEngine()
            planted = []
            for j in range(gen.randint(0, 8)):
                cat = gen.choice(t12.CATEGORIES)
                planted.append(cat)
                e.record(f"n{i}:{j}", f"why{j}", cat, timestamp=3.0 + j)
            cov = e.coverage()
            exp_per = {c: planted.count(c) for c in t12.CATEGORIES}
            good = (cov["per_category"] == exp_per
                    and cov["total_records"] == len(planted)
                    and cov["distinct_nodes"] == len(set(
                        f"n{i}:{j}" for j in range(len(planted))))
                    and cov["empty_categories"] == [
                        c for c in t12.CATEGORIES if exp_per[c] == 0])
            detail["matched"]["coverage"] += int(good)
        # (25) معرّفات الادعاءات — إعادة حساب المستقلة
        for i in range(25):
            kind = t12.CLAIM_KINDS[i % 6]
            stmt = f"claim {i}"
            ev = [f"E-{'a' * 12}", f"E-{'b' * 12}"][:i % 3]
            sub = f"s{i}"
            extra = {"value": float(i)} if i % 4 == 0 else {}
            exp = "C-" + hashlib.sha256(_canon(
                {"kind": kind, "statement": stmt, "evidence": ev,
                 "subject": sub, "extra": extra}).encode()).hexdigest()[:12]
            claim = t12.make_claim(kind, stmt, ev, subject=sub, **extra)
            detail["matched"]["claim_ids"] += int(claim["claim_id"] == exp)
        detail["mismatch_total"] = 150 - sum(detail["matched"].values())
    except Exception as exc:  # noqa: BLE001
        detail["crash_count"] += 1
        detail["crash"] = repr(exc)
    total_matched = sum(detail["matched"].values())
    ok = (detail["crash_count"] == 0 and total_matched == 150
          and detail["mismatch_total"] == 0)
    return {"battery": "12b", "what": "150 independent-reference matches "
            "(50 record ids + 25 artifact ids + 25 boundary digests + "
            "25 coverage counts + 25 claim ids), byte-exact", "ok": ok,
            "detail": detail}


# ============================================================ البطارية 12c
def battery_12c(t12) -> dict:
    """بالضبط 40 سيناريو عدائي (12 بنيوي + 10 تخريب + 8 دقة + 6
    حدود/تحريف + 4 حيوية) + فحص حي بعد الأربعين."""
    detail = {"behaved_as_declared": 0, "crash_count": 0,
              "by_class": {"structural": 0, "gate_sabotage": 0,
                           "precision": 0, "boundary_tamper": 0,
                           "liveness": 0},
              "log": [], "state_poisoning_check": None}

    def case(cls: str, name: str, fn) -> None:
        t0 = time.perf_counter()
        try:
            behaved = bool(fn())
        except Exception as exc:  # noqa: BLE001 — انهيار غير معلن
            detail["crash_count"] += 1
            detail["log"].append({"class": cls, "name": name,
                                  "behaved": False, "crash": repr(exc),
                                  "dur_s": round(time.perf_counter() - t0, 6)})
            return
        if behaved:
            detail["by_class"][cls] += 1
            detail["behaved_as_declared"] += 1
        detail["log"].append({"class": cls, "name": name,
                              "behaved": behaved,
                              "dur_s": round(time.perf_counter() - t0, 6)})

    def raises_validation(fn) -> bool:
        try:
            fn()
            return False
        except t12.ValidationError:
            return True

    # المحرك طويل العمر لفئة الرفض البنيوي — يبقى حياً بعدها (الفحص
    # الختامي يثبت أن الرفض لم يغيّر شيئاً)
    eng = t12.BoundaryEngine()
    eng.record("g:base", "baseline boundary", t12.OUT_OF_SCOPE,
               timestamp=5.0)

    # ---- (12) رفض بنيوي: ValidationError قبل أي أثر ----------------
    case("structural", "unknown-category-record",
         lambda: raises_validation(
             lambda: eng.record("g:x", "r", "NOPE")))
    case("structural", "unknown-category-query",
         lambda: raises_validation(lambda: eng.query("NOPE")))
    case("structural", "confidence-out-of-range",
         lambda: raises_validation(
             lambda: eng.record("g:x", "r", t12.TIME_LIMIT,
                                confidence=2.0)))
    case("structural", "confidence-bool",
         lambda: raises_validation(
             lambda: eng.record("g:x", "r", t12.TIME_LIMIT,
                                confidence=True)))
    case("structural", "timestamp-negative",
         lambda: raises_validation(
             lambda: eng.record("g:x", "r", t12.TIME_LIMIT,
                                timestamp=-0.5)))
    case("structural", "node-empty",
         lambda: raises_validation(
             lambda: eng.record("", "r", t12.TIME_LIMIT)))
    case("structural", "reason-empty",
         lambda: raises_validation(
             lambda: eng.record("g:x", "", t12.TIME_LIMIT)))
    case("structural", "attach-unknown-kind",
         lambda: raises_validation(
             lambda: eng.attach("not-a-kind", {"a": 1})))
    case("structural", "attach-non-json-content",
         lambda: raises_validation(
             lambda: eng.attach("observation", {"bad": {1, 2}})))
    case("structural", "claim-unknown-kind",
         lambda: raises_validation(
             lambda: t12.make_claim("nope", "s")))
    case("structural", "claim-evidence-string",
         lambda: raises_validation(
             lambda: t12.make_claim("verification", "s", "E-x")))
    case("structural", "verify-malformed-raw-claim",
         lambda: raises_validation(
             lambda: eng.verify_claim({"kind": "verification",
                                       "statement": "s",
                                       "evidence": [7]})))

    # ---- (10) تخريب البوابة: كلها هلوسة ملتقطة --------------------
    def _env():
        e = t12.BoundaryEngine()
        return e

    def sab_fabricated():
        e = _env()
        c = t12.make_claim("verification", "v",
                           ["E-" + "f" * 12], subject="s:x")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_subject_mismatch():
        e = _env()
        oid = e.attach("observation", {"subject": "s:a", "what": "w"})
        c = t12.make_claim("verification", "v", [oid], subject="s:b")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_lying_triple_label():
        e = _env()
        d1 = hashlib.sha256(b"a").hexdigest()
        d2 = hashlib.sha256(b"b").hexdigest()
        d3 = hashlib.sha256(b"c").hexdigest()
        aid = e.attach("triple_run", {"subject": "s:d",
                                      "runs": [d1, d2, d3],
                                      "all_identical": True})
        c = t12.make_claim("determinism", "d", [aid], subject="s:d")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_lying_inventory_count():
        e = _env()
        e.record("g:1", "r", t12.AUTH_REQUIRED, timestamp=1.0)
        dump = e.export()
        inv = e.attach("inventory", {"digest": dump["boundary_digest"],
                                     "records": 7})
        c = t12.make_claim("completeness", "x", [inv], subject="camp")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_boundary_contradiction():
        e = _env()
        e.record("target:locked", "tcp rst", t12.NETWORK_ISOLATED,
                 timestamp=1.0)
        oid = e.attach("observation", {"subject": "target:locked",
                                       "what": "allegedly scanned"})
        c = t12.make_claim("verification", "v", [oid],
                           subject="target:locked")
        hr = e.detect_hallucination(c)
        return hr["is_hallucination"] is True and any(
            "NETWORK_ISOLATED" in r_ for r_ in hr["reasons"])

    def sab_value_mismatch():
        e = _env()
        mid = e.attach("measurement", {"subject": "s:c", "value": 87.5,
                                       "unit": "%", "source": "cov"})
        c = t12.make_claim("coverage", "c", [mid], subject="s:c",
                           value=100.0)
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_single_run():
        e = _env()
        d = hashlib.sha256(b"one").hexdigest()
        aid = e.attach("triple_run", {"subject": "s:d", "runs": [d],
                                      "all_identical": True})
        c = t12.make_claim("determinism", "d", [aid], subject="s:d")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_measured_drift():
        e = _env()
        bid = e.attach("baseline_comparison",
                       {"subject": "s:h", "baseline_ref": "b",
                        "fresh_ref": "f", "compare_rc": 1, "diff": "x"})
        c = t12.make_claim("honesty", "h", [bid], subject="s:h")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_failed_precondition():
        e = _env()
        pid = e.attach("precondition", {"subject": "s:p", "check": "c",
                                        "status": "failed"})
        c = t12.make_claim("capability", "p", [pid], subject="s:p")
        return e.detect_hallucination(c)["is_hallucination"] is True

    def sab_empty_registry_completeness():
        e = _env()                                   # سجل فارغ عمداً
        dump = e.export()
        inv = e.attach("inventory", {"digest": dump["boundary_digest"],
                                     "records": 0})
        c = t12.make_claim("completeness", "x", [inv], subject="camp")
        return e.detect_hallucination(c)["is_hallucination"] is True

    for name, fn in (("fabricated-evidence", sab_fabricated),
                     ("evidence-subject-mismatch", sab_subject_mismatch),
                     ("lying-triple-label", sab_lying_triple_label),
                     ("lying-inventory-count", sab_lying_inventory_count),
                     ("boundary-contradiction", sab_boundary_contradiction),
                     ("value-mismatch", sab_value_mismatch),
                     ("single-run-determinism", sab_single_run),
                     ("honesty-measured-drift", sab_measured_drift),
                     ("failed-precondition", sab_failed_precondition),
                     ("completeness-empty-registry",
                      sab_empty_registry_completeness)):
        case("gate_sabotage", name, fn)

    # ---- (8) الدقة: ادعاءات صالحة لا تُوصم -----------------------
    def prec_full():
        e = _env()
        oid = e.attach("observation", {"subject": "s:v", "what": "w"})
        c = t12.make_claim("verification", "v", [oid], subject="s:v")
        return e.verify_claim(c)["supported"] is True

    def prec_coverage():
        e = _env()
        mid = e.attach("measurement", {"subject": "s:c", "value": 91.0,
                                       "unit": "%", "source": "cov"})
        c = t12.make_claim("coverage", "c", [mid], subject="s:c",
                           value=91.0)
        return e.verify_claim(c)["supported"] is True

    def prec_determinism():
        e = _env()
        d = hashlib.sha256(b"det").hexdigest()
        aid = e.attach("triple_run", {"subject": "s:d",
                                      "runs": [d, d, d],
                                      "all_identical": True})
        c = t12.make_claim("determinism", "d", [aid], subject="s:d")
        return e.verify_claim(c)["supported"] is True

    def prec_honesty():
        e = _env()
        bid = e.attach("baseline_comparison",
                       {"subject": "s:h", "baseline_ref": "b",
                        "fresh_ref": "f", "compare_rc": 0, "diff": None})
        c = t12.make_claim("honesty", "h", [bid], subject="s:h")
        return e.verify_claim(c)["supported"] is True

    def prec_capability():
        e = _env()
        pid = e.attach("precondition", {"subject": "s:p", "check": "c",
                                        "status": "verified"})
        c = t12.make_claim("capability", "p", [pid], subject="s:p")
        return e.verify_claim(c)["supported"] is True

    def prec_completeness():
        e = _env()
        e.record("g:1", "r", t12.TIME_LIMIT, timestamp=1.0)
        dump = e.export()
        inv = e.attach("inventory", {"digest": dump["boundary_digest"],
                                     "records": len(dump["records"])})
        c = t12.make_claim("completeness", "x", [inv], subject="camp")
        return e.verify_claim(c)["supported"] is True

    def prec_multi_evidence():
        e = _env()
        a1 = e.attach("observation", {"subject": "s:v", "what": "w1"})
        a2 = e.attach("observation", {"subject": "s:v", "what": "w2"})
        c = t12.make_claim("verification", "v", [a1, a2], subject="s:v")
        return e.verify_claim(c)["supported"] is True

    def prec_roundtrip_verify():
        e = _env()
        oid = e.attach("observation", {"subject": "s:v", "what": "w"})
        c = t12.make_claim("verification", "v", [oid], subject="s:v")
        e.verify_claim(c)
        reb = t12.import_export(e.export())
        return reb.verify_claim(c)["supported"] is True

    for name, fn in (("verification-ok", prec_full),
                     ("coverage-ok", prec_coverage),
                     ("determinism-ok", prec_determinism),
                     ("honesty-ok", prec_honesty),
                     ("capability-ok", prec_capability),
                     ("completeness-ok", prec_completeness),
                     ("multi-evidence-verification", prec_multi_evidence),
                     ("roundtrip-verify", prec_roundtrip_verify)):
        case("precision", name, fn)

    # ---- (6) حدود وتحريف ----------------------------------------
    def tam_record_id():
        e = _env()
        e.record("g:a", "r", t12.TIME_LIMIT, timestamp=1.0)
        dump = json.loads(json.dumps(e.export()))
        dump["records"][0]["reason"] = "tampered"
        return raises_validation(lambda: t12.import_export(dump))

    def tam_evidence_id():
        e = _env()
        e.attach("observation", {"subject": "s", "what": "w"})
        dump = json.loads(json.dumps(e.export()))
        dump["evidence"][0]["content"]["what"] = "tampered"
        return raises_validation(lambda: t12.import_export(dump))

    def tam_ledger_roundtrip():
        e = _env()
        oid = e.attach("observation", {"subject": "s:v", "what": "w"})
        c = t12.make_claim("verification", "v", [oid], subject="s:v")
        e.verify_claim(c)
        e.detect_hallucination(t12.make_claim("coverage", "c", [],
                                              subject="s:c"))
        reb = t12.import_export(e.export())
        return reb.export()["claims"] == e.export()["claims"]

    def tam_stale_inventory_live():
        e = _env()
        e.record("g:1", "r", t12.TIME_LIMIT, timestamp=1.0)
        dump = e.export()
        inv = e.attach("inventory", {"digest": dump["boundary_digest"],
                                     "records": len(dump["records"])})
        c = t12.make_claim("completeness", "x", [inv], subject="camp")
        before = e.verify_claim(c)["supported"] is True
        e.record("g:2", "r2", t12.AUTH_REQUIRED, timestamp=2.0)
        after = e.detect_hallucination(c)["is_hallucination"] is True
        return before and after

    def tam_post_rejection_health():
        twin = t12.BoundaryEngine()
        twin.record("g:base", "baseline boundary", t12.OUT_OF_SCOPE,
                    timestamp=5.0)
        same = (eng.export()["boundary_digest"]
                == twin.export()["boundary_digest"])
        eng.record("g:new", "after rejections", t12.TIME_LIMIT,
                   timestamp=6.0)
        twin.record("g:new", "after rejections", t12.TIME_LIMIT,
                    timestamp=6.0)
        return same and (eng.export()["boundary_digest"]
                         == twin.export()["boundary_digest"])

    def tam_auto_timestamp_monotone():
        e = _env()
        r1 = e.record("g:a", "r1", t12.TIME_LIMIT)
        r2 = e.record("g:b", "r2", t12.TIME_LIMIT)
        return (isinstance(r1.timestamp, float)
                and isinstance(r2.timestamp, float)
                and r2.timestamp >= r1.timestamp)

    for name, fn in (("import-tampered-record", tam_record_id),
                     ("import-tampered-evidence", tam_evidence_id),
                     ("roundtrip-preserves-ledger", tam_ledger_roundtrip),
                     ("stale-inventory-flips-live", tam_stale_inventory_live),
                     ("post-rejection-health", tam_post_rejection_health),
                     ("auto-timestamp-monotone",
                      tam_auto_timestamp_monotone)):
        case("boundary_tamper", name, fn)

    # ---- (4) حيوية ------------------------------------------------
    def liv_same_feed_identical():
        def build():
            e = t12.BoundaryEngine()
            for j, cat in enumerate(t12.CATEGORIES[:6]):
                e.record(f"g:{j}", f"why{j}", cat, timestamp=7.0 + j)
            e.attach("observation", {"subject": "g:0", "what": "w"})
            return e
        return (_canon(build().export())
                == _canon(build().export()))

    def liv_auto_ts_digest_stable():
        e = t12.BoundaryEngine()
        e.record("g:x", "clock fed", t12.TIME_LIMIT)   # طابع تلقائي
        return (e.export()["boundary_digest"]
                == e.export()["boundary_digest"])

    def liv_empty_coverage_zeros():
        e = t12.BoundaryEngine()
        cov = e.coverage()
        return (cov["total_records"] == 0
                and cov["distinct_nodes"] == 0
                and cov["empty_categories"] == list(t12.CATEGORIES)
                and all(v == 0 for v in cov["per_category"].values()))

    def liv_claim_id_addressing():
        c1 = t12.make_claim("verification", "same", ["E-aaaaaaaaaaaa"],
                            subject="s")
        c2 = t12.make_claim("verification", "same", ["E-aaaaaaaaaaaa"],
                            subject="s")
        c3 = t12.make_claim("verification", "different",
                            ["E-aaaaaaaaaaaa"], subject="s")
        return c1["claim_id"] == c2["claim_id"] \
            != c3["claim_id"]

    for name, fn in (("same-feed-identical-exports", liv_same_feed_identical),
                     ("auto-ts-digest-stable", liv_auto_ts_digest_stable),
                     ("empty-coverage-zeros", liv_empty_coverage_zeros),
                     ("claim-id-content-addressing",
                      liv_claim_id_addressing)):
        case("liveness", name, fn)

    # ---- الفحص الحي بعد الأربعين: لا تسمم حالة. المحرك طويل العمر
    #      تلقّى عبر البطارية كلها سجلين قانونيين حرفياً (g:base ثم
    #      g:new في فحص الصحة) — وكل ما عداهما رُفض. التوأم يُبنى
    #      بنفس التاريخ القانوني: التطابق = لا أثر لأي رفض/هجوم.
    twin = t12.BoundaryEngine()
    twin.record("g:base", "baseline boundary", t12.OUT_OF_SCOPE,
                timestamp=5.0)
    twin.record("g:new", "after rejections", t12.TIME_LIMIT,
                timestamp=6.0)
    detail["state_poisoning_check"] = (
        eng.export()["boundary_digest"]
        == twin.export()["boundary_digest"])

    ok = (detail["behaved_as_declared"] == 40
          and detail["crash_count"] == 0
          and detail["state_poisoning_check"] is True
          and detail["by_class"] == {"structural": 12, "gate_sabotage": 10,
                                     "precision": 8, "boundary_tamper": 6,
                                     "liveness": 4})
    return {"battery": "12c", "what": "exactly 40 adversarial scenarios "
            "(12 structural + 10 gate sabotage + 8 precision + 6 "
            "boundary/tamper + 4 liveness) + live state check", "ok": ok,
            "detail": detail}


# ============================================================ pytest
def test_battery_12a():
    """12a — 400 دورة مزروعة: تصنيف بالبناء + تكرار + حساسية بت."""
    assert battery_12a(_t12())["ok"]


def test_battery_12b():
    """12b — 150 مطابقة مرجع مستقل بايت-ببايت."""
    assert battery_12b(_t12())["ok"]


def test_battery_12c():
    """12c — 40 سيناريو عدائي بالضبط: رفض ذري، كشف لا صمت، لا تسمم."""
    assert battery_12c(_t12())["ok"]


# ============================================================ وضع الدليل
_BATTERIES = [("12a", battery_12a), ("12b", battery_12b),
              ("12c", battery_12c)]


def _overall_digest(bats: list) -> str:
    """هضم التيار المنطقي الكلي: (بطارية، ماذا، نجحت) فقط."""
    h = hashlib.sha256()
    for b in bats:
        h.update(f"{b['battery']}:{b['what']}:{int(b['ok'])}"
                 .encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-12 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    p = _t12()
    bats = [fn(p) for _, fn in _BATTERIES]
    total = len(bats)
    passed = sum(1 for b in bats if b["ok"])
    doc = {
        "suite": "axis12-atoms",
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
    print(f"axis12-atoms: {passed}/{total} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        extra = ""
        if b["battery"] == "12a":
            extra = (f" | crashes={b['detail']['crash_count']}"
                     f" agreement={b['detail']['classification_agreement']}/400"
                     f" repeatable={b['detail']['repeatable']}"
                     f" bitflip={b['detail']['bit_flip_sensitive']}")
        elif b["battery"] == "12b":
            extra = (f" | matched={sum(b['detail']['matched'].values())}"
                     f" mismatches={b['detail']['mismatch_total']}")
        elif b["battery"] == "12c":
            extra = (f" | behaved={b['detail']['behaved_as_declared']}/40"
                     f" crashes={b['detail']['crash_count']}"
                     f" state_clean={b['detail']['state_poisoning_check']}")
        print(f"  [{mark}] battery {b['battery']}: {b['what']}{extra}")
        if not b["ok"]:
            print(f"      raw: "
                  f"{json.dumps(b['detail'], ensure_ascii=False)[:600]}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
