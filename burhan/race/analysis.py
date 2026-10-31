#!/usr/bin/env python3
"""burhan/race/analysis.py — تحليل التوقيتات وكشف السباق (AXIS-17).

العقد الحرفي المأمور (ORD-002، الاختباران 3 و4)، منفذًا كما كتبه
المشرف وموثقًا هنا حرفيًا:
  - العينة: {"elapsed": float, "parameter": str, "mutating": bool}
  - التجميع: العينات المعدِّلة (mutating=True) تُجمع حسب parameter؛
    المجموعة القابلة للقرار: حجمها >= 2 (طلبان فأكثر يعدلان نفس
    المعامل = يغيران نفس المورد).
  - القرار: إذا كان التباين الزمني لمجموعة معدِّلة < threshold
    (الافتراضي 0.005 ثانية) -> race_detected = True؛ وإلا False.
  - لا موجب كاذب: معاملات مختلفة لا تشارك موردًا => لا توجد مجموعة
    قابلة للقرار => race_detected = False (الاختبار 4 حرفيًا).

كل عينة تمر بوابة التوقيتات أولًا (gates.validate_timing — ذرة 6):
السالب و> 1000 مرفوض قبل أي حساب ولا يلوث شيئًا.

التباين المستخدم: تبایین العينة ( unbiased، مقسوم n-1 عند n>1 )
على القيم المعتمدة للمجموعة — معلن هنا لأن العقد الحرفي لم يحدد؛
حدّ أمانة: أي تغيير في المقسوم يغير الحساب عند n الصغيرة.

قيد الوحدة (N2): stdlib فقط — لا استيراد؛ دوال نقية تمامًا؛
حتمية بالبناء (لا عشوائية، لا حالة).
"""
from __future__ import annotations

from . import gates


class RaceAnalysisError(ValueError):
    """استثناء تحليل المحور 17 — يُسجل في التقرير (القاعدة 5 من M2)."""


DEFAULT_THRESHOLD = 0.005          # الأمر الحرفي: < 0.005 ثانية
MIN_GROUP = 2                      # طلبان فأكثر معدِّلان لنفس المعامل


def _variance(values):
    """تباين العينة (unbiased) — دالة نقية؛ قائمة فارغة -> 0.0 معلنة."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / (n - 1)


def _admitted_samples(samples):
    """بوابة التوقيتات (ذرة 6) — ترفض المعطوب وتفصح عنه في النتيجة."""
    admitted, rejected = [], []
    for s in samples or []:
        if not isinstance(s, dict):
            raise RaceAnalysisError(f"sample must be dict, got {type(s).__name__}")
        elapsed = s.get("elapsed")
        parameter = s.get("parameter")
        mutating = bool(s.get("mutating", False))
        if parameter is None or str(parameter) == "":
            rejected.append({"sample": s, "why": "empty_parameter"})
            continue
        if not gates.validate_timing(elapsed):
            rejected.append({"sample": s, "why": "invalid_timing"})
            continue
        admitted.append({"elapsed": float(elapsed),
                         "parameter": str(parameter),
                         "mutating": mutating})
    return admitted, rejected


def analyze_timing(samples, *, threshold: float = DEFAULT_THRESHOLD) -> dict:
    """تحليل التوقيتات — العقد الحرفي المأمور (انظر docstring الوحدة).

    ترجع dict معلنًا:
      race_detected (bool), timing_variance (float),
      groups (int) عدد مجموعات معدِّلة قابلة للقرار,
      mutating_samples (int), admitted (int), rejected (list),
      notes (str) — كل القيم حتمية بلا حالة.
    """
    if not isinstance(threshold, (int, float)) or float(threshold) <= 0:
        raise RaceAnalysisError(f"threshold must be positive, got {threshold!r}")
    threshold = float(threshold)

    admitted, rejected = _admitted_samples(samples)

    # التجميع حسب parameter للمعدِّلات فقط
    groups = {}
    for s in admitted:
        if s["mutating"]:
            groups.setdefault(s["parameter"], []).append(s["elapsed"])

    deciding = {p: v for p, v in groups.items() if len(v) >= MIN_GROUP}

    race_detected = False
    best_variance = None
    winner = None
    for p, values in sorted(deciding.items()):      # ترتيب حتمي
        var = _variance(values)
        if best_variance is None or var < best_variance:
            best_variance, winner = var, p
        if var < threshold:
            race_detected = True

    # timing_variance المعلن: تباين أصغر مجموعة معدِّلة قابلة للقرار؛
    # وإن لم توجد: التباين الكلي لكل العينات المعتمدة (معلنة لا مقررة).
    if best_variance is None:
        overall = [s["elapsed"] for s in admitted]
        best_variance = _variance(overall)

    mutating_n = sum(1 for s in admitted if s["mutating"])
    notes = (f"threshold={threshold}; deciding_groups={len(deciding)}; "
             f"rule=mutating-group variance < threshold (ORD-002 literal)")
    if winner is not None:
        notes += f"; winner={winner}"

    return {
        "race_detected": race_detected,
        "timing_variance": float(best_variance),
        "groups": len(deciding),
        "mutating_samples": mutating_n,
        "admitted": len(admitted),
        "rejected": rejected,
        "notes": notes,
    }


def samples_from_results(results, *, parameter: str, mutating: bool = True):
    """بناء عينات تحليل من نتائج الإرسال الفعلية — دالة نقية.

    نتائج send_concurrent تحمل elapsed لكل طلب؛ هذه الدالة تحولها
    إلى عينات التحليل بنفس العقد (متسقة مع التكامل في integration).
    """
    out = []
    for r in results or []:
        out.append({"elapsed": r.get("elapsed", 0.0),
                    "parameter": parameter,
                    "mutating": mutating})
    return out
