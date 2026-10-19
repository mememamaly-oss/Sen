#!/usr/bin/env python3
"""SENTINEL Axis-7 suite — القياس والمؤشرات (Measurement & Metrics).

PROVENANCE (معلنة بأمانة، مقدَّمة):
- جدول الحالات أدناه هو الجدول الحرفي للمشرف من أمر البناء
  2026-10-19 («أمر بناء المحاور 7 و8 و11 و12 — بوابة خمسية لكل محور»).
  هذا هو جدول-H07 المعتمد؛ لا اشتقاق — الحالات الأربعة عشر مسجَّلة
  بنصها وتوكيداتها كما وردت، وكل تعليل مقتبس من نص الأمر.
- كل حالة تستورد sentinel.metrics داخل جسمها (وليس على مستوى الوحدة)
  حتى تكون المحطة الحمراء 0/14 بنمط فشل واحد حرفياً:
  ModuleNotFoundError: No module named 'sentinel.metrics'.
- جناح مستقل، غير مُسجَّل في @case — عقد النواة 227×19=4313 لا يُمس
  بالبناء (نمط المحاور 1/2/3/4/10 المعاد).
- انضباط الهضم: التيار المنطقي فقط (اسم الحالة، نجحت؟) — أزمنة الحائط
  تُسجَّل في dur_s ولا تدخل الهضم أبداً (انضباط المحور 11).

جدول الحالات (حرفياً من أمر المشرف — لا حالة بلا عقد):
  H07_01 — تسجيل مقياس وقراءته:
             assert value == recorded
  H07_02 — تطبيع min-max على [0,1]:
             assert 0.0 <= normalized <= 1.0
             assert min_val → 0.0، max_val → 1.0
  H07_03 — تطبيع Z-score:
             assert abs(mean(normalized)) < 1e-10
             assert abs(std(normalized) - 1.0) < 1e-10
  H07_04 — GPI بأوزان AHP:
             assert abs(gpi - expected) < 1e-10
             assert sum(weights) == 1.0
  H07_05 — أوزان AHP لا تجمع لـ1 → رفض:
             assert raises ValueError
  H07_06 — ARIMA(1,0,0) على سلسلة AR:
             assert abs(forecast_error) < 0.05
  H07_07 — ANOVA على 3 مجموعات مختلفة:
             assert F > F_critical
             assert p_value < 0.05
  H07_08 — ANOVA على 3 مجموعات متطابقة:
             assert F < 1.0
  H07_09 — t-test بمتوسط معروف:
             assert p_value matches scipy reference
  H07_10 — Spearman على ترتيب معكوس:
             assert abs(rho - (-1.0)) < 1e-10
  H07_11 — TTF/TTE/TTT/TTO تُسجَّل وتُجمَّع:
             assert all metrics present in report
  H07_12 — CC معامل التغطية = مثبت/معلن:
             assert CC == verified/declared
             assert CC <= 1.0
  H07_13 — SI مؤشر التخفي في [0,1]:
             assert 0.0 <= SI <= 1.0
  H07_14 — تقرير يحوي "ما لم يُقس" صراحة:
             assert "unmeasured" in report
             assert len(unmeasured) >= 0

ملاحظات الصدق (العقود المفسَّرة — مُعلنة لا مخفية):
  N1 (H07_06) — ARIMA(1,0,0) = AR(1) بثابت: x_t = c + φ·x_{t-1} + ε.
      التقدير بمربعات الصغرى الشرطية (OLS مغلق على المعادلتين)،
      والتنبؤ = ĉ + φ̂·x_n. forecast_error يُقاس مرتين: مقابل المتوسط
      الشرطي الحقيقي φ·x_n (خطأ التقدير) ومقابل القيمة المحقَّقة
      التالية (خطأ التقدير + الابتكار σ=0.01 → هامش 5σ تحت 0.05).
  N2 (H07_04) — أوزان AHP من المصفوفة التبادلية عبر المتجه الذاتي
      الرئيسي (تربيع قوة مع بداية منتظمة — حتمي)، والمصفوفة المتسقة
      3×3 المختارة لها جواب يدوي مضبوط: أوزان (4/7, 2/7, 1/7).
      نسبة الاتساق CR خارج هذا العقد (الأمر لم يطلبها — لا ن claim).
  N3 (H07_08) — «مجموعات متطابقة» قُرئت حرفياً: نفس القيم في
      المجموعات الثلاث → SSB = 0 → العرف المعلن F := 0.0 وp := 1.0
      (0/0 غير معرَّف؛ الرفض الذري هنا يكسر التوكيد الحرفي F < 1.0،
      فالعرف المعلن هو الأمانة). ويُضاف فحص ثانٍ: ثلاث مجموعات من
      التوزيع نفسه (عينات مستقلة ببذرة) → غير معنوي إحصائياً
      (F < F_critical وp > 0.05) — هذا هو المعنى الإحصائي للمطابقة.
  N4 (H07_09/3b) — المحرك نقي stdlib: قيم p عبر بيتا الناقصة
      المنظَّمة ( Continued fraction ). scipy مرجع خارجي في
      الاختبارات فقط — لا يستورده المحرك أبداً؛ التطابق ضمن 1e-9.
  N5 (H07_11) — تعريفات TTF/TTE/TTT/TTO المعلنة (الأمر سمّى الرموز
      ولم يعرّفها): TTF = زمن أول نتيجة موثَّقة منذ البدء،
      TTE = زمن أول دليل مُلتقط منذ البدء، TTO = زمن اكتمال الحكم
      النهائي منذ البدء، TTT = إجمالي زمن التشغيل. ساعة رتيبة
      (time.monotonic) لا حائطية.
  N6 (H07_12/13) — CC = verified/declared (رفض ذري لو verified >
      declared أو declared = 0). SI = 1 - detected/total (رفض ذري
      لو detected > total أو total = 0). كلاهما في [0,1] بالبناء.
  N7 (عام) — كل مدخل غير رقمي أو NaN/Inf أو فارغ أو متنافر الحدود
      يُرفض ذرياً بـ ValueError قبل أي حساب (validation-before-
      mutation)؛ القيم المنطقية (bool) مرفوضة حيث يُشترط رقم رغم
      أنها صنو int في بايثون — قياس «صحيح/خطأ» ليس قياساً.

عقد الواجهة المطلوب من sentinel.metrics في M2 (ما تستورده هذه البطارية):
  Registry    : MetricRegistry (record/get/names)
  Normalize   : minmax_normalize(values, lo=None, hi=None),
                zscore_normalize(values)
  Index       : ahp_weights(matrix), gpi(indicators, weights)
  Forecast    : arima100_fit(series) -> (phi, c),
                arima100_forecast(series) -> float
  Stats       : anova_one_way(groups, alpha=0.05) -> dict,
                ttest_1samp(sample, popmean) -> dict,
                spearman_rho(x, y) -> float
  Timing      : TimingTracker (mark_start/mark_first_evidence/
                mark_first_finding/mark_outcome/mark_end/report)
  Coeffs      : coverage_coefficient(verified, declared),
                stealth_index(total_requests, detected)
  Report      : build_measurement_report(measured, unmeasured)

Usage:
  python3 -m pytest tests/test_axis7_metrics.py --tb=short -q
  python3 tests/test_axis7_metrics.py --out results/axis7/axis7_RED.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _metrics():
    """هدف M2. حتى وجود sentinel/metrics.py كل حالة تفشل RED بالنمط
    الواحد: ModuleNotFoundError: No module named 'sentinel.metrics'."""
    import sentinel.metrics as metrics
    return metrics


# ============================================================ H07_01
def test_H07_01():
    """H07_01 — تسجيل مقياس وقراءته: assert value == recorded."""
    m = _metrics()
    reg = m.MetricRegistry()
    reg.record("http_errors", 42)
    reg.record("mean_rps", 123.5, unit="req/s")
    reg.record("verified_findings", 7, unit="count", note="strong-class")
    # القيمة المسجَّلة تُقرأ كما هي — بلا تحويل ولا تقريب
    assert reg.get("http_errors") == 42, "قراءة القيمة الصحيحة مخالفة"
    assert reg.get("mean_rps") == 123.5, "قراءة العدد العشري مخالفة"
    assert reg.get("verified_findings") == 7, "قراءة القيمة المسجَّلة مخالفة"
    # والوحدات/الملاحظات تُحفظ كسياق لا كقيمة
    meta = reg.meta("mean_rps")
    assert meta["unit"] == "req/s", "سياق الوحدة ضائع"
    # إعادة التسجيل بنفس الاسم: آخر قيمة تسود (سجل القياس لا يراكم)
    reg.record("http_errors", 43)
    assert reg.get("http_errors") == 43, "آخر تسجيل لا يسود"
    assert set(reg.names()) >= {"http_errors", "mean_rps", "verified_findings"}


# ============================================================ H07_02
def test_H07_02():
    """H07_02 — تطبيع min-max على [0,1]:
    assert 0.0 <= normalized <= 1.0؛ assert min_val → 0.0، max_val → 1.0."""
    m = _metrics()
    vals = [10.0, 20.0, 30.0, 40.0, 50.0]
    out = m.minmax_normalize(vals)
    assert len(out) == len(vals), "طول المخرج مخالف لطول المدخل"
    for v in out:
        assert 0.0 <= v <= 1.0, f"قيمة خارج [0,1]: {v}"
    assert out[0] == 0.0, f"الحد الأدنى يجب أن يطبَّع إلى 0.0 (حصل {out[0]})"
    assert out[-1] == 1.0, f"الحد الأقصى يجب أن يطبَّع إلى 1.0 (حصل {out[-1]})"
    assert out[2] == 0.5, f"الوسط يجب أن يطبَّع إلى 0.5 (حصل {out[2]})"
    # بحدود صريحة معلَنة لا مشتقة من العينة
    out2 = m.minmax_normalize([5.0], lo=0.0, hi=10.0)
    assert out2 == [0.5], f"تطبيع بحدود صريحة مخالف: {out2}"
    # قيمة عند الحد الأدنى المعلن → 0.0 وعند الأقصى → 1.0
    out3 = m.minmax_normalize([0.0, 5.0, 10.0], lo=0.0, hi=10.0)
    assert out3[0] == 0.0 and out3[2] == 1.0, "الحدود الصريحة لا تُطبَّع للطرفين"


# ============================================================ H07_03
def test_H07_03():
    """H07_03 — تطبيع Z-score:
    assert abs(mean(normalized)) < 1e-10؛ assert abs(std - 1.0) < 1e-10."""
    m = _metrics()
    rng = random.Random(7003)
    vals = [rng.gauss(50.0, 7.0) for _ in range(60)]
    out = m.zscore_normalize(vals)
    assert len(out) == len(vals), "طول المخرج مخالف"
    mean = sum(out) / len(out)
    var = sum((v - mean) ** 2 for v in out) / len(out)  # انحراف مجتمعي ddof=0
    std = math.sqrt(var)
    assert abs(mean) < 1e-10, f"متوسط المطبَّع {mean} لا يطابق 0"
    assert abs(std - 1.0) < 1e-10, f"انحراف المطبَّع {std} لا يطابق 1"
    # إزاحة وتوسيع المدخلات لا يغيّران الناتج (ثباتية التحويل التآلفي)
    shifted = [v * 1000.0 + 3.5 for v in vals]
    out2 = m.zscore_normalize(shifted)
    for a, b in zip(out, out2):
        assert abs(a - b) < 1e-9, "Z-score ليس ثابتاً تحت التحويل التآلفي"


# ============================================================ H07_04
def test_H07_04():
    """H07_04 — GPI بأوزان AHP:
    assert abs(gpi - expected) < 1e-10؛ assert sum(weights) == 1.0."""
    m = _metrics()
    # مصفوفة تبادلية متسقة 3×3: A:B=2، A:C=4، B:C=2
    # → المتجه الذاتي الرئيسي (4/7, 2/7, 1/7) — محسوب يدوياً
    matrix = [
        [1.0, 2.0, 4.0],
        [0.5, 1.0, 2.0],
        [0.25, 0.5, 1.0],
    ]
    w = m.ahp_weights(matrix)
    expected_w = [4.0 / 7.0, 2.0 / 7.0, 1.0 / 7.0]
    assert len(w) == 3, "عدد الأوزان مخالف لبُعد المصفوفة"
    assert abs(sum(w) - 1.0) < 1e-12, f"مجموع الأوزان {sum(w)} لا يطابق 1.0"
    for got, exp in zip(w, expected_w):
        assert abs(got - exp) < 1e-10, f"وزن AHP {got} لا يطابق اليدوي {exp}"
    # GPI = مجموع مرجَّح للمؤشرات المطبَّعة [0,1] — الجواب اليدوي 5/7
    indicators = [1.0, 0.5, 0.0]
    value = m.gpi(indicators, w)
    expected_gpi = 4.0 / 7.0 * 1.0 + 2.0 / 7.0 * 0.5 + 1.0 / 7.0 * 0.0
    assert abs(value - expected_gpi) < 1e-10, \
        f"GPI {value} لا يطابق المتوقع اليدوي {expected_gpi}"
    # مجموع الأوزان == 1.0 بالضبط البنائي (توكيد الأمر الثاني)
    assert sum(w) == 1.0 or abs(sum(w) - 1.0) < 1e-15, \
        "مجموع الأوزان ليس 1.0 حتى ضمن أدق عتبة"


# ============================================================ H07_05
def test_H07_05():
    """H07_05 — أوزان AHP لا تجمع لـ1 → رفض: assert raises ValueError."""
    m = _metrics()
    indicators = [0.6, 0.4, 0.2]
    # ناقصة المجموع (0.9) → رفض ذري
    try:
        m.gpi(indicators, [0.5, 0.3, 0.1])
        raise AssertionError("أوزان مجموعها 0.9 كان يجب أن تُرفض بـ ValueError")
    except ValueError:
        pass
    # زائدة المجموع (1.2) → رفض ذري
    try:
        m.gpi(indicators, [0.5, 0.4, 0.3])
        raise AssertionError("أوزان مجموعها 1.2 كان يجب أن تُرفض بـ ValueError")
    except ValueError:
        pass
    # صحيحة المجموع (1.0) → لا رفض (التحكم الإيجابي للتوكد أن الرفض
    # سببه المجموع لا شيء آخر)
    v = m.gpi(indicators, [0.5, 0.3, 0.2])
    assert abs(v - (0.5 * 0.6 + 0.3 * 0.4 + 0.2 * 0.2)) < 1e-12, \
        "الأوزان الصحيحة يجب أن تُقبل وتحسب"


# ============================================================ H07_06
def test_H07_06():
    """H07_06 — ARIMA(1,0,0) على سلسلة AR: assert abs(forecast_error) < 0.05."""
    m = _metrics()
    # سلسلة AR(1) حقيقية: x_t = 0 + 0.8·x_{t-1} + ε، σ=0.01، بذرة ثابتة
    rng = random.Random(4207)
    series = [1.0]
    for _ in range(3000):
        series.append(0.8 * series[-1] + rng.gauss(0.0, 0.01))
    phi, c = m.arima100_fit(series)
    f = m.arima100_forecast(series)
    # (أ) خطأ التنبؤ مقابل المتوسط الشرطي الحقيقي 0.8·x_n
    true_cond_mean = 0.8 * series[-1]
    assert abs(f - true_cond_mean) < 0.05, \
        f"خطأ التنبؤ مقابل المتوسط الشرطي {abs(f - true_cond_mean)} >= 0.05"
    # (ب) خطأ التنبؤ مقابل القيمة المحقَّقة التالية (σ=0.01 → هامش 5σ)
    realized_next = 0.8 * series[-1] + rng.gauss(0.0, 0.01)
    forecast_error = abs(f - realized_next)
    assert forecast_error < 0.05, \
        f"خطأ التنبؤ مقابل المحقَّق {forecast_error} >= 0.05"
    # (ج) استرجاع المعامل الحقيقي φ=0.8 (تقدير OLS على 3000 نقطة)
    assert abs(phi - 0.8) < 0.05, f"استرجاع φ {phi} بعيد عن 0.8"
    assert abs(c - 0.0) < 0.05, f"الثابت المقدَّر {c} بعيد عن 0"


# ============================================================ H07_07
def test_H07_07():
    """H07_07 — ANOVA على 3 مجموعات مختلفة:
    assert F > F_critical؛ assert p_value < 0.05."""
    m = _metrics()
    rng = random.Random(7007)
    # ثلاث مجموعات متباعدة الأوساط بوضوح (10/20/30) وتشتت 1.0
    g1 = [rng.gauss(10.0, 1.0) for _ in range(40)]
    g2 = [rng.gauss(20.0, 1.0) for _ in range(40)]
    g3 = [rng.gauss(30.0, 1.0) for _ in range(40)]
    res = m.anova_one_way([g1, g2, g3])
    F, p = res["F"], res["p_value"]
    Fcrit = res["F_critical"]
    assert F > Fcrit, f"F={F} لا يتجاوز الحد الحرج {Fcrit} — الفرق يجب أن يُكشف"
    assert p < 0.05, f"p={p} >= 0.05 — الفرق يجب أن يكون معنوياً"
    # درجات الحرية الصحيحة: k-1=2 و N-k=117
    assert res["df1"] == 2 and res["df2"] == 117, "درجات الحرية مخالفة"


# ============================================================ H07_08
def test_H07_08():
    """H07_08 — ANOVA على 3 مجموعات متطابقة: assert F < 1.0."""
    m = _metrics()
    # (أ) القراءة الحرفية: نفس القيم في المجموعات الثلاث
    vals = [12.5, 13.0, 12.0, 13.5, 12.25, 13.75]
    res = m.anova_one_way([list(vals), list(vals), list(vals)])
    assert res["F"] < 1.0, \
        f"مجموعات متطابقة حرفياً تعطي F={res['F']} >= 1.0 (العرف المعلن: 0.0)"
    assert res["F"] == 0.0, "SSB=0 يجب أن يعطي F=0.0 بالعرف المعلن"
    assert res["p_value"] == 1.0, "F=0 يجب أن يعطي p=1.0"
    # (ب) المعنى الإحصائي: ثلاث عينات من التوزيع نفسه (بذرة مستقلة)
    rng = random.Random(7008)
    same = lambda: [rng.gauss(10.0, 2.0) for _ in range(35)]
    res2 = m.anova_one_way([same(), same(), same()])
    assert res2["F"] < res2["F_critical"], \
        f"عينات من التوزيع نفسه: F={res2['F']} >= الحرج {res2['F_critical']}"
    assert res2["p_value"] > 0.05, \
        f"عينات من التوزيع نفسه: p={res2['p_value']} <= 0.05 (خطأ نوع-I)"


# ============================================================ H07_09
def test_H07_09():
    """H07_09 — t-test بمتوسط معروف:
    assert p_value matches scipy reference."""
    m = _metrics()
    from scipy import stats as scipy_stats  # مرجع خارجي — لا يستورده المحرك
    rng = random.Random(7009)
    sample = [rng.gauss(10.0, 2.0) for _ in range(50)]
    ours = m.ttest_1samp(sample, 10.0)
    ref = scipy_stats.ttest_1samp(sample, 10.0)
    assert abs(ours["t"] - float(ref.statistic)) < 1e-9, \
        f"t={ours['t']} لا يطابق scipy {ref.statistic}"
    assert abs(ours["p_value"] - float(ref.pvalue)) < 1e-9, \
        f"p={ours['p_value']} لا يطابق scipy {ref.pvalue}"
    # وإزاحة المتوسط المعروف عن الحقيقة → رفض قوي متسق مع المرجع
    ours2 = m.ttest_1samp(sample, 10.9)
    ref2 = scipy_stats.ttest_1samp(sample, 10.9)
    assert abs(ours2["p_value"] - float(ref2.pvalue)) < 1e-9, \
        "p للمتوسط المغاير لا يطابق scipy"
    assert ours2["p_value"] < 0.05, "إزاحة 0.45σ (n=50) يجب أن تُكشف"


# ============================================================ H07_10
def test_H07_10():
    """H07_10 — Spearman على ترتيب معكوس:
    assert abs(rho - (-1.0)) < 1e-10."""
    m = _metrics()
    x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    y = list(reversed(x))  # ترتيب معكوس تماماً → rho = -1
    rho = m.spearman_rho(x, y)
    assert abs(rho - (-1.0)) < 1e-10, f"rho={rho} لا يطابق -1.0"
    # التحكم الإيجابي: نفس الترتيب → +1
    assert abs(m.spearman_rho(x, x) - 1.0) < 1e-10, "نفس الترتيب يجب أن يعطي +1"
    # ترتيب خطي تام مقابل خطي معكوس بمقاييس مختلفة (رُتَب فقط تهم)
    a = [0.1, 0.2, 0.3, 0.4, 0.5]
    b = [50.0, 40.0, 30.0, 20.0, 10.0]
    assert abs(m.spearman_rho(a, b) - (-1.0)) < 1e-10, \
        "معكوس خطي بمقاييس مختلفة يجب أن يعطي -1.0"


# ============================================================ H07_11
def test_H07_11():
    """H07_11 — TTF/TTE/TTT/TTO تُسجَّل وتُجمَّع:
    assert all metrics present in report."""
    m = _metrics()
    tt = m.TimingTracker()
    tt.mark_start()
    tt.mark_first_evidence()
    tt.mark_first_finding()
    tt.mark_outcome()
    tt.mark_end()
    rep = tt.report()
    # المؤشرات الأربعة حاضرة جميعها في التقرير المجمَّع — هذا عقد الأمر
    for key in ("TTF", "TTE", "TTT", "TTO"):
        assert key in rep, f"المؤشر {key} غائب عن التقرير المجمَّع"
        assert isinstance(rep[key], float) and rep[key] >= 0.0, \
            f"المؤشر {key} ليس زمناً صالحاً: {rep[key]!r}"
    # الترتيب الفيزيائي المعلن: دليل ← نتيجة ← حكم ← نهاية
    assert rep["TTE"] <= rep["TTF"] + 1e-12, "TTE بعد TTF — الدليل يسبق النتيجة"
    assert rep["TTF"] <= rep["TTO"] + 1e-12, "TTF بعد TTO — النتيجة تسبق الحكم"
    assert rep["TTO"] <= rep["TTT"] + 1e-12, "TTO بعد TTT — الحكم يسبق النهاية"
    # علامات متعددة لنفس الحدث: الأولى تسود (idempotent-first)
    tt2 = m.TimingTracker()
    tt2.mark_start()
    tt2.mark_first_finding()
    tt2.mark_first_finding()  # ثانية لا تغيّر شيئاً
    tt2.mark_end()
    rep2 = tt2.report()
    assert rep2["TTF"] is not None and rep2["TTE"] is None, \
        "أول علامة يجب أن تسود والغائبة تبقى None بصراحة"


# ============================================================ H07_12
def test_H07_12():
    """H07_12 — CC معامل التغطية = مثبت/معلن:
    assert CC == verified/declared؛ assert CC <= 1.0."""
    m = _metrics()
    cc = m.coverage_coefficient(verified=8, declared=10)
    assert cc == 8 / 10, f"CC={cc} لا يطابق verified/declared=0.8"
    assert cc <= 1.0, "CC تجاوز 1.0"
    # تغطية كاملة → 1.0 بالضبط
    assert m.coverage_coefficient(10, 10) == 1.0, "التغطية الكاملة يجب أن تكون 1.0"
    # تغطية معدومة → 0.0 بالضبط
    assert m.coverage_coefficient(0, 10) == 0.0, "التغطية المعدومة يجب أن تكون 0.0"
    # مقياس كسري عشري: النسبة تُعاد كما هي بلا تقريب
    cc3 = m.coverage_coefficient(verified=7, declared=9)
    assert cc3 == 7 / 9 and cc3 <= 1.0, "النسبة الكسرية يجب أن تُعاد كما هي"


# ============================================================ H07_13
def test_H07_13():
    """H07_13 — SI مؤشر التخفي في [0,1]:
    assert 0.0 <= SI <= 1.0."""
    m = _metrics()
    si = m.stealth_index(total_requests=1000, detected=250)
    assert 0.0 <= si <= 1.0, f"SI={si} خارج [0,1]"
    assert si == 0.75, f"SI={si} لا يطابق 1 - 250/1000"
    # الأطراف: لا كشف → 1.0؛ كشف كامل → 0.0
    assert m.stealth_index(1000, 0) == 1.0, "لا كشف يجب أن يعطي SI=1.0"
    assert m.stealth_index(1000, 1000) == 0.0, "كشف كامل يجب أن يعطي SI=0.0"
    # قيم وسيطة على شبكة كثيفة — كلها داخل [0,1]
    for detected in (1, 100, 500, 999):
        v = m.stealth_index(1000, detected)
        assert 0.0 <= v <= 1.0, f"SI({detected}/1000)={v} خارج [0,1]"


# ============================================================ H07_14
def test_H07_14():
    """H07_14 — تقرير يحوي "ما لم يُقس" صراحة:
    assert "unmeasured" in report؛ assert len(unmeasured) >= 0."""
    m = _metrics()
    measured = {"TTF": 12.5, "TTE": 3.2, "verified": 8, "declared": 10}
    unmeasured = [
        "تغطية سطح المصادقة — لم تُمسح (خارج النطاق المعلن)",
        "زمن الاستجابة تحت حمل — لم يُقس (لا مولِّد حمل)",
    ]
    report = m.build_measurement_report(measured=measured,
                                        unmeasured=unmeasured)
    assert "unmeasured" in report, "قسم «ما لم يُقس» غائب عن التقرير"
    assert report["unmeasured"] == unmeasured, \
        "قسم «ما لم يُقس» لا يحفظ البنود كما هي"
    assert len(report["unmeasured"]) >= 0 and len(report["unmeasured"]) == 2
    assert report["measured"] == measured, "القياسات المقيسة ضائعة من التقرير"
    # وبلا بنود غير مقيسة: القسم يبقى حاضراً صراحة (فارغاً) — لا يختفي
    report2 = m.build_measurement_report(measured={"TTF": 1.0},
                                         unmeasured=[])
    assert "unmeasured" in report2, \
        "قسم «ما لم يُقس» يجب أن يبقى حاضراً حتى فارغاً"
    assert len(report2["unmeasured"]) == 0 and report2["unmeasured"] == []


# ============================================================ وضع الدليل
def _run_all() -> list[dict]:
    """تشغيل كل الحالات بترتيبها مع التقاط النتائج — التيار المنطقي فقط."""
    names = [n for n in sorted(globals())
             if n.startswith("test_H07_") and callable(globals()[n])]
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
    خارج الهضم (انضباط المحور 11)."""
    h = hashlib.sha256()
    for r in results:
        h.update(f"{r['name']}:{int(r['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-7 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    doc = {
        "suite": "axis7-metrics",
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
    print(f"axis7: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['name']}"
              + ("" if r["ok"] else f"  {r['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
