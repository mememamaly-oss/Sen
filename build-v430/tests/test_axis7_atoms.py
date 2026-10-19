#!/usr/bin/env python3
"""SENTINEL Axis-7 — M3 ATOMS: البطاريات الإجبارية الثلاث (أمر المشرف 2026-10-19).

PROVENANCE والعقد (معلنة بأمانة، مقدَّمة):
- هذا الجناح ينفّذ بطاريات المحور 7 الحرفية من أمر المشرف 2026-10-19
  («M3 ATOMS للمحور 7 (3 بطاريات)») فوق sentinel/metrics.py (M2 GREEN
  عند eaf83cb) — لا تعديل في المحرك ولا لمس للنواة 227×19=4313
  (جناح مستقل، غير مُسجَّل في @case، كل بطارية تستورد sentinel.metrics
  داخل جسمها — نمط M1/M2).
- انضباط الهضم: التيار المنطقي فقط (battery, what, ok) — أزمنة الحائط
  تُسجَّل في detail ولا تدخل الهضم أبداً (انضباط المحور 11). القيم
  العددية في هضم 3a تُقرَّب إلى 6 منازل عشرية (استقرار عابر للمنصات)
  والبذور ثابتة بالبناء — لا عشوائية حرة.
- خط الإيقاف الحرفي: أي فشل يُلصق خاماً — لا إصلاح بلا إذن.

البطاريات (حرفياً من الأمر):
  3a — 500 سلسلة زمنية عشوائية:
       تطبيع + GPI + ARIMA → صفر انهيار،
       digest قابل للتكرار
  3b — 200 مجموعة إحصائية:
       ANOVA + t-test + Spearman →
       النتائج مطابقة لـ scipy reference
  3c — 50 سيناريو عدائي:
       أوزان سالبة، NaN، Inf، قسمة على صفر،
       سلاسل فارغة → رفض ذري، صفر انهيار

ملاحظات الصدق (الفروقات المُعلنة — لا مخفية):
  N1 (3a) — «عشوائية» تعني هنا مولَّدة ببذور ثابتة معلَنة (seed=100000+i):
      السلاسل عشوائية التوليد حتمية الإعادة — هذا بالضبط ما يجعل
      «digest قابل للتكرار» قابلاً للبرهان، لا ادعاءً. مؤشرات GPI من
      السلسلة المطبَّعة كسور إحصائية في [0,1] بالبناء (نسبة |z|≤1،
      نسبة z>0، نسبة z>1، نسبة z<-1) وأوزانها من مصفوفة AHP متسقة
      ثابتة 4×4 (جواب يدوي: 8/15، 4/15، 2/15، 1/15).
  N2 (3b) — scipy مرجع خارجي (يُستورد داخل البطارية لا في المحرك):
      مطابقة F/t/rho ضمن 1e-9 نسبية؛ وp ضمن 1e-9 مطلقة عندما
      p > 1e-3 وضمن 1e-6 نسبية دون ذلك (كلا التنفيذين يحسب الذيل من
      الجهة الصغرى — المقارنة النسبية هي ذات المعنى هناك). عينات
      Spearman مُكمَّمة عمداً (تقريب لعُشر) لتوليد متعادلات حقيقية
      تمرَّس على معالجة الروابط.
  N3 (3c) — التصنيف: كل الهجمات هنا PRECONDITION_FAILED بحسب فئات
      المحور-12/14 المعاينة (خرق عقد مدخل) — عدا فقدان السجل في
      MetricRegistry وهو عقد KeyError صريح. «صفر انهيار» يعني: لا
      استثناء من نوع غير معلَن، لا TypeError/AttributeError متسرباً،
      ولا تسمم حالة (فحص حي: فشل record لا يترك أثراً في السجل).

Usage:
  python3 -m pytest tests/test_axis7_atoms.py --tb=short -q
  python3 tests/test_axis7_atoms.py --out results/axis7/axis7_ATOMS.json
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
    import sentinel.metrics as metrics
    return metrics


# مصفوفة AHP ثابتة متسقة 4×4: الأوزان (8, 4, 2, 1)/15 — جواب يدوي
_AHP4 = [
    [1.0, 2.0, 4.0, 8.0],
    [0.5, 1.0, 2.0, 4.0],
    [0.25, 0.5, 1.0, 2.0],
    [0.125, 0.25, 0.5, 1.0],
]


def _series_pass(m, sid: int) -> dict:
    """مرور واحد كامل على سلسلة: توليد → تطبيع → GPI → ARIMA.

    أي استثناء هنا = انهيار (تُلتقط عند المستدعي وتُبلَّغ خاماً)."""
    rng = random.Random(100000 + sid)
    phi_t = rng.uniform(-0.95, 0.95)
    c_t = rng.uniform(-5.0, 5.0)
    sigma = rng.uniform(0.01, 0.5)
    n = rng.randint(50, 400)
    series = [rng.uniform(-3.0, 3.0)]
    for _ in range(n - 1):
        series.append(c_t + phi_t * series[-1] + rng.gauss(0.0, sigma))

    # التطبيع min-max: كل المخرجات في [0,1] والطرفان 0.0 و1.0
    mm = m.minmax_normalize(series)
    assert all(0.0 <= v <= 1.0 for v in mm), f"[3a s{sid}] minmax خارج [0,1]"
    assert min(mm) == 0.0 and max(mm) == 1.0, f"[3a s{sid}] أطراف minmax خاطئة"

    # التطبيع Z-score: متوسط 0 وانحراف 1 (ضمن 1e-10)
    zs = m.zscore_normalize(series)
    zmean = sum(zs) / len(zs)
    zstd = math.sqrt(sum((v - zmean) ** 2 for v in zs) / len(zs))
    assert abs(zmean) < 1e-10 and abs(zstd - 1.0) < 1e-10, \
        f"[3a s{sid}] Z-score غير معاير (mean={zmean}, std={zstd})"

    # GPI فوق مؤشرات-كسور من السلسلة المطبَّعة (كلها في [0,1] بالبناء)
    indicators = [
        sum(1 for v in zs if abs(v) <= 1.0) / len(zs),
        sum(1 for v in zs if v > 0.0) / len(zs),
        sum(1 for v in zs if v > 1.0) / len(zs),
        sum(1 for v in zs if v < -1.0) / len(zs),
    ]
    w = m.ahp_weights(_AHP4)
    g = m.gpi(indicators, w)
    assert 0.0 <= g <= 1.0, f"[3a s{sid}] GPI={g} خارج [0,1]"

    # ARIMA(1,0,0): ملاءمة + تنبؤ — قيم منتهية (لا انهيار ولا NaN)
    phi, c = m.arima100_fit(series)
    fc = m.arima100_forecast(series)
    assert math.isfinite(phi) and math.isfinite(c) and math.isfinite(fc), \
        f"[3a s{sid}] ARIMA أنتج غير منتهٍ: phi={phi}, c={c}, fc={fc}"

    return {"sid": sid, "mm": 1, "zs": 1, "gpi": round(g, 6),
            "phi": round(phi, 6), "fc": round(fc, 6)}


# ============================================================ البطارية 3a
def battery_3a(m) -> dict:
    """3a — 500 سلسلة زمنية عشوائية: تطبيع + GPI + ARIMA → صفر انهيار،
    digest قابل للتكرار (مروران مستقلان في نفس العملية → هضم متطابق)."""
    t0 = time.perf_counter()
    crashes = []
    records1: list[dict] = []
    for sid in range(500):
        try:
            records1.append(_series_pass(m, sid))
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
            crashes.append({"sid": sid, "error": repr(exc)})
    # المرور الثاني: نفس البذور → نفس السجلات حرفياً (قابلية التكرار)
    records2: list[dict] = []
    for sid in range(500):
        try:
            records2.append(_series_pass(m, sid))
        except BaseException as exc:  # noqa: BLE001
            crashes.append({"sid": sid, "error": repr(exc), "pass": 2})

    def _dig(recs: list[dict]) -> str:
        h = hashlib.sha256()
        for r in recs:
            h.update(f"{r['sid']}:{r['mm']}:{r['zs']}:{r['gpi']:.6f}:"
                     f"{r['phi']:.6f}:{r['fc']:.6f}".encode())
            h.update(b"\n")
        return h.hexdigest()

    d1, d2 = _dig(records1), _dig(records2)
    ok = (len(crashes) == 0 and len(records1) == 500
          and len(records2) == 500 and d1 == d2)
    return {
        "battery": "3a", "what": "500-series normalize+GPI+ARIMA",
        "ok": ok,
        "detail": {
            "series": 500, "passes": 2, "crashes": crashes,
            "digest_pass1": d1, "digest_pass2": d2,
            "repeatable": d1 == d2,
            "sample_records": records1[:3],
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ البطارية 3b
def _p_close(ours: float, ref: float) -> bool:
    """مقارنة p مع المرجع (N2): مطلقة فوق 1e-3، نسبية 1e-6 دونها."""
    if ref > 1e-3:
        return abs(ours - ref) < 1e-9
    return ref > 0.0 and ours > 0.0 and abs(ours / ref - 1.0) < 1e-6


def battery_3b(m) -> dict:
    """3b — 200 مجموعة إحصائية: ANOVA + t-test + Spearman → مطابقة scipy."""
    from scipy import stats as scipy_stats  # مرجع خارجي — لا يستورده المحرك
    t0 = time.perf_counter()
    mismatches = []
    counts = {"anova": 0, "ttest": 0, "spearman": 0}
    for gid in range(200):
        rng = random.Random(200000 + gid)
        # ANOVA: k مجموعات بمواقع وتباعدهات عشوائية
        k = rng.randint(3, 5)
        base = rng.uniform(-10.0, 10.0)
        spread = rng.uniform(0.5, 8.0)
        sigma = rng.uniform(0.5, 3.0)
        groups = [[rng.gauss(base + spread * j, sigma)
                   for _ in range(rng.randint(15, 60))] for j in range(k)]
        try:
            ours = m.anova_one_way(groups)
            ref = scipy_stats.f_oneway(*groups)
            if (abs(ours["F"] - float(ref.statistic)) > 1e-9 * max(1.0, abs(float(ref.statistic)))
                    or not _p_close(ours["p_value"], float(ref.pvalue))):
                mismatches.append({"gid": gid, "kind": "anova",
                                   "ours_F": ours["F"], "ref_F": float(ref.statistic),
                                   "ours_p": ours["p_value"], "ref_p": float(ref.pvalue)})
            else:
                counts["anova"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"gid": gid, "kind": "anova-crash", "error": repr(exc)})

        # t-test: عينة ضد متوسط معروف (صحيح أحياناً ومزاح أحياناً)
        n_t = rng.randint(20, 80)
        mu = rng.uniform(-5.0, 5.0)
        s_t = rng.uniform(0.5, 3.0)
        sample = [rng.gauss(mu, s_t) for _ in range(n_t)]
        popmean = mu + (rng.choice((0.0, 0.5, -0.5)) * s_t)
        try:
            ours_t = m.ttest_1samp(sample, popmean)
            ref_t = scipy_stats.ttest_1samp(sample, popmean)
            if (abs(ours_t["t"] - float(ref_t.statistic)) > 1e-9
                    or not _p_close(ours_t["p_value"], float(ref_t.pvalue))):
                mismatches.append({"gid": gid, "kind": "ttest",
                                   "ours_t": ours_t["t"], "ref_t": float(ref_t.statistic),
                                   "ours_p": ours_t["p_value"], "ref_p": float(ref_t.pvalue)})
            else:
                counts["ttest"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"gid": gid, "kind": "ttest-crash", "error": repr(exc)})

        # Spearman: كمِّم عمداً لتوليد متعادلات + ضجيج رتبي
        n_s = rng.randint(20, 80)
        xs = [round(rng.uniform(0.0, 10.0), 1) for _ in range(n_s)]
        ys = [round(10.0 - x + rng.gauss(0.0, 1.5), 1) for x in xs]
        try:
            ours_r = m.spearman_rho(xs, ys)
            ref_r = scipy_stats.spearmanr(xs, ys)
            if abs(ours_r - float(ref_r.statistic)) > 1e-9:
                mismatches.append({"gid": gid, "kind": "spearman",
                                   "ours": ours_r, "ref": float(ref_r.statistic)})
            else:
                counts["spearman"] += 1
        except BaseException as exc:  # noqa: BLE001
            mismatches.append({"gid": gid, "kind": "spearman-crash", "error": repr(exc)})

    ok = (len(mismatches) == 0
          and counts["anova"] == 200 and counts["ttest"] == 200
          and counts["spearman"] == 200)
    return {
        "battery": "3b", "what": "200-groups ANOVA+ttest+Spearman vs scipy",
        "ok": ok,
        "detail": {
            "groups": 200, "matched": counts, "mismatches": mismatches[:10],
            "mismatch_total": len(mismatches),
            "reference": "scipy 1.14.1 (external, engine never imports it)",
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ البطارية 3c
def battery_3c(m) -> dict:
    """3c — 50 سيناريو عدائي: رفض ذري، صفر انهيار، لا تسمم حالة.

    كل هجوم: (اسم، استدعاء، الاستثناء المعلَن). النجاح = الاستثناء
    المعلَن بالضبط؛ أي استثناء آخر أو عودة طبيعية = انهيار يُسجَّل خاماً.
    """
    t0 = time.perf_counter()
    nan, inf = float("nan"), float("inf")
    good_w = [0.5, 0.3, 0.2]
    reg_fresh = lambda: m.MetricRegistry()  # noqa: E731

    attacks: list[tuple[str, object, type[BaseException]]] = [
        # --- AHP/GPI (12) — أوزان سالبة/متنافرة/فاسدة
        ("gpi_negative_weight", lambda: m.gpi([0.5, 0.5, 0.5], [-0.2, 0.6, 0.6]), ValueError),
        ("gpi_weights_sum_0.5", lambda: m.gpi([0.6, 0.4, 0.2], [0.2, 0.2, 0.1]), ValueError),
        ("gpi_weights_sum_1.5", lambda: m.gpi([0.6, 0.4, 0.2], [0.7, 0.5, 0.3]), ValueError),
        ("gpi_indicator_above_1", lambda: m.gpi([1.5, 0.5, 0.5], good_w), ValueError),
        ("gpi_indicator_below_0", lambda: m.gpi([-0.1, 0.5, 0.5], good_w), ValueError),
        ("gpi_length_mismatch", lambda: m.gpi([0.5, 0.5], good_w), ValueError),
        ("gpi_nan_indicator", lambda: m.gpi([nan, 0.5, 0.5], good_w), ValueError),
        ("gpi_inf_weight", lambda: m.gpi([0.5, 0.5, 0.5], [inf, 0.0, 0.0]), ValueError),
        ("ahp_zero_entry", lambda: m.ahp_weights([[1, 0, 2], [0, 1, 1], [0.5, 1, 1]]), ValueError),
        ("ahp_negative_entry", lambda: m.ahp_weights([[1, -2, 4], [-0.5, 1, 2], [0.25, 0.5, 1]]), ValueError),
        ("ahp_nonsquare", lambda: m.ahp_weights([[1, 2, 4], [0.5, 1, 2]]), ValueError),
        ("ahp_bad_diagonal", lambda: m.ahp_weights([[2, 1], [1, 1]]), ValueError),
        # --- التطبيع (8) — قسمة على صفر وسلاسل فاسدة
        ("minmax_lo_eq_hi", lambda: m.minmax_normalize([1.0, 2.0], lo=5.0, hi=5.0), ValueError),
        ("minmax_lo_gt_hi", lambda: m.minmax_normalize([1.0, 2.0], lo=9.0, hi=3.0), ValueError),
        ("minmax_out_of_declared_range", lambda: m.minmax_normalize([5.0], lo=0.0, hi=4.0), ValueError),
        ("minmax_empty", lambda: m.minmax_normalize([]), ValueError),
        ("zscore_empty", lambda: m.zscore_normalize([]), ValueError),
        ("zscore_single", lambda: m.zscore_normalize([3.0]), ValueError),
        ("zscore_constant_series", lambda: m.zscore_normalize([7.0, 7.0, 7.0, 7.0]), ValueError),
        ("zscore_nan_inside", lambda: m.zscore_normalize([1.0, nan, 3.0]), ValueError),
        # --- ARIMA (7)
        ("arima_empty", lambda: m.arima100_fit([]), ValueError),
        ("arima_too_short_len3", lambda: m.arima100_fit([1.0, 2.0, 3.0]), ValueError),
        ("arima_constant_series", lambda: m.arima100_fit([5.0] * 50), ValueError),
        ("arima_nan_inside", lambda: m.arima100_fit([1.0, 2.0, nan, 4.0, 5.0, 6.0]), ValueError),
        ("arima_inf_inside", lambda: m.arima100_fit([1.0, 2.0, inf, 4.0, 5.0, 6.0]), ValueError),
        ("arima_forecast_len2", lambda: m.arima100_forecast([1.0, 2.0]), ValueError),
        ("arima_bool_inside", lambda: m.arima100_fit([1.0, True, 3.0, 4.0, 5.0]), ValueError),
        # --- الإحصاء (10)
        ("anova_single_group", lambda: m.anova_one_way([[1.0, 2.0, 3.0]]), ValueError),
        ("anova_group_len1", lambda: m.anova_one_way([[1.0], [2.0, 3.0]]), ValueError),
        ("anova_empty_group", lambda: m.anova_one_way([[1.0, 2.0], []]), ValueError),
        ("anova_nan_group", lambda: m.anova_one_way([[1.0, nan, 3.0], [4.0, 5.0, 6.0]]), ValueError),
        ("anova_alpha_gt1", lambda: m.anova_one_way([[1.0, 2.0], [3.0, 4.0]], alpha=1.5), ValueError),
        ("ttest_n1", lambda: m.ttest_1samp([5.0], 5.0), ValueError),
        ("ttest_constant_sample", lambda: m.ttest_1samp([4.0, 4.0, 4.0], 5.0), ValueError),
        ("ttest_nan_popmean", lambda: m.ttest_1samp([1.0, 2.0, 3.0], nan), ValueError),
        ("spearman_length_mismatch", lambda: m.spearman_rho([1.0, 2.0, 3.0], [1.0, 2.0]), ValueError),
        ("spearman_constant_x", lambda: m.spearman_rho([5.0, 5.0, 5.0], [1.0, 2.0, 3.0]), ValueError),
        # --- السجل/CC/SI/التوقيت (13)
        ("registry_record_string_value", lambda: reg_fresh().record("x", "42"), ValueError),
        ("registry_record_bool_value", lambda: reg_fresh().record("x", True), ValueError),
        ("registry_record_nan_value", lambda: reg_fresh().record("x", nan), ValueError),
        ("registry_get_missing", lambda: reg_fresh().get("ghost"), KeyError),
        ("registry_record_empty_name", lambda: reg_fresh().record("", 1.0), ValueError),
        ("cc_verified_gt_declared", lambda: m.coverage_coefficient(12, 10), ValueError),
        ("cc_declared_zero", lambda: m.coverage_coefficient(0, 0), ValueError),
        ("cc_negative_verified", lambda: m.coverage_coefficient(-1, 10), ValueError),
        ("cc_bool_verified", lambda: m.coverage_coefficient(True, 10), ValueError),
        ("si_detected_gt_total", lambda: m.stealth_index(100, 250), ValueError),
        ("si_total_zero", lambda: m.stealth_index(0, 0), ValueError),
        ("timing_mark_before_start", lambda: m.TimingTracker().mark_first_finding(), ValueError),
        ("report_nonstr_unmeasured_item", lambda: m.build_measurement_report(
            {"TTF": 1.0}, ["بند صالح", 42]), ValueError),
    ]
    assert len(attacks) == 50, f"عدد الهجمات {len(attacks)} != 50 — العقد الحرفي"

    results = []
    crashes = []
    for i, (name, call, expected) in enumerate(attacks):
        try:
            call()
            crashes.append({"i": i, "name": name, "error": "NO EXCEPTION — قبل المدخل الفاسد"})
            results.append({"i": i, "name": name, "ok": False, "kind": "no-reject"})
        except expected:
            results.append({"i": i, "name": name, "ok": True, "kind": "atomic-reject"})
        except BaseException as exc:  # noqa: BLE001 — نوع غير معلَن = انهيار
            crashes.append({"i": i, "name": name, "error": repr(exc)})
            results.append({"i": i, "name": name, "ok": False,
                            "kind": type(exc).__name__})

    # فحص عدم تسمم الحالة: فشل record لا يترك أثراً (validation-before-mutation)
    reg = m.MetricRegistry()
    reg.record("clean", 1.0)
    try:
        reg.record("poison", nan)
    except ValueError:
        pass
    state_clean = ("poison" not in reg.names() and reg.get("clean") == 1.0
                   and reg.names() == ["clean"])

    # هضم الهجمات: (الترتيب، الاسم، النتيجة) — حتمي بالبناء
    h = hashlib.sha256()
    for r in results:
        h.update(f"{r['i']}:{r['name']}:{int(r['ok'])}".encode())
        h.update(b"\n")
    attack_digest = h.hexdigest()

    ok = (len(crashes) == 0 and state_clean
          and sum(1 for r in results if r["ok"]) == 50)
    return {
        "battery": "3c", "what": "50 adversarial scenarios atomic-reject",
        "ok": ok,
        "detail": {
            "attacks": 50, "rejected_atomically": sum(1 for r in results if r["ok"]),
            "crashes": crashes, "state_poisoning_check": state_clean,
            "attack_digest": attack_digest,
            "classification": "PRECONDITION_FAILED (xgraph 14) إلا registry_get_missing "
                              "= عقد KeyError صريح",
            "wall_s": round(time.perf_counter() - t0, 3),
        },
    }


# ============================================================ أغلفة pytest
def test_battery_3a():
    """3a — 500 سلسلة: تطبيع + GPI + ARIMA، صفر انهيار، هضم قابل للتكرار."""
    assert battery_3a(_metrics())["ok"]


def test_battery_3b():
    """3b — 200 مجموعة: ANOVA + t-test + Spearman مطابقة لـ scipy."""
    assert battery_3b(_metrics())["ok"]


def test_battery_3c():
    """3c — 50 سيناريو عدائي: رفض ذري، صفر انهيار، لا تسمم حالة."""
    assert battery_3c(_metrics())["ok"]


# ============================================================ وضع الدليل
_BATTERIES = [("3a", battery_3a), ("3b", battery_3b), ("3c", battery_3c)]


def _overall_digest(bats: list[dict]) -> str:
    """هضم التيار المنطقي الكلي: (بطارية، ماذا، نجحت) فقط (انضباط 11)."""
    h = hashlib.sha256()
    for b in bats:
        h.update(f"{b['battery']}:{b['what']}:{int(b['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-7 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    m = _metrics()
    bats = [fn(m) for _, fn in _BATTERIES]
    total = len(bats)
    passed = sum(1 for b in bats if b["ok"])
    doc = {
        "suite": "axis7-atoms",
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
    print(f"axis7-atoms: {passed}/{total} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        extra = ""
        if b["battery"] == "3a":
            extra = f" | crashes={len(b['detail']['crashes'])} repeatable={b['detail']['repeatable']}"
        elif b["battery"] == "3b":
            extra = f" | matched={b['detail']['matched']} mismatches={b['detail']['mismatch_total']}"
        elif b["battery"] == "3c":
            extra = (f" | rejected={b['detail']['rejected_atomically']}/50"
                     f" crashes={len(b['detail']['crashes'])}"
                     f" state_clean={b['detail']['state_poisoning_check']}")
        print(f"  [{mark}] battery {b['battery']}: {b['what']}{extra}")
        if not b["ok"]:
            print(f"      raw: {json.dumps(b['detail'], ensure_ascii=False)[:600]}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
