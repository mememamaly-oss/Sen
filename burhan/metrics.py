"""burhan.metrics — المحور 7: القياس والمؤشرات (M2 GREEN).

PROVENANCE (معلنة بأمانة):
- عقد هذه الوحدة هو جدول-H07 الحرفي من أمر المشرف 2026-10-19 («أمر بناء
  المحاور 7 و8 و11 و12»)، المسجَّل ب نصه في tests/test_axis7_metrics.py
  عند M1 RED (commit 453b3bc) قبل وجود أي سطر من هذا الملف (القاعدة-2).
- المحرك نقي stdlib: math فقط للرياضيات — لا scipy ولا numpy ولا أي
  حزمة خارجية. scipy يُستخدم مرجعاً خارجياً في الاختبارات فقط (N4)،
  ولا يستورده هذا الملف أبداً.

ملاحظات الصدق (العقود المفسَّرة — مطابقة لنظائرها في ترويسة الجناح):
  N1 — ARIMA(1,0,0) = AR(1) بثابت: x_t = c + φ·x_{t-1} + ε. التقدير
       بمربعات الصغرى الشرطية بصيغة مركزية مغلقة (أثبت عددياً من
       الانحراف)، والتنبؤ = ĉ + φ̂·x_n.
  N2 — أوزان AHP: المتجه الذاتي الرئيسي للمصفوفة التبادلية بتربيع
       القوة (بداية منتظمة، 500 تكرار حدّي، تقارب 1e-15) ثم تطبيع
       المجموع إلى 1 بالضبط. نسبة الاتساق CR خارج العقد.
  N3 — ANOVA الانهيارية: SSB=0 → العرف المعلن F:=0.0 وp:=1.0؛
       SSW=0 مع SSB>0 → F:=inf وp:=0.0 (فصل تام). كلاهما معلن.
  N4 — قيم p عبر بيتا الناقصة المنظَّمة (كسر مستمر مع لانكزوس
       للغاما)؛ التكميل يُحسب من الجهة الصغرى I_{1-x}(b,a) لتفادي
       الإلغاء الكارثي قرب p→0.
  N5 — TTF/TTE/TTT/TTO: زمن أول نتيجة/أول دليل/الحكم النهائي/الإجمالي
       منذ البدء، بساعة رتيبة (time.monotonic)؛ أول علامة تسود،
       والغائب يبقى None بصراحة.
  N6 — CC = verified/declared؛ SI = 1 - detected/total. الرفض الذري
       عند التنافر (verified>declared، detected>total، declared=0،
       total=0) — القسمة على صفر لا تحدث أبداً.
  N7 — كل مدخل يُفحص قبل أي حساب (validation-before-mutation):
       bool مرفوض حيث يُشترط رقم (صنو int في بايثون لكنه ليس قياساً)،
       NaN/Inf مرفوضان، والقواميس/السلاسل/None مرفوضة في مواضع
       الأعداد. الرفض دائماً ValueError برسالة صريحة.

انضباط الحتمية (تمهيد المحور 11): لا ساعة حائط ولا عشوائية داخل أي
دالة أو تقرير تنتجه هذه الوحدة؛ TimingTracker يقيس الزمن لأنه وظيفته
المعلنة، وقيمه لا تدخل أي هضم منطقي (عقد الهضم في الجناح: الاسم
والنجاح فقط).
"""
from __future__ import annotations

import math
import time
from collections.abc import Iterable as _AbcIterable
from typing import Any, Sequence

__all__ = [
    "MetricRegistry",
    "minmax_normalize", "zscore_normalize",
    "ahp_weights", "gpi",
    "arima100_fit", "arima100_forecast",
    "anova_one_way", "ttest_1samp", "spearman_rho",
    "TimingTracker",
    "coverage_coefficient", "stealth_index",
    "build_measurement_report",
]


# ============================================================ تحقق المدخلات (N7)
def _is_number(v: Any) -> bool:
    """رقم حقيقي صالح: int/float (وليس bool) وغير NaN/Inf."""
    if isinstance(v, bool):
        return False
    if not isinstance(v, (int, float)):
        return False
    return math.isfinite(v)


def _check_number(v: Any, what: str) -> float:
    if not _is_number(v):
        raise ValueError(f"{what}: قيمة غير رقمية أو NaN/Inf: {v!r}")
    return float(v)


def _check_series(values: Any, what: str, *, min_len: int = 1) -> list[float]:
    """سلسلة أعداد صالحة: قائمة/تسلسل، طول ≥ min_len، كل عنصر رقم
    منتهٍ (N7). تُعاد قائمة جديدة — لا تُعدَّل مدخلات المستخدم أبداً."""
    if isinstance(values, (str, bytes)) or not isinstance(values, _AbcIterable):
        raise ValueError(f"{what}: ليس تسلسلاً من الأعداد: {type(values).__name__}")
    out: list[float] = []
    for i, v in enumerate(values):
        if not _is_number(v):
            raise ValueError(f"{what}[{i}]: قيمة غير رقمية أو NaN/Inf: {v!r}")
        out.append(float(v))
    if len(out) < min_len:
        raise ValueError(f"{what}: الطول {len(out)} < الأدنى المطلوب {min_len}")
    return out


def _check_count(v: Any, what: str, *, minimum: int) -> int:
    """عدد صحيح ≥ minimum (وليس bool) — لعقود CC/SI."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{what}: مطلوب عدد صحيح (bool ليس قياساً): {v!r}")
    if v < minimum:
        raise ValueError(f"{what}: {v} < الحد الأدنى {minimum}")
    return v


# ============================================================ H07_01 — السجل
class MetricRegistry:
    """سجل القياسات: تسجيل/قراءة بلا تحويل ولا تقريب.

    - record(name, value, unit=None, note=None): آخر تسجيل للاسم يسود.
    - get(name): القيمة كما سُجِّلت (KeyError باسم صريح لو غائب).
    - meta(name): نسخة من السياق الكامل (القيمة/الوحدة/الملاحظة/الترتيب).
    - names(): الأسماء مرتبة أبجدياً — خرج حتمي.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._seq = 0

    def record(self, name: str, value: Any,
               unit: str | None = None, note: str | None = None) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError(f"اسم المقياس يجب أن يكون سلسلة غير فارغة: {name!r}")
        self._seq += 1
        self._store[name] = {
            "value": _check_number(value, f"قيمة المقياس {name!r}"),
            "unit": unit, "note": note, "seq": self._seq,
        }

    def get(self, name: str) -> float:
        try:
            return self._store[name]["value"]
        except KeyError:
            raise KeyError(f"مقياس غير مسجَّل: {name!r}") from None

    def meta(self, name: str) -> dict[str, Any]:
        try:
            return dict(self._store[name])
        except KeyError:
            raise KeyError(f"مقياس غير مسجَّل: {name!r}") from None

    def names(self) -> list[str]:
        return sorted(self._store)


# ============================================================ H07_02 — min-max
def minmax_normalize(values: Sequence[float],
                     lo: float | None = None,
                     hi: float | None = None) -> list[float]:
    """تطبيع min-max إلى [0,1]: (v - lo) / (hi - lo).

    الحدود الافتراضية مشتقة من العينة نفسها (min→0.0، max→1.0).
    الحدود الصريحة عقد نطاق معلَن: أي قيمة خارجهما رفض ذري (N7) —
    المؤشر المطبَّع يجب ألا يتسرب خارج [0,1] بصمت.
    """
    vals = _check_series(values, "minmax_normalize: values")
    if lo is None and hi is None:
        lo, hi = min(vals), max(vals)
    else:
        if lo is None or hi is None:
            raise ValueError("الحدود تُعطى معاً (lo وhi) أو تُشتقان معاً — لا نصف عقد")
        lo = _check_number(lo, "minmax_normalize: lo")
        hi = _check_number(hi, "minmax_normalize: hi")
    if not lo < hi:
        raise ValueError(f"الحد الأدنى يجب أن يكون أصغر من الأقصى: lo={lo}, hi={hi}")
    span = hi - lo
    out = []
    for i, v in enumerate(vals):
        if v < lo or v > hi:
            raise ValueError(
                f"minmax_normalize: القيمة [{i}]={v} خارج النطاق المعلن [{lo}, {hi}]")
        out.append((v - lo) / span)
    return out


# ============================================================ H07_03 — Z-score
def zscore_normalize(values: Sequence[float]) -> list[float]:
    """تطبيع Z-score: متوسط 0 وانحراف مجتمعي 1 (ddof=0).

    التباين الصفري (قيم متطابقة كلها) رفض ذري — القسمة على صفر لا تحدث.
    """
    vals = _check_series(values, "zscore_normalize: values", min_len=2)
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    if var <= 0.0:
        raise ValueError("zscore_normalize: تباين صفري — السلسلة ثابتة لا تُطبَّع")
    std = math.sqrt(var)
    return [(v - mean) / std for v in vals]


# ============================================================ H07_04/05 — AHP + GPI
def ahp_weights(matrix: Sequence[Sequence[float]]) -> list[float]:
    """أوزان AHP: المتجه الذاتي الرئيسي للمصفوفة التبادلية، مجموعه 1.

    تربيع القوة ببداية منتظمة (1/n) — حتمي بلا عشوائية؛ تقارب 1e-15
    وحد 500 تكرار. المصفوفة: n×n، كل عنصر > 0 ومنتهٍ، والقطر 1
    (يُقبل ضمن 1e-9 — مصفوفة المقارنة الذاتية).
    """
    if isinstance(matrix, (str, bytes)) or not isinstance(matrix, _AbcIterable):
        raise ValueError("ahp_weights: المصفوفة يجب أن تكون تسلسل صفوف")
    rows = list(matrix)
    n = len(rows)
    if n < 2:
        raise ValueError(f"ahp_weights: البعد {n} < 2 — لا ترجيح لأقل من معيارين")
    m: list[list[float]] = []
    for i, row in enumerate(rows):
        vals = _check_series(row, f"ahp_weights: الصف {i}", min_len=1)
        if len(vals) != n:
            raise ValueError(
                f"ahp_weights: الصف {i} طوله {len(vals)} لا يطابق البعد {n}")
        if abs(vals[i] - 1.0) > 1e-9:
            raise ValueError(f"ahp_weights: العنصر القطري [{i}][{i}]={vals[i]} != 1")
        for j, v in enumerate(vals):
            if not v > 0.0:
                raise ValueError(
                    f"ahp_weights: العنصر [{i}][{j}]={v} — مقارنات AHP موجبة حصراً")
        m.append(vals)
    v = [1.0 / n] * n
    for _ in range(500):
        w = [sum(m[i][j] * v[j] for j in range(n)) for i in range(n)]
        s = sum(w)
        if not (s > 0.0) or not math.isfinite(s):
            raise ValueError("ahp_weights: انهيار التطبيع أثناء تربيع القوة")
        w = [x / s for x in w]
        delta = max(abs(w[i] - v[i]) for i in range(n))
        v = w
        if delta < 1e-15:
            break
    s = sum(v)
    return [x / s for x in v]  # تطبيع ختامي: المجموع 1 بالضبط البنائي


def gpi(indicators: Sequence[float], weights: Sequence[float]) -> float:
    """GPI = Σ wᵢ·vᵢ — مؤشر أداء عام فوق مؤشرات مطبَّعة في [0,1].

    العقود الذرية: تطابق الأطوال؛ كل مؤشر في [0,1]؛ كل وزن ≥ 0؛
    مجموع الأوزان = 1 ضمن 1e-12 (H07_05: خارج ذلك ValueError).
    """
    ind = _check_series(indicators, "gpi: indicators")
    wts = _check_series(weights, "gpi: weights")
    if len(ind) != len(wts):
        raise ValueError(
            f"gpi: عدد المؤشرات {len(ind)} لا يطابق عدد الأوزان {len(wts)}")
    if len(ind) == 0:
        raise ValueError("gpi: قوائم فارغة — لا مؤشر بلا وزن")
    for i, v in enumerate(ind):
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"gpi: المؤشر [{i}]={v} خارج [0,1] — طبِّعه أولاً")
    for i, w in enumerate(wts):
        if w < 0.0:
            raise ValueError(f"gpi: الوزن [{i}]={w} سالب — الأوزان غير سالبة حصراً")
    total = sum(wts)
    if abs(total - 1.0) > 1e-12:
        raise ValueError(f"gpi: مجموع الأوزان {total} != 1.0 (سماحية 1e-12)")
    return sum(w * v for w, v in zip(wts, ind))


# ============================================================ H07_06 — ARIMA(1,0,0)
def arima100_fit(series: Sequence[float]) -> tuple[float, float]:
    """تقدير ARIMA(1,0,0): (φ, c) بمربعات الصغرى الشرطية (N1).

    الصيغة المركزية: φ = Σ(x̂·ŷ)/Σ(x̂²) على أزواج (x_{t-1}, x_t)؛
    الثابت c = ȳ - φ·x̄. الانحراف الصفري في المتنبئ رفض ذري.
    """
    vals = _check_series(series, "arima100_fit: series", min_len=4)
    xs = vals[:-1]  # x_{t-1}
    ys = vals[1:]   # x_t
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 0.0:
        raise ValueError("arima100_fit: السلسلة ثابتة (انحراف صفري) — لا نموذج")
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    phi = sxy / sxx
    c = my - phi * mx
    return phi, c


def arima100_forecast(series: Sequence[float]) -> float:
    """تنبؤ خطوة واحدة: x_{n+1} = ĉ + φ̂·x_n على معاملات الملاءمة."""
    vals = _check_series(series, "arima100_forecast: series", min_len=4)
    phi, c = arima100_fit(vals)
    return c + phi * vals[-1]


# ============================================================ دوال توزيع خاصة (N4)
_LANCZOS_G = 7.5  # متغير لانكزوس g=7 (n=9): t = z-1+g+0.5 — مُتحقق
#                 ضد math.lgamma ضمن 1e-15 (انظر اختبار البطارية)


def _log_gamma(x: float) -> float:
    """ln Γ(x) — لانكزوس g=7 بمعاملات 9 (دقة ~1e-15 نسبية)."""
    coef = [
        0.99999999999980993,
        676.5203681218851,
        -1259.1392167224028,
        771.32342877765313,
        -176.61502916214059,
        12.507343278686905,
        -0.13857109526572012,
        9.9843695780195716e-6,
        1.5056327351493116e-7,
    ]
    if x < 0.5:
        # انعكاس: Γ(x)Γ(1-x) = π/sin(πx)
        return math.log(math.pi / math.sin(math.pi * x)) - _log_gamma(1.0 - x)
    x -= 1.0
    a = coef[0]
    t = x + _LANCZOS_G
    for i in range(1, 9):
        a += coef[i] / (x + i)
    return 0.5 * math.log(2.0 * math.pi) + (x + 0.5) * math.log(t) - t + math.log(a)


def _betacf(a: float, b: float, x: float) -> float:
    """الكسر المستمر لبيتا الناقصة (Numerical Recipes betacf)."""
    max_it, eps, fpmin = 300, 3e-16, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_it + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < eps:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    """البيتا الناقصة المنظَّمة I_x(a, b) — 0/1 عند الطرفين."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_front = (_log_gamma(a + b) - _log_gamma(a) - _log_gamma(b)
                + a * math.log(x) + b * math.log(1.0 - x))
    bt = math.exp(ln_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def _t_sf(t: float, df: int) -> float:
    """ذيل t الأعلى: P(T > |t|) = 0.5·I_x(df/2, 1/2)، x = df/(df+t²)."""
    x = df / (df + t * t)
    return 0.5 * _betainc(df / 2.0, 0.5, x)


def _f_sf(f: float, d1: int, d2: int) -> float:
    """ذيل F الأعلى من الجهة الصغرى (N4): I_{1-x}(d2/2, d1/2)."""
    x = d1 * f / (d1 * f + d2)
    return _betainc(d2 / 2.0, d1 / 2.0, 1.0 - x)


def _f_ppf(q: float, d1: int, d2: int) -> float:
    """ناظم F (الحد الحرج) بانتشال ثنائي القسم على CDF — حتمي.

    مدى البحث [0, 1e12] و220 تكرار: دقة ~1e-12 نسبية، والغرض عتبة
    قرار (F > F_critical) لا مرجع مطابقة.
    """
    if not 0.0 < q < 1.0:
        raise ValueError(f"_f_ppf: الكمية {q} خارج (0,1)")
    lo, hi = 0.0, 1e12
    for _ in range(220):
        mid = 0.5 * (lo + hi)
        cdf = 1.0 - _f_sf(mid, d1, d2)
        if cdf < q:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


# ============================================================ H07_07/08 — ANOVA
def anova_one_way(groups: Sequence[Sequence[float]],
                  alpha: float = 0.05) -> dict[str, Any]:
    """ANOVA أحادي الاتجاه: F / p_value / F_critical / df1 / df2 (N3).

    العقد: مجموعتان فأكثر، كل مجموعة عنصران فأكثر (df2 = N-k ≥ 2)،
    وalpha في (0,1). الانهياريات بأعرافها المعلنة (SSB=0 → F=0, p=1؛
    SSW=0 مع SSB>0 → F=inf, p=0).
    """
    if isinstance(groups, (str, bytes)) or not isinstance(groups, _AbcIterable):
        raise ValueError("anova_one_way: المجموعات يجب أن تكون تسلسل تسلسلات")
    gs = [list(g) for g in groups]
    if len(gs) < 2:
        raise ValueError(f"anova_one_way: عدد المجموعات {len(gs)} < 2")
    checked: list[list[float]] = []
    for i, g in enumerate(gs):
        checked.append(_check_series(g, f"anova_one_way: المجموعة {i}", min_len=2))
    a = _check_number(alpha, "anova_one_way: alpha")
    if not 0.0 < a < 1.0:
        raise ValueError(f"anova_one_way: alpha {a} خارج (0,1)")
    N = sum(len(g) for g in checked)
    k = len(checked)
    df1, df2 = k - 1, N - k
    grand = sum(sum(g) for g in checked) / N
    ssb = sum(len(g) * (sum(g) / len(g) - grand) ** 2 for g in checked)
    ssw = sum(sum((x - sum(g) / len(g)) ** 2 for x in g) for g in checked)
    if ssb == 0.0:
        F, p = 0.0, 1.0  # العرف المعلن (N3): مجموعات متطابقة
    elif ssw == 0.0:
        F, p = math.inf, 0.0  # فصل تام (N3)
    else:
        F = (ssb / df1) / (ssw / df2)
        p = _f_sf(F, df1, df2)
    return {
        "F": F,
        "p_value": p,
        "F_critical": _f_ppf(1.0 - alpha, df1, df2),
        "df1": df1,
        "df2": df2,
        "ss_between": ssb,
        "ss_within": ssw,
        "alpha": alpha,
    }


# ============================================================ H07_09 — t-test
def ttest_1samp(sample: Sequence[float], popmean: float) -> dict[str, Any]:
    """اختبار t لعينة واحدة ضد متوسط معروف (ثنائي الجانب، ddof=1).

    التباين الصفري رفض ذري (N7): scipy يعيد nan/inf هناك — نحن نعلن
    الرفض بدل تمرير غير المعرف (فرق معلَن، ليس توافقاً صامتاً).
    """
    vals = _check_series(sample, "ttest_1samp: sample", min_len=2)
    mu = _check_number(popmean, "ttest_1samp: popmean")
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / (n - 1)  # عيني ddof=1
    if var <= 0.0:
        raise ValueError("ttest_1samp: تباين صفري — العينة ثابتة، الاختبار غير معرَّف")
    s = math.sqrt(var)
    t = (mean - mu) / (s / math.sqrt(n))
    df = n - 1
    p = 2.0 * _t_sf(abs(t), df)
    return {"t": t, "p_value": p, "df": df, "mean": mean, "n": n}


# ============================================================ H07_10 — Spearman
def _average_ranks(vals: list[float]) -> list[float]:
    """رُتَب متوسطية (المتعادلون يأخذون متوسط مواضعهم) — عرف scipy."""
    n = len(vals)
    order = sorted(range(n), key=lambda i: vals[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # مواضع i..j (مبنية على 1)
        for pos in range(i, j + 1):
            ranks[order[pos]] = avg
        i = j + 1
    return ranks


def spearman_rho(x: Sequence[float], y: Sequence[float]) -> float:
    """معامل سبيرمان: بيرسون على الرُتَب المتوسطية.

    الانحراف الصفري في رُتَب أي طرف رفض ذري (معامل غير معرَّف هناك).
    """
    xs = _check_series(x, "spearman_rho: x", min_len=2)
    ys = _check_series(y, "spearman_rho: y", min_len=2)
    if len(xs) != len(ys):
        raise ValueError(
            f"spearman_rho: الطولان {len(xs)} و{len(ys)} غير متطابقين")
    rx, ry = _average_ranks(xs), _average_ranks(ys)
    n = len(rx)
    mx = sum(rx) / n
    my = sum(ry) / n
    sxx = sum((a - mx) ** 2 for a in rx)
    syy = sum((b - my) ** 2 for b in ry)
    if sxx <= 0.0 or syy <= 0.0:
        raise ValueError(
            "spearman_rho: رُتَب ثابتة (قيم متطابقة كلياً) — المعامل غير معرَّف")
    sxy = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    return sxy / math.sqrt(sxx * syy)


# ============================================================ H07_11 — التوقيت
class TimingTracker:
    """تتبع TTF/TTE/TTT/TTO بساعة رتيبة (N5).

    أول علامة لكل حدث تسود (idempotent-first)؛ الأحداث غير المعلَّمة
    تبقى None بصراحة في التقرير؛ mark_start شرط مسبق لأي علامة أخرى.
    القيم لا تدخل أي هضم منطقي (انضباط المحور 11).
    """

    _EVENTS = ("start", "first_evidence", "first_finding", "outcome", "end")

    def __init__(self) -> None:
        self._marks: dict[str, float] = {}

    def _mark(self, event: str) -> None:
        if event not in self._EVENTS:
            raise ValueError(f"حدث غير معروف: {event!r}")
        if event != "start" and "start" not in self._marks:
            raise ValueError(f"علامة {event!r} قبل mark_start — لا زمن مرجعي")
        if event not in self._marks:  # أول علامة تسود
            self._marks[event] = time.monotonic()

    def mark_start(self) -> None:
        self._mark("start")

    def mark_first_evidence(self) -> None:
        self._mark("first_evidence")

    def mark_first_finding(self) -> None:
        self._mark("first_finding")

    def mark_outcome(self) -> None:
        self._mark("outcome")

    def mark_end(self) -> None:
        self._mark("end")

    def report(self) -> dict[str, Any]:
        t0 = self._marks.get("start")
        out: dict[str, Any] = {}
        for key, event in (("TTF", "first_finding"), ("TTE", "first_evidence"),
                           ("TTO", "outcome"), ("TTT", "end")):
            if t0 is None or event not in self._marks:
                out[key] = None
            else:
                out[key] = self._marks[event] - t0
        out["marks"] = dict(self._marks)
        out["clock"] = "time.monotonic"
        return out


# ============================================================ H07_12/13 — CC وSI
def coverage_coefficient(verified: int, declared: int) -> float:
    """CC = verified/declared — مثبت على معلَن (N6).

    رفض ذري: declared = 0 (لا معلَن → النسبة غير معرَّفة)؛
    verified > declared (مثبت أكثر من المعلن — تنافر).
    """
    v = _check_count(verified, "coverage_coefficient: verified", minimum=0)
    d = _check_count(declared, "coverage_coefficient: declared", minimum=0)
    if d == 0:
        raise ValueError("coverage_coefficient: declared=0 — النسبة غير معرَّفة")
    if v > d:
        raise ValueError(
            f"coverage_coefficient: verified {v} > declared {d} — تنافر عددي")
    return v / d


def stealth_index(total_requests: int, detected: int) -> float:
    """SI = 1 - detected/total — مؤشر التخفي في [0,1] (N6).

    رفض ذري: total = 0 (لا حركة → المؤشر غير معرَّف)؛
    detected > total أو أي سالب.
    """
    t = _check_count(total_requests, "stealth_index: total_requests", minimum=1)
    d = _check_count(detected, "stealth_index: detected", minimum=0)
    if d > t:
        raise ValueError(
            f"stealth_index: detected {d} > total {t} — تنافر عددي")
    return 1.0 - d / t


# ============================================================ H07_14 — التقرير
def build_measurement_report(measured: dict[str, Any],
                             unmeasured: list[str] | None = None) -> dict[str, Any]:
    """تقرير قياس صريح: المقيس + «ما لم يُقس» دائماً حاضر.

    قسم unmeasured لا يختفي حتى لو فارغ — الشفافية عقد لا خيار.
    لا ساعة حائط ولا عشوائية في التقرير (انضباط المحور 11): ما يُدار
    هنا قابل للهضم الحتمي كما هو.
    """
    if not isinstance(measured, dict):
        raise ValueError(
            f"build_measurement_report: measured يجب أن يكون قاموساً: {type(measured).__name__}")
    for key in measured:
        if not isinstance(key, str) or not key:
            raise ValueError(f"build_measurement_report: مفتاح غير صالح: {key!r}")
    if unmeasured is None:
        items: list[str] = []
    elif isinstance(unmeasured, (list, tuple)):
        items = list(unmeasured)  # بلا تحويل — النوع يُفحص بنداً بنداً أدناه
    else:
        raise ValueError(
            "build_measurement_report: unmeasured يجب أن يكون قائمة بنود "
            f"لا {type(unmeasured).__name__}")
    for i, item in enumerate(items):
        if not isinstance(item, str) or not item:
            raise ValueError(f"build_measurement_report: بند unmeasured [{i}] غير صالح: {item!r}")
    return {"measured": dict(measured), "unmeasured": items}
