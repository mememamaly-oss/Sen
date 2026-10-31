#!/usr/bin/env python3
"""burhan/race/gates.py — بوابات أمان المحور 17 (AXIS-17).

البوابات الثلاث المأمورة:
  1) بوابة المفردات التدميرية — تحظر أي خطة يحمل جسمها أو مسارها
     فعلاً تدميريًا أو نقلاً ماليًا قبل أي إرسال (الأمر الحرفي:
     delete / transfer).
  2) سقف الميزانية — تطبيع max-concurrent ونطاقه القانوني.
  3) بوابة التوقيتات — رفض الأزمنة المعطوبة (سالب أو > 1000 ثانية)
     قبل دخولها التحليل (ذرة 6).

قيد الوحدة الحرفي (N2): stdlib فقط — لا استيراد هنا إطلاقاً سوى
json المدمج؛ لا urllib ولا re: تطبيع الكلمات يدويًا بـ translate،
وفك الترميز يدويًا.

إفصاح N8 (حدّ أمانة معلن): SENSITIVE_HEADERS وSENSITIVE_BODY_KEYS
وعلامات التقنع أدناه **نسخة حرفية** من سياسة المحرك الملتزمة في
http_engine.py (RT-05 للرؤوس + بند 3 من ORD-001-REMAND للأجسام).
لا استيراد من المحرك (الاختبار 10) — لذلك هي مضمنة هنا؛ أي تغيير
مستقبلي في سياسة المحرك يتطلب تحديث هذه النسخة يدويًا، وهذا الحدّ
معًلن في ملف حدود الأمانة عند بوابة المحور.
"""
from __future__ import annotations

import json


class RaceGateError(ValueError):
    """استثناء بوابات المحور 17 — يُسجل في التقرير (القاعدة 5 من M2)."""


# ---------------------------------------------------------------- المفردات
# قائمة race المعلنة (إفصاح N8): أفعال تدمير/نقل مالي غير ملتبسة عمليًا
# في أجسام الفحص؛ الأمر الحرفي نص على delete وtransfer — والبقية من
# روح قائمة planner المحرك (DESTRUCTIVE_WORDS) مقتصرة على ما لا يولّد
# موجبات كاذبة على الأجسام العادية.
DESTRUCTIVE_WORDS = frozenset((
    "delete", "transfer", "drop", "purge", "wipe", "truncate", "destroy",
    "uninstall", "erase", "withdraw", "reset", "remove", "clear",
))

# نسخة حرفية من http_engine._SENSITIVE_HEADERS (RT-05) — إفصاح N8
SENSITIVE_HEADERS = frozenset((
    "authorization", "x-api-key", "cookie",
    "x-auth-token", "proxy-authorization",
))

# نسخة حرفية من http_engine.SENSITIVE_BODY_KEYS — إفصاح N8
SENSITIVE_BODY_KEYS = frozenset((
    "password", "passwd", "secret", "token", "credit_card", "cvv", "ssn",
))

BODY_REDACTED = "[REDACTED]"                                   # حرفي من المحرك
BINARY_BODY_OMITTED = "[BINARY_BODY_OMITTED_FOR_SECURITY]"    # حرفي من المحرك
_BINARY_CONTENT_TYPES = frozenset((                           # حرفي من المحرك
    "application/octet-stream", "multipart/form-data",
))
_BINARY_KEEP_UNDER = 1024            # الاستثناء المأمور: < 1KB يبقى حرفيًا

# حدود السقف والزمن (معلنة؛ قابلة للاختبار)
MAX_CONCURRENT_FLOOR = 1
MAX_CONCURRENT_CEIL = 64
TIMING_FLOOR = 0.0
TIMING_CEIL = 1000.0

# تطبيع كلمات يدوي بلا re (N2): كل محرف غير أبجدي-رقمي يصير مسافة
_PUNCT_MAP = {ord(c): " " for c in
               "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t\n\r"}


def _words(text: str) -> set:
    """تقسيم نصي إلى مجموعة كلمات صغيرة — دالة نقية (لا استيراد)."""
    return set((text or "").lower().translate(_PUNCT_MAP).split())


def destructive_vocabulary_gate(body: str, path: str = "") -> tuple:
    """بوابة المفردات التدميرية (البوابة الدائمة الداخلية).

    تفحص جسم الطلب ومساره (والاستعلام ضمنه) ضد DESTRUCTIVE_WORDS
    بحدود كلمات؛ ترجع (allowed: bool, reason: str) — لا حالة، نقية
    تمامًا، حتمية بالبناء.
    """
    hay = f"{body or ''} {path or ''}"
    hits = _words(hay) & DESTRUCTIVE_WORDS
    if hits:
        return False, ("destructive vocabulary: "
                        + ", ".join(sorted(hits)))
    return True, "no destructive vocabulary in body/path"


def enforce_budget(max_concurrent) -> int:
    """تطبيع سقف التزامن — خارج النطاق يُرفض fail-closed باستثناء مخصص."""
    try:
        cap = int(max_concurrent)
    except (TypeError, ValueError) as e:
        raise RaceGateError(f"max-concurrent not an integer: {max_concurrent!r}") from e
    if cap < MAX_CONCURRENT_FLOOR or cap > MAX_CONCURRENT_CEIL:
        raise RaceGateError(
            f"max-concurrent {cap} out of range "
            f"[{MAX_CONCURRENT_FLOOR}..{MAX_CONCURRENT_CEIL}]")
    return cap


def validate_timing(elapsed) -> bool:
    """بوابة التوقيتات (ذرة 6): السالب و> 1000 مرفوض — لا يُبنى عليه قرار."""
    try:
        v = float(elapsed)
    except (TypeError, ValueError):
        return False
    return TIMING_FLOOR <= v <= TIMING_CEIL


def redact_headers(headers: dict) -> dict:
    """تقنع رؤوس الطلب قبل الـjournal — نسخة سلوك RT-05 الحرفية."""
    return {k: (BODY_REDACTED if str(k).lower() in SENSITIVE_HEADERS else v)
            for k, v in (headers or {}).items()}


def redact_body(body, content_type: str) -> str:
    """تقنع جسم الطلب قبل الـjournal — نسخة سلوك بند 3 الحرفية.

    form-urlencoded: مفاتيح حساسة -> [REDACTED] ؛ JSON: مسح هيكلي
    (بمسار يدوي بلا re) ؛ الثنائي/multipart: >= 1KB -> علامة الحذف،
    وأصغر من 1KB يبقى حرفيًا (الاستثناء المأمور حرفيًا).
    """
    if body is None:
        return ""
    b = body if isinstance(body, str) else str(body)
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        out = []
        for pair in b.split("&"):
            k, sep, v = pair.partition("=")
            key = _unquote(k).strip().lower()
            if sep and key in SENSITIVE_BODY_KEYS:
                out.append(f"{k}={BODY_REDACTED}")
            else:
                out.append(pair)
        return "&".join(out)
    if ct == "application/json":
        try:
            parsed = json.loads(b)
        except ValueError:
            return _regex_free_json_redact(b)   # JSON مبتور: مسح يدوي
        return json.dumps(_redact_obj(parsed), ensure_ascii=False)
    if ct in _BINARY_CONTENT_TYPES and len(b) >= _BINARY_KEEP_UNDER:
        return BINARY_BODY_OMITTED
    return b


def _unquote(s: str) -> str:
    """فك ترميز %XX و+ يدويًا (لا urllib — N2) لأغراض مقارنة المفاتيح."""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "+":
            out.extend(b" ")
            i += 1
            continue
        if c == "%" and i + 2 < n:
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(c.encode("utf-8", "replace"))
        i += 1
    return out.decode("utf-8", "replace")


def _redact_obj(o):
    """مسح هيكلي حساس داخل كائن JSON — نسخة سلوك المحرك الحرفية."""
    if isinstance(o, dict):
        return {k: (BODY_REDACTED if str(k).lower() in SENSITIVE_BODY_KEYS
                    else _redact_obj(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_obj(x) for x in o]
    return o


def _regex_free_json_redact(b: str) -> str:
    """مسح JSON مبتور/غير صالح بلا re: مسار نصي يبحث '"key": value'
    للمفاتيح الحساسة ويستبدل القيمة — بحيث لا يحمل السجل سرًا حرفيًا
    أبدًا (نفس عقد المحرك لجسم JSON المبتور)."""
    out = b
    for key in SENSITIVE_BODY_KEYS:
        for quote in ('"', "'"):
            needle_open = f"{quote}{key}{quote}"
            start = 0
            while True:
                i = out.find(needle_open, start)
                if i < 0:
                    break
                colon = out.find(":", i + len(needle_open))
                if colon < 0:
                    break
                j = colon + 1
                while j < len(out) and out[j] in " \t\r\n":
                    j += 1
                if j < len(out) and out[j] == quote:
                    k = out.find(quote, j + 1)
                    end = k + 1 if k >= 0 else len(out)
                else:
                    k = j
                    while k < len(out) and out[k] not in ",}\n":
                        k += 1
                    end = k
                if end > j:
                    out = out[:j] + f"{quote}{BODY_REDACTED}{quote}" + out[end:]
                    start = i + len(needle_open) + 4
                else:
                    start = i + len(needle_open)
    return out


def gate_summary() -> dict:
    """ملخص معلن للبوابات — لأغراض التقرير والأدلة فقط (دالة نقية)."""
    return {
        "destructive_words": sorted(DESTRUCTIVE_WORDS),
        "sensitive_headers": sorted(SENSITIVE_HEADERS),
        "sensitive_body_keys": sorted(SENSITIVE_BODY_KEYS),
        "binary_keep_under": _BINARY_KEEP_UNDER,
        "timing": [TIMING_FLOOR, TIMING_CEIL],
        "budget": [MAX_CONCURRENT_FLOOR, MAX_CONCURRENT_CEIL],
    }
