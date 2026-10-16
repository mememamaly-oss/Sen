"""ترميزات عمودية نقية: RLE وDelta وzigzag/varint — دوال حتمية بلا حالة."""
from __future__ import annotations

from typing import Any

Pair = list[Any]  # [قيمة, عدد تكرارات]


def rle_encode(values: list[Any]) -> list[Pair]:
    """ترميز طول-التكرار للتتابعات المتشابهة المتجاورة (يعمل على أي نوع قابل للمساواة)."""
    if not values:
        return []
    out: list[Pair] = []
    cur, n = values[0], 1
    for v in values[1:]:
        if v == cur:
            n += 1
        else:
            out.append([cur, n])
            cur, n = v, 1
    out.append([cur, n])
    return out


def rle_decode(pairs: list[Pair]) -> list[Any]:
    out: list[Any] = []
    for v, n in pairs:
        out.extend([v] * n)
    return out


def delta_encode(values: list[int]) -> list[int]:
    """[v0, v1-v0, v2-v1, ...] — مفيد للأعمدة الرتيبة/شبه الرتيبة."""
    if not values:
        return []
    out = [values[0]]
    prev = values[0]
    for v in values[1:]:
        out.append(v - prev)
        prev = v
    return out


def delta_decode(deltas: list[int]) -> list[int]:
    if not deltas:
        return []
    out = [deltas[0]]
    for step in deltas[1:]:
        out.append(out[-1] + step)
    return out


def zigzag_encode(n: int) -> int:
    """0,1,-1,2,-2 → 0,2,1,4,3: يحوّل الإشارة إلى حجم صغير للترميز المتغير."""
    return n << 1 if n >= 0 else ((-n) << 1) - 1


def zigzag_decode(e: int) -> int:
    return e >> 1 if e % 2 == 0 else -((e + 1) >> 1)


def varint_size(n: int) -> int:
    """حجم تقديري بالبايتات لعددٍ في ترميز متغير (لأغراض اختيار الترميز)."""
    if n < 0:
        n = -n
    return max(1, (n.bit_length() + 6) // 7)
