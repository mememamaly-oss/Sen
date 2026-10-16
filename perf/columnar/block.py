"""كتلة عمود واحد: قيم + ترميز مُختار بheuristics + خريطة نطاق (min/max) + هضم حتمي."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from perf.columnar.encoding import (delta_decode, delta_encode, rle_decode,
                                    rle_encode, varint_size, zigzag_encode)


def _value_size(v: Any) -> int:
    """حجم تقديري بالبايتات لقيمة واحدة (للمقارنة بين الترميزات)."""
    if isinstance(v, bool):
        return 1
    if isinstance(v, int):
        return varint_size(zigzag_encode(v))
    if isinstance(v, float):
        return 9
    return len(str(v).encode("utf-8")) + 1


def _ints_size(values: list[int]) -> int:
    return sum(varint_size(zigzag_encode(v)) for v in values)


class ColumnBlock:
    """كتلة عمود: مصدر الحقيقة هو raw؛ encoded اشتقاق حتمي قابل لإعادة البناء."""

    def __init__(self, name: str, values: list[Any], encoding: str = "auto") -> None:
        if encoding not in ("auto", "none", "rle", "delta"):
            raise ValueError(f"ترميز غير معروف: {encoding!r}")
        self.name = name
        self.raw = list(values)
        self.n = len(self.raw)
        self.min_value = min(self.raw) if self.raw else None
        self.max_value = max(self.raw) if self.raw else None
        self.encoding = self._choose() if encoding == "auto" else encoding
        if self.encoding == "rle":
            self.encoded = rle_encode(self.raw)
        elif self.encoding == "delta":
            self.encoded = delta_encode(self.raw)
        else:
            self.encoded = None
        if self.encoding == "delta" and not all(
                isinstance(v, int) and not isinstance(v, bool) for v in self.raw):
            raise ValueError("ترميز delta يتطلب أعدادًا صحيحة فقط")

    def _choose(self) -> str:
        """Heuristic معلنة: rle إذا انضغطت الأزواج إلى النصف أو أقل،
        delta إذا وفّرت خصمًا معنويًا (≥25% من الحجم)، وإلا none —
        لا ادعاء ضغط لفارق تافه على بيانات عشوائية."""
        if self.n == 0:
            return "none"
        if len(rle_encode(self.raw)) * 2 <= self.n:
            return "rle"
        if all(isinstance(v, int) and not isinstance(v, bool) for v in self.raw):
            raw_size = _ints_size(self.raw)
            delta_size = _ints_size(delta_encode(self.raw))
            if delta_size * 4 < raw_size * 3:  # خصم ≥25%
                return "delta"
        return "none"

    def values(self) -> list[Any]:
        """فك الترميز — نسخة جديدة (المستدعي يملكها)."""
        if self.encoding == "rle":
            return rle_decode(self.encoded)
        if self.encoding == "delta":
            return delta_decode(self.encoded)
        return list(self.raw)

    def estimate_bytes(self) -> int:
        if self.encoding == "rle":
            return sum(_value_size(v) + varint_size(c) for v, c in self.encoded)
        if self.encoding == "delta":
            return _ints_size(self.encoded)
        return sum(_value_size(v) for v in self.raw)

    def to_json(self) -> str:
        """تمثيل حتمي (مفاتيح مرتبة، فواصل ثابتة) — أساس الهضم."""
        return json.dumps({
            "name": self.name, "n": self.n, "encoding": self.encoding,
            "min": self.min_value, "max": self.max_value,
            "encoded": self.encoded,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            default=str)

    def digest(self) -> str:
        return hashlib.blake2b(self.to_json().encode("utf-8"),
                               digest_size=16).hexdigest()
