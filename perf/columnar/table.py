"""جدول عمودي: صفوف تُقطَّع إلى مجموعات (row groups)، كل عمود كتلة بخريطة نطاق.

ملاحظة صدق: الذيل غير المكتمل (أقل من block_size) يبقى صفوفًا خامًا
حتى اكتمال الكتلة — المسح يغطيه خطيًا بلا تقليم (sound دومًا).
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable

from perf.columnar.block import ColumnBlock


class ColumnTable:
    def __init__(self, name: str, columns: list[str], *, block_size: int = 256) -> None:
        if not columns:
            raise ValueError("عمود واحد على الأقل")
        if block_size < 1:
            raise ValueError("block_size >= 1 مطلوب")
        self.name = name
        self.columns = list(columns)
        self.block_size = block_size
        self._rows: list[dict[str, Any]] = []
        self.blocks: list[dict[str, ColumnBlock]] = []

    @property
    def n_rows(self) -> int:
        return len(self._rows)

    def append_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        """إلحاق صفوف وبناء أي كتل مكتملة جديدة (الكتل السابقة لا تُمس)."""
        for r in rows:
            missing = [c for c in self.columns if c not in r]
            if missing:
                raise ValueError(f"صف ناقص أعمدة {missing}")
        self._rows.extend(rows)
        complete = len(self._rows) - (len(self._rows) % self.block_size)
        while len(self.blocks) * self.block_size < complete:
            bi = len(self.blocks)
            chunk = self._rows[bi * self.block_size:(bi + 1) * self.block_size]
            self.blocks.append({
                c: ColumnBlock(c, [row[c] for row in chunk])
                for c in self.columns
            })

    def all_rows(self) -> list[dict[str, Any]]:
        """الصفوف كما أُلحقت (للمقارنة الاستقصائية brute-force في الاختبارات)."""
        return [dict(r) for r in self._rows]

    def digest(self) -> str:
        """هضم حتمي للجدول كاملًا: نفس الصفوف بنفس الترتيب → نفس الهضم."""
        h = hashlib.blake2b(digest_size=16)
        h.update(self.name.encode("utf-8"))
        h.update(f"|{len(self.blocks)}|{len(self._rows)}".encode())
        for group in self.blocks:
            for c in self.columns:
                h.update(group[c].digest().encode("ascii"))
        return h.hexdigest()
