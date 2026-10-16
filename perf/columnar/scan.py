"""مسح بمُسندات فوق الجدول العمودي مع تقليم بالخرائط النطاقية.

المبدأ الحاكم — سليمية التقليم (soundness):
حذف كتلة يحدث فقط إذا أثبتت خريطة النطاق [min,max] استحالة وجود
أي قيمة مطابقة فيها. أي شك = تُمسح الكتلة صفًا صفًا (لا نتيجة ضائعة أبدًا).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from perf.columnar.table import ColumnTable


@dataclass(frozen=True)
class Eq:
    value: Any

    def test(self, v: Any) -> bool:
        return v == self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        return self.value < lo or self.value > hi


@dataclass(frozen=True)
class Ne:
    value: Any

    def test(self, v: Any) -> bool:
        return v != self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        # التحسين الوحيد السليم: كتلة كل قيمها متساوية وتساوي v
        return lo == hi == self.value


@dataclass(frozen=True)
class Gt:
    value: Any

    def test(self, v: Any) -> bool:
        return v > self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        return hi <= self.value


@dataclass(frozen=True)
class Gte:
    value: Any

    def test(self, v: Any) -> bool:
        return v >= self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        return hi < self.value


@dataclass(frozen=True)
class Lt:
    value: Any

    def test(self, v: Any) -> bool:
        return v < self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        return lo >= self.value


@dataclass(frozen=True)
class Lte:
    value: Any

    def test(self, v: Any) -> bool:
        return v <= self.value

    def prunes(self, lo: Any, hi: Any) -> bool:
        return lo > self.value


@dataclass(frozen=True)
class In:
    values: tuple

    def test(self, v: Any) -> bool:
        return v in self.values

    def prunes(self, lo: Any, hi: Any) -> bool:
        return all(x < lo or x > hi for x in self.values)


@dataclass(frozen=True)
class Range:
    lo: Any
    hi: Any

    def test(self, v: Any) -> bool:
        return self.lo <= v <= self.hi

    def prunes(self, blo: Any, bhi: Any) -> bool:
        return self.hi < blo or self.lo > bhi


def scan(table: ColumnTable, where: dict[str, Any],
         columns: list[str] | None = None) -> dict[str, Any]:
    """مسح بمُسندات: تقليم على مستوى الكتل ثم فحص صفي.

    يعيد {"rows": [...], "stats": {...}} — العدّادات واقعية لقياس فعالية التقليم.
    """
    for col in where:
        if col not in table.columns:
            raise KeyError(f"عمود غير موجود: {col!r}")
    projection = columns or table.columns
    stats = {"blocks_total": len(table.blocks), "blocks_scanned": 0,
             "rows_scanned": 0, "matched": 0}
    results: list[dict[str, Any]] = []

    # (1) الكتل المكتملة: تقليم بخريطة النطاق ثم فحص صفي
    for group in table.blocks:
        pruned = False
        for col, cond in where.items():
            b = group[col]
            if cond.prunes(b.min_value, b.max_value):
                pruned = True
                break
        if pruned:
            continue
        stats["blocks_scanned"] += 1
        vals = {col: group[col].values() for col in
                set(list(where) + list(projection))}
        for i in range(group[table.columns[0]].n):
            stats["rows_scanned"] += 1
            if all(cond.test(vals[col][i]) for col, cond in where.items()):
                results.append({c: vals[c][i] for c in projection})
                stats["matched"] += 1

    # (2) الذيل غير المكتمل: فحص خطي بلا تقليم (sound دومًا)
    tail_start = len(table.blocks) * table.block_size
    for row in table._rows[tail_start:]:
        stats["rows_scanned"] += 1
        if all(cond.test(row[col]) for col, cond in where.items()):
            results.append({c: row[c] for c in projection})
            stats["matched"] += 1

    return {"rows": results, "stats": stats}
