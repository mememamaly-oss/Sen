"""مجموعة عمال بتجزئة متسقة (consistent hashing) فوق نظام الفاعلين.

خصائص مُختبَرة:
- التوجيه دالة نقية في (المفتاح، الحلقة): نفس المفتاح → نفس العامل.
- الاستقرار: إضافة عامل تحرّك جزءًا فقط من المفاتيح (~1/(N+1)) — لا إعادة توزيع كامل.
- عدم الفقد: كل مفتاح مُسنَد قبل التوسيع وبعده (الاتحاد يغطي الكل).
"""
from __future__ import annotations

import asyncio
import bisect
import hashlib
from typing import Any, Callable, Iterable

from perf.actors.actor import Actor, ActorRef
from perf.actors.system import ActorSystem


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")


class _Ring:
    """حلقة تجزئة متسقة بعقد افتراضية — حتمية كاملة لنفس (n_workers, vnodes, seed)."""

    def __init__(self, n_workers: int, vnodes: int = 160, seed: str = "v1") -> None:
        if n_workers < 1:
            raise ValueError("n_workers >= 1 مطلوب")
        if vnodes < 1:
            raise ValueError("vnodes >= 1 مطلوب")
        points: list[tuple[int, int]] = []
        for w in range(n_workers):
            for v in range(vnodes):
                points.append((_h(f"{seed}:w{w}:v{v}"), w))
        points.sort()
        self.n = n_workers
        self._hashes = [p[0] for p in points]
        self._workers = [p[1] for p in points]

    def worker_for(self, key: str) -> int:
        i = bisect.bisect_right(self._hashes, _h(key))
        if i == len(self._hashes):
            i = 0  # لفّ حلقي
        return self._workers[i]


class WorkerPool:
    """N عمال، كل عامل فاعل كامل؛ التوجيه بمفتاح عبر الحلقة."""

    def __init__(self, system: ActorSystem, name: str,
                 worker_factory: Callable[[], Actor], size: int, *,
                 vnodes: int = 160, mailbox_capacity: int = 128) -> None:
        if size < 1:
            raise ValueError("size >= 1 مطلوب")
        self._system = system
        self._name = name
        self._factory = worker_factory
        self._vnodes = vnodes
        self._ring = _Ring(size, vnodes)
        self.size = size
        self._refs: list[ActorRef] = [
            system.spawn(f"{name}-w{i}", worker_factory,
                         mailbox_capacity=mailbox_capacity)
            for i in range(size)
        ]

    def worker_index(self, key: str) -> int:
        """فهرس العامل المسؤول عن المفتاح (دالة نقية — للاختبار والمراقبة)."""
        return self._ring.worker_for(key)

    def _worker_name(self, key: str) -> str:
        return f"{self._name}-w{self._ring.worker_for(key)}"

    def tell(self, key: str, message: Any, sender: str | None = None) -> asyncio.Task:
        return self._system.tell(self._worker_name(key), message, sender=sender)

    async def ask(self, key: str, message: Any, timeout: float | None = None) -> Any:
        return await self._system.ask(self._worker_name(key), message, timeout=timeout)

    async def resize(self, new_size: int, keys: Iterable[str]) -> dict[str, int]:
        """توسيع/تقليص + إعادة بناء الحلقة. `keys` = فضاء المفاتيح المعروف
        (المتصل يعرفه) لحساب إحصاءات الانتقال بصدق، لا لتخمين داخلي."""
        if new_size < 1:
            raise ValueError("new_size >= 1 مطلوب")
        keys = list(keys)
        old = {k: self._ring.worker_for(k) for k in keys}
        self._ring = _Ring(new_size, self._vnodes)
        for i in range(self.size, new_size):  # ولّد الجدد
            self._refs.append(self._system.spawn(f"{self._name}-w{i}", self._factory))
        if new_size < self.size:  # أوقف الزائدة إيقافًا منظّمًا (يصرّف رسائله أولًا)
            for ref in self._refs[new_size:]:
                try:
                    ref.stop("pool-resize")
                except KeyError:
                    pass  # مات سابقًا — لا يهم
            self._refs = self._refs[:new_size]
        await asyncio.sleep(0)  # فرصة جدولة لإيقافات منظّمة
        moved = sum(1 for k in keys if old[k] != self._ring.worker_for(k))
        self.size = new_size
        return {"keys": len(keys), "moved": moved}
