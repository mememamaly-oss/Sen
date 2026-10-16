"""خط أنابيب مراحل غير متزامن: طوابير محدودة بين المراحل → ضغط خلفي طبيعي.

دلالات:
- كل مرحلة تعالج عنصرًا واحدًا في كل لحظة (ترتيب محفوظ داخل الخط أحادي المسار).
- المرحلة قد تعيد DROP لإسقاط العنصر (تصفية) — مسجّل في عدّاد dropped.
- فشل مرحلة = إسقاط العنصر (at-most-once) + تسجيل في errors؛ الخط يكمل.
- الإغلاق متدرّج: إغلاق مدخل المرحلة الأولى → كل مرحلة تصرّف ما عندها ثم تغلق مخرجها.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from perf.actors.mailbox import Mailbox, MailboxClosed

DROP = object()  # علامة تصفية: مرحلة تعيدها لإسقاط العنصر


class Pipeline:
    def __init__(self, stages: list[Callable[[Any], Awaitable[Any]]], *,
                 capacity: int = 4) -> None:
        if not stages:
            raise ValueError("مرحلة واحدة على الأقل")
        if capacity < 1:
            raise ValueError("capacity >= 1 مطلوب")
        self._stages = list(stages)
        self._qs = [Mailbox(capacity) for _ in range(len(self._stages) + 1)]
        self._tasks = [asyncio.ensure_future(self._stage(i))
                       for i in range(len(self._stages))]
        self._closed_input = False
        self.processed = [0] * len(self._stages)
        self.dropped = 0
        self.errors: list[str] = []

    async def _stage(self, i: int) -> None:
        q_in, q_out = self._qs[i], self._qs[i + 1]
        while True:
            try:
                item = await q_in.get()
            except MailboxClosed:
                q_out.close()  # الإغلاق يتدرّج للمرحلة التالية
                return
            try:
                out = await self._stages[i](item)
            except BaseException as exc:
                self.errors.append(f"stage{i}: {exc!r}")
                continue
            self.processed[i] += 1
            if out is not DROP:
                await q_out.put(out)

    async def put(self, item: Any) -> None:
        """إيداع في المدخل — ينتظر عند امتلاء طابور المرحلة الأولى (ضغط خلفي)."""
        if self._closed_input:
            raise RuntimeError("مدخل الخط مغلق")
        await self._qs[0].put(item)

    async def take(self) -> Any:
        """استلام نتيجة من المخرج؛ MailboxClosed بعد تصريف كل شيء عند الإغلاق."""
        return await self._qs[-1].get()

    async def close(self) -> None:
        """إغلاق المدخل وانتظار تصريف كل المراحل (المستهلك يستهلك بالتوازي)."""
        self._closed_input = True
        self._qs[0].close()
        await asyncio.gather(*self._tasks)

    async def collect(self, n: int, timeout: float = 5.0) -> list[Any]:
        """جمع حتى n نتيجة (يتوقف مبكرًا عند النفاد بعد الإغلاق أو المهلة)."""
        out: list[Any] = []
        try:
            while len(out) < n:
                out.append(await asyncio.wait_for(self.take(), timeout))
        except (MailboxClosed, asyncio.TimeoutError):
            pass
        return out
