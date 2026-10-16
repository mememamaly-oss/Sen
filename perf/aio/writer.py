"""كاتب سجلات مجمّع غير متزامن: دفعات بحدّ حجم/زمن + سلسلة هضم blake2b
قابلة لإعادة الحساب من المُستقبِل + ضغط خلفي بطابور محدود.

ضمانات مُختبَرة:
- كل سطر مقبول يصل إلى sink مرة واحدة بالضبط (إلا إذا فشل sink نفسه — يسجَّل في errors).
- لا دفعة تتجاوز batch_size.
- الدفعات تصل إلى sink بالترتيب (قفل تجميع-وكتابة واحد يسلسل (جمع→كتابة)).
- سلسلة الهضم دالة نقية في الدفعات المكتوبة: إعادة حسابها من ما استلمه sink تساوي last_digest.
- الضغط الخلفي: submit ينتظر عند امتلاء الطابور (max_pending) — لا إسقاط.
- الإغلاق: قفل إدخال يمنع أي سباق بين submit وclose؛ الباقي يُصرَّف قبل الموت.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Awaitable, Callable

from perf.aio.policy import TokenBucket

EMPTY_DIGEST = "0" * 16


class WriterClosed(RuntimeError):
    """الكاتب مغلق: رفض إيداع جديد."""


class BatchedWriter:
    def __init__(self, sink: Callable[[list[bytes]], Awaitable[None]], *,
                 batch_size: int = 64, flush_interval_s: float = 0.05,
                 max_pending: int = 1024,
                 admission: TokenBucket | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if batch_size < 1 or max_pending < 1 or flush_interval_s <= 0:
            raise ValueError("batch_size>=1, max_pending>=1, flush_interval_s>0")
        self._sink = sink
        self._batch_size = batch_size
        self._interval = flush_interval_s
        self._q: asyncio.Queue = asyncio.Queue(maxsize=max_pending)
        self._admission = admission
        self._clock = clock
        self._ingest = asyncio.Lock()     # يسلسل (فحص الإغلاق + الإيداع) ضد close
        self._seq = asyncio.Lock()        # يسلسل (جمع + كتابة) — يمنع انقلاب ترتيب الدفعات
        self._closed = False
        self._loop_task: asyncio.Task | None = None
        self.errors: list[str] = []
        self.batches = 0
        self.written_lines = 0
        self.rejected = 0
        self._digest = EMPTY_DIGEST

    # ---------------- تشغيل ----------------

    def start(self) -> "BatchedWriter":
        if self._loop_task is None:
            self._loop_task = asyncio.ensure_future(self._loop())
        return self

    # ---------------- إيداع ----------------

    async def submit(self, line: str) -> bool:
        """False = مرفوض بسياسة القبول (لا إيداع). يرفع WriterClosed بعد الإغلاق.
        ينتظر عند امتلاء الطابور — هذا هو الضغط الخلفي."""
        if self._admission is not None and not self._admission.allow():
            self.rejected += 1
            return False
        async with self._ingest:
            if self._closed:
                raise WriterClosed("الكاتب مغلق")
            await self._q.put(line.encode("utf-8"))
        return True

    # ---------------- الحلقة ----------------

    async def _loop(self) -> None:
        while not self._closed:
            async with self._seq:
                batch = await self._collect()
                if batch:
                    await self._write(batch)

    async def _collect(self) -> list[bytes]:
        """جمع دفعة: حتى batch_size أو انقضاء المهلة — أيهما أولًا."""
        deadline = self._clock() + self._interval
        batch: list[bytes] = []
        while len(batch) < self._batch_size:
            timeout = deadline - self._clock()
            if timeout <= 0:
                break
            try:
                item = await asyncio.wait_for(self._q.get(), timeout)
            except asyncio.TimeoutError:
                break
            batch.append(item)
        return batch

    async def _write(self, batch: list[bytes]) -> None:
        try:
            await self._sink(batch)
        except BaseException as exc:  # فشل sink: يسجَّل، الدفعة تُفقد بصدق، الباقي يكمل
            self.errors.append(repr(exc))
            return
        self.batches += 1
        self.written_lines += len(batch)
        self._digest = self._chain(self._digest, batch)

    @staticmethod
    def _chain(prev: str, batch: list[bytes]) -> str:
        """هضم السلسلة: دالة نقية في (هضم الدفعات السابقة، محتوى الدفعة)."""
        h = hashlib.blake2b(digest_size=16)
        h.update(prev.encode("ascii"))
        h.update(b"|" + str(len(batch)).encode() + b"|")
        for b in batch:
            h.update(b)
            h.update(b"\x1e")  # فاصل سجل — يمنع التحام الحدود بين الأسطر
        return h.hexdigest()

    # ---------------- تصريف وإغلاق ----------------

    async def flush(self) -> None:
        """تصريف فوري لما في الطابور (بنفس تسلسل الجمع-والكتابة المحكم)."""
        async with self._seq:
            while True:
                batch = self._drain_nowait()
                if not batch:
                    return
                await self._write(batch)

    def _drain_nowait(self) -> list[bytes]:
        batch: list[bytes] = []
        while len(batch) < self._batch_size:
            try:
                batch.append(self._q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def close(self) -> None:
        """إغلاق ذري: لا submit جديد بعده؛ كل ما قُبل قبل الإغلاق يُكتب."""
        async with self._ingest:
            self._closed = True
        if self._loop_task is not None:
            try:
                await asyncio.wait_for(self._loop_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._loop_task.cancel()
                try:
                    await self._loop_task
                except (asyncio.CancelledError, Exception):
                    pass
            except Exception as exc:  # اللوب لا يفشل عادة — يسجَّل إن فشل
                self.errors.append(f"loop: {exc!r}")
        await self.flush()  # حزام وأحزمة: أي متبقٍ بعد خروج اللوب

    @property
    def last_digest(self) -> str:
        return self._digest
