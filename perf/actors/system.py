"""نظام الفاعلين: تشغيل، إشراف بحد إعادة تشغيل داخل نافذة زمنية، ask/tell، إغلاق منظّم.

دلالات معلنة (لا ضمنية):
- التسليم at-most-once: الرسالة التي تفشل تُسقط عند RESTART/ESCALATE ولا تُعاد.
- إعادة التشغيل = مثيل جديد من نفس المصنع (حالة صفرية) مع الاحتفاظ بصندوق البريد.
- الإشراف مسطّح أحادي المستوى (لا شجرة هرمية) — قيد معلن.
- فشل pre_start (أوليًا أو بعد إعادة تشغيل) = تصعيد فوري.
- فشل استثناء داخل receive يصل إلى السائل عبر ask (يرى رسالته فشلت).
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Callable

from perf.actors.actor import Actor, ActorRef
from perf.actors.mailbox import Mailbox, MailboxClosed
from perf.actors.messages import Envelope, Stop, SystemMessage, next_correlation
from perf.actors.supervisor import Directive, FailureContext, OneForOne


class ActorNotFound(KeyError):
    """المستهدف غير مسجّل: لم يولد أو مات."""

    def __init__(self, name: str) -> None:
        super().__init__(f"لا يوجد فاعل حي باسم {name!r}")


class ActorDied(RuntimeError):
    """ask وصل إلى فاعل مات (أو نُظم) قبل الرد."""


class _Cell:
    """سجل داخلي لفاعل واحد: صندوقه، سياسته، عدّادات نافذة الفشل، وسلسلة الإيداع."""

    __slots__ = ("name", "factory", "mailbox", "policy", "task",
                 "failures", "restarts", "alive", "put_chain")

    def __init__(self, name: str, factory: Callable[[], Actor],
                 mailbox: Mailbox, policy: OneForOne) -> None:
        self.name = name
        self.factory = factory
        self.mailbox = mailbox
        self.policy = policy
        self.task: asyncio.Task | None = None
        self.failures: deque[float] = deque()
        self.restarts: deque[float] = deque()
        self.alive = True
        self.put_chain: asyncio.Task | None = None


class ActorSystem:
    """حاوية فاعلين بإشراف مسطّح. النافذة الزمنية ملك النظام (ساعة قابلة للحقن)."""

    def __init__(self, window_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._window_s = window_s
        self._cells: dict[str, _Cell] = {}
        self._pending: dict[str, tuple[asyncio.Future, str]] = {}
        self.events: list[dict[str, Any]] = []
        self._closed = False

    # ---------------- توليد ----------------

    def spawn(self, name: str, factory: Callable[[], Actor], *,
              mailbox_capacity: int = 128,
              policy: OneForOne | None = None) -> ActorRef:
        if self._closed:
            raise RuntimeError("النظام مغلق: لا توليد بعد shutdown")
        if not name or name in self._cells:
            raise ValueError(f"اسم فاعل فارغ أو مكرر: {name!r}")
        cell = _Cell(name, factory, Mailbox(mailbox_capacity), policy or OneForOne())
        self._cells[name] = cell
        cell.task = asyncio.ensure_future(self._run(cell))
        return ActorRef(self, name)

    # ---------------- توجيه ----------------

    def _deposit(self, cell: _Cell, env: Envelope) -> asyncio.Task:
        """إيداع مُسلسل: كل إيداع ينتظر سابقه → ترتيب FIFO مضمون عبر السلسلة."""
        prev = cell.put_chain

        async def _chained() -> None:
            if prev is not None:
                try:
                    await prev
                except MailboxClosed:
                    raise  # السلسلة ماتت: الإيداع الحالي مرفوض بنفس السبب
                except Exception:
                    pass  # سلسلة سابقة أُلغيت؛ الإيداع الحالي سيواجه مصيره بنفسه
            await cell.mailbox.put(env)

        def _retrieved(t: asyncio.Task) -> None:
            # استرجاع الاستثناء إن تُرك بلا انتظار — يكتم تحذير GC دون أن
            # يحجب الرمي عمّن ينتظر المهمة فعلاً (await يعيد رفع الاستثناء)
            if not t.cancelled():
                t.exception()

        task = asyncio.ensure_future(_chained())
        task.add_done_callback(_retrieved)
        cell.put_chain = task
        return task

    def tell(self, name: str, message: Any, sender: str | None = None) -> asyncio.Task:
        cell = self._cells.get(name)
        if cell is None or not cell.alive:
            raise ActorNotFound(name)
        return self._deposit(cell, Envelope(sender=sender, receiver=name, message=message))

    async def ask(self, name: str, message: Any, timeout: float | None = None) -> Any:
        cell = self._cells.get(name)
        if cell is None or not cell.alive:
            raise ActorNotFound(name)
        corr = next_correlation()
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[corr] = (fut, name)
        self._deposit(cell, Envelope(sender=None, receiver=name,
                                     message=message, correlation_id=corr))
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(corr, None)
            if not fut.done():
                fut.cancel()

    # ---------------- دورة الحياة ----------------

    async def _run(self, cell: _Cell) -> None:
        instance = cell.factory()
        instance.bind(self, cell.name)
        try:
            await instance.pre_start()
        except BaseException as exc:
            self._record("pre_start_failed", cell, exc, directive=Directive.ESCALATE)
            await self._die(cell, Directive.ESCALATE, f"pre_start: {exc!r}", instance)
            return
        self._record("started", cell)
        while True:
            try:
                env = await cell.mailbox.get()
            except MailboxClosed:
                await self._die(cell, Directive.STOP, "mailbox-closed", instance)
                return
            if isinstance(env.message, SystemMessage):
                if isinstance(env.message, Stop):
                    await self._die(cell, Directive.STOP, env.message.reason, instance)
                    return
                continue  # رسالة نظام غير مُدارة: تُتجاهل بأمان
            try:
                result = await instance.receive(env)
            except BaseException as exc:
                if env.correlation_id is not None:
                    self._fail_pending(env.correlation_id, exc)  # السائل يرى فشل رسالته
                directive = self._decide(cell, exc)
                if directive is Directive.RESUME:
                    self._record("resumed", cell, exc, directive=directive)
                    continue
                if directive is Directive.RESTART:
                    cell.restarts.append(self._clock())
                    self._record("restarted", cell, exc, directive=directive)
                    try:
                        await instance.post_stop()
                    except BaseException:
                        pass  # تنظيف فاشل لا يمنع إعادة التشغيل
                    instance = cell.factory()
                    instance.bind(self, cell.name)
                    try:
                        await instance.pre_start()
                    except BaseException as exc2:
                        self._record("pre_start_failed", cell, exc2, directive=Directive.ESCALATE)
                        await self._die(cell, Directive.ESCALATE, f"pre_start(restart): {exc2!r}", instance)
                        return
                    continue
                await self._die(cell, directive, repr(exc), instance)
                return
            if env.correlation_id is not None:
                self._resolve(env.correlation_id, result)

    def _decide(self, cell: _Cell, exc: BaseException) -> Directive:
        """تحديث عدّادات النافذة ثم سؤال السياسة بسياق نقي."""
        now = self._clock()
        horizon = now - self._window_s
        cell.failures.append(now)
        while cell.failures and cell.failures[0] < horizon:
            cell.failures.popleft()
        while cell.restarts and cell.restarts[0] < horizon:
            cell.restarts.popleft()
        ctx = FailureContext(cell.name, exc,
                             failures_in_window=len(cell.failures),
                             restarts_in_window=len(cell.restarts))
        return cell.policy.decide(ctx)

    async def _die(self, cell: _Cell, directive: Directive, reason: str,
                   instance: Actor) -> None:
        cell.alive = False
        self._cells.pop(cell.name, None)
        for corr, (fut, owner) in list(self._pending.items()):
            if owner == cell.name:
                self._pending.pop(corr, None)
                if not fut.done():
                    fut.set_exception(ActorDied(f"الفاعل {cell.name!r} مات قبل الرد: {reason}"))
        cell.mailbox.drain()   # ما تبقى لن يُعالج (at-most-once، معلَن)
        cell.mailbox.close()   # أي إيداع سلسلة معلّق يُكمل في الفراغ ثم ينتهي
        try:
            await instance.post_stop()
        except BaseException as exc:
            self._record("post_stop_failed", cell, exc)
        self._record("dead", cell, reason=reason, directive=directive)

    # ---------------- ردود ask ----------------

    def _resolve(self, corr: str, result: Any) -> None:
        entry = self._pending.pop(corr, None)
        if entry is None:
            return  # انتهت مهلة السائل وأُلغيت: الرد المتأخر يُتجاهل بأمان
        fut, _ = entry
        if not fut.done():
            fut.set_result(result)

    def _fail_pending(self, corr: str, exc: BaseException) -> None:
        entry = self._pending.pop(corr, None)
        if entry is None:
            return
        fut, _ = entry
        if not fut.done():
            fut.set_exception(exc)

    # ---------------- مراقبة وإغلاق ----------------

    def stats(self) -> dict[str, dict[str, Any]]:
        return {
            name: {"alive": c.alive, "queued": c.mailbox.qsize(),
                   "failures": len(c.failures), "restarts": len(c.restarts)}
            for name, c in self._cells.items()
        }

    def _record(self, kind: str, cell: _Cell, exc: BaseException | None = None, *,
                reason: str | None = None, directive: Directive | None = None) -> None:
        self.events.append({
            "ts": self._clock(), "kind": kind, "actor": cell.name,
            "reason": reason, "error": repr(exc) if exc is not None else None,
            "directive": directive.value if directive is not None else None,
        })

    async def shutdown(self, timeout: float = 5.0) -> None:
        """إغلاق منظّم: صناديق الجميع تُغلق → كل فاعل يصرّف رسائله ثم post_stop."""
        self._closed = True
        cells = list(self._cells.values())
        for c in cells:
            c.mailbox.close()
        tasks = [c.task for c in cells if c.task is not None]
        if tasks:
            await asyncio.wait(tasks, timeout=timeout)
        for corr, (fut, owner) in list(self._pending.items()):
            self._pending.pop(corr, None)
            if not fut.done():
                fut.set_exception(ActorDied(f"النظام أُغلق والفاعل {owner!r} لم يرد"))
