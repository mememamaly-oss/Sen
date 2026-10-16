#!/usr/bin/env python3
"""اختبارات المحور-10 الحقيقية — كل اختبار يعلّل سبب وجوده صراحةً.

المبدأ: لا ادعاء بلا دليل. كل حالة تختبر سلوكًا ملحوظًا (نواتج، عدّادات،
حالات مهام، أحداث إشراف) — لا مجرد "لا استثناء".
التشغيل: python3 perf/tests/run_tests.py  (خروج 0 = الكل نجح)
"""
from __future__ import annotations

import asyncio
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from perf.actors import (Actor, ActorDied, ActorNotFound, ActorSystem, Mailbox,
                         MailboxClosed, OneForOne, Directive, Poison, Stop,
                         WorkerPool)
from perf.aio import DROP, BatchedWriter, Pipeline, TokenBucket, WriterClosed
from perf.columnar import (ColumnBlock, ColumnTable, Eq, Gt, Gte, In, Lt,
                           Lte, Ne, Range, delta_decode, delta_encode,
                           rle_decode, rle_encode, scan, zigzag_decode,
                           zigzag_encode)
from perf.aio.writer import EMPTY_DIGEST

TESTS = []


def test(name: str, rationale: str):
    def deco(fn):
        TESTS.append((name, rationale, fn))
        return fn
    return deco


async def yields(n: int = 10) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


class FakeClock:
    """ساعة محقونة — تجعل اختبارات النافذة الزمنية حتمية تمامًا."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Recorder(Actor):
    """يسجل (وسم المثيل، الرسالة) — يكشف هوية المثيل بعد إعادة التشغيل."""

    def __init__(self, log: list, tag: str) -> None:
        self.log = log
        self.tag = tag

    async def receive(self, envelope) -> str:
        if isinstance(envelope.message, Poison):
            raise RuntimeError(f"poisoned:{envelope.message.note}")
        self.log.append((self.tag, envelope.message))
        return self.tag


class Gated(Actor):
    """يحتجز الرسالة عند بوابة — لاختبار الطوابير والضغط الخلفي."""

    def __init__(self, gate: asyncio.Event) -> None:
        self.gate = gate

    async def receive(self, envelope) -> str:
        await self.gate.wait()
        return "ok"


def recorder_factory(log: list, counter: list) -> "type":
    counter = counter

    def make() -> Recorder:
        counter[0] += 1
        return Recorder(log, f"inst{counter[0]}")

    return make


# ═══════════════════════ (أ) صندوق البريد ═══════════════════════

@test("mailbox_fifo", "FIFO صارم: 100 إيداع تُستلم بترتيبها بالضبط — أساس كل ترتيب الرسائل")
async def t_mailbox_fifo():
    mb = Mailbox(capacity=128)
    for i in range(100):
        await mb.put(i)
    got = [await mb.get() for _ in range(100)]
    assert got == list(range(100)), f"الفهرسة اختلت: {got[:5]}..."


@test("mailbox_backpressure", "put ينتظر عند الامتلاء ولا يسقط: الإيداع الثالث لا يكتمل إلا بعد استهلاك الأول")
async def t_mailbox_backpressure():
    mb = Mailbox(capacity=1)
    await mb.put("a")
    t2 = asyncio.ensure_future(mb.put("b"))
    await yields()
    assert not t2.done(), "الإيداع الثاني اكتمل رغم امتلاء الصندوق — الضغط الخلفي معطّل"
    assert await mb.get() == "a"
    await t2
    assert await mb.get() == "b"


@test("mailbox_close_semantics", "الإغلاق يرفض الجديد ويصرف القديم: 3 عناصر ثم الحارس")
async def t_mailbox_close():
    mb = Mailbox(capacity=8)
    for i in range(3):
        await mb.put(i)
    mb.close()
    try:
        await mb.put("x")
        raise AssertionError("الإيداع بعد الإغلاق لم يُرفض")
    except MailboxClosed:
        pass
    assert [await mb.get() for _ in range(3)] == [0, 1, 2], "الإغلاق أضاع عناصر مصطفة قبله"
    try:
        await mb.get()
        raise AssertionError("لم يصل حارس الإغلاق")
    except MailboxClosed:
        pass


@test("mailbox_capacity_validation", "سعة أقل من 1 خطأ صريح لا صمت")
async def t_mailbox_capacity():
    try:
        Mailbox(capacity=0)
        raise AssertionError("لم يرفض السعة 0")
    except ValueError:
        pass


# ═══════════════════════ (ب) النظام والإشراف ═══════════════════════

@test("ask_roundtrip", "ask يعيد قيمة return من receive — عقد الطلب/الرد")
async def t_ask_roundtrip():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]))
    tag = await system.ask("r", "hello")
    assert tag == "inst1" and log == [("inst1", "hello")]
    await system.shutdown()


@test("ask_timeout_is_real", "مهلة ask فعلية: الفاعل البطيء يرفع TimeoutError لا تعليقًا أبديًا")
async def t_ask_timeout():
    system = ActorSystem()
    gate = asyncio.Event()
    system.spawn("slow", lambda: Gated(gate))
    t0 = time.monotonic()
    try:
        await system.ask("slow", "x", timeout=0.05)
        raise AssertionError("لم تنفجر المهلة")
    except asyncio.TimeoutError:
        pass
    assert time.monotonic() - t0 < 0.5, "المهلة استغرقت أضعاف المطلوب"
    gate.set()
    await system.shutdown()


@test("tell_fifo_chain", "50 tell متتالية بلا انتظار تصل بترتيب الإرسال — سلسلة الإيداع تحفظ FIFO")
async def t_tell_fifo():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]))
    tasks = [system.tell("r", i) for i in range(50)]
    await asyncio.gather(*tasks)
    await yields(20)
    msgs = [m for _, m in log]
    assert msgs == list(range(50)), f"ترتيب مفقود: {msgs[:8]}... (n={len(msgs)})"


@test("ask_surfaces_actor_exception", "استثناء داخل receive يصل إلى السائل نفسه — يعرف أن رسالته فشلت")
async def t_ask_exception():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]),
                 policy=OneForOne(on_failure=Directive.RESUME))
    try:
        await system.ask("r", Poison("x"))
        raise AssertionError("الاستثناء لم يصل السائل")
    except RuntimeError as e:
        assert "poisoned:x" in str(e)
    tag = await system.ask("r", "still-alive")
    assert tag == "inst1", "RESUME يجب أن يبقي نفس المثيل"
    await system.shutdown()


@test("ordered_stop", "Stop يُعالج في موضعه: 5 رسائل قبله تُنجز أولًا ثم يموت الفاعل")
async def t_ordered_stop():
    system = ActorSystem()
    log: list = []
    ref = system.spawn("r", recorder_factory(log, [0]))
    for i in range(5):
        ref.tell(i)
    ref.stop("done")
    deadline = time.monotonic() + 2.0
    while "r" in system.stats() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert "r" not in system.stats(), "الفاعل لم يمت بعد Stop"
    assert [m for _, m in log] == [0, 1, 2, 3, 4], f"Stop أضاع رسائل: {log}"


@test("dead_actors_refuse", "بعد الموت بالتصعيد: ask المعلق خلف السم يرفع ActorDied وtell يرفض ActorNotFound")
async def t_dead_refuse():
    system = ActorSystem()
    log: list = []
    # max_restarts=0: أول فشل يُصعَّد فورًا (الموت في مكانه)
    system.spawn("r", recorder_factory(log, [0]),
                 policy=OneForOne(max_restarts=0))
    system.tell("r", Poison("kill"))                      # رسالة 1: قاتلة
    pending = asyncio.ensure_future(system.ask("r", "reply-me"))  # رسالة 2: معلقة خلفها
    await yields(30)  # السم يُعالَج → تصعيد → موت → الرد المعلق يفشل
    try:
        await asyncio.wait_for(pending, timeout=2.0)
        raise AssertionError("ask المعلق لم يفشل بموت الفاعل")
    except ActorDied:
        pass
    try:
        system.tell("r", "late")
        raise AssertionError("tell لم يرفض بعد الموت")
    except ActorNotFound:
        pass
    await system.shutdown()


@test("supervision_resume_keeps_state", "RESUME يسقط الرسالة الفاشلة ويكمل بنفس المثيل وحالته")
async def t_resume():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]),
                 policy=OneForOne(on_failure=Directive.RESUME))
    system.tell("r", Poison("1"))
    system.tell("r", "after")
    await yields(20)
    tags = {t for t, _ in log}
    assert tags == {"inst1"}, f"RESUME غيّر المثيل: {tags}"
    assert [m for _, m in log] == ["after"], "الرسالة بعد السم نجحت — لكن السم نفسه لا يُسجَّل"
    assert any(e["kind"] == "resumed" for e in system.events), "لا حدث resumed"
    await system.shutdown()


@test("supervision_restart_zeroes_state_keeps_mailbox", "RESTART: مثيل جديد (عداد من الصفر) والرسائل المنتظرة تُسلَّم للمثيل الجديد")
async def t_restart():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]))  # السياسة الافتراضية RESTART
    system.tell("r", "a")
    system.tell("r", Poison("boom"))
    system.tell("r", "b")
    await yields(30)
    tags = [t for t, _ in log]
    assert "inst1" in tags and "inst2" in tags, f"لم تُعاد الولادة: {tags}"
    msgs = [m for _, m in log]
    assert msgs == ["a", "b"], f"الرسائل المنتظرة ضاعت أو تكررت: {msgs}"
    assert any(e["kind"] == "restarted" for e in system.events), "لا حدث restarted"
    await system.shutdown()


@test("restart_limit_then_escalate", "max_restarts=2: سمان → إعادتا تشغيل → السم الثالث يُصعَّد ويموت الفاعل والنظام يبقى")
async def t_restart_limit():
    system = ActorSystem()
    log: list = []
    system.spawn("r", recorder_factory(log, [0]),
                 policy=OneForOne(max_restarts=2))
    for i in range(3):
        system.tell("r", Poison(str(i)))
    deadline = time.monotonic() + 2.0
    while "r" in system.stats() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    ev = [e for e in system.events if e["actor"] == "r"]
    restarts = [e for e in ev if e["kind"] == "restarted"]
    dead = [e for e in ev if e["kind"] == "dead"]
    assert len(restarts) == 2, f"عدد الإعادات {len(restarts)} != 2"
    assert dead and dead[0]["directive"] == "escalate", f"الموت ليس تصعيدًا: {dead}"
    assert "r" not in system.stats(), "المصعَّد يجب أن يكون ميتًا"
    await system.shutdown()


@test("failure_window_is_real", "نفس الفاعل: إعادتان، ثم مرور النافذة يُنقّي العدّادات فيسمح بإعادتين أخريين قبل التصعيد — ساعة محقونة")
async def t_window():
    clock = FakeClock()
    system = ActorSystem(window_s=1.0, clock=clock)
    log: list = []
    system.spawn("r", recorder_factory(log, [0]),
                 policy=OneForOne(max_restarts=2))
    # (أ) سمان في نفس اللحظة → إعادتان (الحد 2)
    system.tell("r", Poison("1"))
    system.tell("r", Poison("2"))
    await yields(30)
    n_restarts = len([e for e in system.events
                      if e["actor"] == "r" and e["kind"] == "restarted"])
    assert n_restarts == 2, f"المتوقع إعادتان: {n_restarts}"
    # (ب) تقديم الساعة بعد النافذة → التنقية تسمح بإعادتين جديدتين
    clock.t += 10.0
    system.tell("r", Poison("3"))
    system.tell("r", Poison("4"))
    await yields(30)
    n_restarts = len([e for e in system.events
                      if e["actor"] == "r" and e["kind"] == "restarted"])
    assert n_restarts == 4, f"النافذة لم تُنقَّ (لَتصعّد الثالث فورًا): {n_restarts}"
    # (ج) الخامس داخل النافذة الجديدة → تصعيد وموت
    system.tell("r", Poison("5"))
    deadline = time.monotonic() + 2.0
    while "r" in system.stats() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    dead = [e for e in system.events if e["actor"] == "r" and e["kind"] == "dead"]
    assert dead and dead[0]["directive"] == "escalate", f"الموت ليس تصعيدًا: {dead}"
    await system.shutdown()


@test("pre_start_failure_escalates", "فشل التهيئة = تصعيد فوري بلا معالجة رسائل (لا فاعل نصف مولود)")
async def t_pre_start_fail():
    class Broken(Actor):
        async def pre_start(self):
            raise RuntimeError("init-broken")

        async def receive(self, envelope):
            raise AssertionError("لا يجب أن تصل رسالة لفاعل فاشل التهيئة")

    system = ActorSystem()
    system.spawn("broken", Broken)
    await yields(20)
    ev = [e for e in system.events if e["actor"] == "broken"]
    assert any(e["kind"] == "pre_start_failed" for e in ev), f"لا حدث فشل تهيئة: {ev}"
    assert "broken" not in system.stats()
    await system.shutdown()


@test("stats_queued_is_observable", "stats تعكس الواقع: فاعل محتجز عند بوابة → قائمة انتظاره مرئية بالعدد")
async def t_stats():
    system = ActorSystem()
    gate = asyncio.Event()
    system.spawn("g", lambda: Gated(gate))
    for i in range(6):
        system.tell("g", i)
    await yields(30)
    assert system.stats()["g"]["queued"] == 5, f"المتوقع 5 (واحدة قيد المعالجة): {system.stats()}"
    gate.set()
    await system.shutdown()


# ═══════════════════════ (ج) المجموعة والتجزئة ═══════════════════════

@test("pool_routes_and_processes_exactly_once", "100 مفتاح عبر 3 عمال: كل مفتاح عولج مرة واحدة بالضبط (لا فقد ولا تكرار)")
async def t_pool_work():
    system = ActorSystem()
    log: list = []
    pool = WorkerPool(system, "p", recorder_factory(log, [0]), 3)
    keys = [f"key-{i}" for i in range(100)]
    for k in keys:
        pool.tell(k, k)
    deadline = time.monotonic() + 5.0
    while len(log) < 100 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    msgs = sorted(m for _, m in log)
    assert msgs == sorted(keys), f"فقد/تكرار: {len(log)} عنصر"
    await system.shutdown()


@test("pool_routing_pure_and_balanced", "التوجيه دالة نقية + توزيع متوازن: 1000 مفتاح/3 عمال داخل نطاق 6σ النظري لكل عامل")
async def t_pool_routing():
    system = ActorSystem()
    log: list = []
    pool = WorkerPool(system, "p", recorder_factory(log, [0]), 3)
    keys = [f"k{i}" for i in range(1000)]
    counts = [0, 0, 0]
    for k in keys:
        counts[pool.worker_index(k)] += 1
    # متوقع 333؛ انحراف معياري نظري ≈ 8.3 (vnodes=160) → نطاق 6σ ≈ [283, 383]
    assert all(280 <= c <= 390 for c in counts), f"اختلال توزيع خارج 6σ: {counts}"
    assert pool.worker_index("stable-key") == pool.worker_index("stable-key")
    await system.shutdown()


@test("pool_resize_stability", "التوسيع 3→4 يحرّك أقلية فقط (~125/500) ولا يفقد مفتاحًا، والعمال الجدد يعملون")
async def t_pool_resize():
    system = ActorSystem()
    log: list = []
    pool = WorkerPool(system, "p", recorder_factory(log, [0]), 3)
    keys = [f"key-{i}" for i in range(500)]
    before = {k: pool.worker_index(k) for k in keys}
    stats = await pool.resize(4, keys)
    after = {k: pool.worker_index(k) for k in keys}
    assert 1 <= stats["moved"] <= 350, f"انتقال غير متسق مع التجزئة المتسقة: {stats}"
    assert all(0 <= after[k] < 4 for k in keys), "مفتاح بلا عامل بعد التوسيع"
    assert stats["moved"] == sum(1 for k in keys if before[k] != after[k])
    pool.tell("key-0", "post-resize")  # العمال الجدد أحياء فعلاً
    deadline = time.monotonic() + 3.0
    while len(log) < 1 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert len(log) == 1
    await system.shutdown()


@test("pool_shrink_stops_workers_orderly", "التقليص 2→1 يوقف العامل الزائد إيقافًا منظّمًا (حدث dead بس原因 pool-resize)")
async def t_pool_shrink():
    system = ActorSystem()
    log: list = []
    pool = WorkerPool(system, "p", recorder_factory(log, [0]), 2)
    stats = await pool.resize(1, [f"k{i}" for i in range(100)])
    assert stats["moved"] >= 0 and pool.size == 1
    deadline = time.monotonic() + 2.0
    while "p-w1" in system.stats() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert "p-w1" not in system.stats(), "العامل الزائد لم يُوقف"
    await system.shutdown()


# ═══════════════════════ (د) الكاتب المجمّع ═══════════════════════

@test("writer_exactly_once_and_batch_cap", "200 سطر: كلها تصل مرة واحدة ولا دفعة تتجاوز batch_size")
async def t_writer_once():
    sink: list[list[bytes]] = []
    w = BatchedWriter(lambda b: _sink_append(sink, b), batch_size=16,
                      flush_interval_s=0.01).start()
    for i in range(200):
        assert await w.submit(f"line-{i}") is True
    deadline = time.monotonic() + 3.0
    while w.written_lines < 200 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    await w.close()
    assert w.written_lines == 200, f"أسطر مكتوبة {w.written_lines} != 200"
    assert all(len(b) <= 16 for b in sink), "دفعة تجاوزت الحد"
    flat = [x for b in sink for x in b]
    assert sorted(flat) == sorted(f"line-{i}".encode() for i in range(200)), "فقد/تكرار أسطر"
    assert flat == [f"line-{i}".encode() for i in range(200)], "ترتيب الأسطر انكسر بين الدفعات"


async def _sink_append(sink: list, batch: list) -> None:
    sink.append(list(batch))


@test("writer_interval_flush", "دفعة الزمن: سطر واحد يُكتب بمهلة الفاصل دون flush صريح")
async def t_writer_interval():
    sink: list[list[bytes]] = []
    w = BatchedWriter(lambda b: _sink_append(sink, b), batch_size=1000,
                      flush_interval_s=0.03).start()
    await w.submit("solo")
    deadline = time.monotonic() + 1.5
    while w.written_lines < 1 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert w.written_lines == 1, f"المهلة الزمنية لم تكتب السطر: {w.written_lines}"
    await w.close()


@test("writer_digest_chain_recomputable", "سلسلة الهضم دالة نقية: إعادة حسابها من دفعات sink = last_digest")
async def t_writer_digest():
    sink: list[list[bytes]] = []
    w = BatchedWriter(lambda b: _sink_append(sink, b), batch_size=10,
                      flush_interval_s=0.01).start()
    for i in range(35):
        await w.submit(f"d-{i}")
    deadline = time.monotonic() + 3.0
    while w.written_lines < 35 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    await w.close()
    assert len(sink) >= 3, "الترتيب يجب أن ينتج عدة دفعات"
    d = EMPTY_DIGEST
    for batch in sink:
        d = BatchedWriter._chain(d, batch)
    assert d == w.last_digest, "الهضم غير قابل لإعادة الحساب — السلسلة ليست نقية"
    assert w.last_digest != EMPTY_DIGEST


@test("writer_backpressure_blocks", "max_pending=2 وsink محتجز: الإيداع الخامس ينتظر فعليًا حتى يتحرر sink")
async def t_writer_backpressure():
    gate = asyncio.Event()
    sink: list[list[bytes]] = []

    async def gated_sink(batch: list[bytes]) -> None:
        await gate.wait()
        sink.append(list(batch))

    w = BatchedWriter(gated_sink, batch_size=2, flush_interval_s=0.01,
                      max_pending=2).start()
    await w.submit("1")
    await w.submit("2")
    await yields(30)  # اللوب جمع دفعة 2 وحتجز داخل sink
    for i in (3, 4):
        await w.submit(str(i))
    t5 = asyncio.ensure_future(w.submit("5"))
    await yields(20)
    assert not t5.done(), "الإيداع الخامس اكتمل رغم امتلاء كل شيء — الضغط الخلفي معطّل"
    gate.set()
    await t5
    await w.close()
    assert w.written_lines == 5, f"النهاية يجب أن تكتب 5: {w.written_lines}"


@test("writer_close_flushes_and_rejects", "الإغلاق: يكتب الباقي كاملًا ثم يرفض أي إيداع جديد")
async def t_writer_close():
    sink: list[list[bytes]] = []
    w = BatchedWriter(lambda b: _sink_append(sink, b), batch_size=1000,
                      flush_interval_s=0.005).start()
    for i in range(50):
        await w.submit(f"c-{i}")
    await w.close()
    assert w.written_lines == 50, f"الإغلاق أضاع أسطرًا: {w.written_lines}"
    try:
        await w.submit("late")
        raise AssertionError("الإيداع بعد الإغلاق لم يُرفض")
    except WriterClosed:
        pass


@test("writer_survives_sink_failure", "فشل sink لا يقتل الكاتب: الدفعة الفاشلة تُسجَّل ويفقدانها، والباقي يُكتب والسلسلة متسقة")
async def t_writer_sink_error():
    sink: list[list[bytes]] = []

    async def flaky(batch: list[bytes]) -> None:
        if b"boom" in batch:
            raise RuntimeError("sink-error")
        sink.append(list(batch))

    w = BatchedWriter(flaky, batch_size=4, flush_interval_s=0.01).start()
    for i in range(12):
        await w.submit("ok" if i not in (4, 5, 6, 7) else ("boom" if i == 5 else "ok"))
    deadline = time.monotonic() + 3.0
    while w.written_lines < 8 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    await w.close()
    assert w.errors and "sink-error" in w.errors[0], "الفشل لم يُسجَّل"
    flat = [x for b in sink for x in b]
    assert b"boom" not in flat, "الدفعة الفاشلة وصلت sink (كان يجب أن تُفقد وتُسجَّل)"
    d = EMPTY_DIGEST
    for batch in sink:
        d = BatchedWriter._chain(d, batch)
    assert d == w.last_digest, "السلسلة شملت دفعة لم تصل sink"


@test("token_bucket_deterministic", "دلو الرموز بساعة محقونة: انفجار 2 ثم رفض ثم سماح بعد التعويض — حتميًا")
async def t_token_bucket():
    clock = FakeClock()
    tb = TokenBucket(rate=10.0, capacity=2, clock=clock)
    assert tb.allow() and tb.allow(), "السماحية الانفجارية"
    assert not tb.allow(), "الرفض بعد استنفاد الرموز"
    clock.t += 0.1  # تعويض 1 رمز بالضبط بمعدل 10/ث
    assert tb.allow(), "رمز واحد تعوّض"
    assert not tb.allow()
    assert (tb.accepted, tb.rejected) == (3, 2)


@test("writer_admission_rejects", "سياسة القبول مدمجة: الكاتب يرفض بالسياسة (False) ويعدّ المرفوض دون أن يفقدهم كخطأ")
async def t_writer_admission():
    clock = FakeClock()
    tb = TokenBucket(rate=1.0, capacity=2, clock=clock)
    sink: list[list[bytes]] = []
    w = BatchedWriter(lambda b: _sink_append(sink, b), batch_size=8,
                      flush_interval_s=0.01, admission=tb).start()
    assert await w.submit("a") is True
    assert await w.submit("b") is True
    assert await w.submit("c") is False, "السياسة كان يجب أن ترفض الثالث"
    assert w.rejected == 1
    clock.t += 1.0
    assert await w.submit("d") is True
    await w.close()
    assert w.written_lines == 3


# ═══════════════════════ (هـ) خط الأنابيب ═══════════════════════

@test("pipeline_transforms_in_order", "3 مراحل تحوّل وتحفظ الترتيب: نتائج مطابقة للمرجع الحسابي")
async def t_pipeline_order():
    async def s1(x):
        return x + 1

    async def s2(x):
        return x * 2

    async def s3(x):
        return f"v{x}"

    p = Pipeline([s1, s2, s3], capacity=8)
    for i in range(20):
        await p.put(i)
    closer = asyncio.ensure_future(p.close())
    got = await p.collect(20)
    await closer
    assert got == [f"v{(i + 1) * 2}" for i in range(20)], "التحويل أو الترتيب اختل"


@test("pipeline_backpressure", "سعة 1 ومرحلة أخيرة محتجزة: الإيداع الثالث ينتظر — الضغط يتسرّب للمصدر")
async def t_pipeline_backpressure():
    gate = asyncio.Event()

    async def gated(x):
        await gate.wait()
        return x

    p = Pipeline([gated], capacity=1)
    await p.put(1)
    await yields(20)
    await p.put(2)
    t3 = asyncio.ensure_future(p.put(3))
    await yields(20)
    assert not t3.done(), "الإيداع الثالث لم ينتظر — لا ضغط خلفي"
    gate.set()
    await t3
    closer = asyncio.ensure_future(p.close())
    got = await p.collect(3)
    await closer
    assert got == [1, 2, 3]


@test("pipeline_close_drains_all", "الإغلاق يصرّف كل ما داخل الخط: 12 عنصرًا ولا واحد يضيع (مستهلك متزامن مع الإيداع والإغلاق)")
async def t_pipeline_drain():
    async def slow_double(x):
        await asyncio.sleep(0)
        return x * 2

    p = Pipeline([slow_double, slow_double], capacity=2)
    collector = asyncio.ensure_future(p.collect(12))
    for i in range(12):  # الطوابير أصغر من العناصر → الإيداع يعتمد على المستهلك المتزامن
        await p.put(i)
    closer = asyncio.ensure_future(p.close())
    got = await collector
    await closer
    assert got == [i * 4 for i in range(12)], f"ضياع أو خطأ: {len(got)}/12"
    try:
        await p.put("late")
        raise AssertionError("الإيداع بعد الإغلاق لم يُرفض")
    except RuntimeError:
        pass


@test("pipeline_real_concurrency", "توقيت حقيقي: 6 عناصر × 3 مراحل × 40ms تكتمل في ~الحد الأدنى الأنبوبي لا التسلسلي")
async def t_pipeline_concurrency():
    async def delay(x):
        await asyncio.sleep(0.04)
        return x

    p = Pipeline([delay, delay, delay], capacity=8)
    t0 = time.monotonic()
    for i in range(6):
        await p.put(i)
    closer = asyncio.ensure_future(p.close())
    got = await p.collect(6)
    await closer
    wall = time.monotonic() - t0
    assert got == list(range(6))
    assert wall >= 0.28, f"أسرع من الحد النظري — الأرقام مزورة؟ {wall:.3f}s"
    assert wall < 0.70, f"لا توازي حقيقي بين المراحل (تسلسلي ≈ 0.72s): {wall:.3f}s"


@test("pipeline_drop_and_errors", "DROP يصفّي والعنصر الفاشل يُسقط ويسجَّل — الخط لا يموت")
async def t_pipeline_drop():
    async def filter_even(x):
        return x if x % 2 == 0 else DROP

    async def fail_on_six(x):
        if x == 6:  # 6 يعبر المرحلة الأولى (زوجي) ليفشل في الثانية — عزل الطبقتين
            raise ValueError("six")
        return x

    p = Pipeline([filter_even, fail_on_six], capacity=8)
    for i in range(10):
        await p.put(i)
    closer = asyncio.ensure_future(p.close())
    got = await p.collect(10, timeout=1.0)
    await closer
    assert got == [0, 2, 4, 8], f"التصفية/الإسقاط خاطئ: {got}"
    assert any("six" in e for e in p.errors), "فشل المرحلة لم يُسجَّل"


# ═══════════════════════ (و) العمودي ═══════════════════════

@test("encoding_roundtrips", "RLE/Delta/zigzag: عودة الطريق بالضبط على مدخلات عشوائية وحدّية (بذرة ثابتة)")
async def t_encoding_roundtrip():
    rng = random.Random(42)
    runs = [7] * 100 + [3] * 50 + ["x"] * 10
    assert rle_decode(rle_encode(runs)) == runs
    ints = [rng.randint(-10**6, 10**6) for _ in range(500)]
    assert delta_decode(delta_encode(ints)) == ints
    assert rle_decode(rle_encode([])) == []
    assert delta_decode(delta_encode([])) == []
    for n in (0, 1, -1, 2, -2, 10**9, -10**9):
        assert zigzag_decode(zigzag_encode(n)) == n


@test("block_encoding_choice_and_size", "اختيار الترميز صادق: ثابت→rle، مرتب→delta، عشوائي→none، والحجم يتبع")
async def t_block_choice():
    b_const = ColumnBlock("c", [7] * 100)
    assert b_const.encoding == "rle", f"الثابت يجب rle: {b_const.encoding}"
    b_sorted = ColumnBlock("i", list(range(1000)))
    assert b_sorted.encoding == "delta", f"المرتب يجب delta: {b_sorted.encoding}"
    rng = random.Random(7)
    b_rand = ColumnBlock("r", [rng.randint(0, 10**6) for _ in range(500)])
    assert b_rand.encoding == "none", f"العشوائي بلا ضغط حقيقي: {b_rand.encoding}"
    none_sorted = ColumnBlock("i2", list(range(1000)), encoding="none")
    assert b_sorted.estimate_bytes() < none_sorted.estimate_bytes(), "delta لم يصغّر الحجم"
    assert b_const.estimate_bytes() < 10, f"rle الثابت يجب ~2 بايت: {b_const.estimate_bytes()}"
    assert b_const.values() == [7] * 100 and b_sorted.values() == list(range(1000))


@test("scan_pruning_effective_and_correct", "8 كتل مرتبة + Gt(700): تُمسح كتلة واحدة فقط والنتيجة تطابق الاستقصاء (99 صفًا)")
async def t_scan_pruning():
    table = ColumnTable("t", ["id", "v"], block_size=100)
    table.append_rows([{"id": i, "v": i} for i in range(800)])
    out = scan(table, {"v": Gt(700)}, columns=["id"])
    brute = [r["id"] for r in table.all_rows() if r["v"] > 700]
    assert [r["id"] for r in out["rows"]] == brute == list(range(701, 800))
    assert out["stats"]["blocks_total"] == 8
    assert out["stats"]["blocks_scanned"] == 1, f"التقليم لم يعمل: {out['stats']}"
    assert out["stats"]["rows_scanned"] == 100


@test("scan_impossible_prunes_all", "مُسند مستحيل: صفر كتل ممسوحة ونتيجة فارغة (لا عمل بلا جدوى)")
async def t_scan_impossible():
    table = ColumnTable("t", ["v"], block_size=100)
    table.append_rows([{"v": i} for i in range(500)])
    out = scan(table, {"v": Gt(10**9)})
    assert out["rows"] == []
    assert out["stats"]["blocks_scanned"] == 0 and out["stats"]["rows_scanned"] == 0


@test("scan_ne_refinement_sound", "كتلة كل قيمها 42: Ne(42) تُقلَّم بأمان؛ كتلة متنوعة تُمسح — والنتيجتان صحيحتان")
async def t_scan_ne():
    table = ColumnTable("t", ["v"], block_size=100)
    rows = [{"v": 42} for _ in range(100)] + [{"v": (i % 5) * 42} for i in range(100)]
    table.append_rows(rows)
    out = scan(table, {"v": Ne(42)})
    brute = [r for r in table.all_rows() if r["v"] != 42]
    assert [r["v"] for r in out["rows"]] == [r["v"] for r in brute]
    assert out["stats"]["blocks_scanned"] == 1, f"الكتلة المتساوية كان يجب أن تُقلَّم: {out['stats']}"


@test("scan_fuzz_soundness_45_trials", "الإثبات الحاسم: 45 تجربة عشوائية (بذرة ثابتة) — نتائج المسح = الاستقصاء الشامل دائمًا")
async def t_scan_fuzz():
    names = ["ali", "sara", "omar", "laila"]
    pruned_any = False
    for trial in range(45):
        rng = random.Random(1000 + trial)
        table = ColumnTable("t", ["id", "score", "name", "flag"], block_size=100)
        rows = [{
            "id": i,
            "score": rng.randint(0, 1000),
            "name": rng.choice(names),
            "flag": rng.random() < 0.5,
        } for i in range(450)]  # 4 كتل + ذيل 50
        table.append_rows(rows)
        col = rng.choice(["id", "score", "name", "flag"])
        if col == "id":
            cond = rng.choice([Gt(rng.randint(0, 450)), Range(rng.randint(0, 200), rng.randint(200, 450))])
        elif col == "score":
            cond = rng.choice([Eq(rng.randint(0, 1000)), Gt(rng.randint(0, 1000)),
                               Lt(rng.randint(0, 1000)),
                               In((rng.randint(0, 500), rng.randint(500, 1000)))])
        elif col == "name":
            cond = rng.choice([Eq(rng.choice(names)), In(tuple(rng.sample(names, 2))),
                               Ne(rng.choice(names))])
        else:
            cond = Eq(True)
        out = scan(table, {col: cond}, columns=["id"])
        brute = sorted(r["id"] for r in table.all_rows() if cond.test(r[col]))
        got = sorted(r["id"] for r in out["rows"])
        assert got == brute, f"تجربة {trial} عمود {col} {cond}: مسح={len(got)} استقصاء={len(brute)}"
        if out["stats"]["blocks_scanned"] < out["stats"]["blocks_total"]:
            pruned_any = True
    assert pruned_any, "التقليم لم يُفعَّل في أي تجربة — الاختبار لا يختبر شيئًا"


@test("table_digest_determinism", "نفس البذرة → نفس هضم الجدول حرفيًا؛ بذرة مختلفة → هضم مختلف")
async def t_table_digest():
    def build(seed: int) -> str:
        rng = random.Random(seed)
        t = ColumnTable("t", ["id", "score", "name"], block_size=64)
        t.append_rows([{"id": i, "score": rng.randint(0, 999),
                        "name": rng.choice(["a", "b", "c"])} for i in range(300)])
        return t.digest()

    assert build(7) == build(7), "نفس البذرة أنتجت هضمين مختلفين"
    assert build(7) != build(8), "بذرتان مختلفتان أنتجتا نفس الهضم"


# ═══════════════════════ المُشغّل ═══════════════════════

def main() -> int:
    print("=" * 72)
    print("اختبارات المحور-10 — البنية التحتية للأداء (actors / aio / columnar)")
    print("=" * 72)
    passed = failed = 0
    failures: list[str] = []
    for name, rationale, fn in TESTS:
        t0 = time.monotonic()
        try:
            # كلب حراسة لكل اختبار: أي تعليق = فشل معلَل لا تجميد للجناح كله
            asyncio.run(asyncio.wait_for(fn(), timeout=20.0))
            passed += 1
            print(f"  PASS  {name}  ({time.monotonic() - t0:.2f}s)")
        except BaseException as exc:  # noqa: BLE001 — التقرير الكامل هو المطلوب
            failed += 1
            failures.append((name, repr(exc)))
            print(f"  FAIL  {name}: {exc!r}")
    print("-" * 72)
    print(f"النتيجة: {passed}/{len(TESTS)} نجح، {failed} فشل")
    for name, err in failures:
        print(f"  ✗ {name}: {err[:300]}")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
