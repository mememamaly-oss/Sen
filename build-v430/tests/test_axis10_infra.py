#!/usr/bin/env python3
"""SENTINEL Axis-10 suite — البنية التحتية: Actors / Async I/O / Columnar.

PROVENANCE (معلنة بأمانة، مقدَّمة):
- جدول الحالات أدناه هو الجدول الحرفي للمشرف من أمر البناء الشامل
  2026-10-17 («إغلاق المحور 10 رسمياً — المحتوى موجود، يحتاج بوابة
  خمسية فقط»). هذا هو جدول-H المعتمد الذي كانت القاعدة-1 المنتصبة
  عند 5975d38 / 7ea2de4 تنتظره («axis-10 rebuild awaits the supervisor's
  H-table approval» / «no H-table on record for axis-10»). لا اشتقاق هنا.
- هدف التنفيذ (محطة M2) هو المحتوى المسترد: perf/actors + perf/aio +
  perf/columnar (استُرد في 91267c5، ونجح جناحه المسترد 40/40 عند
  7ea2de4 — لكن بإطار صادق: نجاح جناح، لا إغلاق خماسي، وصفر ادعاءات
  أداء). عقد هذه البطارية يُنفَّذ عبر واجهة sentinel.infra التي ستربط
  المحتوى المسترد — لا إعادة كتابة.
- كل حالة تستورد sentinel.infra داخل جسمها (وليس على مستوى الوحدة)
  حتى تكون المحطة الحمراء 0/20 بنمط فشل واحد حرفياً:
  ModuleNotFoundError: No module named 'sentinel.infra'.
- جناح مستقل، غير مُسجَّل في @case — عقد النواة 227×19=4313 لا يُمس
  بالبناء (برهان المحاور 1/2/3 المعاد).
- انضباط الهضم: التيار المنطقي فقط (نتائج الحالات) — أزمنة الحائط
  تُسجَّل ولا تدخل الهضم أبداً (انضباط المحور 11).

جدول الحالات (حرفياً من أمر المشرف — لا حالة بلا تعليل):
  H10_01 — Actor يستقبل رسالة ويردّ: يثبت الدورة الأساسية
  H10_02 — Actor ميت يرفض الرسائل ذرياً: يثبت العزل
  H10_03 — المشرف يعيد تشغيل Actor فاشل: يثبت restart
  H10_04 — تصعيد بعد N فشل متتالٍ: يثبت escalate
  H10_05 — نافذة إعادة التشغيل تنتهي: يثبت الحد الزمني
  H10_06 — الكاتب المجمّع يكتب دفعة: يثبت batch write
  H10_07 — سلسلة الهضم قابلة لإعادة الحساب: يثبت
             SHA256 متطابق عند إعادة الحساب
  H10_08 — الضغط الخلفي يوقف الإنتاج: يثبت backpressure
  H10_09 — خط الأنابيب يصرف الكتابة: يثبت drain
  H10_10 — التخزين العمودي يشفّر الصف: يثبت encoding
  H10_11 — التقليم على عمود مرتب يتخطى ≥50% صفوف:
             يثبت pruning فعّال
  H10_12 — التقليم يُعطي نفس النتيجة مع الاستقصاء الشامل:
             يثبت السلامة
  H10_13 — 3 حزم بذور مختلفة تعطي digests مختلفة:
             يثبت الحتمية الداخلية
  H10_14 — نفس البذرة مرتين تعطي digest متطابقاً:
             يثبت التكرار الحتمي
  H10_15 — الكاتب المجمّع يرفض الكتابة بعد الإغلاق:
             يثبت الإغلاق الآمن
  H10_16 — Actor Pool يوزع العمل على N عمال:
             يثبت التوازي
  H10_17 — قياس throughput حقيقي ≥ 50k رسالة/ث:
             يثبت الأداء الفعلي (ليس تقديرياً)
  H10_18 — قياس throughput كاتب ≥ 100k صف/ث:
             يثبت الأداء الفعلي
  H10_19 — ضغط delta يحقق خصم ≥ 25% فعلياً:
             يثبت العتبة المعنوية (ليست تافهة)
  H10_20 — فريق أحمر: Actor تحت حمل 10x لا ينهار:
             يثبت المتانة العدائية

عقد الواجهة المطلوب من sentinel.infra في M2 (ما تستورده هذه البطارية):
  Actors    : Actor, ActorRef, ActorSystem, ActorNotFound, ActorDied,
              Directive, FailureContext, OneForOne, WorkerPool
  Async I/O : BatchedWriter, WriterClosed, Pipeline, DROP,
              recompute_chain_digest, EMPTY_DIGEST
  Columnar  : ColumnTable, ColumnBlock, scan,
              Eq, Ne, Gt, Gte, Lt, Lte, In, Range
  Bench     : bench_actor_throughput, bench_writer_throughput
  (سلسلة الهضم في العقد SHA256 — لا blake2b كما في الجناح المسترد؛
   الفارق مقصود بأمر المشرف الحرفي H10_07.)

Usage:
  python3 -m pytest tests/test_axis10_infra.py --tb=short -q
  python3 tests/test_axis10_infra.py --out results/axis10/axis10_RED.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _infra():
    """هدف M2. حتى وجود sentinel/infra.py كل حالة تفشل RED بالنمط
    الواحد: ModuleNotFoundError: No module named 'sentinel.infra'."""
    import sentinel.infra as infra
    return infra


# ============================================================ مساعدات
async def _wait_event(system, kind: str, actor: str | None = None,
                      timeout: float = 5.0) -> dict:
    """انتظار حدث في سجل النظام (تسمح بجدولة الحلقة — لا انتظار ميت)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for e in system.events:
            if e["kind"] == kind and (actor is None or e["actor"] == actor):
                return e
        await asyncio.sleep(0.001)
    raise TimeoutError(f"الحدث {kind!r} لـ {actor!r} لم يُسجَّل خلال {timeout}s")


async def _wait_cond(cond, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        await asyncio.sleep(0.001)
    raise TimeoutError("الشرط لم يتحقق خلال المهلة")


def _chain_digest_reference(batches) -> str:
    """المرجع المستقل لسلسلة الهضم (SHA256) — يعاد كتابته هنا عمداً
    ليكون الاختبار برهاناً ذاتياً لا دائرة مصادقة على التنفيذ نفسه:
    d0 = EMPTY_DIGEST ; di = SHA256(prev + "|" + len(batch) + "|" +
    الأسطر مفصولة بـ \\x1e)."""
    d = "0" * 64
    for batch in batches:
        h = hashlib.sha256()
        h.update(d.encode("ascii"))
        h.update(b"|" + str(len(batch)).encode() + b"|")
        for b in batch:
            h.update(b)
            h.update(b"\x1e")
        d = h.hexdigest()
    return d


# ============================================================ H10_01
def test_H10_01():
    """H10_01 — Actor يستقبل رسالة ويردّ: يثبت الدورة الأساسية."""
    infra = _infra()

    class Echo(infra.Actor):
        async def receive(self, envelope):
            return ("echo", envelope.message)

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("echo", Echo)
            reply = await ref.ask({"op": "ping", "n": 1}, timeout=5.0)
            assert reply == ("echo", {"op": "ping", "n": 1}), \
                f"الرد غير مطابق: {reply!r}"
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_02
def test_H10_02():
    """H10_02 — Actor ميت يرفض الرسائل ذرياً: يثبت العزل."""
    infra = _infra()

    class Boom(infra.Actor):
        async def receive(self, envelope):
            raise RuntimeError("boom")

    async def body():
        system = infra.ActorSystem()
        try:
            # max_restarts=0 → الفشل الأول يخترق الحد → ESCALATE → موت
            ref = system.spawn("boom", Boom,
                               policy=infra.OneForOne(max_restarts=0))
            try:
                await ref.ask("go", timeout=5.0)
                raise AssertionError("كان يجب أن يفشل الطلب الأول")
            except RuntimeError:
                pass  # فشل receive وصل إلى السائل كما هو معلن
            await _wait_event(system, "dead", "boom")
            assert "boom" not in system.stats(), "الفاعل الميت ما زال في الجدول"
            # الرفض الذري: tell وask يُرفضان قبل أي إيداع — لا حالة جزئية
            try:
                system.tell("boom", "late")
                raise AssertionError("tell بعد الموت كان يجب أن يُرفض")
            except infra.ActorNotFound:
                pass
            try:
                await system.ask("boom", "late")
                raise AssertionError("ask بعد الموت كان يجب أن يُرفض")
            except infra.ActorNotFound:
                pass
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_03
def test_H10_03():
    """H10_03 — المشرف يعيد تشغيل Actor فاشل: يثبت restart."""
    infra = _infra()

    class Counter(infra.Actor):
        def __init__(self):
            self.n = 0

        async def receive(self, envelope):
            m = envelope.message
            if m == "state":
                return self.n
            if m == "bump":
                self.n += 1
                return self.n
            if m == "fail":
                raise ValueError("planned")
            raise ValueError(f"رسالة غير معروفة: {m!r}")

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("c", Counter,
                               policy=infra.OneForOne(
                                   on_failure=infra.Directive.RESTART,
                                   max_restarts=3))
            assert await ref.ask("bump", 5.0) == 1
            assert await ref.ask("bump", 5.0) == 2
            try:
                await ref.ask("fail", 5.0)
                raise AssertionError("كان يجب أن تفشل رسالة fail")
            except ValueError:
                pass
            await _wait_event(system, "restarted", "c")
            # إعادة التشغيل = مثيل جديد بحالة صفرية، وصندوق البريد محفوظ
            assert await ref.ask("state", 5.0) == 0, "الحالة لم تُصفَّر"
            assert await ref.ask("bump", 5.0) == 1, "الفاعل لا يعمل بعد restart"
            restarts = [e for e in system.events
                        if e["kind"] == "restarted" and e["actor"] == "c"]
            assert len(restarts) == 1, f"عدد عمليات restart: {len(restarts)}"
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_04
def test_H10_04():
    """H10_04 — تصعيد بعد N فشل متتالٍ: يثبت escalate."""
    infra = _infra()

    class Fragile(infra.Actor):
        async def receive(self, envelope):
            raise ValueError("always")

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("frag", Fragile,
                               policy=infra.OneForOne(
                                   on_failure=infra.Directive.RESTART,
                                   max_restarts=2,
                                   on_breach=infra.Directive.ESCALATE))
            for i in range(3):
                try:
                    await ref.ask("go", 5.0)
                    raise AssertionError("كان يجب أن يفشل")
                except ValueError:
                    pass
                if i < 2:
                    await _wait_event(system, "restarted", "frag")
            dead = await _wait_event(system, "dead", "frag")
            assert dead["directive"] == "escalate", \
                f"التوجيه النهائي ليس escalate: {dead!r}"
            restarts = [e for e in system.events
                        if e["kind"] == "restarted" and e["actor"] == "frag"]
            assert len(restarts) == 2, \
                f"المطلوب restart×2 قبل التصعيد، وجد {len(restarts)}"
            assert "frag" not in system.stats(), "المصعَّد ما زال حياً"
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_05
def test_H10_05():
    """H10_05 — نافذة إعادة التشغيل تنتهي: يثبت الحد الزمني."""
    infra = _infra()

    class Fragile(infra.Actor):
        async def receive(self, envelope):
            raise ValueError("always")

    async def body():
        t = {"now": 100.0}
        system = infra.ActorSystem(window_s=10.0, clock=lambda: t["now"])
        try:
            ref = system.spawn("w", Fragile,
                               policy=infra.OneForOne(
                                   on_failure=infra.Directive.RESTART,
                                   max_restarts=1,
                                   on_breach=infra.Directive.ESCALATE))

            async def fail():
                try:
                    await ref.ask("go", 5.0)
                    raise AssertionError("كان يجب أن يفشل")
                except ValueError:
                    pass

            # فشل @100 → restart (العدّاد داخل النافذة = 1)
            await fail()
            await _wait_event(system, "restarted", "w")

            # تقدُّم الزمن المنطقي خارج النافذة: الإعادة القديمة تنتهي صلاحيتها
            t["now"] = 111.0
            await fail()
            await _wait_event(system, "restarted", "w")
            restarts = [e for e in system.events
                        if e["kind"] == "restarted" and e["actor"] == "w"]
            assert len(restarts) == 2, \
                "انتهاء النافذة كان يجب أن يسمح بإعادة تشغيل ثانية"
            assert restarts[0]["ts"] == 100.0 and restarts[1]["ts"] == 111.0, \
                f"الطوابع الزمنية المنطقية غير مطابقة: {restarts!r}"

            # داخل النافذة الجديدة: إعادة واحدة مسجَّلة → الفشل التالي يصعَّد
            t["now"] = 111.5
            await fail()
            dead = await _wait_event(system, "dead", "w")
            assert dead["directive"] == "escalate", \
                f"الحد داخل النافذة لم يُطبَّق: {dead!r}"
            assert dead["ts"] == 111.5, f"طابع زمني غير متوقع: {dead!r}"
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_06
def test_H10_06():
    """H10_06 — الكاتب المجمّع يكتب دفعة: يثبت batch write."""
    infra = _infra()

    async def body():
        batches: list[list[bytes]] = []

        async def sink(batch):
            batches.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.02)
        w.start()
        try:
            for i in range(8):
                ok = await w.submit(f"line-{i}")
                assert ok is True, f"السطر {i} رُفض"
            await _wait_cond(lambda: w.batches >= 1 and w.written_lines == 8)
            assert any(len(b) == 8 for b in batches), \
                f"لم تُكتب دفعة كاملة من 8: {batches!r}"
            flat = [x for b in batches for x in b]
            assert flat == [f"line-{i}".encode() for i in range(8)], \
                "الأسطر غير مكتملة أو بغير الترتيب"
        finally:
            await w.close()
        assert w.written_lines == 8 and w.errors == [], \
            f"written_lines={w.written_lines} errors={w.errors!r}"

    asyncio.run(body())


# ============================================================ H10_07
def test_H10_07():
    """H10_07 — سلسلة الهضم قابلة لإعادة الحساب: يثبت SHA256 متطابق
    عند إعادة الحساب."""
    infra = _infra()

    async def body():
        batches: list[list[bytes]] = []

        async def sink(batch):
            batches.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=16, flush_interval_s=0.02,
                                max_pending=4096)
        w.start()
        n = 40
        for i in range(n):
            assert await w.submit(f"row-{i:04d}")
        await _wait_cond(lambda: w.written_lines == n)
        await w.close()

        final = w.last_digest
        assert isinstance(final, str) and len(final) == 64, \
            f"الهضم ليس SHA256 (64 hex): {final!r}"

        # (1) إعادة الحساب من ما استلمه sink عبر دالة العقد
        recomputed = infra.recompute_chain_digest(batches)
        assert recomputed == final, \
            f"إعادة الحساب disagreed: {recomputed} != {final}"

        # (2) نقاء الدالة: استدعاءان متطابقان
        assert infra.recompute_chain_digest(batches) == recomputed

        # (3) مرجع مستقل داخل الاختبار (برهان ذاتي لا مصادقة دائرية)
        reference = _chain_digest_reference(batches)
        assert reference == final, \
            f"السلسلة لا تطابق مرجع SHA256 المستقل: {reference} != {final}"

        # (4) السلسلة فارغة → الهضم الفارغ المعلن
        assert infra.recompute_chain_digest([]) == infra.EMPTY_DIGEST

    asyncio.run(body())


# ============================================================ H10_08
def test_H10_08():
    """H10_08 — الضغط الخلفي يوقف الإنتاج: يثبت backpressure."""
    infra = _infra()

    async def body():
        release = asyncio.Event()

        async def blocked_sink(batch):
            await release.wait()  # الحوض متعطل عمداً

        w = infra.BatchedWriter(blocked_sink, batch_size=4,
                                flush_interval_s=0.02, max_pending=4)
        w.start()
        try:
            # الدفعة الأولى (4) تلتقطها حلقة الكاتب وتعلق عند الحوض
            for i in range(4):
                assert await w.submit(f"l{i}")
            await asyncio.sleep(0.15)  # حلقة الكاتب تمسك الدفعة وتتعطل

            # طابور الانتظار يمتلئ (4) ثم الإنتاج يتوقف — لا إسقاط
            for i in range(4, 8):
                assert await w.submit(f"l{i}")

            stuck = asyncio.ensure_future(w.submit("l8"))
            await asyncio.sleep(0.1)
            assert not stuck.done(), \
                "الإنتاج لم يتوقف عند امتلاء الطابور (لا ضغط خلفي)"
            assert not stuck.cancelled(), "الإنتاج أُلغي بدل الانتظار"

            release.set()  # تحرير الحوض
            assert await asyncio.wait_for(stuck, 5.0) is True, \
                "السطر المكتوم لم يُقبل بعد التحرير"
        finally:
            await w.close()
        assert w.written_lines == 9, \
            f"المكتوب {w.written_lines} والمطلوب 9 — فقد أثناء الضغط"
        assert w.errors == [], f"أخطاء أثناء الضغط الخلفي: {w.errors!r}"

    asyncio.run(body())


# ============================================================ H10_09
def test_H10_09():
    """H10_09 — خط الأنابيب يصرف الكتابة: يثبت drain."""
    infra = _infra()

    async def body():
        async def double(x):
            return x * 2

        async def inc(x):
            return x + 1

        p = infra.Pipeline([double, inc], capacity=2)
        try:
            for i in range(10):
                await p.put(i)
        finally:
            await p.close()  # إغلاق المدخل → كل مرحلة تصرّف ما عندها

        out = await p.collect(10, timeout=5.0)
        assert sorted(out) == [2 * i + 1 for i in range(10)], \
            f"التصريف لم يحفظ النتائج: {out!r}"
        assert p.dropped == 0, f"عناصر مُسقطة: {p.dropped}"
        assert p.errors == [], f"أخطاء مراحل: {p.errors!r}"
        assert p.processed == [10, 10], f"عدّادات المراحل: {p.processed!r}"

    asyncio.run(body())


# ============================================================ H10_10
def test_H10_10():
    """H10_10 — التخزين العمودي يشفّر الصف: يثبت encoding."""
    infra = _infra()

    async def body():
        tbl = infra.ColumnTable("t", ["id", "kind"], block_size=4)
        rows = [{"id": i, "kind": "scan"} for i in range(8)]
        tbl.append_rows(rows)
        assert tbl.n_rows == 8
        assert len(tbl.blocks) == 2, f"عدد الكتل: {len(tbl.blocks)}"

        b_kind = tbl.blocks[0]["kind"]
        assert b_kind.encoding == "rle", \
            f"عمود ثابت القيمة يجب أن يختار rle: {b_kind.encoding!r}"
        assert b_kind.values() == ["scan"] * 4, "فك rle غير مطابق"
        assert b_kind.encoded == [["scan", 4]], f"ترميز rle: {b_kind.encoded!r}"

        b_id = tbl.blocks[0]["id"]
        assert b_id.values() == [0, 1, 2, 3], "فك ترميز id غير مطابق"

        # ترميز delta صريح على أعداد رتيبة — فقدان صفري
        ts = [1_700_000_000 + i * 3 for i in range(6)]
        blk = infra.ColumnBlock("ts", ts, encoding="delta")
        assert blk.values() == ts, "delta ليس عديم الفقد"

        # رفض ذري لترميز delta على غير الأعداد الصحيحة
        try:
            infra.ColumnBlock("bad", ["a", "b"], encoding="delta")
            raise AssertionError("delta على نصوص كان يجب أن يُرفض")
        except ValueError:
            pass

    asyncio.run(body())


# ============================================================ H10_11
def test_H10_11():
    """H10_11 — التقليم على عمود مرتب يتخطى ≥50% صفوف: يثبت pruning
    فعّال."""
    infra = _infra()

    async def body():
        tbl = infra.ColumnTable("t", ["v"], block_size=100)
        tbl.append_rows([{"v": i} for i in range(1000)])  # مرتب 0..999
        res = infra.scan(tbl, {"v": infra.Gt(500)})
        st = res["stats"]
        total = tbl.n_rows
        skipped = total - st["rows_scanned"]
        assert st["blocks_total"] == 10
        assert skipped / total >= 0.50, \
            f"التقليم تخطى {skipped}/{total} فقط — ليس فعّالاً"
        assert st["matched"] == 499, f"المطابقات: {st['matched']} والمطلوب 499"
        assert len(res["rows"]) == 499

    asyncio.run(body())


# ============================================================ H10_12
def test_H10_12():
    """H10_12 — التقليم يُعطي نفس النتيجة مع الاستقصاء الشامل: يثبت
    السلامة."""
    infra = _infra()
    import random

    async def body():
        rng = random.Random(1234)
        rows = [{"v": rng.randrange(0, 500),
                 "k": rng.choice("ab")} for _ in range(500)]
        tbl = infra.ColumnTable("t", ["v", "k"], block_size=32)
        tbl.append_rows(rows)

        predicates = [
            {"v": infra.Gt(250)},
            {"v": infra.Range(100, 200)},
            {"v": infra.Eq(42)},
            {"v": infra.In((7, 77, 777))},
            {"v": infra.Lte(10)},
            {"v": infra.Ne(0)},
            {"k": infra.Eq("a")},
            {"v": infra.Gte(400), "k": infra.Eq("b")},
        ]
        for where in predicates:
            res = infra.scan(tbl, where)
            brute = [dict(r) for r in tbl.all_rows()
                     if all(cond.test(r[c]) for c, cond in where.items())]
            assert res["rows"] == brute, \
                f"التقليم خالف الاستقصاء الشامل عند {where!r}: " \
                f"{len(res['rows'])} != {len(brute)}"

    asyncio.run(body())


# ============================================================ H10_13
def test_H10_13():
    """H10_13 — 3 حزم بذور مختلفة تعطي digests مختلفة: يثبت الحتمية
    الداخلية."""
    infra = _infra()
    import random

    def build(seed: int) -> str:
        rng = random.Random(seed)
        tbl = infra.ColumnTable(f"t{seed}", ["v", "k"], block_size=64)
        tbl.append_rows([{"v": rng.randrange(10 ** 6),
                          "k": rng.choice("xyz")} for _ in range(300)])
        return tbl.digest()

    async def body():
        d1, d2, d3 = build(1), build(2), build(3)
        assert len({d1, d2, d3}) == 3, \
            f"بذور مختلفة أعطت هضوماً متطابقة: {d1} {d2} {d3}"

    asyncio.run(body())


# ============================================================ H10_14
def test_H10_14():
    """H10_14 — نفس البذرة مرتين تعطي digest متطابقاً: يثبت التكرار
    الحتمي."""
    infra = _infra()
    import random

    def build(seed: int) -> str:
        rng = random.Random(seed)
        tbl = infra.ColumnTable("t", ["v"], block_size=64)
        tbl.append_rows([{"v": rng.randrange(10 ** 6)} for _ in range(300)])
        return tbl.digest()

    async def body():
        assert build(42) == build(42), "نفس البذرة أعطت هضمين مختلفين"

    asyncio.run(body())


# ============================================================ H10_15
def test_H10_15():
    """H10_15 — الكاتب المجمّع يرفض الكتابة بعد الإغلاق: يثبت الإغلاق
    الآمن."""
    infra = _infra()

    async def body():
        batches: list[list[bytes]] = []

        async def sink(batch):
            batches.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=4, flush_interval_s=0.02)
        w.start()
        assert await w.submit("a")
        await w.close()

        try:
            await w.submit("b")
            raise AssertionError("الكتابة بعد الإغلاق كانت يجب أن تُرفض")
        except infra.WriterClosed:
            pass

        # رفض ذري: لا كتابة جزئية بعد الإغلاق
        assert w.written_lines == 1, \
            f"كتابة جزئية بعد الإغلاق: written_lines={w.written_lines}"
        flat = [x for b in batches for x in b]
        assert flat == [b"a"], f"وصل للحوض أكثر من المكتوب: {flat!r}"

    asyncio.run(body())


# ============================================================ H10_16
def test_H10_16():
    """H10_16 — Actor Pool يوزع العمل على N عمال: يثبت التوازي."""
    infra = _infra()

    class Worker(infra.Actor):
        def __init__(self):
            self.count = 0

        async def receive(self, envelope):
            if envelope.message == "count":
                return self.count
            self.count += 1

    async def body():
        system = infra.ActorSystem()
        try:
            pool = infra.WorkerPool(system, "pool", Worker, size=4,
                                    mailbox_capacity=4096)
            keys = [f"key-{i}" for i in range(200)]
            tasks = [pool.tell(k, "job") for k in keys]
            await asyncio.gather(*tasks)  # كل الإيداعات اكتملت

            # عدّ كل عامل: الطلب يقع في طابور العامل بعد كل وظائفه (FIFO)
            counts = []
            for i in range(4):
                counts.append(await system.ask(f"pool-w{i}", "count", 5.0))

            assert sum(counts) == 200, \
                f"فقد في التوزيع: مجموع العدّادات {sum(counts)} != 200"
            assert all(c >= 1 for c in counts), \
                f"عامل بلا عمل — التوزيع لا يغطي كل العمال: {counts!r}"
            # التجزئة المتسقة: نفس المفتاح → نفس العامل (نقاء التوجيه)
            assert len({pool.worker_index(k) for k in keys}) <= 4
            assert pool.worker_index("key-7") == pool.worker_index("key-7")
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ H10_17
def test_H10_17():
    """H10_17 — قياس throughput حقيقي ≥ 50k رسالة/ث: يثبت الأداء الفعلي
    (ليس تقديرياً)."""
    infra = _infra()

    async def body():
        stats = await infra.bench_actor_throughput(n_messages=60_000,
                                                   n_workers=8)
        # قياس فعلي: أرقام مسجَّلة لا تقديرات
        assert stats["messages"] == 60_000, f"الرسائل: {stats['messages']}"
        assert stats["delivered"] == 60_000, \
            f"المُسلَّم {stats['delivered']} != 60_000 — فقد أثناء القياس"
        assert stats["elapsed_s"] > 0, "زمن غير صالح"
        assert stats["msgs_per_s"] >= 50_000, \
            f"الأداء الفعلي {stats['msgs_per_s']:.0f} رسالة/ث < 50,000"
        assert stats["workers"] == 8

    asyncio.run(body())


# ============================================================ H10_18
def test_H10_18():
    """H10_18 — قياس throughput كاتب ≥ 100k صف/ث: يثبت الأداء الفعلي."""
    infra = _infra()

    async def body():
        stats = await infra.bench_writer_throughput(n_rows=300_000,
                                                    batch_size=1_000)
        assert stats["rows"] == 300_000, f"الصفوف: {stats['rows']}"
        assert stats["written_lines"] == 300_000, \
            f"المكتوب {stats['written_lines']} != 300,000 — فقد أثناء القياس"
        assert stats["elapsed_s"] > 0, "زمن غير صالح"
        assert stats["rows_per_s"] >= 100_000, \
            f"أداء الكاتب الفعلي {stats['rows_per_s']:.0f} صف/ث < 100,000"
        assert stats["batches"] >= 1

    asyncio.run(body())


# ============================================================ H10_19
def test_H10_19():
    """H10_19 — ضغط delta يحقق خصم ≥ 25% فعلياً: يثبت العتبة المعنوية
    (ليست تافهة)."""
    infra = _infra()

    async def body():
        # أزمنة رتيبة: الخام كبير البايتات، الفروق صغيرة
        vals = [1_700_000_000 + i * 3 for i in range(1000)]

        auto = infra.ColumnBlock("ts", vals, encoding="auto")
        assert auto.encoding == "delta", \
            f"heuristic لم تختر delta للعمود الرتيب: {auto.encoding!r}"

        raw = infra.ColumnBlock("ts", vals, encoding="none")
        delta = infra.ColumnBlock("ts", vals, encoding="delta")
        raw_b, enc_b = raw.estimate_bytes(), delta.estimate_bytes()
        reduction = 1.0 - (enc_b / raw_b)
        assert reduction >= 0.25, \
            f"الخصم الفعلي {reduction:.1%} < 25% (raw={raw_b}, enc={enc_b})"
        assert delta.values() == vals, "الضغط ليس عديم الفقد"

    asyncio.run(body())


# ============================================================ H10_20
def test_H10_20():
    """H10_20 — فريق أحمر: Actor تحت حمل 10x لا ينهار: يثبت المتانة
    العدائية."""
    infra = _infra()

    class Sink(infra.Actor):
        def __init__(self):
            self.n = 0

        async def receive(self, envelope):
            if envelope.message == "count":
                return self.n
            self.n += 1

    async def body():
        cap = 64
        system = infra.ActorSystem()
        try:
            ref = system.spawn("target", Sink, mailbox_capacity=cap,
                               policy=infra.OneForOne(max_restarts=5))
            # حمل عدائي: 10x سعة الصندوق دفعة واحدة، رسائل منتفخة
            payload = {"seq": 0, "junk": "x" * 64}
            tasks = []
            for i in range(cap * 10):
                payload["seq"] = i
                tasks.append(ref.tell(dict(payload)))
            await asyncio.gather(*tasks)  # كل الإيداعات عبر الضغط الخلفي

            # لا انهيار: لا موت، لا استثناءات خارج السيطرة
            dead = [e for e in system.events
                    if e["kind"] == "dead" and e["actor"] == "target"]
            assert not dead, f"الفاعل مات تحت الحمل: {dead!r}"
            assert "target" in system.stats(), "الفاعل اختفى من الجدول"

            # عدّاد بعد كل الرسائل (FIFO): صفر فقد، صفر تكرار
            n = await ref.ask("count", timeout=10.0)
            assert n == cap * 10, \
                f"تحت الحمل: عولج {n} من {cap * 10} — فقد أو ازدواج"

            # ما زال يجيب بعد العاصفة
            assert "target" in system.stats()
        finally:
            await system.shutdown()

    asyncio.run(body())


# ============================================================ وضع الدليل
def _run_all() -> list[dict]:
    """تشغيل كل الحالات بترتيبها مع التقاط النتائج — التيار المنطقي فقط."""
    names = [n for n in sorted(globals())
             if n.startswith("test_H10_") and callable(globals()[n])]
    results = []
    for name in names:
        fn = globals()[name]
        t0 = time.perf_counter()
        try:
            fn()
            results.append({"name": name, "ok": True, "error": None,
                            "dur_s": round(time.perf_counter() - t0, 6)})
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
            results.append({"name": name, "ok": False, "error": repr(exc),
                            "dur_s": round(time.perf_counter() - t0, 6)})
    return results


def _digest(results: list[dict]) -> str:
    """هضم التيار المنطقي: (اسم الحالة، نجحت؟) فقط — الأزمنة والرسائل
    خارج الهضم (انضباط المحور 11)."""
    h = hashlib.sha256()
    for r in results:
        h.update(f"{r['name']}:{int(r['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-10 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    doc = {
        "suite": "axis10-infra",
        "station": "M1-RED" if passed == 0 else "run",
        "total": total,
        "passed_count": passed,
        "failed": total - passed,
        "passed": passed == total,
        "digest": _digest(results),
        "cases": results,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis10: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['name']}"
              + ("" if r["ok"] else f"  {r['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
