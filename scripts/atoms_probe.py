#!/usr/bin/env python3
"""فحص استباقي لدلالات حرجة قبل كتابة بطاريات M3 ATOMS.
كل نتيجة هنا تحدد التوكيد الصحيح في الجناح — لا افتراضات."""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, "/home/z/my-project/build-v430")

from sentinel import infra  # noqa: E402


def probe_t3_deposit_cancel():
    """هل إلغاء مهمة إيداع one يسمّم سلسلة الإيداع؟ (تحليل: CancelledError
    BaseException لا يلتقطها except Exception في _deposit)."""
    class Sink(infra.Actor):
        def __init__(self):
            self.n = 0

        async def receive(self, envelope):
            self.n += 1

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("s", Sink)
            t1 = ref.tell("x")
            t1.cancel()  # إلغاء فوري قبل أي جدولة
            await asyncio.sleep(0.02)
            t2 = ref.tell("y")
            try:
                await asyncio.wait_for(t2, 1.0)
                fate2 = "deposited"
            except asyncio.TimeoutError:
                fate2 = "hung"
            except asyncio.CancelledError:
                fate2 = "cancelled-cascade"
            # هل الإيداع الثالث؟
            t3 = ref.tell("z")
            try:
                await asyncio.wait_for(t3, 1.0)
                fate3 = "deposited"
            except asyncio.TimeoutError:
                fate3 = "hung"
            except asyncio.CancelledError:
                fate3 = "cancelled-cascade"
            await asyncio.sleep(0.05)
            return {"t1_cancelled": t1.cancelled(), "fate2": fate2,
                    "fate3": fate3, "n": ref._system.stats().get("s", {}).get("queued", "?")}
        finally:
            await system.shutdown()
    return asyncio.run(body())


def probe_a1_midflight_death():
    """موت الفاعل أثناء معالجة رسالة بطيئة → ask لاحق معلّق → ActorDied؟"""
    class SlowFragile(infra.Actor):
        async def receive(self, envelope):
            m = envelope.message
            if isinstance(m, tuple) and m[0] == "slow":
                await asyncio.sleep(m[1])
                return "done"
            if m == "fail":
                raise ValueError("planned")
            return "pong"

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("v", SlowFragile,
                               policy=infra.OneForOne(max_restarts=0))
            r1 = asyncio.ensure_future(ref.ask(("slow", 0.05), 5.0))
            await asyncio.sleep(0.01)          # E1 داخل receive
            e2 = asyncio.ensure_future(ref.ask("fail", 5.0))     # E2 في الطابور
            await asyncio.sleep(0.005)
            e3 = asyncio.ensure_future(ref.ask("quick", 5.0))    # E3 معلّق
            out = {}
            out["r1"] = await r1
            try:
                await e2
                out["e2"] = "ok?!"
            except ValueError:
                out["e2"] = "ValueError-to-asker"
            try:
                await e3
                out["e3"] = "ok?!"
            except infra.ActorDied:
                out["e3"] = "ActorDied"
            except asyncio.TimeoutError:
                out["e3"] = "TIMEOUT-hang"
            out["dead"] = any(e["kind"] == "dead" and e["actor"] == "v"
                              for e in system.events)
            return out
        finally:
            await system.shutdown()
    return asyncio.run(body())


def probe_a2_shutdown_pending_ask():
    """إغلاق النظام مع ask معلّق (أُودع بعد إغلاق الصندوق) → ActorDied؟"""
    class Slow(infra.Actor):
        async def receive(self, envelope):
            if isinstance(envelope.message, tuple):
                await asyncio.sleep(envelope.message[1])
                return "done"
            return "pong"

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("s", Slow)
            r1 = asyncio.ensure_future(ref.ask(("slow", 0.1), 5.0))
            await asyncio.sleep(0.01)
            shut = asyncio.ensure_future(system.shutdown())
            await asyncio.sleep(0.005)         # الصناديق أُغلقت الآن
            e2 = None
            try:
                e2fut = asyncio.ensure_future(ref.ask("quick", 5.0))
                e2 = await e2fut
                e2 = f"ok:{e2!r}"
            except infra.ActorDied:
                e2 = "ActorDied"
            except asyncio.TimeoutError:
                e2 = "TIMEOUT-hang"
            except RuntimeError as exc:
                e2 = f"RuntimeError:{exc}"
            r1v = await r1
            await shut
            return {"r1": r1v, "e2": e2}
        finally:
            pass
    return asyncio.run(body())


def probe_o13_mailbox_flood_close():
    """إغراق صندوق سعة 4 بمئة إيداع + إغلاق + إلغاء المعلّقين."""
    async def body():
        mb = infra.Mailbox.__new__(infra.Mailbox)
        mb.__init__(capacity=4) if hasattr(mb, "__init__") else None
        mb = infra.Mailbox(4)
        tasks = [asyncio.ensure_future(mb.put(i)) for i in range(100)]
        await asyncio.sleep(0.02)
        qsize_at_peak = mb.qsize()
        mb.close()
        # إلغاء المعلّقين
        n_cancelled = 0
        for t in tasks:
            if not t.done():
                t.cancel()
                n_cancelled += 1
        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await mb.put("fresh")
            fresh = "accepted?!"
        except infra.MailboxClosed:
            fresh = "MailboxClosed-atomic"
        return {"qsize_peak": qsize_at_peak, "cancelled": n_cancelled,
                "fresh_put": fresh}
    return asyncio.run(body())


def probe_t1_stage_cancel():
    """إلغاء مهمة مرحلة أولى أثناء التشغيل → لا انهيار + خط جديد يعمل؟"""
    async def body():
        async def slow_double(x):
            await asyncio.sleep(0.001)
            return x * 2

        async def inc(x):
            return x + 1

        p = infra.Pipeline([slow_double, inc], capacity=4)
        puts = [asyncio.ensure_future(p.put(i)) for i in range(20)]
        await asyncio.sleep(0.02)
        p._tasks[0].cancel()
        await asyncio.sleep(0.01)
        for t in puts:
            t.cancel()
        for t in puts:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        # قابلية التشغيل: خط جديد كامل
        p2 = infra.Pipeline([slow_double, inc], capacity=4)
        for i in range(5):
            await p2.put(i)
        await p2.close()
        out = await p2.collect(5, timeout=3.0)
        return {"p2_results": sorted(out),
                "p2_ok": sorted(out) == [2 * i + 1 for i in range(5)]}
    return asyncio.run(body())


def probe_t2_cell_task_cancel():
    """إلغاء مهمة خلية فاعل مباشرة → إغلاق نظيف؟"""
    class Ping(infra.Actor):
        async def receive(self, envelope):
            return "pong"

    async def body():
        system = infra.ActorSystem()
        try:
            ref = system.spawn("victim", Ping)
            await asyncio.sleep(0.01)
            system._cells["victim"].task.cancel()
            await asyncio.sleep(0.01)
            still_listed = "victim" in system.stats()
            t0 = time.perf_counter()
            await system.shutdown(timeout=5.0)
            return {"still_listed_after_cancel": still_listed,
                    "shutdown_s": round(time.perf_counter() - t0, 3)}
        finally:
            pass
    return asyncio.run(body())


def probe_writer_close_twice_and_put_after_close():
    """إغلاق مزدوج للكاتب + put بعد إغلاق خط."""
    async def body():
        got = []

        async def sink(batch):
            got.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.01,
                                max_pending=64).start()
        for i in range(3):
            await w.submit(f"l{i}")
        await w.close()
        w1 = w.written_lines
        try:
            await w.close()
            second = "clean"
        except BaseException as exc:
            second = f"RAISED:{exc!r}"
        p = infra.Pipeline([(lambda x: x)], capacity=2)
        await p.close()
        try:
            await p.put(1)
            put_after = "accepted?!"
        except RuntimeError:
            put_after = "RuntimeError-atomic"
        return {"written": w1, "close2": second, "put_after_close": put_after,
                "sink_batches": len(got)}
    return asyncio.run(body())


def probe_3c_round_timing():
    """زمن دورة واحدة كاملة (3 أحجام × 10k رسالة) لتقدير زمن 200 دورة."""
    class Recorder(infra.Actor):
        def __init__(self):
            self.n = 0
            self.seqs = []

        async def receive(self, envelope):
            self.n += 1
            self.seqs.append(envelope.message[0])

    async def pool_run(size, stream):
        system = infra.ActorSystem()
        try:
            recs = []

            def factory():
                r = Recorder()
                recs.append(r)
                return r

            pool = infra.WorkerPool(system, "p", factory, size,
                                    mailbox_capacity=1024)
            t0 = time.perf_counter()
            await asyncio.gather(*[pool.tell(k, m) for k, m in stream])
            total = sum(r.n for r in recs)
            while total < len(stream):
                await asyncio.sleep(0.002)
                total = sum(r.n for r in recs)
            el = time.perf_counter() - t0
            seqs = sorted(s for r in recs for s in r.seqs)
            ok = seqs == list(range(len(stream)))
            return {"size": size, "delivered": total, "exact": ok,
                    "per_worker": [r.n for r in recs], "s": round(el, 3)}
        finally:
            await system.shutdown(timeout=10.0)

    async def body():
        stream = [(f"acct-{(s * 7919) % 512}", (s, f"m{s}"))
                  for s in range(10_000)]
        return [await pool_run(sz, stream) for sz in (1, 2, 4)]
    return asyncio.run(body())


if __name__ == "__main__":
    t0 = time.perf_counter()
    print("T3 deposit-cancel:", probe_t3_deposit_cancel())
    print("A1 midflight-death:", probe_a1_midflight_death())
    print("A2 shutdown-pending-ask:", probe_a2_shutdown_pending_ask())
    print("O13 mailbox-flood:", probe_o13_mailbox_flood_close())
    print("T1 stage-cancel:", probe_t1_stage_cancel())
    print("T2 cell-task-cancel:", probe_t2_cell_task_cancel())
    print("W/P close-guards:", probe_writer_close_twice_and_put_after_close())
    r = probe_3c_round_timing()
    print("3c one round:", r)
    per_round = sum(x["s"] for x in r)
    print(f"3c estimate: {per_round:.2f}s/round -> 200 rounds ~= "
          f"{per_round * 200 / 60:.1f} min")
    print(f"total probe {time.perf_counter() - t0:.1f}s")
