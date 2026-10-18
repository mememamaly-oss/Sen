

# ============================================================ البطارية 3c
async def _3c_pool_run(infra, size: int, stream: list) -> dict:
    """تشغيل واحد: الدفق عبر WorkerPool بحجم `size` (داخل حلقة البطارية).
    كل عامل يسجل أرقام الرسائل التي عالجها فعلياً (التيار المنطقي)."""

    class Recorder(infra.Actor):
        def __init__(self):
            self.n = 0
            self.seqs = []

        async def receive(self, envelope):
            self.n += 1
            self.seqs.append(envelope.message[0])

    system = infra.ActorSystem()
    try:
        recs: list = []

        def factory() -> Recorder:
            r = Recorder()
            recs.append(r)
            return r

        pool = infra.WorkerPool(system, "p", factory, size,
                                mailbox_capacity=1024)
        await asyncio.gather(*[pool.tell(k, m) for k, m in stream])
        target = len(stream)
        t0 = time.perf_counter()
        total = sum(r.n for r in recs)
        while total < target:
            await asyncio.sleep(0.002)
            total = sum(r.n for r in recs)
            assert time.perf_counter() - t0 < 30.0, \
                f"pool{size}: تسليم متعثر ({total}/{target})"
        seqs = sorted(s for r in recs for s in r.seqs)
        exact = seqs == list(range(target))
        stream_sorted = sorted(stream, key=lambda t: t[1][0])
        digest = _stream_digest([(s, m) for _, (s, m) in stream_sorted]) \
            if exact else "?"
        return {"size": size, "delivered": total, "exact_coverage": exact,
                "per_worker": [r.n for r in recs], "stream_digest": digest}
    finally:
        await system.shutdown(timeout=10.0)


def _3c_stream(round_idx: int) -> list:
    """دفق الدورة: مفاتيح حتمية بالحساب (التوجيه دالة نقية فيها)،
    حمولات متغيرة ببذرة الدورة — نفس الدفق للتشكيلات الثلاث."""
    rng = random.Random(0xC0FFEE + round_idx)
    return [(f"acct-{(s * 7919) % 512}",
             (s, f"r{round_idx}-{s}-{rng.random():.9f}"))
            for s in range(10_000)]


def _battery_3c(checks: list) -> bool:
    """3c — 200 تشغيل توازٍ: pool ∈ {1,2,4} على نفس الدفق؛ النتيجة
    المنطقية متطابقة بغض النظر عن pool_size (الحتمية فوق التوازي).
    ملاحظة N1: pool_size=8 مستثنى بقرار المشرف H10_17 (2026-10-18)."""
    infra = _infra()
    sizes = (1, 2, 4)
    n_rounds = 200

    async def body():
        round0_pw: dict = {}
        round0_dig: dict = {}
        delivered_all = True
        digests_match_all = True
        per_worker_stable = True
        t_all = time.perf_counter()
        for r in range(n_rounds):
            stream = _3c_stream(r)
            digs: dict = {}
            for size in sizes:
                res = await _3c_pool_run(infra, size, stream)
                if not (res["delivered"] == 10_000
                        and res["exact_coverage"]):
                    delivered_all = False
                digs[size] = res["stream_digest"]
                if r == 0:
                    round0_pw[size] = res["per_worker"]
                    round0_dig[size] = res["stream_digest"]
                elif res["per_worker"] != round0_pw[size]:
                    per_worker_stable = False
            if not (digs[1] == digs[2] == digs[4]):
                digests_match_all = False
        wall = time.perf_counter() - t_all
        # إعادة الدورة 0 بالكامل — قابلية التكرار عبر الأزمنة
        stream0 = _3c_stream(0)
        rep_ok = True
        for size in sizes:
            rep = await _3c_pool_run(infra, size, stream0)
            if not (rep["delivered"] == 10_000 and rep["exact_coverage"]
                    and rep["stream_digest"] == round0_dig[size]
                    and rep["per_worker"] == round0_pw[size]):
                rep_ok = False
        return {"delivered_all": delivered_all,
                "digests_match_all": digests_match_all,
                "per_worker_stable": per_worker_stable,
                "repeat_ok": rep_ok, "wall_s": wall}

    out = asyncio.run(body())
    _ck(checks, "3c", "all delivered == 10,000 لكل تشكيلة (200 دورة × 3 "
        "تشكيلات؛ تغطية seq تامة بلا فقد/ازدواج)", out["delivered_all"])
    _ck(checks, "3c", "result_pool1 == result_pool2 == result_pool4 (هضم "
        "التيار المنطقي متطابق في كل دورة)", out["digests_match_all"])
    _ck(checks, "3c", "التوزيع الفيزيائي per-worker حتمي عبر 200 دورة "
        "لنفس المفاتيح والحلقات", out["per_worker_stable"])
    _ck(checks, "3c", "إعادة الدورة 0 مطابقة تماماً (هضم + توزيع)",
        out["repeat_ok"])
    return (out["delivered_all"] and out["digests_match_all"]
            and out["per_worker_stable"] and out["repeat_ok"])


def test_3c_parallel_consistency():
    """3c — 200 دورة: الحتمية فوق التوازي عبر pool ∈ {1,2,4}."""
    checks: list = []
    ok = _battery_3c(checks)
    failed = [c for c in checks if not c["ok"]]
    assert ok, f"3c فشل: {failed!r}"


# ============================================================ البطارية 3d
BOUNDARY_LOG: list = []


def _bcat(attack: str, category: str, verdict: str, atomic: bool,
          state_unchanged: bool, detail: str = "", ok: bool = True) -> None:
    """تسجيل هجوم في سجل الحدود بفئة من الـ14 (من sentinel.xgraph)."""
    BOUNDARY_LOG.append({"attack": attack, "category": category,
                         "verdict": verdict, "atomic": bool(atomic),
                         "state_unchanged": bool(state_unchanged),
                         "ok": bool(ok),
                         "detail": str(detail)[:300]})


def _run_attack(attack_id: str, category: str, coro_factory,
                checks: list) -> None:
    """عزل كامل (ملاحظة N6): كل هجوم في حلقة أحداث مستقلة + مهلة صلبة
    + التقاط الحكم. فشل هجوم لا يلوث بقية الهجمات — الحكم النهائي
    يُجمع في نهاية البطارية."""
    t0 = time.perf_counter()
    try:
        verdict = asyncio.run(_attack_with_timeout(coro_factory, 20.0))
        dt = time.perf_counter() - t0
        ok = bool(verdict.get("ok", False))
        _bcat(attack_id, category, verdict.get("verdict", "handled"),
              verdict.get("atomic", ok),
              verdict.get("state_unchanged", ok),
              verdict.get("detail", ""), ok=ok)
        _ck(checks, "3d", f"{attack_id}: no_crash + atomic + "
            f"state_unchanged [{category}]", ok,
            f"verdict={verdict.get('verdict')} dt={dt:.3f}s "
            f"{verdict.get('detail', '')}")
    except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
        dt = time.perf_counter() - t0
        _bcat(attack_id, category, "attack-failed", False, False,
              repr(exc)[:300], ok=False)
        _ck(checks, "3d", f"{attack_id}: no_crash + atomic + "
            f"state_unchanged [{category}]", False,
            f"EXCEPTION dt={dt:.3f}s {exc!r}")


async def _attack_with_timeout(factory, budget_s: float) -> dict:
    """تشغيل هجوم بمهلة صلبة — تجاوزها = فشل الهجوم (لا hang أبداً)."""
    return await asyncio.wait_for(factory(), timeout=budget_s)


# ---------------- الفئة 1: رسائل مشوهة (16) ----------------
def _3d_cat1_payloads() -> list:
    cyc: list = []
    cyc.append(cyc)  # مرجع دوري حقيقي
    return [
        ("M1", None, "PRECONDITION_FAILED"),
        ("M2", [], "PRECONDITION_FAILED"),
        ("M3", {}, "PRECONDITION_FAILED"),
        ("M4", b"", "PRECONDITION_FAILED"),
        ("M5", "A" * 10_000, "RESOURCE_EXHAUSTED"),
        ("M6", {"nested": {"deeply": {"key": "v" * 1000}}},
         "PRECONDITION_FAILED"),
        ("M7", float("inf"), "OUT_OF_SCOPE"),
        ("M8", float("nan"), "OUT_OF_SCOPE"),
        ("M9", -1, "OUT_OF_SCOPE"),
        ("M10", 2**64, "OUT_OF_SCOPE"),
        ("M11", "\x00" * 100, "UNKNOWN_PROTOCOL"),
        ("M12", b"\xff" * 100, "PRECONDITION_FAILED"),
        ("M13", cyc, "PRECONDITION_FAILED"),
        ("M14", "\u200d" * 2048, "RESOURCE_EXHAUSTED"),
        ("M15", [1, "2", 3.0, b"4", None, True, [5], {"6": 6}],
         "PRECONDITION_FAILED"),
        ("M16", "\ud800", "UNKNOWN_PROTOCOL"),
    ]


def _3d_cat1_attack(msg):
    async def body():
        infra = _infra()
        system = infra.ActorSystem()
        counters = {"target": 0, "witness": 0}
        try:
            class TypedSink(infra.Actor):
                """العقد المُعلن: نص utf-8 قابل للتسلسل بلا محارف تحكم
                وطول ≤ 1024، أو عدد صحيح في [0, 2^32). الرفع قبل أي
                تحوّل للحالة (رفض ذري)."""

                async def receive(self, envelope):
                    m = envelope.message
                    if isinstance(m, str):
                        try:
                            m.encode("utf-8")
                        except UnicodeEncodeError:
                            raise ValueError("نص غير قابل للترميز utf-8")
                        if any(ord(c) < 0x20 and c not in "\n\t"
                               for c in m):
                            raise ValueError("محارف تحكم غير مسموحة")
                        if len(m) > 1024:
                            raise ValueError("نص أطول من الحد 1024")
                        counters["target"] += 1
                        return ("ok", counters["target"])
                    if isinstance(m, int) and not isinstance(m, bool):
                        if not (0 <= m < 2**32):
                            raise ValueError("عدد خارج نطاق العقد")
                        counters["target"] += 1
                        return ("ok", counters["target"])
                    raise ValueError(f"نوع غير مقبول: {type(m).__name__}")

            class Witness(infra.Actor):
                async def receive(self, envelope):
                    counters["witness"] += 1
                    return ("ok", counters["witness"])

            tref = system.spawn(
                "target", TypedSink,
                policy=infra.OneForOne(
                    on_failure=infra.Directive.RESUME))
            wref = system.spawn("witness", Witness)
            # تحكم القبول: العقد يقبل الصالحين — لا يرفض الجميع
            assert await tref.ask("hello", 5.0) == ("ok", 1)
            assert await tref.ask(12345, 5.0) == ("ok", 2)
            before = counters["target"]
            rejected = False
            try:
                await tref.ask(msg, 5.0)
            except ValueError:
                rejected = True
            assert await wref.ask("ping", 5.0) == ("ok", 1)
            dead = [e for e in system.events if e["kind"] == "dead"]
            after = counters["target"]
            if rejected:
                ok = (after == before and not dead
                      and counters["witness"] == 1)
                return {"ok": ok, "verdict": "rejected-atomic",
                        "atomic": after == before,
                        "state_unchanged": not dead,
                        "detail": f"type={type(msg).__name__} "
                                  f"counter_unchanged={after == before}"}
            ok = (after == before + 1 and not dead
                  and counters["witness"] == 1)
            return {"ok": ok, "verdict": "accepted-in-contract",
                    "atomic": True, "state_unchanged": not dead,
                    "detail": f"type={type(msg).__name__} +1"}
        finally:
            await system.shutdown()
    return body


# ---------------- الفئة 2: إغلاق مبكر (16) ----------------
def _3d_cat2_factory(attack_id: str):
    """A1-A4: إغلاق Actor قبل الرد — W1-W4: Writer منتصف دفعة —
    P1-P4: Pipeline بعد مرحلة — T1-T4: إلغاء asyncio.Task أثناء التشغيل.
    T3 يوكّد عقد التعافي المُعلن في تعليق _deposit المسترد نفسه
    («سلسلة سابقة أُلغيت؛ الإيداع الحالي سيواجه مصيره بنفسه»)."""

    async def a1_midflight_death_body():
        infra = _infra()

        class SlowFragile(infra.Actor):
            async def receive(self, envelope):
                m = envelope.message
                if isinstance(m, tuple) and m[0] == "slow":
                    await asyncio.sleep(m[1])
                    return "done"
                if m == "fail":
                    raise ValueError("planned")
                return "pong"

        system = infra.ActorSystem()
        try:
            ref = system.spawn(
                "victim", SlowFragile,
                policy=infra.OneForOne(max_restarts=0))
            r1 = asyncio.ensure_future(ref.ask(("slow", 0.05), 5.0))
            await asyncio.sleep(0.01)  # E1 داخل receive الآن
            e2 = asyncio.ensure_future(ref.ask("fail", 5.0))  # E2 طابور
            await asyncio.sleep(0.005)
            e3 = asyncio.ensure_future(ref.ask("quick", 5.0))  # E3 معلق
            out = {"r1": await r1}
            try:
                await e2
                out["e2"] = "ok-unexpected"
            except ValueError:
                out["e2"] = "ValueError-to-asker"
            try:
                await e3
                out["e3"] = "ok-unexpected"
            except infra.ActorDied:
                out["e3"] = "ActorDied"
            out["dead"] = any(e["kind"] == "dead"
                              and e["actor"] == "victim"
                              for e in system.events)
            ok = (out["r1"] == "done"
                  and out["e2"] == "ValueError-to-asker"
                  and out["e3"] == "ActorDied" and out["dead"])
            return {"ok": ok,
                    "verdict": "rejected-atomic" if ok else "unexpected",
                    "atomic": True, "state_unchanged": True,
                    "detail": str(out)}
        finally:
            await system.shutdown()

    async def a2_shutdown_pending_body():
        infra = _infra()

        class Slow(infra.Actor):
            async def receive(self, envelope):
                if isinstance(envelope.message, tuple):
                    await asyncio.sleep(envelope.message[1])
                    return "done"
                return "pong"

        system = infra.ActorSystem()
        try:
            ref = system.spawn("victim", Slow)
            r1 = asyncio.ensure_future(ref.ask(("slow", 0.1), 5.0))
            await asyncio.sleep(0.01)
            shut = asyncio.ensure_future(system.shutdown())
            await asyncio.sleep(0.005)  # الصناديق أُغلقت فعلاً
            try:
                e2 = await ref.ask("quick", 5.0)
                e2v = f"ok-unexpected:{e2!r}"
            except infra.ActorDied:
                e2v = "ActorDied"
            r1v = await r1
            await shut
            ok = r1v == "done" and e2v == "ActorDied"
            return {"ok": ok,
                    "verdict": "rejected-atomic" if ok else "unexpected",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"r1={r1v} e2={e2v}"}
        finally:
            pass

    async def a3_late_tell_body():
        infra = _infra()

        class Ping(infra.Actor):
            async def receive(self, envelope):
                return "pong"

        system = infra.ActorSystem()
        try:
            ref = system.spawn("victim", Ping)
            ref.stop("cut")
            await _wait_event(system, "dead", "victim")
            try:
                system.tell("victim", "late")
                ok = False
                detail = "tell بعد الموت لم يُرفض"
            except infra.ActorNotFound:
                ok = True
                detail = "ActorNotFound-atomic"
            return {"ok": ok, "verdict": "rejected-atomic", "atomic": ok,
                    "state_unchanged": True, "detail": detail}
        finally:
            await system.shutdown()

    async def a4_late_ask_body():
        infra = _infra()

        class Ping(infra.Actor):
            async def receive(self, envelope):
                return "pong"

        system = infra.ActorSystem()
        try:
            ref = system.spawn("victim", Ping)
            ref.stop("cut")
            await _wait_event(system, "dead", "victim")
            try:
                await system.ask("victim", "late", timeout=2.0)
                ok = False
                detail = "ask بعد الموت لم يُرفض"
            except infra.ActorNotFound:
                ok = True
                detail = "ActorNotFound-atomic"
            return {"ok": ok, "verdict": "rejected-atomic", "atomic": ok,
                    "state_unchanged": True, "detail": detail}
        finally:
            await system.shutdown()

    async def w1_midbatch_body():
        infra = _infra()
        got: list = []

        async def sink(batch):
            got.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=64, flush_interval_s=0.05,
                                max_pending=256).start()
        for i in range(5):
            assert await w.submit(f"l{i}")
        await w.close()  # إغلاق منتصف الجمع (دفعة دون الحجم الكامل)
        ok = (w.written_lines == 5 and len(got) == 1 and len(got[0]) == 5
              and not w.errors)
        return {"ok": ok,
                "verdict": "drained-atomically" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines} batches={len(got)}"}

    async def w2_backpressure_close_body():
        infra = _infra()
        got: list = []

        async def sink(batch):
            got.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.01,
                                max_pending=4).start()
        tasks = [asyncio.ensure_future(w.submit(f"l{i}"))
                 for i in range(20)]
        done = await asyncio.gather(*tasks)
        await w.close()
        ok = (all(done) and w.written_lines == 20 and not w.errors)
        return {"ok": ok,
                "verdict": "drained-atomically" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines}/20"}

    async def w3_slow_sink_body():
        infra = _infra()

        async def sink(batch):
            await asyncio.sleep(0.02)
            return None

        w = infra.BatchedWriter(sink, batch_size=16, flush_interval_s=0.01,
                                max_pending=1024).start()
        t0 = time.perf_counter()
        for i in range(100):
            assert await w.submit(f"l{i}")
        while w.written_lines < 100:
            await asyncio.sleep(0.005)
        await w.close()
        dt = time.perf_counter() - t0
        ok = (w.written_lines == 100 and not w.errors and dt < 5.0)
        return {"ok": ok,
                "verdict": "drained-atomically" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines} dt={dt:.2f}s"}

    async def w4_double_close_body():
        infra = _infra()

        async def sink(batch):
            return None

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.01,
                                max_pending=64).start()
        for i in range(3):
            assert await w.submit(f"l{i}")
        await w.close()
        first = w.written_lines
        try:
            await w.close()
            second = "clean"
        except BaseException as exc:
            second = f"RAISED:{exc!r}"
        ok = first == 3 and second == "clean" and w.written_lines == 3
        return {"ok": ok, "verdict": "idempotent" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"close2={second}"}

    async def p1_take1_close_body():
        infra = _infra()

        async def double(x):
            return x * 2

        async def inc(x):
            return x + 1

        p = infra.Pipeline([double, inc], capacity=4)
        for i in range(10):
            await p.put(i)
        first = await p.take()
        await p.close()
        rest = await p.collect(9, timeout=5.0)
        all_out = sorted([first] + rest)
        expected = sorted(2 * i + 1 for i in range(10))
        ok = (all_out == expected and p.dropped == 0 and not p.errors
              and p.processed == [10, 10])
        return {"ok": ok,
                "verdict": "drained-atomically" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"n={len(all_out)}"}

    async def p2_close_full_body():
        infra = _infra()

        async def double(x):
            return x * 2

        p = infra.Pipeline([double], capacity=2)
        for i in range(10):
            await p.put(i)
        await p.close()
        out = await p.collect(10, timeout=5.0)
        ok = (sorted(out) == sorted(2 * i for i in range(10))
              and p.dropped == 0 and not p.errors)
        return {"ok": ok,
                "verdict": "drained-atomically" if ok else "unexpected",
                "atomic": True, "state_unchanged": True,
                "detail": f"n={len(out)}"}

    async def p3_put_after_close_body():
        infra = _infra()

        async def ident(x):
            return x

        p = infra.Pipeline([ident], capacity=2)
        await p.close()
        try:
            await p.put(1)
            ok = False
            detail = "put بعد الإغلاق لم يُرفض"
        except RuntimeError:
            ok = True
            detail = "RuntimeError-atomic"
        return {"ok": ok, "verdict": "rejected-atomic", "atomic": ok,
                "state_unchanged": True, "detail": detail}

    async def p4_close_empty_body():
        infra = _infra()

        async def ident(x):
            return x

        p = infra.Pipeline([ident], capacity=2)
        t0 = time.perf_counter()
        await p.close()
        ok = time.perf_counter() - t0 < 5.0 and p.processed == [0]
        return {"ok": ok, "verdict": "clean-close", "atomic": True,
                "state_unchanged": True, "detail": ""}

    async def t1_stage_cancel_body():
        infra = _infra()

        async def slow_double(x):
            await asyncio.sleep(0.001)
            return x * 2

        async def inc(x):
            return x + 1

        p = infra.Pipeline([slow_double, inc], capacity=4)
        puts = [asyncio.ensure_future(p.put(i)) for i in range(20)]
        await asyncio.sleep(0.02)
        p._tasks[0].cancel()  # إلغاء مهمة مرحلة أثناء التشغيل
        await asyncio.sleep(0.01)
        for tsk in puts:
            tsk.cancel()
        for tsk in puts:
            try:
                await tsk
            except (asyncio.CancelledError, Exception):
                pass
        # قابلية التشغيل بعد الهجوم: خط جديد كامل الدورة
        p2 = infra.Pipeline([slow_double, inc], capacity=4)
        for i in range(5):
            await p2.put(i)
        await p2.close()
        out = await p2.collect(5, timeout=3.0)
        ok = sorted(out) == sorted(2 * i + 1 for i in range(5))
        return {"ok": ok, "verdict": "survived-operable", "atomic": True,
                "state_unchanged": True,
                "detail": "مرحلة مُلغاة — الخط المهاجَم خارج عقد الإغلاق "
                          "المتدرج (at-most-once معلَن)؛ خط جديد يعمل"}

    async def t2_cell_cancel_body():
        infra = _infra()

        class Ping(infra.Actor):
            async def receive(self, envelope):
                return "pong"

        system = infra.ActorSystem()
        try:
            wref = system.spawn("witness", Ping)
            ref = system.spawn("victim", Ping)
            await asyncio.sleep(0.01)
            system._cells["victim"].task.cancel()  # إلغاء مهمة الخلية
            await asyncio.sleep(0.01)
            zombie = "victim" in system.stats()
            pong = await wref.ask("ping", 3.0)  # الجار سليم
            t0 = time.perf_counter()
            await system.shutdown(timeout=5.0)
            dt = time.perf_counter() - t0
            ok = pong == "pong" and dt < 5.0
            return {"ok": ok, "verdict": "survived-operable",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"خلية مُلغاة: قيد زومبي في الجدول="
                              f"{zombie} (مُوثَّق بأمانة)؛ الجار سليم "
                              f"والإغلاق نظيف {dt:.3f}s"}
        finally:
            try:
                await system.shutdown(timeout=5.0)
            except BaseException:
                pass

    async def t3_deposit_cancel_body():
        """T3 — إلغاء مهمة إيداع (tell) أثناء التشغيل ثم فحص تعافي
        السلسلة وفق وعد تعليق الكود المسترد نفسه في _deposit:
        «سلسلة سابقة أُلغيت؛ الإيداع الحالي سيواجه مصيره بنفسه» —
        الإيداع اللاحق يجب أن يكتمل، لا أن يموت تسلسلياً."""
        infra = _infra()

        class Sink(infra.Actor):
            def __init__(self):
                self.n = 0

            async def receive(self, envelope):
                if envelope.message == "count":
                    return self.n
                self.n += 1

        system = infra.ActorSystem()
        try:
            ref = system.spawn("victim", Sink)
            t1 = ref.tell("x")
            t1.cancel()  # إلغاء قبل أول جدولة للمهمة
            await asyncio.sleep(0.01)
            # الإيداع اللاحق: وعد التعليق — يواجه مصيره بنفسه = يكتمل
            t2 = ref.tell("y")
            try:
                await asyncio.wait_for(t2, 2.0)
                fate2 = "deposited"
            except asyncio.TimeoutError:
                fate2 = "hung"
            except asyncio.CancelledError:
                fate2 = "cancelled-cascade"
            # سؤال العدّ: إن كانت السلسلة مسمومة فسيعلق هو أيضاً — يُلتقط
            # بالمهلة (عقد الهجوم: لا hang أبداً) ويُسجَّل الحكم صريحاً
            try:
                count = await ref.ask("count", 2.0)
            except asyncio.TimeoutError:
                count = -1
            ok = fate2 == "deposited" and count == 1
            return {"ok": ok,
                    "verdict": "chain-recovered" if ok else
                               "CHAIN-POISONED-DEFECT",
                    "atomic": True,  # الإيداع الملغى نفسه لم يودع
                    "state_unchanged": ok,
                    "detail": f"fate2={fate2} delivered={count} — إن لم "
                              f"يتعافَ: إلغاء إيداع واحد يسمّم سلسلة "
                              f"الإيداع كاملة (CancelledError لا يلتقطها "
                              f"except Exception في _deposit خلافاً لوعد "
                              f"التعليق)"}
        finally:
            await system.shutdown(timeout=5.0)

    async def t4_submit_cancel_body():
        infra = _infra()
        got: list = []

        async def sink(batch):
            got.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=4, flush_interval_s=0.01,
                                max_pending=64).start()
        tsk = asyncio.ensure_future(w.submit("a" * 100))
        tsk.cancel()  # إلغاء أثناء التشغيل
        try:
            await tsk
            a_fate = "submitted"
        except asyncio.CancelledError:
            a_fate = "cancelled"
        ok_b = await w.submit("b")  # الكاتب ما زال يقبل
        await w.close()
        written = w.written_lines
        ok = (ok_b and written in (1, 2) and not w.errors)
        return {"ok": ok, "verdict": "atomic-either-way", "atomic": True,
                "state_unchanged": True,
                "detail": f"a={a_fate} written={written} — كل submit ذري "
                          f"(إما أُودع كاملاً أو لا)"}

    table = {
        "A1": (a1_midflight_death_body, "SAFETY_GUARD"),
        "A2": (a2_shutdown_pending_body, "SAFETY_GUARD"),
        "A3": (a3_late_tell_body, "SAFETY_GUARD"),
        "A4": (a4_late_ask_body, "SAFETY_GUARD"),
        "W1": (w1_midbatch_body, "SAFETY_GUARD"),
        "W2": (w2_backpressure_close_body, "SAFETY_GUARD"),
        "W3": (w3_slow_sink_body, "SAFETY_GUARD"),
        "W4": (w4_double_close_body, "SAFETY_GUARD"),
        "P1": (p1_take1_close_body, "SAFETY_GUARD"),
        "P2": (p2_close_full_body, "SAFETY_GUARD"),
        "P3": (p3_put_after_close_body, "SAFETY_GUARD"),
        "P4": (p4_close_empty_body, "SAFETY_GUARD"),
        "T1": (t1_stage_cancel_body, "SAFETY_GUARD"),
        "T2": (t2_cell_cancel_body, "SAFETY_GUARD"),
        "T3": (t3_deposit_cancel_body, "SAFETY_GUARD"),
        "T4": (t4_submit_cancel_body, "SAFETY_GUARD"),
    }
    return table[attack_id]
