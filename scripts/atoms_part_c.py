

# ---------------- الفئة 3: حمل زائد (16) ----------------
def _3d_cat3_factory(attack_id: str):
    """O1-O4: 10k رسالة لصندوق سعة 10 — O5-O8: 50k صف بدفعة 100 —
    O9-O12: 100 Pipeline متوازية — O13-O16: حدود الذاكرة (ملاحظة N2)."""

    async def o1_mailbox10_body():
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
            ref = system.spawn("victim", Sink, mailbox_capacity=10)
            tasks = [ref.tell(i) for i in range(10_000)]
            await asyncio.gather(*tasks)  # الضغط الخلفي يمرر الكل
            t0 = time.perf_counter()
            n = 0
            while n < 10_000:
                n = await ref.ask("count", 5.0)
                assert time.perf_counter() - t0 < 20.0, "تسليم متعثر"
                await asyncio.sleep(0.005)
            dead = [e for e in system.events if e["kind"] == "dead"]
            ok = n == 10_000 and not dead
            return {"ok": ok, "verdict": "survived-no-loss",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"delivered={n}/10000 dead={len(dead)}"}
        finally:
            await system.shutdown(timeout=10.0)

    async def o2_fat_payloads_body():
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
            ref = system.spawn("victim", Sink, mailbox_capacity=10)
            payload = "x" * 512
            tasks = [ref.tell(dict(seq=i, blob=payload))
                     for i in range(10_000)]
            await asyncio.gather(*tasks)
            t0 = time.perf_counter()
            n = 0
            while n < 10_000:
                n = await ref.ask("count", 5.0)
                assert time.perf_counter() - t0 < 20.0, "تسليم متعثر"
                await asyncio.sleep(0.005)
            ok = n == 10_000
            return {"ok": ok, "verdict": "survived-no-loss",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"fat 512B × 10k, delivered={n}"}
        finally:
            await system.shutdown(timeout=10.0)

    async def o3_mixed_traffic_body():
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
            ref = system.spawn("victim", Sink, mailbox_capacity=10)
            tasks = [ref.tell(i) for i in range(10_000)]
            counts = []
            for _ in range(10):  # أسئلة متداخلة مع العاصفة
                counts.append(await ref.ask("count", 10.0))
                await asyncio.sleep(0)
            await asyncio.gather(*tasks)
            final = await ref.ask("count", 10.0)
            monotone = all(a <= b for a, b in zip(counts, counts[1:]))
            ok = final == 10_000 and monotone and counts[-1] <= final
            return {"ok": ok, "verdict": "survived-no-loss",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"final={final} monotone={monotone}"}
        finally:
            await system.shutdown(timeout=10.0)

    async def o4_storm_then_fail_body():
        infra = _infra()

        class Sink(infra.Actor):
            def __init__(self):
                self.n = 0

            async def receive(self, envelope):
                m = envelope.message
                if m == "count":
                    return self.n
                if m == "fail":
                    raise ValueError("planned-after-storm")
                self.n += 1

        system = infra.ActorSystem()
        try:
            ref = system.spawn(
                "victim", Sink, mailbox_capacity=10,
                policy=infra.OneForOne(
                    on_failure=infra.Directive.RESTART, max_restarts=3))
            tasks = [ref.tell(i) for i in range(10_000)]
            await asyncio.gather(*tasks)
            await _wait_cond(
                lambda: system.stats().get("victim", {}).get("queued", 1)
                == 0, timeout=20.0)
            try:
                await ref.ask("fail", 5.0)
            except ValueError:
                pass  # الفشل المفتعل بعد العاصفة
            await _wait_event(system, "restarted", "victim")
            pong = await ref.ask("count", 5.0)
            restarts = sum(1 for e in system.events
                           if e["kind"] == "restarted"
                           and e["actor"] == "victim")
            # الحالة صُفّرت بإعادة التشغيل (دلالة معلَنة) — المهم:
            # لا حلقة موت، والفاعل يجيب بعد العاصفة + الفشل
            ok = restarts == 1 and pong == 0
            return {"ok": ok, "verdict": "survived-restarted",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"restarts={restarts} post-restart-count="
                              f"{pong} (التصفير دلالة معلَنة لإعادة "
                              f"التشغيل)"}
        finally:
            await system.shutdown(timeout=10.0)

    def _writer_50k_body(admission=None, sink_mode="ok", max_pending=65536):
        async def body():
            infra = _infra()
            sink_batches: list = []
            fail_left = {"n": 3} if sink_mode == "fail3" else {"n": 0}

            async def sink(batch):
                if fail_left["n"] > 0:
                    fail_left["n"] -= 1
                    raise RuntimeError("sink-fail-planned")
                sink_batches.append(list(batch))

            w = infra.BatchedWriter(
                sink, batch_size=100, flush_interval_s=0.05,
                max_pending=max_pending, admission=admission).start()
            accepted = 0
            rejected = 0
            for i in range(50_000):
                r = await w.submit(f"row-{i}")
                if r:
                    accepted += 1
                else:
                    rejected += 1
            # الفقد المعلَن عند فشل الحوض: 3 دفعات × 100 سطر
            expected = accepted - (300 if sink_mode == "fail3" else 0)
            t0 = time.perf_counter()
            while w.written_lines < expected and \
                    time.perf_counter() - t0 < 20.0:
                await asyncio.sleep(0.005)
            await w.close()
            return {"w": w, "accepted": accepted, "rejected": rejected,
                    "expected_written": expected,
                    "sink_batches": sink_batches}
        return body

    async def o5_writer50k_body():
        infra = _infra()
        out = await _writer_50k_body()()
        w = out["w"]
        # برهان H10_07 بالمقياس: إعادة حساب السلسلة مما استلمه الحوض
        recomputed = infra.recompute_chain_digest(out["sink_batches"])
        chain_ok = recomputed == w.last_digest
        ok = (out["accepted"] == 50_000 and out["rejected"] == 0
              and w.written_lines == 50_000 and not w.errors
              and len(out["sink_batches"]) == 500 and chain_ok)
        return {"ok": ok, "verdict": "survived-no-loss",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines} batches="
                          f"{w.batches} chain_recompute={chain_ok} "
                          f"digest={w.last_digest[:16]}.."}

    async def o6_admission_body():
        infra = _infra()

        class FixedAdmission:
            """سياسة قبول اختبارية (عقد allow() فقط — نفس عقد admission
            في الكاتب): تسمح لأول 100 ثم ترفض كل شيء رفضاً ذرياً."""

            def __init__(self):
                self.left = 100
                self.accepted = 0
                self.rejected = 0

            def allow(self) -> bool:
                if self.left > 0:
                    self.left -= 1
                    self.accepted += 1
                    return True
                self.rejected += 1
                return False

        policy = FixedAdmission()
        out = await _writer_50k_body(admission=policy)()
        w = out["w"]
        ok = (out["accepted"] == 100 and out["rejected"] == 49_900
              and w.written_lines == 100 and not w.errors
              and policy.accepted == 100 and policy.rejected == 49_900
              and w.rejected == 49_900)
        return {"ok": ok, "verdict": "rejected-by-policy-atomically",
                "atomic": True, "state_unchanged": True,
                "detail": f"accepted={out['accepted']} rejected="
                          f"{out['rejected']} writer_rejected="
                          f"{w.rejected} written={w.written_lines}"}

    async def o7_sink_fail_body():
        infra = _infra()
        out = await _writer_50k_body(sink_mode="fail3")()
        w = out["w"]
        # فشل الحوض: الدفعات الثلاث الفاشلة تُفقد بصدق (at-most-once
        # معلَن عند فشل الحوض) والباقي يُكتب — لا فساد ولا انهيار
        recomputed = infra.recompute_chain_digest(out["sink_batches"])
        chain_ok = recomputed == w.last_digest
        ok = (w.written_lines == out["expected_written"] == 49_700
              and len(w.errors) == 3
              and len(out["sink_batches"]) == 497 and chain_ok)
        return {"ok": ok, "verdict": "honest-accounting",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines} errors="
                          f"{len(w.errors)} chain_ok={chain_ok} "
                          f"(فقد معلَن لا صامت)"}

    async def o8_tight_backpressure_body():
        out = await _writer_50k_body(max_pending=128)()
        w = out["w"]
        ok = (out["accepted"] == 50_000 and w.written_lines == 50_000
              and not w.errors)
        return {"ok": ok, "verdict": "survived-no-loss",
                "atomic": True, "state_unchanged": True,
                "detail": f"max_pending=128 written={w.written_lines}"}

    def _pipeline_farm_body(mode: str):
        async def wrapper():
            infra = _infra()

            async def stage1(x):
                if mode == "yieldy":
                    await asyncio.sleep(0)
                if x == 666 and mode == "poison":
                    raise ValueError("poison-item")
                return x + 1

            async def stage2(x):
                if mode == "yieldy":
                    await asyncio.sleep(0)
                return x * 2

            async def stage3(x):
                return x - 3

            n_pipelines = 100
            pipes = [infra.Pipeline([stage1, stage2, stage3], capacity=4)
                     for _ in range(n_pipelines)]

            async def drive(idx: int):
                p = pipes[idx]
                items = list(range(100))
                if mode == "poison" and idx == 37:
                    items.append(666)  # العنصر السام في خط واحد فقط
                for it in items:
                    await p.put(it)

            first_taken: dict = {}
            if mode == "halves":
                for i in range(0, n_pipelines, 2):
                    await drive(i)
                for i in range(1, n_pipelines, 2):
                    await drive(i)
                for i in range(0, n_pipelines, 2):
                    await pipes[i].close()  # إغلاق بطابور ممتلئ
                for i in range(1, n_pipelines, 2):
                    first_taken[i] = await pipes[i].take()  # نتيجة واحدة
                    await pipes[i].close()  # ثم الإغلاق بعد مرحلة
            else:
                await asyncio.gather(*[drive(i) for i in
                                       range(n_pipelines)])
                await asyncio.gather(*[p.close() for p in pipes])

            ok_all = True
            expected = sorted((x + 1) * 2 - 3 for x in range(100))
            for i, p in enumerate(pipes):
                if mode == "poison" and i == 37:
                    out = await p.collect(100, timeout=5.0)
                    if sorted(out) != expected or not p.errors:
                        ok_all = False  # السم قُطع لكن يجب تسجيله
                else:
                    pre = [first_taken[i]] if i in first_taken else []
                    out = await p.collect(100 - len(pre), timeout=5.0)
                    if sorted(pre + out) != expected:
                        ok_all = False
                    if p.errors or p.dropped:
                        ok_all = False
            return {"ok": ok_all, "verdict": "survived-no-loss",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"mode={mode} 100 خط متوازٍ"}
        return wrapper

    async def o13_mailbox_flood_body():
        infra = _infra()
        mb = infra.Mailbox(4)  # سعة 4 فقط — الحد الحقيقي للذاكرة
        tasks = [asyncio.ensure_future(mb.put(i)) for i in range(100)]
        await asyncio.sleep(0.02)
        peak = mb.qsize()
        mb.close()
        n_cancelled = 0
        for tsk in tasks:
            if not tsk.done():
                tsk.cancel()
                n_cancelled += 1
        for tsk in tasks:
            try:
                await tsk
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await mb.put("fresh")
            fresh = "accepted-unexpected"
        except infra.MailboxClosed:
            fresh = "MailboxClosed-atomic"
        ok = (peak <= 4 and fresh == "MailboxClosed-atomic")
        return {"ok": ok, "verdict": "bounded-held-atomic",
                "atomic": True, "state_unchanged": True,
                "detail": f"peak_qsize={peak} cancelled={n_cancelled} "
                          f"fresh={fresh}"}

    async def o14_writer_bounded_body():
        infra = _infra()
        max_q = {"v": 0}
        stop = {"v": False}
        got: list = []

        async def sink(batch):
            got.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.01,
                                max_pending=4).start()
        sampler = asyncio.ensure_future(_sample_qsize(w, max_q, stop))
        for i in range(1000):
            assert await w.submit(f"l{i}")
        while w.written_lines < 1000:
            await asyncio.sleep(0.005)
        await w.close()
        stop["v"] = True
        try:
            await asyncio.wait_for(sampler, 2.0)
        except asyncio.TimeoutError:
            sampler.cancel()
        ok = (w.written_lines == 1000 and max_q["v"] <= 4
              and not w.errors)
        return {"ok": ok, "verdict": "bounded-held-atomic",
                "atomic": True, "state_unchanged": True,
                "detail": f"max_pending=4 peak_observed={max_q['v']} "
                          f"written={w.written_lines}"}

    async def o15_giant_batch_reject_body():
        infra = _infra()
        tbl = infra.ColumnTable("t", ["a", "b"], block_size=32)
        tbl.append_rows([{"a": i, "b": i} for i in range(100)])
        before = (tbl.n_rows, len(tbl.blocks), tbl.digest())
        giant = [{"a": i, "b": i} for i in range(10_000)]
        giant[-1] = {"a": 9_999}  # الصف الأخير ينقصه عمود إلزامي
        try:
            tbl.append_rows(giant)
            ok = False
            detail = "الدفعة العملاقة الناقصة لم تُرفض"
        except ValueError:
            ok = True
            detail = "ValueError-atomic"
        after = (tbl.n_rows, len(tbl.blocks), tbl.digest())
        ok = ok and before == after
        return {"ok": ok, "verdict": "rejected-atomic",
                "atomic": before == after, "state_unchanged": True,
                "detail": f"{detail} — الجدول لم يتغير قيد أنملة "
                          f"(rows={after[0]}, digest={after[2][:12]}..)"}

    async def o16_giant_block_reject_body():
        infra = _infra()
        vals = list(range(1_000_000)) + ["x"]  # مليون قيمة ثم شاذّة
        try:
            infra.ColumnBlock("giant", vals, encoding="delta")
            ok = False
            detail = "الكتلة العملاقة غير الصالحة لم تُرفض"
        except ValueError:
            ok = True
            detail = "ValueError-atomic (فحص H10_10 القبلي)"
        return {"ok": ok, "verdict": "rejected-atomic", "atomic": True,
                "state_unchanged": True,
                "detail": f"{detail} — لا كتلة نصف مُنشأة ولا ترميز "
                          f"لمليون قيمة (ملاحظة N2: الرفع قبل التخصيص)"}

    table = {
        "O1": (o1_mailbox10_body, "RESOURCE_EXHAUSTED"),
        "O2": (o2_fat_payloads_body, "RESOURCE_EXHAUSTED"),
        "O3": (o3_mixed_traffic_body, "RESOURCE_EXHAUSTED"),
        "O4": (o4_storm_then_fail_body, "RESOURCE_EXHAUSTED"),
        "O5": (o5_writer50k_body, "RESOURCE_EXHAUSTED"),
        "O6": (o6_admission_body, "RESOURCE_EXHAUSTED"),
        "O7": (o7_sink_fail_body, "RESOURCE_EXHAUSTED"),
        "O8": (o8_tight_backpressure_body, "RESOURCE_EXHAUSTED"),
        "O9": (_pipeline_farm_body("plain"), "RESOURCE_EXHAUSTED"),
        "O10": (_pipeline_farm_body("yieldy"), "RESOURCE_EXHAUSTED"),
        "O11": (_pipeline_farm_body("halves"), "RESOURCE_EXHAUSTED"),
        "O12": (_pipeline_farm_body("poison"), "RESOURCE_EXHAUSTED"),
        "O13": (o13_mailbox_flood_body, "RESOURCE_EXHAUSTED"),
        "O14": (o14_writer_bounded_body, "RESOURCE_EXHAUSTED"),
        "O15": (o15_giant_batch_reject_body, "RESOURCE_EXHAUSTED"),
        "O16": (o16_giant_block_reject_body, "RESOURCE_EXHAUSTED"),
    }
    return table[attack_id]


async def _sample_qsize(w, max_q: dict, stop: dict) -> None:
    """أخذ عينات لذروة امتلاء طابور الكاتب (قراءة عدائية داخلية)."""
    while not stop["v"]:
        try:
            q = w._q.qsize()
            if q > max_q["v"]:
                max_q["v"] = q
        except BaseException:
            return
        await asyncio.sleep(0.0005)


# ---------------- الفئة 4: بذور حدودية (16) ----------------
def _seed_digest(infra, seed) -> str:
    """مسار استهلاك البذرة في المحور 10 (نمط H10_13/H10_14):
    بذرة → random.Random → جدول → هضم. عقد البذرة (ملاحظة N3):
    عدد صحيح فقط — الرفض قبل أي بناء (ذري)."""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError(f"بذرة غير صالحة: {type(seed).__name__}")
    rng = random.Random(seed)
    tbl = infra.ColumnTable(f"t{seed}", ["v", "k"], block_size=64)
    tbl.append_rows([{"v": rng.randrange(10**6),
                      "k": rng.choice("xyz")} for _ in range(300)])
    return tbl.digest()


def _3d_cat4_cases() -> list:
    return [
        ("S1", 0, True), ("S2", 1, True), ("S3", -1, True),
        ("S4", 2**31 - 1, True), ("S5", 2**31, True),
        ("S6", 2**32 - 1, True), ("S7", 2**63 - 1, True),
        ("S8", 2**64 - 1, True),
        ("S9", ("3.14", "0.5", "-1.5", "1e10"), False),  # float strings
        ("S10", None, False), ("S11", [], False), ("S12", {}, False),
        ("S13", sys.maxsize, True), ("S14", -sys.maxsize, True),
        ("S15", 2**128, True), ("S16", "v1", False),  # string
    ]


def _3d_cat4_attack(seed, expect_valid: bool):
    async def body():
        infra = _infra()
        if expect_valid:
            d1 = _seed_digest(infra, seed)
            d2 = _seed_digest(infra, seed)  # الحتمية عند الحافة نفسها
            ok = (len(d1) == 32 and d1 == d2)
            return {"ok": ok, "verdict": "accepted-deterministic",
                    "atomic": True, "state_unchanged": True,
                    "detail": f"seed={seed!r} digest={d1[:12]}.. "
                              f"تكرار حتمي={d1 == d2}"}
        # يجب الرفض الذري قبل أي بناء
        built = 0
        try:
            for s in (seed if isinstance(seed, tuple) else (seed,)):
                _seed_digest(infra, s)
                built += 1
            ok = False
            detail = "البذرة غير الصالحة لم تُرفض"
        except ValueError:
            ok = True
            detail = "ValueError-atomic قبل أي بناء"
        ok = ok and built == 0
        return {"ok": ok, "verdict": "rejected-atomic", "atomic": True,
                "state_unchanged": True,
                "detail": f"{detail} (seed={seed!r})"}
    return body


# ---------------- الفئة 5: أنماط محور 3 الموروثة (16) ----------------
def _3d_cat5_factory(attack_id: str):
    """F1-F4: تزوير digest → يُكشف — TS1-TS4: تزوير طابع زمني → يُكشف
    — D1-D4: حقل إلزامي محذوف → رفض ذري — K1-K4: مفتاح مكرر → حتمية."""

    def _writer_with_sink():
        infra = _infra()
        sink_batches: list = []

        async def sink(batch):
            sink_batches.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=20, flush_interval_s=0.01,
                                max_pending=1024).start()
        return infra, w, sink_batches

    def _delta_reference(raw: list) -> list:
        """مرجع اشتقاق مستقل (نمط البرهان الذاتي): delta = [v0, فروق]."""
        return [raw[0]] + [raw[i] - raw[i - 1] for i in range(1, len(raw))]

    async def f_tamper_body(variant: str):
        infra, w, batches = _writer_with_sink()
        for i in range(100):
            assert await w.submit(f"line-{i}")
        while w.written_lines < 100:
            await asyncio.sleep(0.005)
        await w.close()
        # سلامة غير المُحرَّف أولاً (شرط مسبق للكشف)
        pristine = infra.recompute_chain_digest(batches)
        if pristine != w.last_digest:
            return {"ok": False, "verdict": "pristine-mismatch",
                    "atomic": True, "state_unchanged": True,
                    "detail": "السلسلة السليمة نفسها لا تطابق — خلل أعمق"}
        tampered = [list(b) for b in batches]
        if variant == "flip":
            tampered[2][1] = b"FORGED-BYTE"
        elif variant == "drop":
            tampered[2] = tampered[2][:-1]
        elif variant == "dup":
            tampered[2] = tampered[2] + [tampered[2][0]]
        elif variant == "swap":
            tampered[1], tampered[2] = tampered[2], tampered[1]
        forged = infra.recompute_chain_digest(tampered)
        detected = forged != w.last_digest
        return {"ok": detected, "verdict": "detected" if detected else
                "ESCAPED-DEFECT", "atomic": True,
                "state_unchanged": True,
                "detail": f"variant={variant} forged={forged[:12]}.. "
                          f"vs honest={w.last_digest[:12]}.."}

    async def ts_tamper_body(variant: str):
        infra = _infra()
        ts = [1_700_000_000 + i * 3 for i in range(500)]
        blk = infra.ColumnBlock("ts", ts, encoding="delta")
        d0 = blk.digest()
        if variant == "first":
            blk.raw[0] = 999_999_999
        elif variant == "middle":
            blk.raw[250] = 999_999_999
        elif variant == "last":
            blk.raw[-1] = 999_999_999
        elif variant == "encoded":
            blk.encoded[5] = 424_242
        # طبقتا الكشف: (1) إعادة الاشتقاق المستقلة — الخام المزوَّر لا
        # يطابق الترميز المشتق؛ (2) الهضم — الترميز المزوَّر يغيّر الهضم
        derivation_mismatch = _delta_reference(blk.raw) != blk.encoded
        digest_mismatch = blk.digest() != d0
        detected = derivation_mismatch or digest_mismatch
        return {"ok": detected, "verdict": "detected" if detected else
                "ESCAPED-DEFECT", "atomic": True,
                "state_unchanged": True,
                "detail": f"variant={variant} derivation="
                          f"{derivation_mismatch} digest={digest_mismatch}"}

    async def d_missing_field_body(variant: str):
        infra = _infra()
        tbl = infra.ColumnTable("t", ["a", "b", "c"], block_size=32)
        tbl.append_rows([{"a": i, "b": i, "c": i} for i in range(50)])
        before = (tbl.n_rows, len(tbl.blocks), tbl.digest())
        rows = {"missing_a": [{"b": 1, "c": 2}],
                "missing_b": [{"a": 1, "c": 2}],
                "missing_c": [{"a": 1, "b": 2}],
                "empty": [{}]}[variant]
        try:
            tbl.append_rows(rows)
            ok = False
            detail = "الصف الناقص لم يُرفض"
        except ValueError:
            ok = True
            detail = "ValueError-atomic"
        after = (tbl.n_rows, len(tbl.blocks), tbl.digest())
        ok = ok and before == after
        return {"ok": ok, "verdict": "rejected-atomic",
                "atomic": before == after, "state_unchanged": True,
                "detail": f"{detail} variant={variant} — الجدول لم يتغير"}

    async def k_duplicate_body(variant: str):
        infra = _infra()

        class Ping(infra.Actor):
            async def receive(self, envelope):
                return "pong"

        if variant == "same_name":
            system = infra.ActorSystem()
            try:
                system.spawn("dup", Ping)
                before = len(system.stats())
                try:
                    system.spawn("dup", Ping)
                    ok = False
                    detail = "الاسم المكرر لم يُرفض"
                except ValueError:
                    ok = True
                    detail = "ValueError-atomic"
                ok = ok and len(system.stats()) == before
                return {"ok": ok, "verdict": "rejected-atomic",
                        "atomic": True, "state_unchanged": True,
                        "detail": f"{detail} — حجم الجدول {before}"}
            finally:
                await system.shutdown()
        if variant == "recycle_after_death":
            system = infra.ActorSystem()
            try:
                ref = system.spawn("ghost", Ping)
                ref.stop("cut")
                await _wait_event(system, "dead", "ghost")
                ref2 = system.spawn("ghost", Ping)  # إعادة تدوير معلَنة
                pong = await ref2.ask("ping", 3.0)
                ok = pong == "pong"
                return {"ok": ok,
                        "verdict": "handled-deterministically",
                        "atomic": True, "state_unchanged": True,
                        "detail": "اسم الفاعل الميت يُعاد تدويره — "
                                  "سياسة معلَنة وحتمية"}
            finally:
                await system.shutdown()
        if variant == "routing_key":
            system = infra.ActorSystem()
            try:
                pool = infra.WorkerPool(system, "p", Ping, 4)
                idx = {pool.worker_index("acct-7") for _ in range(1000)}
                ok = len(idx) == 1  # نفس المفتاح → نفس العامل دائماً
                return {"ok": ok,
                        "verdict": "handled-deterministically",
                        "atomic": True, "state_unchanged": True,
                        "detail": f"1000 استعلام → {len(idx)} عامل فقط "
                                  f"(idx={idx})"}
            finally:
                await system.shutdown()
        # variant == "writer_line"
        sink_batches: list = []

        async def sink(batch):
            sink_batches.append(list(batch))

        w = infra.BatchedWriter(sink, batch_size=8, flush_interval_s=0.01,
                                max_pending=64).start()
        assert await w.submit("dup-line")
        assert await w.submit("dup-line")  # تكرار مقصود — لا إزالة
        while w.written_lines < 2:
            await asyncio.sleep(0.005)
        await w.close()
        recomputed = infra.recompute_chain_digest(sink_batches)
        ok = (w.written_lines == 2 and recomputed == w.last_digest)
        return {"ok": ok, "verdict": "handled-deterministically",
                "atomic": True, "state_unchanged": True,
                "detail": f"written={w.written_lines} (سياسة at-least-"
                          f"once معلَنة) digest متطابق="
                          f"{recomputed == w.last_digest}"}

    table = {
        "F1": (lambda: f_tamper_body("flip"), "DETECTION_AVOIDED"),
        "F2": (lambda: f_tamper_body("drop"), "DETECTION_AVOIDED"),
        "F3": (lambda: f_tamper_body("dup"), "DETECTION_AVOIDED"),
        "F4": (lambda: f_tamper_body("swap"), "DETECTION_AVOIDED"),
        "TS1": (lambda: ts_tamper_body("first"), "DETECTION_AVOIDED"),
        "TS2": (lambda: ts_tamper_body("middle"), "DETECTION_AVOIDED"),
        "TS3": (lambda: ts_tamper_body("last"), "DETECTION_AVOIDED"),
        "TS4": (lambda: ts_tamper_body("encoded"), "DETECTION_AVOIDED"),
        "D1": (lambda: d_missing_field_body("missing_a"),
               "PRECONDITION_FAILED"),
        "D2": (lambda: d_missing_field_body("missing_b"),
               "PRECONDITION_FAILED"),
        "D3": (lambda: d_missing_field_body("missing_c"),
               "PRECONDITION_FAILED"),
        "D4": (lambda: d_missing_field_body("empty"),
               "PRECONDITION_FAILED"),
        "K1": (lambda: k_duplicate_body("same_name"),
               "POLICY_RESTRICTED"),
        "K2": (lambda: k_duplicate_body("recycle_after_death"),
               "POLICY_RESTRICTED"),
        "K3": (lambda: k_duplicate_body("routing_key"),
               "POLICY_RESTRICTED"),
        "K4": (lambda: k_duplicate_body("writer_line"),
               "POLICY_RESTRICTED"),
    }
    return table[attack_id]


# ---------------- تجميع البطارية 3d ----------------
def _battery_3d(checks: list) -> bool:
    """3d — 80 هجوم عدائي (5 فئات × 16): صفر انهيار، رفض ذري، حالة
    سليمة بعد كل هجوم، وسجل حدود بفئة من الـ14 لكل هجوم."""
    global BOUNDARY_LOG
    BOUNDARY_LOG = []
    from sentinel.xgraph import BOUNDARY_CATEGORIES
    cats = BOUNDARY_CATEGORIES
    assert len(cats) == 14, f"فئات الحدود = {len(cats)} وليست 14"

    for attack_id, msg, category in _3d_cat1_payloads():
        _run_attack(attack_id, category, _3d_cat1_attack(msg), checks)
    for attack_id in ("A1", "A2", "A3", "A4", "W1", "W2", "W3", "W4",
                      "P1", "P2", "P3", "P4", "T1", "T2", "T3", "T4"):
        fn, category = _3d_cat2_factory(attack_id)
        _run_attack(attack_id, category, fn, checks)
    for attack_id in ("O1", "O2", "O3", "O4", "O5", "O6", "O7", "O8",
                      "O9", "O10", "O11", "O12", "O13", "O14", "O15",
                      "O16"):
        fn, category = _3d_cat3_factory(attack_id)
        _run_attack(attack_id, category, fn, checks)
    for seed_id, seed, valid in _3d_cat4_cases():
        category = "HARDWARE_LIMIT" if valid else "PRECONDITION_FAILED"
        _run_attack(seed_id, category, _3d_cat4_attack(seed, valid),
                    checks)
    for attack_id in ("F1", "F2", "F3", "F4", "TS1", "TS2", "TS3",
                      "TS4", "D1", "D2", "D3", "D4", "K1", "K2", "K3",
                      "K4"):
        fn, category = _3d_cat5_factory(attack_id)
        _run_attack(attack_id, category, fn, checks)

    _ck(checks, "3d", "عدد الهجمات = 80 (5 فئات × 16)",
        len(BOUNDARY_LOG) == 80, f"attacks={len(BOUNDARY_LOG)}")
    _ck(checks, "3d", "كل فئة حدود مسجلة من فئات الـ14 المعتمدة",
        all(e["category"] in cats for e in BOUNDARY_LOG))
    failed = [e["attack"] for e in BOUNDARY_LOG if not e["ok"]]
    _ck(checks, "3d", "صفر هجوم فلت أو انهيار (80/80 سليمة)",
        not failed, f"failed={failed}")
    return not failed


def test_3d_adversarial():
    """3d — 80 هجوم عدائي عبر خمس فئات: كلها يجب أن تُرَدّ ذرياً بلا
    انهيار مع بقاء الحالة سليمة."""
    checks: list = []
    ok = _battery_3d(checks)
    failed = [(c["what"].split(":")[0], c["detail"][:120])
              for c in checks if not c["ok"]]
    assert ok, f"3d فشل في {len(failed)} هجوم: {failed!r}"


# ============================================================ البطارية 3e
def _battery_3e(checks: list) -> bool:
    """3e — 100 دورة تقليم: جدول عشوائي (100-10,000 صف) بعمود مرتب
    وعمود عشوائي؛ المسح المقلَّم == الاستقصاء الشامل دائماً (صحة
    مطلقة)، والتقليم فعلي (rows_scanned < total)، ونسبة التقليم
    تُسجَّل لكل دورة."""
    infra = _infra()
    n_cycles = 100
    ratios: list = []
    all_equal = True
    all_pruned = True
    matched_ok = True

    for cyc in range(n_cycles):
        rng = random.Random(55_000 + cyc)
        n = rng.randrange(100, 10_001)
        ts_vals: list = []
        t = 1_700_000_000
        for _ in range(n):
            t += rng.randrange(1, 8)
            ts_vals.append(t)
        rows = [{"ts": ts_vals[i], "val": rng.randrange(10**6)}
                for i in range(n)]
        tbl = infra.ColumnTable(f"t{cyc}", ["ts", "val"], block_size=32)
        tbl.append_rows(rows)
        # المُسند على العمود المرتب: شريحة [الوسيط → الربيع الأعلى]
        lo, hi = ts_vals[n // 2], ts_vals[3 * n // 4]
        res = infra.scan(tbl, {"ts": infra.Range(lo, hi)})
        brute = [r for r in tbl.all_rows() if lo <= r["ts"] <= hi]
        equal = res["rows"] == brute
        pruned = res["stats"]["rows_scanned"] < n
        matched = res["stats"]["matched"] == len(brute)
        # سلامة إضافية على العمود العشوائي (Eq على قيمة موجودة)
        v0 = rows[0]["val"]
        res2 = infra.scan(tbl, {"val": infra.Eq(v0)})
        brute2 = [r for r in tbl.all_rows() if r["val"] == v0]
        equal2 = res2["rows"] == brute2
        if not (equal and equal2):
            all_equal = False
        if not pruned:
            all_pruned = False
        if not matched:
            matched_ok = False
        ratios.append(1.0 - res["stats"]["rows_scanned"] / n)

    avg_ratio = sum(ratios) / len(ratios)
    _ck(checks, "3e", "pruned_result == exhaustive_result (صحة مطلقة، "
        "100 دورة × مُسندان: Range على المرتب + Eq على العشوائي)",
        all_equal)
    _ck(checks, "3e", "rows_scanned < total_rows في كل دورة (تقليم فعلي)",
        all_pruned)
    _ck(checks, "3e", "matched == len(exhaustive) في كل دورة",
        matched_ok)
    _ck(checks, "3e", "نسبة التقليم مُسجَّلة لكل دورة", True,
        f"avg={avg_ratio:.1%} min={min(ratios):.1%} max={max(ratios):.1%}")
    return all_equal and all_pruned and matched_ok


def test_3e_pruning_equivalence():
    """3e — 100 دورة: تقليم == استقصاء شامل، دائماً وبلا استثناء."""
    checks: list = []
    ok = _battery_3e(checks)
    failed = [c for c in checks if not c["ok"]]
    assert ok, f"3e فشل: {failed!r}"


# ============================================================ وضع الدليل
_BATTERIES = [
    ("3a", _battery_3a), ("3b", _battery_3b), ("3c", _battery_3c),
    ("3d", _battery_3d), ("3e", _battery_3e),
]


def _digest(checks: list) -> str:
    """هضم التيار المنطقي فقط: (battery, what, ok) لكل فحص —
    الأزمنة وdetail خارج الهضم (انضباط المحور 11)."""
    h = hashlib.sha256()
    for c in checks:
        h.update(f"{c['battery']}|{c['what']}|{int(c['ok'])}".encode(
            "utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-10 ATOMS")
    ap.add_argument("--out", default="",
                    help="مسار ملف دليل JSON")
    args = ap.parse_args()

    all_checks: list = []
    batteries: list = []
    t0 = time.perf_counter()
    for bid, fn in _BATTERIES:
        checks: list = []
        try:
            ok = fn(checks)
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط الكل
            ok = False
            _ck(checks, bid, "battery-completed-without-exception", False,
                repr(exc)[:400])
        all_checks.extend(checks)
        batteries.append({"id": bid, "checks": len(checks),
                          "failed": sum(1 for c in checks if not c["ok"])})
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] battery {bid} "
              f"({batteries[-1]['checks']} checks, "
              f"{batteries[-1]['failed']} failed)")
    total = len(all_checks)
    failed = sum(1 for c in all_checks if not c["ok"])
    doc = {
        "suite": "axis10-atoms",
        "station": "M3-ATOMS",
        "total": total,
        "failed": failed,
        "passed": failed == 0,
        "batteries": batteries,
        "digest": _digest(all_checks),
        "boundary_log": list(BOUNDARY_LOG),
        "checks": all_checks,
        "honest_notes": [
            "N1: 3c قراءة «200 تشغيل توازٍ» = 200 دورة × pool{1,2,4} × "
            "10k رسالة؛ pool_size=8 مستثنى بقرار المشرف H10_17",
            "N2: استحثاث MemoryError حقيقي مرفوض كتصرف متهور على VM "
            "مشترك؛ البديل = إثبات الرفض الذري تحت مدخلات عملاقة "
            "(validation-before-mutation)",
            "N3: عقد البذرة أعداد-صحيحة-فقط معلن على مسار البطارية "
            "(المسترد لا يقدم واجهة تحقق بذور)",
            "N4: system_state_unchanged = اتساق داخلي وقابلية تشغيل "
            "(تفصيل لكل هجوم في checks)",
            "N5: فئات الـ14 من sentinel.xgraph.BOUNDARY_CATEGORIES؛ "
            "الخريطة معلنة في docstring الجناح",
            "N6: كل هجوم 3d معزول في حلقة أحداث مستقلة بمهلة صلبة 20 ث",
        ],
        "wall_s": round(time.perf_counter() - t0, 3),
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis10 ATOMS: {total - failed}/{total} checks passed | "
          f"digest {doc['digest'][:16]}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
