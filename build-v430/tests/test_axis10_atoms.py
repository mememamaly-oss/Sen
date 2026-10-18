#!/usr/bin/env python3
"""SENTINEL Axis-10 — M3 ATOMS: البطاريات الإجبارية الخمس (أمر المشرف 2026-10-18).

PROVENANCE والعقد (معلنة بأمانة، مقدَّمة):
- هذا الجناح ينفّذ أمر المشرف الحرفي «أمر الدفع + إكمال M3 إلى M5
  للمحور 10» (2026-10-18): خمس بطاريات إجبارية (3a..3e) فوق جسر
  sentinel.infra (M2 GREEN عند 5773ad9) والمحتوى المسترد perf/ كما هو —
  لا تعديل فيه ولا لمس للنواة 227×19=4313 (جناح مستقل، غير مُسجَّل في
  @case، كل بطارية تستورد sentinel.infra داخل جسمها — نمط M1/M2).
- انضباط الهضم: التيار المنطقي فقط (battery, what, ok) — أزمنة الحائط
  تُسجَّل في detail ولا تدخل الهضم أبداً (انضباط المحور 11).
- خط الإيقاف الحرفي: «أي فشل: الصق الخام وتوقف — لا إصلاح بلا إذن».

ملاحظات الصدق (الفروقات المُعلنة — لا مخفية):
  N1 (3c) — قراءة «200 تشغيل توازٍ»: 200 دورة استقلال-توازٍ؛ كل دورة
      تُمرّر نفس الدفق المُبذَّر (10,000 رسالة، مفاتيح حتمية بالحساب
      لا بالعشوائية) عبر pool_size ∈ {1,2,4} وتطابق النتيجة المنطقية
      بين التشكيلات الثلاث. pool_size=8 مستثنى بقرار المشرف H10_17
      (2026-10-18): 8 عمال على العتاد المرجعي ثنائي النوى تفرط في
      الاشتراك (قياس حقبة M2: pool-8 دون الأرضية بينما pool-4 حقق
      44k+) — والأمر نفسه نصّ على الاستثناء مع التوثيق في التعليق.
  N2 (3d فئة-3) — «استنفد الذاكرة باصطناع»: استحثاث MemoryError حقيقي
      (تخصيص غيغابايتات) مرفوض صراحةً كتصرف متهور على VM مشترك — قد
      يقتل عملية الدليل نفسها ويدمّر المحطة كلها. البديل الأمين المُعلن:
      إثبات عقد الرفض الذري تحت ضغط مدخلات عملاقة عبر التحقق-قبل-
      التحويل (validation-before-mutation) — وهو حارس الاستنزاف الفعلي
      في هذا الكود. النتيجة تُسجَّل بفئة RESOURCE_EXHAUSTED.
  N3 (3d فئة-4) — عقد البذرة: أعداد صحيحة فقط. المسترد لا يقدّم واجهة
      تحقق من البذور؛ الحارس مُعلن على مستوى مسار البذرة في البطارية
      (نفس مسار H10_13/H10_14: بذرة → random.Random → جدول → هضم).
      البذور الصالحة تُوثَّق بفئة HARDWARE_LIMIT (حواف عرض العدد
      المعمارية)، والمرفوضة بفئة PRECONDITION_FAILED.
  N4 (3d) — دلالة «system_state_unchanged»: يبقى النظام متسقاً داخلياً
      وقابلاً للتشغيل (لا فساد، الجيران سالمون، الإغلاق نظيف)؛ وتُفصَّل
      لكل هجوم في سجل الفحوص. هجوم T3 (إلغاء مهمة إيداع) يفحص التعافي
      وفق وعد تعليق الكود نفسه («سلسلة سابقة أُلغيت؛ الإيداع الحالي
      سيواجه مصيره بنفسه») — التوكيد على السلوك المُعلن لا على المتوقع.
  N5 (3d) — تصنيف الـ14: فئات sentinel.xgraph.BOUNDARY_CATEGORIES
      (معاينة المحور 12) تُستخدم لتصنيف الهجمات؛ الخريطة معلنة:
      خرق النوع/العقد → PRECONDITION_FAILED، التضخيم الحجمي →
      RESOURCE_EXHAUSTED، نطاق القيم → OUT_OF_SCOPE، المحتوى المعادي
      للترميز → UNKNOWN_PROTOCOL، حراس الموارد المغلقة → SAFETY_GUARD،
      محاولات التزوير → DETECTION_AVOIDED (مع verdict=detected)،
      سياسة التكرار/التسمية → POLICY_RESTRICTED.
  N6 (عام) — البطاريات معزولة: كل هجوم في 3d يعمل في حلقة أحداث مستقلة
      (asyncio.run خاصة به) — فشل هجوم لا يلوث بقية الهجمات، وسجل
      الفحوص يلتقط حكم كل هجوم على حدة ثم يجمع البطارية الحكم النهائي.

Usage:
  python3 -m pytest tests/test_axis10_atoms.py --tb=short -q
  python3 tests/test_axis10_atoms.py --out results/axis10/axis10_ATOMS.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _infra():
    """نمط M1/M2: الاستيراد داخل الجسم — الجناح مستقل عن آلية التجميع."""
    import sentinel.infra as infra
    return infra


# ============================================================ مساعدات مشتركة
async def _wait_event(system, kind: str, actor: str | None = None,
                      timeout: float = 5.0) -> dict:
    """انتظار حدث في سجل النظام (استطلاع يسمح بجدولة الحلقة)."""
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


def _ser(msg) -> str:
    """تسلسل حتمي لرسالة واحدة (للهضم) — نفس البناء → نفس السلسلة."""
    return f"{type(msg).__name__}:{msg!r}\n"


def _stream_digest(messages) -> str:
    h = hashlib.sha256()
    for m in messages:
        h.update(_ser(m).encode("utf-8"))
    return h.hexdigest()


def _ck(checks: list, battery: str, what: str, ok: bool, detail: str = "") -> None:
    """تسجيل فحص واحد في التيار المنطقي (detail خارج الهضم دائماً)."""
    checks.append({"battery": battery, "what": what, "ok": bool(ok),
                   "detail": str(detail)[:400]})


# ============================================================ البطارية 3a
def _3a_messages(rng: random.Random, n: int = 1000) -> list:
    """1000 رسالة عشوائية من أربع عائلات: نص/أرقام/unicode/بايتات."""
    msgs = []
    uni_pool = "مرحباالعالم世界日本🎉🚀𝕏ᚠُِْٰ́﷽Ω"
    for i in range(n):
        f = i % 4
        if f == 0:  # نص ascii
            msgs.append("".join(rng.choice("abcdefXYZ-_09 .,")
                                for _ in range(rng.randrange(1, 40))))
        elif f == 1:  # أرقام (int/float بالتناوب)
            if i % 8 == 1:
                msgs.append(rng.randrange(-2**62, 2**62))
            else:
                msgs.append(rng.random() * 10**6)
        elif f == 2:  # unicode (CJK/RTL/emoji/combining)
            msgs.append("".join(rng.choice(uni_pool)
                                for _ in range(rng.randrange(1, 30))))
        else:  # بايتات خام (بما فيها \x00 و \xff)
            msgs.append(bytes(rng.randrange(256)
                              for _ in range(rng.randrange(1, 32))))
    return msgs


def _3a_run_once(seed: int) -> dict:
    """تشغيل كامل واحد: 1000 رسالة → Actor → مؤشرات + هضم المُسلَّم."""
    infra = _infra()
    rng = random.Random(seed)
    msgs = _3a_messages(rng)
    box = {"delivered": [], "inflight": 0, "raced": False}

    async def body():
        system = infra.ActorSystem()
        try:
            class Echo(infra.Actor):
                def __init__(self):
                    self.n = 0

                async def receive(self, envelope):
                    box["inflight"] += 1
                    if box["inflight"] > 1:
                        box["raced"] = True
                    try:
                        self.n += 1
                        box["delivered"].append(envelope.message)
                        return ("ok", self.n)
                    finally:
                        box["inflight"] -= 1

            ref = system.spawn("sink", Echo, mailbox_capacity=256)
            delivered = 0
            for i, m in enumerate(msgs):
                reply = await ref.ask(m, timeout=5.0)
                assert reply == ("ok", i + 1), f"الرد {reply!r} عند الرسالة {i}"
                delivered += 1
            crashes = sum(
                1 for e in system.events
                if e["kind"] in ("dead", "pre_start_failed",
                                 "post_stop_failed") and e["actor"] == "sink")
            return {"delivered": delivered, "crashes": crashes,
                    "raced": box["raced"],
                    "digest": _stream_digest(box["delivered"])}
        finally:
            await system.shutdown(timeout=10.0)

    return asyncio.run(body())


def _battery_3a(checks: list) -> bool:
    """3a — 1000 رسالة عشوائية: delivered==sent، صفر فقد، صفر انهيار،
    هضم التيار المُسلَّم متطابق بين تشغيلين (حتمية)."""
    seed = 20261018
    r1 = _3a_run_once(seed)
    r2 = _3a_run_once(seed)
    ok1 = r1["delivered"] == 1000
    ok2 = r2["delivered"] == 1000
    lost = (1000 - r1["delivered"]) + (1000 - r2["delivered"])
    _ck(checks, "3a", "run1: delivered == sent (1000/1000)", ok1,
        f"delivered={r1['delivered']}")
    _ck(checks, "3a", "run2: delivered == sent (1000/1000)", ok2,
        f"delivered={r2['delivered']}")
    _ck(checks, "3a", "lost == 0 (صفر فقد مطلق، التشغيلان)", lost == 0,
        f"lost={lost}")
    _ck(checks, "3a", "crashes == 0 (صفر انهيار، التشغيلان)",
        r1["crashes"] == 0 and r2["crashes"] == 0,
        f"crashes={r1['crashes']},{r2['crashes']}")
    _ck(checks, "3a", "no concurrent receive (حارس السباق)",
        not r1["raced"] and not r2["raced"])
    _ck(checks, "3a", "digest run1 == digest run2 (SHA256 على تسلسل "
        "الرسائل المُسلَّمة)", r1["digest"] == r2["digest"],
        f"digest={r1['digest'][:16]}..")
    all_ok = (ok1 and ok2 and lost == 0 and r1["crashes"] == 0
              and r2["crashes"] == 0 and not r1["raced"]
              and r1["digest"] == r2["digest"])
    return all_ok


def test_3a_random_messages():
    """3a — 1000 رسالة عشوائية عبر Actor: صفر فقد/انهيار + حتمية الهضم."""
    checks: list = []
    ok = _battery_3a(checks)
    failed = [c for c in checks if not c["ok"]]
    assert ok, f"3a فشل: {failed!r}"


# ============================================================ البطارية 3b
def _battery_3b(checks: list) -> bool:
    """3b — 500 دورة restart/escalate: restart>=1 لكل دورة، تصعيد عند
    الحد الصحيح بالضبط، صفر deadlock (كل دورة < 5 ث)، صفر سباق."""
    infra = _infra()
    total_cycles = 500
    stats = {"escalations": 0, "restarts": 0, "max_cycle_s": 0.0,
             "raced": False, "bad_directive": 0, "bad_restart_count": 0}

    async def body():
        for i in range(total_cycles):
            k = 1 + (i % 4)  # max_restarts يتغير 1..4 — التصعيد عند الحد
            t0 = time.perf_counter()
            system = infra.ActorSystem()
            box = {"inflight": 0, "raced": False}
            try:
                class Fragile(infra.Actor):
                    def __init__(self):
                        self.n = 0

                    async def receive(self, envelope):
                        box["inflight"] += 1
                        try:
                            if box["inflight"] > 1:
                                box["raced"] = True
                            m = envelope.message
                            if m == "ping":
                                return ("pong", self.n)
                            if m == "fail":
                                raise ValueError("planned")
                            raise AssertionError(f"رسالة غير معروفة: {m!r}")
                        finally:
                            box["inflight"] -= 1

                ref = system.spawn(
                    "victim", Fragile,
                    policy=infra.OneForOne(
                        on_failure=infra.Directive.RESTART,
                        max_restarts=k,
                        on_breach=infra.Directive.ESCALATE))
                # (1) تشغيل عادي أولاً
                assert await ref.ask("ping", 5.0) == ("pong", 0)
                # (2) فشل متعمد → إعادة تشغيل (على الأقل واحدة لكل دورة)
                try:
                    await ref.ask("fail", 5.0)
                    raise AssertionError("fail كان يجب أن يفشل")
                except ValueError:
                    pass
                await _wait_event(system, "restarted", "victim")
                # (3) كرر الفشل حتى التصعيد — عند الحد الصحيح بالضبط
                restarts = 1
                while True:
                    try:
                        await ref.ask("fail", 5.0)
                        raise AssertionError("fail كان يجب أن يفشل")
                    except ValueError:
                        pass
                    if restarts < k:
                        await _wait_event(system, "restarted", "victim")
                        restarts += 1
                    else:
                        break  # الفشل القادم عبر الحد → تصعيد
                dead = await _wait_event(system, "dead", "victim")
                if dead["directive"] != "escalate":
                    stats["bad_directive"] += 1
                n_restarts = sum(1 for e in system.events
                                 if e["kind"] == "restarted"
                                 and e["actor"] == "victim")
                if n_restarts != k:
                    stats["bad_restart_count"] += 1
                stats["restarts"] += n_restarts
                stats["escalations"] += 1
            finally:
                await system.shutdown(timeout=5.0)
            dt = time.perf_counter() - t0
            stats["max_cycle_s"] = max(stats["max_cycle_s"], dt)
            assert dt < 5.0, f"دورة {i} استغرقت {dt:.2f}s — deadlock محتمل"
            stats["raced"] = stats["raced"] or box["raced"]

    asyncio.run(body())
    expected_restarts = 125 * (1 + 2 + 3 + 4)  # k يتكرر 125 مرة لكل قيمة
    _ck(checks, "3b", "500 دورة اكتملت جميعها",
        stats["escalations"] == total_cycles,
        f"escalations={stats['escalations']}")
    _ck(checks, "3b", "restarts >= 1 لكل دورة (و== الحد بالضبط)",
        stats["bad_restart_count"] == 0 and stats["restarts"] ==
        expected_restarts,
        f"restarts={stats['restarts']} expected={expected_restarts}")
    _ck(checks, "3b", "escalations == expected (500، واحد لكل دورة)",
        stats["escalations"] == 500 and stats["bad_directive"] == 0)
    _ck(checks, "3b", "no deadlock: كل دورة < 5 ثوانٍ",
        stats["max_cycle_s"] < 5.0,
        f"max_cycle_s={stats['max_cycle_s']:.3f}")
    _ck(checks, "3b", "no race: لا معالجة رسالتين بالتوازي أبداً",
        not stats["raced"])
    return (stats["escalations"] == total_cycles
            and stats["bad_restart_count"] == 0
            and stats["restarts"] == expected_restarts
            and stats["bad_directive"] == 0
            and stats["max_cycle_s"] < 5.0 and not stats["raced"])


def test_3b_restart_escalate():
    """3b — 500 دورة إعادة تشغيل/تصعيد: الحد الصحيح، صفر deadlock/سباق."""
    checks: list = []
    ok = _battery_3b(checks)
    failed = [c for c in checks if not c["ok"]]
    assert ok, f"3b فشل: {failed!r}"


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
