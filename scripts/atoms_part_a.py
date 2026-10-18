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
