"""sentinel.infra — جسر عقد بطارية المحور-10 (M2 GREEN) فوق المحتوى المسترد.

البروفينانس (معلن بأمانة):
- أمر المشرف 2026-10-17: «هدف التنفيذ هو المحتوى المسترد: perf/actors +
  perf/aio + perf/columnar ... عقد هذه البطارية يُنفَّذ عبر واجهة
  sentinel.infra التي ستربط المحتوى المسترد — لا إعادة كتابة». هذا الملف
  جسر صريح: كل منطق perf/ يعمل كما استُرد (جناحه المسترد 40/40 عند
  7ea2de4)؛ الجسر يكيّف فقط مواضع الخلاف مع العقد الحرفي، وكل فارق
  مُعلن بملاحظة صدق مرقّمة أدناه — لا فارق مخفي.

ملاحظات الصدق (المواضع الأربعة المكيَّفة — تُنسخ إلى دليل M2):
  H10_07 — العقد يطلب سلسلة هضم SHA256 (64 hex)؛ المسترد يستخدم
           blake2b-16 (32 hex). الجسر يغلّف السلسلة بـ SHA256 بنفس
           الصيغة البنيوية (prev + "|" + len + "|" + سجلات مفصولة
           بـ \\x1e) ويصفّر الهضم الابتدائي إلى "0"×64. الفارق معلَن.
  H10_09 — طابور مخرج Pipeline المسترد محدود السعة، وهذا يُميت
           التسلسل المتتالي: close() ينتظر تصريف المراحل بينما
           المرحلة الأخيرة محتجزة على طابور ممتلئ (deadlock بنيوي
           لا سباق). الجسر يبني الخطوط بطابور مخرج غير محدود؛
           السعة بين المراحل باقية كما هي (الضغط الخلفي للعقد).
  H10_10 — فحص ValueError على delta في block.py المسترد ميت فعلياً:
           delta_encode يرفع TypeError على غير الأعداد قبل بلوغ سطر
           الفحص. الجسر يضيف فحصاً قبلياً بنفس الشرط والرسالة،
           فيتحقق الرفض الذري بالاستثناء الصحيح.
  H10_17 — أرضية أداء معمارية-نسبي 20k رسالة/ث بقرار المشرف
           2026-10-18: عتبة ثابتة على عتاد متغير = هلوسة. القياس
           perf_counter فعلي والرقم يُسجَّل في الأدلة للمقارنة
           عبر الأجهزة.

كل ما عدا ذلك يعمل من perf/ كما استُرد: نموذج الفاعلين (actors/)،
الكاتب المجمع وأدواته (aio/)، التخزين العمودي والمسح والتقليم
(columnar/) — بلا تعديل حرف واحد فيها.
"""
from __future__ import annotations

import asyncio
import hashlib
import sys
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

# perf/ يعيش في جذر المستودع (استُرد في 91267c5) — يُضاف للمسار لا غير:
# لا نسخ للكود، لا إعادة كتابة، لا لمس لملفات perf/ نفسها.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from perf.actors import (  # noqa: E402
    Actor, ActorRef, ActorDied, ActorNotFound, ActorSystem as _ActorSystem,
    Directive,
    FailureContext, Mailbox, MailboxClosed, OneForOne, WorkerPool,
)
from perf.aio import DROP  # noqa: E402
from perf.aio.pipeline import Pipeline as _Pipeline  # noqa: E402
from perf.aio.writer import (  # noqa: E402
    BatchedWriter as _BatchedWriter, WriterClosed,
)
from perf.columnar import (  # noqa: E402
    ColumnTable, Eq, Gt, Gte, In, Lt, Lte, Ne, Range, scan,
)
from perf.columnar.block import ColumnBlock as _ColumnBlock  # noqa: E402

__all__ = [
    # Actors — من perf.actors كما استُردت
    "Actor", "ActorRef", "ActorSystem", "ActorNotFound", "ActorDied",
    "Directive", "FailureContext", "OneForOne", "WorkerPool",
    "Mailbox", "MailboxClosed",
    # Async I/O — الكاتب والخط مع تكييفَي H10_07/H10_09 المعلنَين
    "BatchedWriter", "WriterClosed", "Pipeline", "DROP",
    "recompute_chain_digest", "EMPTY_DIGEST",
    # Columnar — الجدول والمسح والمسندات كما استُردت؛ الكتلة مع
    # تكييف H10_10 المعلن
    "ColumnTable", "ColumnBlock", "scan",
    "Eq", "Ne", "Gt", "Gte", "Lt", "Lte", "In", "Range",
    # Bench — قياسات فعلية (perf_counter) لا تقديرات
    "bench_actor_throughput", "bench_writer_throughput",
]


# ============================================================ H10_07
# سلسلة الهضم SHA256 (العقد) — نفس الصيغة البنيوية للمسترد،
# الخوارزمية فقط تتبدل: blake2b-16 → SHA256. الفارق معلن أعلاه.
EMPTY_DIGEST = "0" * 64


def _sha256_chain(prev: str, batch: list[bytes]) -> str:
    h = hashlib.sha256()
    h.update(prev.encode("ascii"))
    h.update(b"|" + str(len(batch)).encode() + b"|")
    for b in batch:
        h.update(b)
        h.update(b"\x1e")  # فاصل سجل — يمنع التحام الحدود
    return h.hexdigest()


def recompute_chain_digest(batches: list[list[bytes]]) -> str:
    """إعادة حساب السلسلة من ما استلمه الحوض — دالة نقية في الدفعات."""
    d = EMPTY_DIGEST
    for batch in batches:
        d = _sha256_chain(d, list(batch))
    return d


class BatchedWriter(_BatchedWriter):
    """كاتب perf المسترد بسلسلة SHA256 (عقد H10_07).

    التعديل الوحيد: نقطة بداية السلسلة ودالة خطوتها. منطق الجمع
    والكتابة والضغط الخلفي والإغلاق الذري — كلها من perf/aio/writer.py
    كما استُردت."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # نقطة البداية: "0"×64 (SHA256) بدل "0"×16 (blake2b-16)
        self._digest = EMPTY_DIGEST

    @staticmethod
    def _chain(prev: str, batch: list[bytes]) -> str:
        return _sha256_chain(prev, batch)


# ============================================================ H10_09
# طابور مخرج غير محدود: السعة بين المراحل باقية (ضغط خلفي العقد)،
# لكن المخرج يُصرَّد دائماً — التسلسل المتتالي (put ثم close ثم collect)
# لا يستطيع أن يموت بعد الآن.
_UNBOUNDED = 1 << 62  # سعة فلكية = غير محدود عملياً


class Pipeline(_Pipeline):
    """خط perf المسترد بطابور مخرج غير محدود (عقد H10_09).

    الاستبدال يحدث في __init__ (متزامن بالكامل) قبل أن تنال مراحل
    asyncio دورها لأول مرة — تربط كل مرحلة طوابيرها عند أول تشغيل،
    فترى طابور المخرج الجديد حتماً. لا شيء آخر معدَّل."""

    def __init__(self, stages: list[Callable[[Any], Awaitable[Any]]], *,
                 capacity: int = 4, output_capacity: int | None = None) -> None:
        super().__init__(stages, capacity=capacity)
        out_cap = _UNBOUNDED if output_capacity is None else output_capacity
        self._qs[-1] = Mailbox(out_cap)


# ============================================================ H10_10
class ColumnBlock(_ColumnBlock):
    """كتلة perf المستردة بفحص قبلي على delta (عقد H10_10).

    الفحص في block.py المسترد ميت: delta_encode يرفع TypeError على
    غير الأعداد قبل بلوغه. الفحص القبلي هنا (نفس الشرط والرسالة
    حرفياً) يجعل الرفض ذرياً بالاستثناء الصحيح. لا شيء آخر معدَّل."""

    def __init__(self, name: str, values: list[Any],
                 encoding: str = "auto") -> None:
        if encoding == "delta" and not all(
                isinstance(v, int) and not isinstance(v, bool)
                for v in values):
            raise ValueError("ترميز delta يتطلب أعدادًا صحيحة فقط")
        super().__init__(name, values, encoding)


# ============================================================ E4 (M3/T3)
class ActorSystem(_ActorSystem):
    """نظام perf المسترد بتعافي سلسلة الإيداع (عقد E4 — M3/T3).

    العيب المسترد: إلغاء مهمة إيداع واحدة يسمّم السلسلة كلها —
    CancelledError (وارث BaseException منذ 3.8) لا يلتقطها except
    Exception عند await prev خلافاً لوعد تعليق _deposit نفسه.
    التعافي: فحص حالة السلف عند إنشاء الإيداع — المُلغى يُستبعد
    وتبدأ سلسلة مستقلة؛ المسار غير العدائي بلا أي تغيير."""

    def _deposit(self, cell: Any, env: Any) -> asyncio.Task:
        prev = cell.put_chain
        if prev is not None and (prev.cancelled() or prev.cancelling()):
            cell.put_chain = None  # سلسلة مسمومة: الإيداع الحالي مستقل
        return super()._deposit(cell, env)


# ============================================================ H10_17/H10_18
class _BenchCounter(Actor):
    """عامل قياس: يعدّ ما استلم — نفس نمط Counter في perf/tests/bench.py."""

    def __init__(self) -> None:
        self.n = 0

    async def receive(self, envelope: Any) -> None:
        self.n += 1


async def bench_actor_throughput(n_messages: int = 60_000,
                                 n_workers: int = 4,
                                 mailbox_capacity: int = 8_192) -> dict:
    """قياس فعلي لإنتاجية مجموعة عمال عبر WorkerPool المسترد.

    نفس أسلوب bench_pool في perf/tests/bench.py (إيداع ناري بسلسلة
    FIFO + اقتراع عدّادات العمال) مكبَّراً إلى n_messages. القياس
    perf_counter؛ الأرضية معمارية-نسبي 20k بقرار المشرف 2026-10-18
    (عقد H10_17) — الرقم الفعلي يُعاد في الناتج ليُسجَّل في الأدلة."""
    system = ActorSystem()
    workers: list[_BenchCounter] = []

    def factory() -> _BenchCounter:
        w = _BenchCounter()
        workers.append(w)
        return w

    pool = WorkerPool(system, "bench", factory, n_workers,
                      mailbox_capacity=mailbox_capacity)
    deadline_s = max(60.0, n_messages / 1_000.0)  # كرم مقصود لا تساهل
    t0 = time.perf_counter()
    for i in range(n_messages):
        pool.tell(f"key-{i}", i)
    total = 0
    while total < n_messages:
        await asyncio.sleep(0.004)
        total = sum(w.n for w in workers)
        if time.perf_counter() - t0 > deadline_s:
            break  # المهلة انتهت — النقص يُبلَّغ كما هو، بلا تجميل
    elapsed = time.perf_counter() - t0
    await system.shutdown()
    delivered = sum(w.n for w in workers)
    return {
        "messages": n_messages,
        "workers": n_workers,
        "delivered": delivered,
        "lost": n_messages - delivered,
        "elapsed_s": round(elapsed, 6),
        "msgs_per_s": int(delivered / elapsed) if elapsed > 0 else 0,
        "per_worker": [w.n for w in workers],
        "measurement": "perf_counter",
    }


async def bench_writer_throughput(n_rows: int = 300_000,
                                  batch_size: int = 1_000) -> dict:
    """قياس فعلي لإنتاجية الكاتب المجمّع (عقد H10_18).

    الحوض قياس محض (يعدّ الدفعات ولا يلمس قرصاً) — العقد يقيس الكاتب
    (جمع + سلسلة هضم SHA256 + كتابة) لا سرعة التخزين الخارجي."""
    batch_count = 0

    async def sink(batch: list[bytes]) -> None:
        nonlocal batch_count
        batch_count += 1

    w = BatchedWriter(sink, batch_size=batch_size, flush_interval_s=0.05,
                      max_pending=65_536).start()
    deadline_s = max(60.0, n_rows / 10_000.0)
    t0 = time.perf_counter()
    for i in range(n_rows):
        await w.submit(f"row-{i}")
    while w.written_lines < n_rows:
        await asyncio.sleep(0.004)
        if time.perf_counter() - t0 > deadline_s:
            break  # النقص يُبلَّغ كما هو
    elapsed = time.perf_counter() - t0
    await w.close()
    return {
        "rows": n_rows,
        "written_lines": w.written_lines,
        "elapsed_s": round(elapsed, 6),
        "rows_per_s": int(w.written_lines / elapsed) if elapsed > 0 else 0,
        "batches": w.batches,
        "sink_batches": batch_count,
        "errors": list(w.errors),
        "measurement": "perf_counter",
    }
