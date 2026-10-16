"""الفاعل: دورة حياة معلنة + مرجع تواصل (ActorRef).

حالة الفاعل = حقوله فقط؛ إعادة التشغيل تعني مثيلًا جديدًا من نفس المصنع
(حالة صفرية) مع الاحتفاظ بصندوق البريد والرسائل المنتظرة.
"""
from __future__ import annotations

import asyncio
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # استيراد نوعي فقط لتفادي الاستيراد الدائري
    from perf.actors.system import ActorSystem


class Actor:
    """الفاعل الأساس. المعالجة متسلسلة: لا يتداخل receive مع receive."""

    name: str = ""

    def bind(self, system: "ActorSystem", name: str) -> None:
        self._system: "ActorSystem" = system
        self.name = name

    @property
    def system(self) -> "ActorSystem":
        return self._system

    async def pre_start(self) -> None:
        """قبل أول رسالة (تهيئة). فشله = تصعيد فوري."""

    async def receive(self, envelope) -> Any:
        """معالجة مظروف واحد. القيمة المعادة تُردّ على السائل (ask) إن وجد."""
        raise NotImplementedError

    async def post_stop(self) -> None:
        """بعد التوقف لأي سبب (تنظيف)."""


class ActorRef:
    """مرجع لفاعل حي. tell يعيد مهمة الإيداع (سلسلة FIFO) ولا ينتظرها إلزامًا."""

    def __init__(self, system: "ActorSystem", name: str) -> None:
        self._system = system
        self.name = name

    def tell(self, message: Any, sender: str | None = None) -> asyncio.Task:
        """إرسال ناري: يعيد مهمة الإيداع؛ انتظارها اختياري (الترتيب محفوظ بالسلسلة)."""
        return self._system.tell(self.name, message, sender=sender)

    async def ask(self, message: Any, timeout: float | None = None) -> Any:
        """إرسال بانتظار رد: قيمة return من receive، أو خطأ، أو مهلة."""
        return await self._system.ask(self.name, message, timeout=timeout)

    def stop(self, reason: str = "stop") -> None:
        """إيقاف نظيف عبر الطابور (يعالَج كل ما قبله أولًا)."""
        self._system.tell(self.name, _stop_msg(reason), sender="system")


def _stop_msg(reason: str):
    from perf.actors.messages import Stop
    return Stop(reason)
