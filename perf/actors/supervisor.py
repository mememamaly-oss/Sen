"""الإشراف: توجيهات القرار عند الفشل + سياسة واحدة-لواحد بحد إعادة تشغيل.

النافذة الزمنية ملك النظام (ActorSystem(window_s=...)) — السياسة ترى
العدّادات مُصفّاة داخل النافذة فقط، فلا ازدواج في مصدر الحقيقة.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Directive(Enum):
    RESUME = "resume"      # أسقط الرسالة الفاشلة، أكمل بالحالة الحالية
    RESTART = "restart"    # مثيل جديد (حالة صفرية) مع الاحتفاظ بصندوق البريد
    STOP = "stop"          # توقف نظيف (post_stop ثم موت)
    ESCALATE = "escalate"  # موت + تسجيل تصعيد على مستوى النظام


@dataclass(frozen=True)
class FailureContext:
    """ما تراه السياسة عند كل فشل: هوية الفاعل والاستثناء والعدّادات داخل النافذة."""
    actor_name: str
    exc: BaseException
    failures_in_window: int
    restarts_in_window: int


@dataclass(frozen=True)
class OneForOne:
    """سياسة لفاعل واحد: on_failure حتى بلوغ max_restarts داخل النافذة،
    بعدها on_breach. القرار دالة نقية في السياق — قابل للاختبار مباشرة."""
    on_failure: Directive = Directive.RESTART
    max_restarts: int = 3
    on_breach: Directive = Directive.ESCALATE

    def __post_init__(self) -> None:
        if self.max_restarts < 0:
            raise ValueError("max_restarts >= 0 مطلوب")

    def decide(self, ctx: FailureContext) -> Directive:
        if ctx.restarts_in_window >= self.max_restarts:
            return self.on_breach
        return self.on_failure


# خطاف لتمديد السياسات (استراتيجيات مخصصة) دون تعديل النظام
StrategyFn = Callable[[FailureContext], Directive]
