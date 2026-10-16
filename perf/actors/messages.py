"""عقود الرسائل: مظروف + رسائل النظام + معرفات الارتباط (ask)."""
from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any


class SystemMessage:
    """علام: رسائل يديرها النظام (تُعالج قبل receive ولا تصل إليه)."""


@dataclass(frozen=True)
class Stop(SystemMessage):
    """إيقاف نظيف: يُعالج كل ما قبله في الصندوق ثم يتوقف الفاعل."""
    reason: str = "stop"


@dataclass(frozen=True)
class Poison:
    """رسالة اختبارية: تُرغم receive على رفع استثناء (لاختبار الإشراف)."""
    note: str = "poison"


@dataclass(frozen=True)
class Envelope:
    """مظروف الرسالة: مرسل/مستقبل/معرّف ارتباط لـ ask + طابع زمني نانوي."""
    sender: str | None
    receiver: str
    message: Any
    correlation_id: str | None = None
    created_ns: int = field(default_factory=time.time_ns)


_corr = itertools.count(1)


def next_correlation() -> str:
    """معرّف ارتباط فريد أحادي التصاعد (حتمي الترتيب داخل العملية)."""
    return f"corr-{next(_corr)}"
