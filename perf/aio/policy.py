"""سياسة قبول: دلو رموز (token bucket) بساعة قابلة للحقن — حتمية قابلة للاختبار."""
from __future__ import annotations

from typing import Callable


class TokenBucket:
    """سماحية انفجارية capacity ثم تعويض بمعدل rate/ثانية.

    دالة نقية في (الحالة، الزمن المحقون): نفس تسلسل الأزمنة → نفس القرارات.
    """

    def __init__(self, rate: float, capacity: int,
                 clock: Callable[[], float]) -> None:
        if rate <= 0:
            raise ValueError("rate > 0 مطلوب")
        if capacity < 1:
            raise ValueError("capacity >= 1 مطلوب")
        self.rate = rate
        self.capacity = capacity
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()
        self.accepted = 0
        self.rejected = 0

    def allow(self) -> bool:
        now = self._clock()
        self._tokens = min(float(self.capacity),
                           self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self.accepted += 1
            return True
        self.rejected += 1
        return False
