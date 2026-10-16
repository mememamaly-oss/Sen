"""صندوق بريد محدود السعة: FIFO مضمون + ضغط خلفي (backpressure) + إغلاق نظيف.

ضمانات مُختبَرة:
- الترتيب: asyncio.Queue داخليًا → FIFO صارم للإيداعات المكتملة.
- الضغط الخلفي: put ينتظر عند الامتلاء بدل الإسقاط أو الرمي.
- الإغلاق: بعد close يُرفض أي إيداع جديد (MailboxClosed) ويحصل
  المستهلك النهائي على MailboxClosed بعد تصريف ما تبقى + حارس الإغلاق.
"""
from __future__ import annotations

import asyncio
from typing import Any

_CLOSED = object()  # حارس إغلاق — لا يمكن أن يساويه مظروف مستخدم


class MailboxClosed(RuntimeError):
    """الصندوق مغلق: لا إيداع جديد ولا استلام بعد التصريف."""


class Mailbox:
    def __init__(self, capacity: int = 128) -> None:
        if capacity < 1:
            raise ValueError("capacity >= 1 مطلوب")
        self._q: asyncio.Queue = asyncio.Queue(maxsize=capacity)
        self._closed = False

    @property
    def capacity(self) -> int:
        return self._q.maxsize

    @property
    def closed(self) -> bool:
        return self._closed

    def qsize(self) -> int:
        return self._q.qsize()

    async def put(self, item: Any) -> None:
        """إيداع ينتظر عند الامتلاء — هذا هو الضغط الخلفي، لا إسقاط أبدًا."""
        if self._closed:
            raise MailboxClosed("صندوق مغلق: رفض إيداع جديد")
        await self._q.put(item)

    async def get(self) -> Any:
        """استلام FIFO؛ يرفع MailboxClosed عند استهلاك حارس الإغلاق."""
        item = await self._q.get()
        if item is _CLOSED:
            raise MailboxClosed("صندوق مغلق: لا مزيد للاستلام")
        return item

    def drain(self) -> list[Any]:
        """تصريف غير معلّق لكل ما في الصندوق (يستهلك حارس الإغلاق إن وُجد)."""
        out: list[Any] = []
        while True:
            try:
                item = self._q.get_nowait()
            except asyncio.QueueEmpty:
                return out
            if item is not _CLOSED:
                out.append(item)

    def close(self) -> None:
        """إغلاق أحادي: يحقن الحارس فورًا إن وُجدت خانة، وإلا بعد التصريف."""
        if self._closed:
            return
        self._closed = True
        try:
            self._q.put_nowait(_CLOSED)
        except asyncio.QueueFull:
            asyncio.get_running_loop().create_task(self._send_close_sentinel())

    async def _send_close_sentinel(self) -> None:
        """الصندوق كان ممتلئًا: الحارس ينتظر فراغ خانة بعد استهلاك العناصر."""
        await self._q.put(_CLOSED)
