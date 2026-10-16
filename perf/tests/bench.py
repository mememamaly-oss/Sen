#!/usr/bin/env python3
"""قياسات أداء المحور-10 الفعلية — أرقام ملحوظة لا ادعاءات.

التشغيل: python3 perf/tests/bench.py  → يطبع ويكتب perf/results/bench_axis10.json
كل قياس يعلّل ما يقيسه. الأرقام من هذه الآلة بهذه الجولة — قابلة للتكرار.
"""
from __future__ import annotations

import asyncio
import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from perf.actors import Actor, ActorSystem, WorkerPool
from perf.aio import BatchedWriter, Pipeline
from perf.columnar import ColumnTable, Gt, scan

N_ACTOR_MSGS = 20_000
N_POOL_MSGS = 20_000
N_WRITER_LINES = 50_000
N_PIPE_ITEMS = 20_000
N_SCAN_ROWS = 200_000


class Counter(Actor):
    def __init__(self) -> None:
        self.count = 0

    async def receive(self, envelope) -> None:
        self.count += 1


async def bench_actor_tell() -> dict:
    """إنتاجية tell أحادي الفاعل: رسالة/ثانية عبر سلسلة الإيداع FIFO."""
    system = ActorSystem()
    actor = Counter()
    ref = system.spawn("counter", lambda: actor)
    t0 = time.monotonic()
    for i in range(N_ACTOR_MSGS):
        ref.tell(i)
    deadline = time.monotonic() + 30.0
    while actor.count < N_ACTOR_MSGS and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    dt = time.monotonic() - t0
    await system.shutdown()
    assert actor.count == N_ACTOR_MSGS
    return {"msgs": N_ACTOR_MSGS, "seconds": round(dt, 3),
            "msgs_per_sec": int(N_ACTOR_MSGS / dt)}


async def bench_pool() -> dict:
    """إنتاجية مجموعة 4 عمال: الرسائل تُوزَّع بالتجزئة وتُعالَج بالتوازي."""
    system = ActorSystem()
    actors: list[Counter] = []

    def factory() -> Counter:
        a = Counter()
        actors.append(a)
        return a

    pool = WorkerPool(system, "bench", factory, 4)
    t0 = time.monotonic()
    for i in range(N_POOL_MSGS):
        pool.tell(f"key-{i}", i)
    deadline = time.monotonic() + 30.0
    total = 0
    while total < N_POOL_MSGS and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
        total = sum(a.count for a in actors)
    dt = time.monotonic() - t0
    per_worker = [a.count for a in actors]
    await system.shutdown()
    assert total == N_POOL_MSGS
    return {"msgs": N_POOL_MSGS, "workers": 4, "seconds": round(dt, 3),
            "msgs_per_sec": int(N_POOL_MSGS / dt),
            "per_worker": per_worker,
            "imbalance_pct": round(100 * (max(per_worker) - min(per_worker))
                                   / (N_POOL_MSGS / 4), 1)}


async def bench_writer() -> dict:
    """إنتاجية الكاتب المجمّع: سطر/ثانية عبر الدفعات وسلسلة الهضم."""
    batches: list[list[bytes]] = []

    async def sink(batch: list[bytes]) -> None:
        batches.append(batch)

    w = BatchedWriter(sink, batch_size=512, flush_interval_s=0.02,
                      max_pending=8192).start()
    t0 = time.monotonic()
    for i in range(N_WRITER_LINES):
        await w.submit(f"line-{i}")
    deadline = time.monotonic() + 60.0
    while w.written_lines < N_WRITER_LINES and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    dt = time.monotonic() - t0
    await w.close()
    assert w.written_lines == N_WRITER_LINES
    assert sum(len(b) for b in batches) == N_WRITER_LINES
    return {"lines": N_WRITER_LINES, "seconds": round(dt, 3),
            "lines_per_sec": int(N_WRITER_LINES / dt),
            "batches": len(batches),
            "avg_batch": round(N_WRITER_LINES / len(batches), 1)}


async def bench_pipeline() -> dict:
    """إنتاجية خط 3 مراحل: عنصر/ثانية عبر الطوابير المحدودة."""
    async def stage1(x):
        return x + 1

    async def stage2(x):
        return x * 2

    async def stage3(x):
        return x

    p = Pipeline([stage1, stage2, stage3], capacity=256)
    collector = asyncio.ensure_future(p.collect(N_PIPE_ITEMS, timeout=60.0))
    t0 = time.monotonic()
    for i in range(N_PIPE_ITEMS):
        await p.put(i)
    got = await collector
    dt = time.monotonic() - t0
    closer = asyncio.ensure_future(p.close())
    await closer
    assert len(got) == N_PIPE_ITEMS and got[0] == 2 and got[1] == 4
    return {"items": N_PIPE_ITEMS, "stages": 3, "seconds": round(dt, 3),
            "items_per_sec": int(N_PIPE_ITEMS / dt)}


def bench_columnar() -> dict:
    """أثر التقليم بالخرائط النطاقية على 200 ألف صف: كم كتلة وصفًا مُسِرًا."""
    rng = random.Random(11)
    table = ColumnTable("bench", ["id", "v", "tag"], block_size=1000)
    rows = [{"id": i, "v": rng.randint(0, 10**6),
             "tag": rng.choice(["a", "b", "c"])} for i in range(N_SCAN_ROWS)]
    table.append_rows(rows)
    # عمود مرتب إضافي للتقليم: نقيس على v (عشوائي = أسوأ حالة) وعلى id (مرتب)
    t0 = time.monotonic()
    out_rand = scan(table, {"v": Gt(900_000)})
    dt_rand = time.monotonic() - t0
    t0 = time.monotonic()
    out_sorted = scan(table, {"id": Gt(180_000)})
    dt_sorted = time.monotonic() - t0
    # الاستقصاء الشامل للتحقق من السليمية
    brute_rand = sum(1 for r in rows if r["v"] > 900_000)
    brute_sorted = sum(1 for r in rows if r["id"] > 180_000)
    assert len(out_rand["rows"]) == brute_rand
    assert len(out_sorted["rows"]) == brute_sorted
    sr, ss = out_rand["stats"], out_sorted["stats"]
    return {
        "rows": N_SCAN_ROWS, "blocks": ss["blocks_total"],
        "random_col": {"ms": round(dt_rand * 1000, 1),
                       "blocks_scanned": sr["blocks_scanned"],
                       "rows_scanned": sr["rows_scanned"]},
        "sorted_col": {"ms": round(dt_sorted * 1000, 1),
                       "blocks_scanned": ss["blocks_scanned"],
                       "rows_scanned": ss["rows_scanned"],
                       "rows_saved_pct": round(100 * (1 - ss["rows_scanned"] / N_SCAN_ROWS), 1)},
    }


async def main() -> None:
    print("قياسات المحور-10 — أرقام فعلية من هذه الآلة")
    results = {
        "actor_tell": await bench_actor_tell(),
        "pool_4_workers": await bench_pool(),
        "writer_batched": await bench_writer(),
        "pipeline_3_stages": await bench_pipeline(),
        "columnar_scan": bench_columnar(),
    }
    for name, r in results.items():
        print(f"  {name}: {json.dumps(r, ensure_ascii=False)}")
    out = Path(__file__).resolve().parents[1] / "results" / "bench_axis10.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": sys.version.split()[0], "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  → {out}")


if __name__ == "__main__":
    asyncio.run(main())
