import asyncio, sys
sys.path.insert(0, '..')
import sentinel.infra as infra

async def quick_e4():
    system = infra.ActorSystem()
    actor = system.spawn('a', infra.Actor)
    task = actor.tell({'n': 1})
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass
    try:
        r2 = await asyncio.wait_for(
            actor.tell({'n': 2}), timeout=2.0)
        print('E4_FIX: ok')
    except asyncio.TimeoutError:
        print('E4_FIX: FAILED — still poisoned')
    await system.shutdown()

asyncio.run(quick_e4())
