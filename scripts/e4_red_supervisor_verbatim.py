import asyncio, sys
sys.path.insert(0, '.')
import sentinel.infra as infra

async def test_e4_red():
    system = infra.ActorSystem()
    actor = system.spawn(infra.Actor)
    task = asyncio.create_task(actor.tell({'n': 1}))
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        r2 = await asyncio.wait_for(
            actor.tell({'n': 2}), timeout=2.0)
        fate2 = 'ok' if r2 is not None else 'none'
    except asyncio.TimeoutError:
        fate2 = 'cancelled-cascade'
    except Exception as e:
        fate2 = f'error:{e}'
    try:
        r3 = await asyncio.wait_for(
            actor.tell({'n': 3}), timeout=2.0)
        fate3 = 'ok' if r3 is not None else 'none'
    except asyncio.TimeoutError:
        fate3 = 'cancelled-cascade'
    except Exception as e:
        fate3 = f'error:{e}'
    print(f'RED fate2={fate2}')
    print(f'RED fate3={fate3}')
    await system.shutdown()

asyncio.run(test_e4_red())
