import asyncio, sys
sys.path.insert(0, '.')
import sentinel.infra as infra

# تكييف سكربت المشرف على الواجهة الفعلية (perf كما استُرد):
# - spawn(name, factory) يعيد ActorRef (لا spawn(Class))
# - ref.tell() متزامن يعيد مهمة الإيداع نفسها (لا create_task/await tell)
# - الإلغاء قبل أول جدولة للمهمة (نمط T3 المُثبت) — sleep(0) بين tell
#   وcancel كان سيسمح للإيداع الأول بالاكتمال (صندوق فارغ) فيصير الإلغاء
#   لا-عملية ويختفي الاستدلال كلياً
# - مهام الإيداع تعيد None عند النجاح → 'ok' = اكتمال الإيداع (لا r is not None)
# - CancelledError تُلتقط صريحة (وارثة BaseException — except Exception لا تلتقطها)

async def test_e4_red():
    box = []

    class Sink(infra.Actor):
        def __init__(self):
            self.n = 0

        async def receive(self, envelope):
            self.n += 1
            return self.n

    def factory():
        s = Sink()
        box.append(s)
        return s

    system = infra.ActorSystem()
    ref = system.spawn("victim", factory)
    task = ref.tell({'n': 1})   # مهمة الإيداع الأولى
    task.cancel()               # إلغاؤها قبل أول جدولة
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        await asyncio.wait_for(ref.tell({'n': 2}), timeout=2.0)
        fate2 = 'ok'            # الإيداع اكتمل (الوديعة تعيد None عند النجاح)
    except asyncio.TimeoutError:
        fate2 = 'timeout'
    except asyncio.CancelledError:
        fate2 = 'cancelled-cascade'
    except Exception as e:
        fate2 = f'error:{e}'
    try:
        await asyncio.wait_for(ref.tell({'n': 3}), timeout=2.0)
        fate3 = 'ok'
    except asyncio.TimeoutError:
        fate3 = 'timeout'
    except asyncio.CancelledError:
        fate3 = 'cancelled-cascade'
    except Exception as e:
        fate3 = f'error:{e}'
    delivered = box[0].n if box else -1
    print(f'RED fate2={fate2}')
    print(f'RED fate3={fate3}')
    print(f'delivered={delivered}')
    await system.shutdown()

asyncio.run(test_e4_red())
