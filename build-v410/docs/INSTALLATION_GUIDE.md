# دليل تثبيت SENTINEL v4.0.0

SENTINEL ماسح أمني حتمي (DAST) يعمل من سطر الأوامر — بدون خادم مركزي وبدون أي خدمات سحابية إلزامية.

## المتطلبات

| المتطلب | الحد الأدنى | ملاحظات |
|---|---|---|
| Python | 3.10+ | اختُبر على 3.12 و3.13 |
| نظام التشغيل | Linux / macOS | اختُبر على Linux x64 |
| الشبكة | وصول HTTP/HTTPS صادر | للأهداف الحية وقناة OAST العامة |
| القرص | ~10 MB للمصدر + قاعدة البيانات | SQLite يتوسع مع النتائج |

**اختياري (يُوصى به):** `playwright` + Chromium — لتفعيل محرك المتصفح/DOM الكامل (إثبات تنفيذ XSS في DOM). بدونه يعمل SENTINEL في وضع التحليل الساكن للـDOM مع تحذير صريح من `doctor`.

## التثبيت من حزمة المصدر (source.zip)

```bash
unzip sentinel-4.0.0-source.zip -d sentinel
cd sentinel
python3 sentinel/cli.py doctor
```

لا توجد خطوة تثبيت إضافية: SENTINEL مكتبة Python نقية (stdlib فقط) تعمل مباشرة من شجرة المصدر.

## التثبيت من الحزمة الكاملة (complete-bundle.zip)

الحزمة الكاملة = المصدر + الوثائق + الاختبارات + Benchmark + نتائج الجودة المرجعية:

```bash
unzip sentinel-4.0.0-complete-bundle.zip -d sentinel-bundle
cd sentinel-bundle
python3 sentinel/cli.py doctor
```

## التحقق من التثبيت (doctor)

```bash
python3 sentinel/cli.py doctor
```

يجب أن ترى `"overall": "PASS"` مع 15/15 فحصًا. في بيئة بلا playwright سيظهر
`"overall": "DEGRADED"` مع تحذير واضح في فحص `browser_engine` — هذا سلوك مقصود
(تراجع آمن ومُعلن، وليس فشلًا صامتًا): كل قدرات الفحص تعمل ما عدا "إثبات تنفيذ
DOM XSS" الذي يتحول إلى تحليل ساكن للـ sinks.

## تشغيل الاختبار الذاتي الكامل (اختياري)

```bash
python3 tests/run_tests.py all
# المتوقع: {"total": 82, "failed": 0}
```

## تفعيل محرك المتصفح (اختياري)

```bash
pip install playwright
python3 -m playwright install chromium
python3 sentinel/cli.py doctor   # يجب أن يصبح browser_engine = PASS
```

## أين تُحفظ البيانات؟

- **قاعدة النتائج:** المسار الذي تمرره لـ `--db` (تُنشأ تلقائيًا، SQLite + WAL).
- **Vault المفاتيح:** `vault keygen --out <ملف>` — يُنشأ بصلاحية 0600، لا يُرفع أبدًا لمستودع.
- **التقارير:** المسار الذي تمرره لـ `--out` في أمر `report`.

## إلغاء التثبيت

احذف مجلد الشجرة وملفات `--db`/`--vault` التي أنشأتها. لا توجد ملفات نظام أو
خدمات خلفية أو مفاتيح سجل تبقى بعد الحذف.

## استكشاف الأخطاء

| المشكلة | السبب المحتمل | الحل |
|---|---|---|
| doctor: `DEGRADED 14/15` | playwright غير مثبت | مقبول للفحص الساكن، أو ثبّت playwright |
|doctor: `egress FAIL` | جدار حماية يحجب الخروج | افتح المنفذ 443 صاعدًا |
| `scope_policy` يرفض هدفًا داخليًا | نطاق خاص محجوب افتراضيًا | أضف `--allow-private` (لأهداف المختبِر المصرّح بها فقط) |
| فشل تسجيل الدخول للأهداف الحية | بيانات دخول خاطئة أو شكل نموذج مختلف | استخدم `--auth-user-field/--auth-pass-field` المطابقين لحقول النموذج |
