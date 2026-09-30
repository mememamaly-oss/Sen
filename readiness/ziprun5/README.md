# SENTINEL v4.0.0 — Security Digital Twin Scanner

ماسح أمني حتمي (DAST) يبني **توأمًا رقميًا أمنيًا** للتطبيق، يولّد فرضيات
الهجوم من بيانات فعلية، ولا يُصدر أي نتيجة بلا إثبات قابل لإعادة الإنتاج.

> SENTINEL لا يفحص التطبيق فحسب — بل يبني نموذجًا أمنيًا قابلًا للاختبار
> للتطبيق، ثم يبحث عن الطرق المؤدية إلى أثر حقيقي.

## البدء السريع

```bash
unzip sentinel-4.0.0-source.zip -d sentinel && cd sentinel
python3 sentinel/cli.py doctor                          # 15/15 (أو DEGRADED موثق بلا playwright)
python3 sentinel/cli.py scan https://target.example/ \
  --db results/target.db --out results/scan.json        # فحص
python3 sentinel/cli.py findings --db results/target.db # نتائج
python3 sentinel/cli.py reproduce --finding F-xxxx --db results/target.db
python3 sentinel/cli.py report --db results/target.db --format glass --out g.html
```

## الوثائق

| الوثيقة | المحتوى |
|---|---|
| `docs/INSTALLATION_GUIDE.md` | المتطلبات، التثبيت، playwright، استكشاف الأخطاء |
| `docs/USER_GUIDE.md` | دورة العمل الكاملة خطوة بخطوة (فحص/مصادقة/تفويض/سير عمل/تقارير) |
| `docs/API_CLI_REFERENCE.md` | كل الأعلام والمسارات ورموز الخروج |
| `docs/THREAT_MODEL.md` | أصولنا، سطوح الهجوم، التحكمات، خارج النطاق |
| `docs/SECURITY_MODEL.md` | المبادئ الخمسة وطبقات التحكم وعزل العملاء |
| `docs/KNOWN_LIMITATIONS.md` | الحدود الموثقة بصراحة |
| `docs/SUPPORTED_ENVIRONMENTS.md` | البيئات المختبرة والمتوقعة والقيود |
| `docs/RELEASE_POLICY.md` | الترقيم، بوابات الإصدار، سياسة العيوب |
| `docs/ARCHITECTURE_IP.md` | المعمارية الست طبقات والخنادق التقنية |
| `docs/BENCHMARK_AUDIT.md` | كيف يُراجع طرف ثالث أرقام الجودة |
| `docs/DEMO_5MIN.md` | العرض التوضيحي المكتوب (5 دقائق) |

## القيم الأمنية الثلاثة

1. لا Finding بلا إثبات أثر.
2. الأفعال المغيّرة للحالة خلف علم صريح؛ والمدمِّرة محجوبة دائمًا.
3. الأسرار لا تظهر خامًا في أي مخرجات — خزنة مشفرة + أقنعة فقط.

## أرقام الجودة (v4.0.0)

- الاختبارات: **82/82** · Doctor: **15/15**
- Benchmark: **F1 = 1.000** ثلاث مرات متطابقة (TP=38 / FP=0 / FN=0 / TN=35)
- الفحص من ZIP النهائي + تثبيت نظيف + حملة حية على 4 أهداف مصرّح بها — كلها خضراء
- التفاصيل الكاملة بالأدلة: `PRODUCTION_READINESS_v4.0.0.md`

## الاستخدام المصرّح به فقط

SENTINEL أداة اختبار أمني نشطة — استخدمه فقط على أنظمة تملكها أو تملك تصريحًا
خطيًا صريحًا باختبارها.
