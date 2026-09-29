# SENTINEL 2.5.0 — ملفات التنزيل الكاملة
# Deterministic Self-Healing DAST Platform — Full Deliverables Index

## الحزمة الرئيسية (حمّل هذه أولًا)
- **sentinel-2.5.0-complete-bundle.zip** — كل شيء في ملف واحد (107 ملفات):
  المصدر الكامل v2.5.0 (16 وحدة، **9 كواشف** بما فيها SSRF وحقن الأوامر الأعمى وCORS) +
  كل المسوحات الحقيقية + تطور المعايير + التقارير + قاعدة البيانات + السجلات
  (اجتازت الفحص الذاتي: doctor 12/12 + معيار F1=1.000 من داخل الحزمة المستخرجة)

## حزم المصدر (التطور التاريخي)
- sentinel-2.5.0-source.zip — **الأحدث (Phase 53 — تحصين الكواشف)**: كواشف SSRF
  (OOB عبر OAST + VR-09) وحقن أوامر أعمى (بطارية فواصل shell + VR-11 بصيغة مستقلة)
  وCORS (انعكاس Origin مع credentials + VR-10 بأصل جديد) + حارس ENG-08 ضد
  self-callbacks (المحرك يتبع redirects لنفس المستضيف — عيب حقيقي اكتُشف حيًّا وأُصلح)
- sentinel-2.4.0-source.zip — Phase 52: نقطة OAST العامة (webhook.site) بإسناد المصدر
- sentinel-2.3.0-source.zip — Phase 51: المسح بعد المصادقة (جلسات ذاتية الشفاء)
- sentinel-2.2.0-source.zip — Phase 50: محرك متصفح/DOM حقيقي + حقن سمات مقاوم للـ WAF
- sentinel-2.1.0-source.zip / -complete-bundle.zip — خدمات المنصة (REST/UI/OAST/DB)
- sentinel-2.0.x-source.zip — الإصدارات الأولى (0.0→0.3)

## مجلد sentinel-results/ (الملفات المسطحة)
### مسوحات أهداف حقيقية (مصرّح بها)
- **scan_ginjuice_v250_PUBLIC_OAST.json** — الفحص الإنتاجي v2.5.0 عبر القناة العامة:
  الفئات الجديدة الثلاث **صفر إنذار كاذب على هدف حقيقي** (نفي أمين — الهدف لا يملك
  هذه الفئات)، وXXE storeId ما زالت مؤكدة OOB من IP خادم الهدف، وصفر انحدار
- **live_validation_v250.json** — أدلة الحملة الحية: فحوص CORS يدوية على الأهداف
  الأربعة (لا انعكاس في أي منها) + **التأكيد المستقل الحي لـ XXE productId**
  (callback من 18.200.201.133، UA الهدف نفسه) عبر كود v2.5.0
- scan_ginjuice_v240_PUBLIC_OAST.json — XXE الأعمى ×2 عبر القناة العامة (Phase 52)
- scan_testfire_AUTH_v230.json — المسح المُصادق (10 نقاط /bank/*، 4 ثغرات جديدة)
- scan_testasp/testaspnet/testfire_*.json — بقية الأهداف المرخّصة

### المعايير (Benchmark)
- benchmark_v250_det1/2/3.json — **إثبات الحتمية ×3** (TP=22 FP=0 FN=0 TN=16،
  مجموعة نتائج متطابقة تمامًا، OAST محلي ×7 تفاعلات في كل جولة)
- benchmark_v240/v5/v4/v1_* — تطور المعيار حتى F1=1.000
- benchmark_broken + repair_candidates — حلقة الإصلاح الذاتي

### التقارير والحالة والوثائق
- SENTINEL_Results_Report_AR.pdf — التقرير العربي الشامل
- sentinel.db / strategy_store.json / ground_truth.json (v6: 22 TP / 16 TN)
- WORKLOG.md (10 مهام) / CHANGELOG.md (حتى v2.5.0) / test-scripts/

## البوابات النوعية (آخر حالة مؤكدة — v2.5.0)
- اختبارات: **52/52** | دكتور: **12/12** (9 كواشف) | معيار مُصادق: **F1=1.000** حتمي ×3
- أهداف حقيقية: 4 منصات مصرّح بها — **21 ثغرة مؤكدة، 0 إنذار كاذب** (بما فيها
  الفئات الجديدة على هدف حقيقي من أول تشغيل)
- **فئات مغطاة الآن**: SQLi (خطأ/بولي/أعمى) + XSS (انعكاسي/DOM عبر متصفح حقيقي) +
  اجتياز مسار + XXE (استجابة/OOB أعمى) + SSRF + حقن أوامر أعمى + CORS + توجيه مفتوح +
  حقن ترويسات + تبعيات JS + فحص سلبي — كلها ببوابة تحقق مستقلة

## التشغيل السريع
    cd source && python3 sentinel/cli.py doctor
    python3 sentinel/cli.py benchmark
    python3 sentinel/cli.py scan <هدف-مصرّح-به> --oast public --out results/scan.json
    python3 sentinel/cli.py scan <هدف> --auth-user <u> --auth-pass <p> --auth-url <دخول>
    python3 sentinel/cli.py serve   # REST + لوحة تحكم على 127.0.0.1:8022

⚠️ استخدم الأداة على أهداف مصرّح لك باختبارها فقط.
