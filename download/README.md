# SENTINEL 2.6.0 — ملفات التنزيل الكاملة
# Deterministic Self-Healing DAST Platform — Full Deliverables Index

## الحزمة الرئيسية (حمّل هذه أولًا)
- **sentinel-2.6.0-complete-bundle.zip** — كل شيء في ملف واحد (111 ملفًا):
  المصدر الكامل v2.6.0 (16 وحدة، **9 كواشف + محور التخفي/التشغيل الكامل**) +
  كل المسوحات الحقيقية + أدلة SARIF + تطور المعايير + قاعدة البيانات + السجلات
  (اجتازت الفحص الذاتي: doctor 12/12 من داخل الحزمة المستخرجة)

## حزم المصدر (التطور التاريخي)
- sentinel-2.6.0-source.zip — **الأحدث (Phase 54 — محورا التخفي والتشغيل)**:
  بصمة WAF/التقنيات **السلبية** (صفر طلبات إضافية، أدلة موثّقة، نفي أمين) +
  بطارية XSS **متكيفة مع السياق** DETECT-14 (اكتشفت انعكاس Angular {{}} حقيقيًّا
  على الهدف الحي!) + تراجع أسي عند 429/503 مع احترام Retry-After + مصادقة
  **Bearer/مفاتيح API** مع عدّ رفض أمين + بذر **OpenAPI/Swagger** + تصدير
  **SARIF 2.1.0** (CLI + REST)
- sentinel-2.5.0-source.zip — Phase 53: كواشف SSRF وحقن الأوامر الأعمى وCORS
- sentinel-2.4.0-source.zip — Phase 52: نقطة OAST العامة (webhook.site) بإسناد المصدر
- sentinel-2.3.0-source.zip — Phase 51: المسح بعد المصادقة (جلسات ذاتية الشفاء)
- sentinel-2.2.0-source.zip — Phase 50: محرك متصفح/DOM حقيقي + حقن سمات مقاوم للـ WAF
- sentinel-2.1.0-source.zip / -complete-bundle.zip — خدمات المنصة (REST/UI/OAST/DB)
- sentinel-2.0.x-source.zip — الإصدارات الأولى (0.0→0.3)

## مجلد sentinel-results/ (الملفات المسطحة)
### مسوحات أهداف حقيقية (مصرّح بها)
- **scan_ginjuice_v260.json** — المسح الإنتاجي v2.6.0: **45 مؤكدة / 0 مرفوضة /
  0 إنذار كاذب** — كل النشطات الخمس السابقة سليمة (صفر انحدار) +
  **اكتشاف حي جديد: انعكاس تعبير AngularJS {{}} على /catalog?searchTerm**
  عبر بطارية DETECT-14 (تسليحها جاء من بصمة angularjs السلبية)، مؤكد بـ
  re-test:fresh-ng-expression — وXXE storeId ما زالت مؤكدة OOB من 54.170.155.72
- **scan_ginjuice_v260.sarif** — نفس المسح بصيغة SARIF 2.1.0 (34 نتيجة، 7 قواعد
  ثابتة، جاهز لرفعه على GitHub code scanning)
- **live_validation_v260.json** — حزمة أدلة المرحلة 54 الحية: بصمة الأهداف
  الأربعة (AngularJS في ginandjuice، Java في testfire، ASP.NET في vulnweb —
  كلها صحيحة) + دليل المسح الإنتاجي + إثبات SARIF + إثبات Bearer حي
- scan_ginjuice_v250_PUBLIC_OAST.json — v2.5.0: الفئات الجديدة الثلاث صفر إنذار
  كاذب على هدف حقيقي + التأكيد المستقل الحي لـ XXE productId
- scan_ginjuice_v240_PUBLIC_OAST.json — XXE الأعمى ×2 عبر القناة العامة
- scan_testfire_AUTH_v230.json — المسح المُصادق (10 نقاط /bank/*، 4 ثغرات جديدة)
- scan_testasp/testaspnet/testfire_*.json — بقية الأهداف المرخّصة

### المعايير (Benchmark)
- benchmark_v260_det1/2/3.json — **إثبات الحتمية ×3 لنسخة 2.6.0** (TP=22 FP=0
  FN=0 TN=16، F1=1.000، run-3c0652b6be متطابقة تمامًا، مع إحصاءات البصمة
  وrate_limit الجديدة في كل تقرير)
- benchmark_v250_det1/2/3.json وv240/v5/v4/v1_* — تطور المعيار التاريخي
- benchmark_broken + repair_candidates — حلقة الإصلاح الذاتي

### التقارير والحالة والوثائق
- SENTINEL_Results_Report_AR.pdf — التقرير العربي الشامل (حتى v2.0)
- CHANGELOG.md — ملاحظات الإصدارات الكاملة (أحدثها v2.6.0 بالأعلى)
- WORKLOG.md — سجل العمل متعدد الوكلاء (المهام 1–11)
- sentinel_v260.db — قاعدة بيانات SQLite لمسح الإنتاج الأخير
- ground_truth v1–v6 — تطور الحقيقة الأرضية مع كل مرحلة كواشف

## إجمالي الأهداف الحقيقية (عبر كل الإصدارات)
**4 منصات، 22 ثغرة نشطة مؤكدة، 0 إنذار كاذب، 11 فئة ثغرات** —
كل اكتشاف مقفول بإعادة تشغيل مستقلة (verification-gated) قبل اعتماده.

## جودة الإصدار 2.6.0
اختبارات **59/59** (52→59) | doctor **12/12** | معيار F1=**1.000** حتمي ×3
