# SENTINEL 2.2.0 — ملفات التنزيل الكاملة
# Deterministic Self-Healing DAST Platform — Full Deliverables Index

## الحزمة الرئيسية (حمّل هذه أولًا)
- **sentinel-2.2.0-complete-bundle.zip** — كل شيء في ملف واحد (82 ملفًا):
  المصدر الكامل v2.2.0 (14 وحدة بما فيها محرك المتصفح) + كل المسوحات الحقيقية +
  تطور المعايير + التقارير + قاعدة البيانات + السجلات
  (اجتازت الفحص الذاتي: doctor 10/10 من داخل الحزمة المستخرجة)

## حزم المصدر (التطور التاريخي)
- sentinel-2.2.0-source.zip — **الأحدث (Phase 50)**: محرك متصفح/DOM حقيقي + حقن سمات مقاوم للـ WAF
- sentinel-2.1.0-source.zip / -complete-bundle.zip — خدمات المنصة (REST/UI/OAST/DB)
- sentinel-2.0.3-source.zip — محرك الاكتشاف الموسع (JS ثابت، XXE، CRLF)
- sentinel-2.0.2-source.zip — إصلاحات النقل (POST/Content-Type/redirects)
- sentinel-2.0.1-source.zip — OP-01 التشغيل الذاتي للـ fixture
- sentinel-2.0.0-source.zip — الإصدار الأول

## مجلد sentinel-results/ (الملفات المسطحة)
### مسوحات أهداف حقيقية (مصرّح بها)
- scan_testasp_*.json — SQLi أعمى + اجتياز مسار + XSS (خطر 85)
- scan_testaspnet_*.json — SQLi عمياء Comments.aspx?id (مؤكد بثلاث نواقل جديدة)
- scan_testfire_*.json — 5 ثغرات مؤكدة منها SQLi حرجة تجاوز مصادقة /doLogin
- scan_ginjuice_*.json — 5 ثغرات مؤكدة (SQLi حرجة + XSS + حقن ترويسة + توجيه + تبعية)
  LIVE→BASELINE→PRODUCTION→FINAL→v210 يوثّق تطور الاكتشاف من 0 إلى 5

### المعايير (Benchmark)
- benchmark_v1 → v210: تطور F1 من 0.833 إلى 1.000 (TP=13 FP=0 FN=0 TN=10)
- benchmark_broken + repair_candidateA/B: حلقة الإصلاح الذاتي (مرشح A مرفوض، B مقبول)
- repro_a/b: قابلية إعادة الإنتاج (run-3c0652b6be)

### التقارير
- SENTINEL_Results_Report_AR.pdf — التقرير العربي الشامل (8 صفحات)
- report_v210_ginjuice.html — تقرير آخر مسح إنتاجي
- report_ar.html / report_live_test.html — تقارير HTML

### الحالة والذكاء
- sentinel.db — قاعدة SQLite (الجريات + النتائج + التكرارات + الفروق بين الجريات)
- strategy_store.json — مخزن تعلم الاستراتيجية (Wilson LB)
- ground_truth.json — الحقيقة الأرضية للـ fixture (13 TP / 10 TN)

### الوثائق
- WORKLOG.md — السجل الكامل للبناء والإصلاحات (6 مهام)
- CHANGELOG.md — سجل إصدارات المنصة
- test-scripts/ — سكربتات اختبار API والمخزن والاستراتيجية

## البوابات النوعية (آخر حالة مؤكدة — v2.2.0)
- اختبارات: 41/41 | دكتور: 10/10 | معيار: F1=1.000 (TP=17 FP=0 FN=0 TN=12) حتمي ×3 حتى مع متصفح حقيقي
- أهداف حقيقية: 4 منصات اختبار عامة مصرّح بها — 15 ثغرة مؤكدة إجمالًا، 0 إنذار كاذب
- **إغلاق فجوة Phase 50 الموثقة**: xss_dom على /blog?search مؤكدة على ginandjuice.shop
  (برهان تنفيذ حي + إعادة تحقق بـ canary جديدة + متجه حقن سمات تجاوز فلتر الوسوم/المعالجات الحقيقي)

## التشغيل السريع
    cd source && python3 sentinel/cli.py doctor
    python3 sentinel/cli.py benchmark
    python3 sentinel/cli.py scan <هدف-مصرّح-به> --max-pages 25 --out results/scan.json
    python3 sentinel/cli.py serve   # REST + لوحة تحكم على 127.0.0.1:8787

⚠️ استخدم الأداة على أهداف مصرّح لك باختبارها فقط.
