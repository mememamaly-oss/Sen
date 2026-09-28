# SENTINEL 2.3.0 — ملفات التنزيل الكاملة
# Deterministic Self-Healing DAST Platform — Full Deliverables Index

## الحزمة الرئيسية (حمّل هذه أولًا)
- **sentinel-2.3.0-complete-bundle.zip** — كل شيء في ملف واحد (101 ملفًا):
  المصدر الكامل v2.3.0 (15 وحدة بما فيها محرك المصادقة auth.py) + كل المسوحات الحقيقية
  (بما فيها المسح المُصادق على testfire) + تطور المعايير + التقارير + قاعدة البيانات + السجلات
  (اجتازت الفحص الذاتي: doctor 11/11 من داخل الحزمة المستخرجة)

## حزم المصدر (التطور التاريخي)
- sentinel-2.3.0-source.zip — **الأحدث (Phase 51)**: المسح بعد المصادقة — دخول ذكي بالنموذج
  (CSRF مرتبط بالجلسة) + مراقب فقدان الجلسة ذاتي الشفاء + مزامنة جلسة المتصفح + إصلاحا ENG-06/ENG-07
- sentinel-2.2.0-source.zip — Phase 50: محرك متصفح/DOM حقيقي + حقن سمات مقاوم للـ WAF
- sentinel-2.1.0-source.zip / -complete-bundle.zip — خدمات المنصة (REST/UI/OAST/DB)
- sentinel-2.0.3-source.zip — محرك الاكتشاف الموسع (JS ثابت، XXE، CRLF)
- sentinel-2.0.2-source.zip — إصلاحات النقل (POST/Content-Type/redirects)
- sentinel-2.0.1-source.zip — OP-01 التشغيل الذاتي للـ fixture
- sentinel-2.0.0-source.zip — الإصدار الأول

## مجلد sentinel-results/ (الملفات المسطحة)
### مسوحات أهداف حقيقية (مصرّح بها)
- **scan_testfire_AUTH_v230.json** — المسح المُصادق الحقيقي (حساب jsmith التجريبي العام):
  695 طلبًا (مقابل 190 مجهولة)، 10 نقاط /bank/* غير مرئية للمجهول، **4 ثغرات جديدة**:
  SQLi حرجة /bank/ccApply?passwd + XSS /bank/customize.jsp?lang + XSS /bank/queryxpath.jsp?query
  + open redirect — الجلسة انتهت 3 مرات أثناء المسح وشُفيت ذاتيًا في كل مرة (reauths=3, فشل=0)
- scan_testasp_*.json — SQLi أعمى + اجتياز مسار + XSS (خطر 85)
- scan_testaspnet_*.json — SQLi عمياء Comments.aspx?id (مؤكد بثلاث نواقل جديدة)
- scan_testfire_*.json — 5 ثغرات مؤكدة منها SQLi حرجة تجاوز مصادقة /doLogin
- scan_ginjuice_*.json — 5 ثغرات مؤكدة (SQLi حرجة + XSS + حقن ترويسة + توجيه + تبعية)
  LIVE→BASELINE→PRODUCTION→FINAL→v210→v220 يوثّق تطور الاكتشاف من 0 إلى 5

### المعايير (Benchmark)
- benchmark_v5_* — **المعيار المُصادق**: F1=1.000 (TP=19 FP=0 FN=0 TN=13) حتمي ×3
  (run-3c0652b6be، 694 طلبًا، logins=1، reauths=0)
- benchmark_v1 → v4: تطور F1 من 0.833 إلى 1.000 مع محرك المتصفح
- benchmark_broken + repair_candidateA/B: حلقة الإصلاح الذاتي (مرشح A مرفوض، B مقبول)
- repro_a/b: قابلية إعادة الإنتاج

### التقارير
- SENTINEL_Results_Report_AR.pdf — التقرير العربي الشامل (8 صفحات)
- report_v210_ginjuice.html — تقرير آخر مسح إنتاجي
- report_ar.html / report_live_test.html — تقارير HTML

### الحالة والذكاء
- sentinel.db — قاعدة SQLite (الجريات + النتائج + التكرارات + الفروق بين الجريات)
- strategy_store.json — مخزن تعلم الاستراتيجية (Wilson LB)
- ground_truth.json — الحقيقة الأرضية v5 للـ fixture (19 TP / 13 TN)

### الوثائق
- WORKLOG.md — السجل الكامل للبناء والإصلاحات (8 مهام)
- CHANGELOG.md — سجل إصدارات المنصة
- test-scripts/ — سكربتات اختبار API والمخزن والاستراتيجية

## البوابات النوعية (آخر حالة مؤكدة — v2.3.0)
- اختبارات: 46/46 | دكتور: 11/11 | معيار مُصادق: F1=1.000 (TP=19 FP=0 FN=0 TN=13) حتمي ×3
- أهداف حقيقية: 4 منصات اختبار عامة مصرّح بها — **19 ثغرة مؤكدة إجمالًا، 0 إنذار كاذب**
- **إغلاق فجوة Phase 51 الموثقة**: السطح المصادق على testfire مفتوح بالكامل —
  كل ثغرة جديدة أُعيد تأكيدها استقلالًا بمتجهات وكانياري مختلفة عن الماسح

## التشغيل السريع
    cd source && python3 sentinel/cli.py doctor
    python3 sentinel/cli.py benchmark
    python3 sentinel/cli.py scan <هدف-مصرّح-به> --max-pages 25 --out results/scan.json
    python3 sentinel/cli.py scan <هدف> --auth-user <user> --auth-pass <pass> \
        --auth-url <صفحة-الدخول> --auth-success-marker "<علامة-النجاح>"
    python3 sentinel/cli.py serve   # REST + لوحة تحكم على 127.0.0.1:8787

⚠️ استخدم الأداة على أهداف مصرّح لك باختبارها فقط.
