# SENTINEL 2.4.0 — ملفات التنزيل الكاملة
# Deterministic Self-Healing DAST Platform — Full Deliverables Index

## الحزمة الرئيسية (حمّل هذه أولًا)
- **sentinel-2.4.0-complete-bundle.zip** — كل شيء في ملف واحد (102 ملفًا):
  المصدر الكامل v2.4.0 (15 وحدة بما فيها OAST عام `PublicWebhookProvider`) + كل المسوحات
  الحقيقية (بما فيها تأكيد XXE الأعمى عبر القناة العامة) + تطور المعايير + التقارير +
  قاعدة البيانات + السجلات
  (اجتازت الفحص الذاتي: doctor 12/12 من داخل الحزمة المستخرجة)

## حزم المصدر (التطور التاريخي)
- sentinel-2.4.0-source.zip — **الأحدث (Phase 52)**: نقطة OAST العامة — قناة OOB عبر
  webhook.site بلا أي بنية تحتية مملوكة، مع إسناد المصدر (IP+UA) في الدليل، سياسة اختيار
  القناة `--oast auto|local|public`، إحصائية `stats.oast` الشفافة، وفحص doctor جديد
- sentinel-2.3.0-source.zip — Phase 51: المسح بعد المصادقة (دخول ذكي + مراقب جلسة ذاتي الشفاء)
- sentinel-2.2.0-source.zip — Phase 50: محرك متصفح/DOM حقيقي + حقن سمات مقاوم للـ WAF
- sentinel-2.1.0-source.zip / -complete-bundle.zip — خدمات المنصة (REST/UI/OAST/DB)
- sentinel-2.0.3-source.zip — محرك الاكتشاف الموسع (JS ثابت، XXE، CRLF)
- sentinel-2.0.2-source.zip — إصلاحات النقل (POST/Content-Type/redirects)
- sentinel-2.0.1-source.zip — OP-01 التشغيل الذاتي للـ fixture
- sentinel-2.0.0-source.zip — الإصدار الأول

## مجلد sentinel-results/ (الملفات المسطحة)
### مسوحات أهداف حقيقية (مصرّح بها)
- **scan_ginjuice_v240_PUBLIC_OAST.json** — الفحص الإنتاجي v2.4.0 عبر القناة العامة
  (446 طلبًا، 468 ثانية، `stats.oast = public-webhook × 4 تفاعلات`): **XXE حرجة أعمى على
  /catalog/product/stock** — الهدف نفسه جلب الكيان الخارجي من 54.170.155.72
  (UA يؤكد ginandjuice.shop) والاستجابة بقيت 400 بلا محتوى = الدليل الوحيد هو الـ callback؛
  معرّفا عنصرين (storeId + productId) لكل منهما سلسلة أدلة مستقلة (كشف + تحقق بمعرفات
  تفاعل مختلفة) + **صفر انحدار**: نتائج v2.2.0 الخمس كلها باقية
- **scan_testfire_AUTH_v230.json** — المسح المُصادق الحقيقي (حساب jsmith التجريبي العام):
  695 طلبًا (مقابل 190 مجهولة)، 10 نقاط /bank/* غير مرئية للمجهول، **4 ثغرات جديدة**:
  SQLi حرجة /bank/ccApply?passwd + XSS /bank/customize.jsp?lang + XSS /bank/queryxpath.jsp?query
  + open redirect — الجلسة انتهت 3 مرات أثناء المسح وشُفيت ذاتيًا في كل مرة (reauths=3, فشل=0)
- scan_testasp_*.json — SQLi أعمى + اجتياز مسار + XSS (خطر 85)
- scan_testaspnet_*.json — SQLi عمياء Comments.aspx?id (مؤكد بثلاث نواقل جديدة)
- scan_testfire_*.json — 5 ثغرات مؤكدة منها SQLi حرجة تجاوز مصادقة /doLogin
- scan_ginjuice_*.json — تطور الاكتشاف من 0 إلى 8 ثغرات (LIVE→…→v220→v240_PUBLIC_OAST)

### المعايير (Benchmark)
- benchmark_v240_det1/2/3.json — **إثبات الحتمية ×3**: نفس run-3c0652b6be ومصفوفة
  TP=19 FP=0 FN=0 TN=13 ومجموعة نتائج متطابقة تمامًا (مع oast local ×2 تفاعلات في كل جولة)
- benchmark_v5_* — المعيار المُصادق (Phase 51): F1=1.000 حتمي
- benchmark_v1 → v4: تطور F1 من 0.833 إلى 1.000
- benchmark_broken + repair_candidateA/B: حلقة الإصلاح الذاتي (مرشح A مرفوض، B مقبول)
- repro_a/b: قابلية إعادة الإنتاج

### التقارير
- SENTINEL_Results_Report_AR.pdf — التقرير العربي الشامل (8 صفحات)
- report_v210_ginjuice.html — تقرير مسح إنتاجي
- report_ar.html / report_live_test.html — تقارير HTML

### الحالة والذكاء
- sentinel.db — قاعدة SQLite (الجريات + النتائج + التكرارات + الفروق بين الجريات)
- strategy_store.json — مخزن تعلم الاستراتيجية (Wilson LB)
- ground_truth.json — الحقيقة الأرضية v5 للـ fixture (19 TP / 13 TN)

### الوثائق
- WORKLOG.md — السجل الكامل للبناء والإصلاحات (9 مهام)
- CHANGELOG.md — سجل إصدارات المنصة (حتى v2.4.0)
- test-scripts/ — سكربتات اختبار API والمخزن والاستراتيجية

## البوابات النوعية (آخر حالة مؤكدة — v2.4.0)
- اختبارات: 49/49 | دكتور: 12/12 | معيار مُصادق: F1=1.000 (TP=19 FP=0 FN=0 TN=13) حتمي ×3
- أهداف حقيقية: 4 منصات اختبار عامة مصرّح بها — **21 ثغرة مؤكدة إجمالًا (منها XXE أعمى ×2)، 0 إنذار كاذب**
- **إغلاق آخر فجوة معمارية موثقة (Phase 52)**: ثغرات الفئة العمياء أصبحت قابلة للتأكيد
  على الأهداف البعيدة عبر قناة عامة — بانتهائها اكتملت كل مراحل المعمارية الـ 55

## التشغيل السريع
    cd source && python3 sentinel/cli.py doctor
    python3 sentinel/cli.py benchmark
    python3 sentinel/cli.py scan <هدف-مصرّح-به> --oast public --out results/scan.json
    python3 sentinel/cli.py scan <هدف> --auth-user <user> --auth-pass <pass> \
        --auth-url <صفحة-الدخول> --auth-success-marker "<علامة-النجاح>"
    python3 sentinel/cli.py serve   # REST + لوحة تحكم على 127.0.0.1:8022

⚠️ استخدم الأداة على أهداف مصرّح لك باختبارها فقط.
