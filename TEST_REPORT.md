# TEST_REPORT.md — النتائج الفعلية بالأوامر ورموز الخروج

> **النسخة المختبرة:** commit `b31dd30` (فرع `qa/real-testing-gate`) — البناء المختبر يعادل كود هذا الالتزام حرفياً (تغييرات ما بعد البناء كانت Caddyfile/ci.yml فقط ولا تدخل في بناء التطبيق).
> **التاريخ:** 2026-10-23 · **البيئة:** pod معزول — bun 1.3.14, node 24.21, Python 3.12.15, Caddy مدمج, Docker غير متوفر.
> **التصنيفات:** PASS نُفّذ واجتاز · FAIL نُفّذ وفشل · BLOCKED تعذّر لسبب بيئة/صلاحية · NOT RUN لم يُنفّذ · INCONCLUSIVE أدلة غير كافية.
>
> هذا التقرير **يحل محل** تقرير 2026-10-23 الأولي (task-16): كل نتائجه أُعيد التحقق منها هنا ضمن بطارية أشمل، وعيوب جديدة اكتُشفت وأُصلحت (`b31dd30`).

---

## 0. خط الأساس المثبت

| الفحص | النتيجة | الدليل |
|---|---|---|
| git fetch origin (قراءة فقط) | PASS | origin/main = `722d9fd` — الريموت لم يُمَسّ (لا push إطلاقاً في هذه المهمة) |
| المحلي main | — | `02a2211` = origin/main + إصلاحات task-16 (لم تُدفع قط — توثيق 401 في worklog) |
| فرع العمل | — | `qa/real-testing-gate` من `02a2211` — **كل التزامات هذه المهمة محلية هنا** |
| توكن الدفع | **BLOCKED** | القيمة الكاملة غير مخزنة على القرص (بروتوكول البصمة فقط: آخر4=`50pN`)، وآخر حالة موثقة لها 401؛ المهمة نفسها تمنع الدفع — **لا حاجة لتوكن في مهمة قراءة-فقط** |

## 1. البطارية النهائية (بعد آخر تعديل — Level 5)

| # | الأمر | النتيجة | رمز الخروج |
|---|-------|---------|-----------|
| 1 | `bun install --frozen-lockfile` | PASS — 670 installs، لا تغييرات | 0 |
| 2 | `bun run lint` | PASS — صفر تحذيرات | 0 |
| 3 | `bun run typecheck` | PASS | 0 |
| 4 | `bun run test` (وحدات) | **PASS 21/21** (منها اختبارا انحدار جديدان للإصلاحات) | 0 |
| 5 | `python3 -m pytest tests/ -q` | **PASS 57/57** (18.66s) | 0 |
| 6 | `bash scripts/run_integration_tests.sh` | **PASS 12/12** (7.23s) | 0 |
| 7 | `bun run build` (مع NEXTAUTH_SECRET اختباري) | PASS — بناء standalone كامل | 0 |
| 7b | `bun run build` (بدون NEXTAUTH_SECRET) | **فشل مقصود — الحارس الأمني يعمل** (يرفض البناء بلا سر) | 1 ✔ |
| 8 | `python3 -m sentinel.cli doctor` | **PASS 19/19** | 0 |
| 9 | `python3 -m sentinel.cli benchmark` | **PASS — precision 1.0 / recall 1.0 / F1 1.0** على `local-fixture-v11` (**synthetic** — fixture مصمم، ليس قياس إنترنت واقعي) | 0 |
| 10 | `bash scripts/qa_cli_contract.sh` (عقد README) | **PASS 5/5**: scan (result.json 1.47MB) · reproduce F-0d8399fd3d (وصفة كاملة) · report HTML (1.95MB) · doctor 19 · أعلام `--race --symbolic` | 0 |
| 11 | `bash scripts/qa_caddy_validate.sh` | PASS — `caddy validate`: "Valid configuration" (كانت تفشل بـ`//` قبل الإصلاح) | 0 |
| 12 | `bash scripts/qa_caddy_behavior.sh` | PASS — بروكسي 200 · **`?XTransformPort=8998` لا يُناوب** (يذهب للتطبيق) · headers تمر | 0 |
| 13 | `python3 scripts/qa_live_battery.py` (خادم إنتاج مبني :3100 + قاعدة نظيفة) | **PASS 33/33** — التفصيل الكامل أدناه | 0 |
| 14 | مسح الأسرار (نمط CI) على الملفات المتتبعة | PASS — نظيف | 0 |

**مجموع الفحوصات الآلية الناجحة في البطارية النهائية: 147** (21+57+12+33+5+19) زائد البناء والتحققين.

## 2. البطارية الحية التفصيلية (33/33) — scripts/qa_live_battery.py

**ضد بناء إنتاجي حقيقي (standalone) على قاعدة نظيفة معزولة — ليس dev:**

### وظيفي (A1–A14)
| المعرف | الاختبار | النتيجة | الدليل المختصر |
|--------|----------|---------|----------------|
| A1 | needsBootstrap=true على قاعدة نظيفة | PASS | HTTP 200 |
| A2 | صفحة الدخول تعرض (عربي RTL) | PASS | HTTP 200, lang="ar" |
| A3 | /api/me بلا جلسة → 401 | PASS | 401 |
| A4 | **سباق bootstrap: 10 POST متزامنة → فائز واحد بالضبط** | PASS | winners=1, losers=9 (409) |
| A5 | bootstrap ثانٍ → 409 | PASS | 409 |
| A6 | دخول credentials → كوكي جلسة | PASS | next-auth.session-token صدر |
| A6.1 | /api/me يعيد المالك | PASS | owner@sentinel.test |
| A6.2 | كوكي الجلسة HttpOnly + SameSite | PASS | كلاهما true |
| A7 | كلمة مرور خاطئة → لا جلسة | PASS | بلا كوكي جلسة |
| A8 | إنشاء الهدف التجريبي (fixture مُدار) | **PASS بعد إصلاح D-01** (كان 503) | isDemo=true |
| A8.1 | fixture حي على 127.0.0.1:8777 | PASS | TCP متصل |
| A9 | هدف عام (إنشاء فقط — لم يُفحص أبداً) | PASS | 200 |
| A10 | بدء فحص على الهدف التجريبي | PASS | RUNNING |
| A11 | **الفحص يكتمل عبر المحرك الحقيقي** | PASS | COMPLETED + runId + duration |
| A11.1 | نتائج مثبتة (19 نتيجة: SQLi حرج، SSTI حرج، Host-Header متوسط...) | PASS | 19 صف في القاعدة |
| A12 | توليد 5 صيغ تقارير | PASS | HTML/JSON/SARIF/EXECUTIVE/GLASS كلها OK |
| A12.1 | استرجاع محتوى التقرير | PASS | 200 |
| A13 | OWNER يضيف MEMBER وVIEWER | PASS | 200/200 |
| A14 | سجل التدقيق يسجل العمليات | PASS | 4+ إدخالات (bootstrap.admin_created, target.created, member.added×2) |

### أمني (B1–B12) — مقارن بـOWASP WSTG
| المعرف | WSTG | الاختبار | النتيجة | الدليل |
|--------|------|----------|---------|--------|
| B1 | ATHN/ATHZ-01 | مصفوفة 9 مسارات محمية بلا جلسة → 401 | PASS | كلها 401 (bootstrap عام بالتصميم GET) |
| B2 | ATHN-07 | **تحديد معدل الدخول** | PASS | المحاولات 1-10 ≈33ms (حرق scrypt متساوٍ)، 11-13 ≈2.7ms + جسم `error=RATE_LIMITED` — **فشل مغلق** |
| B3 | INPV/SSRF | **18 صيغة عناوين خاصة/بديلة تُرفض** (loopback, RFC1918, CGNAT, link-local/ metadata, [::1], [fd00::1], [::ffff:127.0.0.1], [::ffff:10.0.0.5], 0.0.0.0, ثماني 0177، عشري 2130706433, ست عشري 0x7f000001, localhost, metadata hosts, بيانات اعتماد في URL, Azure metadata) | PASS | مرفوض=18/18، لا هروب |
| B4 | ATHZ-02 | VIEWER لا ينشئ أهدافاً | PASS | 403 |
| B4.1 | ATHZ-04 | MEMBER لا يفحص هدف OWNER (مستوى الكتابة) | PASS | 403 |
| B4.2 | ATHZ-04 | عزل بين المؤسسات → 404 | PASS | 404 (لا تمييز وجودية) |
| B5 | INPV-05 | مدخلات بشكل SQLi: لا تسريب أخطاء SQL ولا 500 | PASS | لا leak، لا 500 (Prisma مُعلْمَت) |
| B6 | ERRL-01 | JSON مشوه → بلا stack trace | PASS | رسالة عربية عامة فقط |
| B7 | CLNT/CSP | ترويسات أمنية على كل الاستجابات | **PASS بعد إصلاح D-02** (كانت غائبة كلياً) | nosniff + XFO:DENY + Referrer-Policy + CSP(frame-ancestors 'none') |
| B8 | CONF | تنزيل التقرير: nosniff + attachment | PASS | كلاهما موجودان |
| B9 | INPV-02 | تقرير HTML خالٍ من حقن `<script>` خام | PASS | لا raw-script |
| B10 | SESS-06 | مسار الخروج يعمل | PASS | 200 |
| B11 | CONF-06 | OPTIONS على API | PASS | 204 |
| B12 | INPV/SSRF | PATCH هدف إلى URL خاص → مرفوض | **PASS بعد زوال شلال D-01** | 400 |

## 3. اختبار المتصفح الحقيقي (Level 3) — ضد بناء الإنتاج

| التدفق | النتيجة | الدليل |
|--------|---------|--------|
| صفحة الدخول تعرض (عربي RTL، حقول، زر) | PASS | snapshot + `browser-01-overview.png` |
| دخول owner@sentinel.test → تحويل /overview | PASS | URL تغير، الجلسة قائمة |
| لوحة الملاحة الكاملة (نظرة عامة/أهداف/فحوصات/ثغرات/تقارير/توأم/منظمة/تدقيق) | PASS | snapshot كامل |
| صفحة الأهداف تعرض الهدف التجريبي المُدار | PASS | "Sentinel Demo App (vulnapp محلي) مُدار" |
| صفحة التقارير: 5 صيغ بعدّاد لكل صيغة | PASS | browser-03 |
| **عارض التقرير HTML: iframe بـ`sandbox=""` بلا allow-same-origin** | PASS | `{"sandbox":"","srcdocLen":1974531,"hasAllowSameOrigin":false}` |
| **عزل نافذة التقرير (opaque origin)** | PASS | الوصول من الأب: `BLOCKED: DOMException` |
| صفر أخطاء صفحة/كونسول بعد إضافة CSP الجديدة | PASS | `errors` فارغ على كل الصفحات |
| صفحة الثغرات تعرض الحرجة | PASS | browser-05 (3 حرجة) |
| صفحة التوأم الرقمي تعرض | PASS | browser-06 |

## 4. ما لم يُنفّذ (حالات BLOCKED / NOT RUN موثقة)

| البند | الحالة | السبب الحرفي |
|-------|--------|--------------|
| اختبار خارجي عبر شبكة عامة (Level 4) | **BLOCKED** | لا توجد بيئة staging منشورة مصرح بها؛ القاعدة: لا ادعاء اختبار خارجي بلا تفويض — التفصيل في EXTERNAL_TEST_REPORT.md |
| سير CI على GitHub | **NOT RUN** | الدفع ممنوع بموجب المهمة؛ **بديلاً عنه:** كل خطوة من خطوات ci.yml نُفذت محلياً واجتازت (lint/typecheck/unit/integration/build/doctor/pytest/secrets) — لا يعني ذلك أن CI سيمرّ على GitHub حكماً |
| Docker | **BLOCKED** | غير مثبت في البيئة |
| فحص هدف HTTPS عام حقيقي | **NOT RUN** | يتطلب هدفاً مصرحاً به — لا يوجد؛ الفحص الخارجي بلا تفويض محظور |
| بنك اختبار حمل/أداء عالي | **NOT RUN** | خارج النطاق المصرح (لا DoS/flooding) |
| `db:migrate` (Prisma migrations) | NOT RUN | المشروع يستخدم `db push` (لا مجلد migrations أصلاً) — مخطط بالكامل عبر push مُختبر |

## 5. العيوب المكتشفة والمُصلحة خلال هذه المهمة (قبل البطارية النهائية)

| المعرف | الخطورة | العيب | الإصلاح | الدليل |
|--------|---------|-------|---------|--------|
| D-01 | عالية | **نشر الإنتاج معطوب**: خادم standalone يغيّر cwd إلى `.next/standalone` → جسر المحرك يشغّل المحرك/الهدف التجريبي من مخرجات البناء → 503 للهدف التجريبي وفشل كل الفحوصات في مسار الإنتاج (dev كان يعمل فيخفي العيب) | `resolveProjectRoot()` في engine.ts: صعود من cwd مع تخطي نسخ `.next` المتتبعة الجزئية | قبل: 503 + سجل "can't open file .../standalone/fixtures/vulnapp.py"؛ بعد: 33/33 و19 نتيجة من فحص حقيقي |
| D-02 | متوسطة | صفر ترويسات أمنية على كل الاستجابات | next.config.ts: nosniff/XFO/Referrer-Policy/CSP | قبل: لا شيء؛ بعد: البطارية B7 + المتصفح بلا كسر |
| D-04 | منخفضة | CI يشغّل `bun test` السائب فيلتقط ملف التكامل ذا المسار غير الموثوق (self-spawn) | ci.yml: وحدات عبر `bun run test` + تكامل عبر السكربت الرسمي | فشل موثق للself-spawn في هذه البيئة (مهلة 121s) |
| D-05 | عالية | **Caddyfile "المُصلح" لا يُحمَّل أصلاً**: تعليقات `//` غير معروفة في صيغة Caddyfile — أي نشر بالكلفة المصلحة كان سيفشل بالكامل | تحويل إلى `#` | قبل: "unrecognized directive: //"؛ بعد: "Valid configuration" + اختبار سلوكي |
| ENV-1 | حرجة (بيئة، ليس الكود) | الكلفة الحية للـpod على :81 (`/app/Caddyfile` — root) ما تزال تحمل relay `XTransformPort` مكشوفاً على كل الواجهات (IP عام 21.0.6.201) — **خارج صلاحياتي** (لا root) | **مطلوب من المشغل**: استبدال /app/Caddyfile بالنسخة المصلحة من المستودع + reload | إثبات مباشر: canary على 8999 وصل عبر `:81/?XTransformPort=8999` |

## 6. إعادة التشغيل (قابلية إعادة الاختبار — Level 5)

كل ما سبق قابل لإعادة التنفيذ حرفياً من الالتزام `b31dd30` عبر:
`bash scripts/run_integration_tests.sh` · `python3 scripts/qa_live_battery.py` (بعد `bash scripts/qa_start_prod.sh`) · `bash scripts/qa_cli_contract.sh` · `bash scripts/qa_caddy_validate.sh && bash scripts/qa_caddy_behavior.sh` · `bun run test` · `python3 -m pytest tests/ -q` — لا أسرار مطلوبة (NEXTAUTH_SECRET يولد per-run).
