# TEST REPORT — كل أمر ونتيجته الفعلية

**التاريخ:** 2026-10-23 · **البيئة:** Python 3.12.15 / bun 1.3.14 / Node 24 / Linux (container)
**مدير الحزم:** bun (bun.lock — استُخدم `bun install/update`، لم يُستخدم npm ci لأنه غير مطابق للمشروع)

> لا اختبار ادّعى نجاحه هنا دون سطر نتيجة فعلي أدناه. عمليات لم تُنفذ موثقة بـ NOT RUN/BLOCKED مع السبب.

---

## البطارية النهائية (تشغيل واحد متماسك بعد آخر تعديل)

| # | الأمر | النتيجة | الحالة |
|---|---|---|---|
| 1 | `bun run lint` (eslint .) | خروج 0، صفر أخطاء/تحذيرات | **PASS** |
| 2 | `bun run typecheck` (tsc --noEmit) | خروج 0 | **PASS** |
| 3 | `bun test --preload ./tests/setup.ts tests/security.test.ts` | **19 pass / 0 fail** (66 expect) | **PASS** |
| 4 | `python3 -m pytest tests/test_network_policy.py tests/test_engine_smoke.py -q` | **57 passed** in 19.44s | **PASS** |
| 5 | `bash scripts/run_integration_tests.sh` | خادم dev حقيقي على 3177 + قاعدة scratch → **12 pass / 0 fail** (46 expect)، rc=0 | **PASS** |
| 6 | `python3 -m sentinel.cli doctor` | **19/19 PASS** (0 FAIL, 0 WARN) | **PASS** |
| 7 | `bun run build` (مع DATABASE_URL/SECRET تجريبيين) | ✓ Compiled successfully، 20/20 صفحة، standalone مولّد | **PASS** |
| 8 | `bunx prisma validate` | "The schema at prisma/schema.prisma is valid" | **PASS** |
| 9 | `bun audit` | 28 (19 high / 8 moderate / 1 low) — **كلها سلاسل أدوات تطوير**، 0 إنتاج، 0 حرجة (كانت 107/5 حرجة) | **PASS بتحفظ موثق** |
| 10 | مسح الأسرار (نمط CI) `git grep -E '(github_pat_…\|ghp_…\|sk-…\|BEGIN PRIVATE KEY)'` | نظيف على الملفات المتتبعة | **PASS** |
| 11 | مسح تاريخ git الكامل (7288 blob) | لا قيم اعتماد حقيقية (التفصيل في SECURITY_AUDIT §P-02) | **PASS** |

## تفصيل اختبارات الانحدار الأمنية (الأسماء الفعلية من المخرجات)

### `tests/security.test.ts` — 19/19
```
(pass) SSRF policy: normalizeScanOptions (audit 2026-10-23) > THE REGRESSION: client-supplied allowPrivate:true is IGNORED for non-demo public targets
(pass) SSRF policy > client allowPrivate:false on the demo target still allows private (server policy wins both ways)
(pass) SSRF policy > demo target => private egress allowed (platform-managed fixture)
(pass) SSRF policy > non-demo local URL is denied without explicit lab mode
(pass) SSRF policy > non-demo local URL is allowed ONLY in explicit lab mode
(pass) SSRF policy > numeric option clamping survives (regression guard)
(pass) isLocalUrl heuristic > loopback + RFC1918 + CGNAT + link-local literals are local (13 حالة)
(pass) isLocalUrl heuristic > wildcard DNS conventions count as local (5 حالات)
(pass) isLocalUrl heuristic > public hosts are not local (5 حالات)
(pass) isLocalUrl heuristic > IPv4-mapped IPv6 and exotic v4 forms are local (6 حالات — أضيفت بعد المراجعة العدائية)
(pass) isLocalUrl heuristic > garbage is not local
(pass) login rate limiter > allows up to N hits then blocks, with retryAfter
(pass) login rate limiter > keys are isolated
(pass) login rate limiter > window slides (expired hits free the key)
(pass) password hashing > round-trip verify
(pass) password hashing > unique salts: same password, different hashes
(pass) password hashing > malformed stored hash fails closed
(pass) RBAC helpers > role ranking is total and correct
(pass) RBAC helpers > slugify: ascii, arabic, fallback
```

### `tests/test_network_policy.py` — 54/54
- 38 حالة عنوان خطر محجوبة (loopback بكل أشكاله، RFC1918، 169.254.169.254، CGNAT 100.64/10، unspecified/multicast/reserved، IPv6 ULA/link-local/loopback، IPv4-mapped، 6to4، `0177.0.0.1`/`2130706433`/`0x7f.0.0.1`، `localhost`، أسماء غير قابلة للحل = فشل مغلق)
- 7 عناوين عامة حدّية مسموحة (172.32.0.1، 100.128.0.1، …)
- بوابة النطاق: هدف خاص بلا `--allow-private` → مرفوض؛ قفزة redirect إلى loopback → مرفوضة (بالسماح المضيف وبدونه)؛ file/ftp/gopher/dict/ws → مرفوضة؛ المنافذ والمسارات الممنوعة مفروضة
- **إثبات حي**: سيرفر redirect محلي 302→loopback: البوابة ترفض القفزة **ولا تُفتح أي وصلة للوجهة** (recorder بلا أي اتصال)
- VERSION=4.4.0، سلامة fixtures/benchmarks الثلاثة، مسار cli الافتراضي يحل الملفات

### `tests/test_engine_smoke.py` — 3/3
```
(pass) test_vulnapp_serves_index            — السيرفر يخدم صفحة فهرس حقيقية
(pass) test_engine_scan_smoke_on_fixture    — فحص حي قصير: run_id + نتائج ≥3 + missing_security_headers + عقد result.json
(pass) test_doctor_no_failures              — 19 فحصاً، صفر FAIL
```

### `tests/api.integration.test.ts` — 12/12 (عبر السلك، خادم Next.js حقيقي)
```
(pass) fresh instance reports needsBootstrap=true
(pass) RACE: 10 concurrent bootstrap POSTs — exactly ONE wins   ← 200×1 + 409×9 + DB: مستخدم واحد/قفل واحد
(pass) unauthenticated /api/me is 401
(pass) the winning account can log in and see OWNER org
(pass) SSRF chain: private-network target creation is rejected  ← 6 عناوين داخلية كلها 400
(pass) public target creation succeeds; URL with credentials is rejected
(pass) OWNER adds a MEMBER and a VIEWER
(pass) MEMBER logs in, creates own target, but CANNOT scan the OWNER's target (write-level fix) ← 403
(pass) MEMBER can start a scan on their OWN target (policy still functional)
(pass) VIEWER can read but cannot create targets (RBAC matrix)  ← قراءة 200 / إنشاء 403
(pass) cross-org isolation: MEMBER of org A gets 404 for a foreign org id
(pass) login rate limiting: 11th bad attempt on a fresh email is refused ← 401 فاشل-مغلق
```

## أدلة تجريبية أثناء التطوير (قيم ولها دلالتها)

- **سباق bootstrap قبل الإصلاح النهائي (10 متزامنة على النسخة ذات المعاملة التفاعلية):** فائز واحد + خاسرون P1008/P2028 (عواصف مهلة SQLite بتجمع اتصال=1) — هذا القياس هو مبرر إعادة التصميم إلى INSERT ذرّي مفرد. بعد إعادة التصميم: فائز واحد + 409 نظيفة، صفر مهلات.
- **محاولات وهم العرض أثناء التدقيق:** وثّق أن مخرجات بعض الأوامر كانت تُحرف `[mid]`→`id]` في العرض فقط؛ صحّح المنهجية بفحوص md5/عدّ أدلة على الملفات نفسها. أثر ذلك على التقارير: لا شيء (الاستنتاجات النهائية كلها مبنية على أدلة ملفات لا على عرض طرفية).

## NOT RUN / BLOCKED (بلا استثناءات)

| البند | الحالة | السبب الحرفي |
|---|---|---|
| `prisma migrate dev` على قاعدة حقيقية | NOT RUN | لا توجد قاعدة إنتاج في هذه البيئة؛ القاعدة الاختبارية عبر `db push` على ملف scratch فقط (قاعدة اختبار معزولة — لا بيانات حقيقية لُمسّت) |
| E2E واجهة بمتصفح (تحديد سلوك sandbox بصرياً) | NOT RUN | بيئة التدقيق بلا متصفح؛ السمة موثقة بنيوياً في الملف وفي البناء |
| فحص أمني هجومي على أنظمة خارجية | NOT RUN **بقرار** | محظور بتعليمات المهمة — كل الاختبارات الحية على loopback محلي معزول أو fixtures خاصة |
| `npm audit` | NOT RUN | غير مطابق — المشروع بـ bun.lock؛ استُخدم `bun audit` |
| دفع الفرع إلى GitHub | **BLOCKED** | التوكن المزود يُرجع 401 Bad credentials على /user و/repos (مُلغى أو خطأ نسخ)؛ الفرع كامل محلياً وجاهز |
| فتح PR | BLOCKED | يتطلب الدفع أولاً |
