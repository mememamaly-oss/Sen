# REMEDIATION REPORT — كل ملف عُدّل وسبب التعديل

**الفرع:** `security/audit-remediation` (من `main @ 722d9fd`) · **التاريخ:** 2026-10-23
كل تعديل مرتبط بمعرّف ثغرة من SECURITY_AUDIT.md ودليل اختبار من TEST_REPORT.md.

---

## ملفات المصدر (SaaS)

| الملف | التغيير | الثغرة |
|---|---|---|
| `Caddyfile` | حذف كامل لمعالج `@transform_port_query` (اختيار upstream من query param غير موثوق)؛ upstream ثابت `localhost:3000`؛ تعليق توثيقي بقواعد النشر الملازمة (loopback فقط للخدمات الداخلية، حظر إعادة إدخال اختيار upstream ديناميكي) | V-01 |
| `src/lib/engine.ts` | (1) `normalizeScanOptions` بتوقيع جديد `(input, target: {url, isDemo})` — `allowPrivate` يُحسب خادمياً فقط: `isDemo \|\| (labMode && isLocalUrl)`؛ مدخل `input.allowPrivate` يُتجاهل قصداً. (2) `labModeEnabled()` جديد (SENTINEL_ALLOW_PRIVATE_TARGETS=1). (3) `isLocalUrl` معاد كتابته: IPv6 كامل (ULA fe80 loopback)، IPv4-mapped بنسختي dotted+hex (ملاحظة: URL parser يطبّع `[::ffff:10.0.0.1]`→`::ffff:a00:1`)، أشكال v4 الغريبة، لواحق nip.io/sslip.io/localtest.me/.local/.internal/.localhost. (4) `readFingerprintsSync`: المسار عبر argv بدل تضمينه في نص `python -c` | V-02, V-03, V-09 |
| `src/app/api/scans/route.ts` | POST: `requireTargetAccess(..., "write")` بدل "read" (بدء فحص = كتابة) + تمرير `{url, isDemo}` لسياسة الخادم + تعليق توثيقي للقرار | V-05, V-02 |
| `src/app/api/targets/route.ts` | POST: رفض URL ببيانات اعتماد مدمجة (400) + رفض العناوين الداخلية خارج وضع المختبر (400) مع رسالة تدل على متطلب وضع المختبر | V-03 |
| `src/app/api/targets/[id]/route.ts` | PATCH: نفس رفضَي POST (بيانات اعتماد + داخلي) — إغلاق طريق الالتفاف | V-03 |
| `src/app/api/bootstrap/route.ts` | إعادة كتابة POST بالكامل: حارس سباق بـ INSERT ذرّي مفرد على `PlatformLock` (بلا معاملات تفاعلية — قرار هندسي موثق بعد قياس عواصف P1008/P2028 على SQLite)؛ فحص count داخل القفل؛ تعويض عند فشل أي خطوة يحذف الحالة الجزئية والقفل؛ استرداد قفل معلق من محاولة منهارة؛ كل خاسر → 409 حتمي | V-04 |
| `src/app/api/orgs/route.ts` | POST: حلقة إنشاء slug بمعالجة P2002/P2034 (إعادة محاولة مقيّدة ≤5) بدل 500 خام | V-06 |
| `src/app/api/orgs/[id]/members/route.ts` | POST: تبنّي آمن لمستخدم أنشأه طلب متزامن (P2002→findUnique)؛ تعارض عضوية → 409 صريح بدل 500 | V-06 |
| `src/lib/auth.ts` | (1) معادلة توقيت تعداد الحسابات: scrypt وهمي ثابت عند بريد غير موجود. (2) rate limiting داخل authorize (10/15د لكل بريد، 50/15د لكل IP من X-Real-IP/X-Forwarded-For) — يفشل مغلقاً برمي RATE_LIMITED. (3) رفض إقلاع صريح في الإنتاج عند غياب NEXTAUTH_SECRET | V-08 |
| `src/lib/rate-limit.ts` | **ملف جديد** — نافذة منزلقة داخلية (خريطة buckets على globalThis) مع واجهة قابلة للاستبدال بمخزن مشترك؛ حظر حتى خروج أقدم hit من النافذة (لا جداول قفل دائمة) | V-08 |
| `src/app/(app)/reports/[id]/page.tsx` | iframe: `sandbox=""` بدل `sandbox="allow-same-origin"` + تعليق توثيقي كامل للمبرر | V-07 |
| `src/app/api/reports/[id]/route.ts` | ترويسة `X-Content-Type-Options: nosniff` على تنزيل التقارير | V-07 |
| `prisma/schema.prisma` | نموذج جديد `PlatformLock {key @id, createdAt}` — القيد الفريد كمبدأ DB-لإنشاء-مدير-واحد + تعليق توثيقي | V-04 |
| `sentinel/core.py` | `VERSION = "4.4.0"` (محاذاة مع الإصدار المقصود المثبت بثلاثة مصادر) | V-12 |
| `scripts/start_prod_server.sh` | فحص مسبق: رفض الإقلاع بصوت عالٍ عند غياب NEXTAUTH_SECRET مع أمر التوليد | V-08ج |
| `package.json` | اسم/إصدار `sentinel-saas@0.3.0`؛ حذف `--accept-data-loss` من db:push؛ سكربتات جديدة: `typecheck`, `test`, `test:integration`, `test:py` | V-10, V-12 |
| `tsconfig.json` | إضافة include الذي كتبه next بنفسه (`.next/dev/dev/types`) — تغيير توليدي من أداة البناء، مُبقّى لأن البناء يعتمده | — |

## ملفات مستعادة (من `backup/pre-clean-2026-10-23` بتطابق SHA256)

| الملف | البايتات | SHA256 (مطابق للمصدر a051fe6) |
|---|---|---|
| `fixtures/vulnapp.py` | 82,382 | `b3f23d85e534a2619b1e17ac772b0200e870581cd2c17f55410ccbda56489719` |
| `benchmarks/ground_truth.json` | 11,259 | `f98cd5a0bc9485538777c38f58318e6defdcc7f6a7a090248d12d2b349f03dcb` |
| `benchmarks/authz_accounts.json` | 669 | `21438d0ec258826ab7722cde2aeeb1c1de91af95f52930bf7e9394c50c641373` |

## ملفات جديدة (اختبارات + CI + أدوات)

| الملف | الغرض |
|---|---|
| `tests/conftest.py` | إتاحة استيراد حزمة sentinel من جذر المستودع |
| `tests/test_network_policy.py` | 54 اختباراً: مصنف العناوين (38 حالة خطرة/7 عامة حدّية)، بوابة النطاق (هدف خاص/قفزة redirect/مخططات/منافذ/مسارات)، إثبات حي بسيرفرات محلية أن وجهة redirect الداخلية لا تُوصل، سلامة الـ fixtures المستعادة، VERSION=4.4.0 |
| `tests/test_engine_smoke.py` | 3 اختبارات: إقلاع vulnapp على منفذ عشوائي، فحص محرك حي قصير (نتائج ≥3 + missing_security_headers + result.json صالح)، doctor بلا FAIL (19 فحصاً) |
| `tests/setup.ts` | بيئة اختبارات bun (DATABASE_URL/NEXTAUTH_SECRET/SENTINEL_DATA_DIR قبل أي استيراد) |
| `tests/security.test.ts` | 19 اختباراً: انحدار SSRF المركزي، مصفوفة isLocalUrl (بما فيها IPv4-mapped والأشكال البديلة)، limiter (حد/عزل/انزلاق نافذة)، scrypt (ذهاب/عودة/أملاح/فشل مغلق)، RBAC helpers، slugify |
| `tests/api.integration.test.ts` | 12 اختباراً عبر السلك على خادم حقيقي: سباق bootstrap العشري، جلسات NextAuth، رفض الأهداف الداخلية الستة، مصفوفة RBAC (VIEWER/MEMBER)، عزل المؤسسات، rate limiting |
| `scripts/run_integration_tests.sh` | المشغّل المدعوم لاختبار التكامل (bash يدير الخادم — بيئة التدقيق أثبتت أن خوادم مولّدة من داخل bun test غير موثوقة؛ موثق في الملف) |
| `.github/workflows/ci.yml` | CI بثلاث وظائف: web (install/lint/typecheck/test/build)، engine (doctor/pytest)، secrets (مسح أنماط اعتماديات عالية الإشارة على الملفات المتتبعة) |

## الاعتماديات

- ترقيات متوافقة داخل النطاقات: `next-auth 4.24.15` (أمنية)، `next 16.4.2`، `sharp 0.35.5`، `zod 4.6.7`، `zustand 5.0.16` (+ باقي `bun update` داخل النطاقات).
- إزالة تبعيات ميتة (صفر استيراد في src — مُثبت بفحص): `react-syntax-highlighter`, `@mdxeditor/editor`, `@dnd-kit/core|sortable|utilities`, `@tanstack/react-table`, `@reactuses/core`, `next-intl`, `uuid`, `date-fns`.
- النتيجة: 5 حرجة → 0 حرجة؛ الباقي 28 كلها سلاسل أدوات تطوير غير مشمولة في بناء الإنتاج.

## ما **لم** يُعدَّل (عن قصد)

- `sentinel/` (52 وحدة) عدا سطر VERSION — **سياسة عدم لمس المحرك**؛ طبقته الدفاعية فُحصت وثبتت (57 اختباراً) ولم تحتج شيئاً.
- `src/app/api/orgs/[id]/members/[mid]/route.ts` — كان سليماً؛ الادعاء الأولي بكسره كان وهم عرض (توثيق كامل في SECURITY_AUDIT §3).
- `src/lib/passwords.ts` — scrypt أصلاً سليم.
- واجهات الـ API القائمة (التوافق حُفظ — كل التغييرات سلوكية أمنية داخل نفس العقود، عدا حزمة `options.allowPrivate` التي أُبطلت **عن قصد** كإصلاح الثغرة).
