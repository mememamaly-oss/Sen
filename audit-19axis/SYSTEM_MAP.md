# SYSTEM MAP — SEN (19-Axis Audit, 2026-10-23)

كل استنتاج أدناه مرتبط بمسار ملف فعلي أو أمر مُنفَّذ. لا افتراضات.

## 1. اللغات والأطر ومداخل التشغيل

| المكوّن | التقنية | الدليل |
|---|---|---|
| تطبيق SaaS | Next.js 16.4.2 (App Router, standalone output), React 19, TypeScript 5.9.3, Tailwind | `package.json`, `next.config.ts` |
| قاعدة البيانات | SQLite عبر Prisma 6.19.3 (client + CLI) | `prisma/schema.prisma`, `src/lib/db.ts` |
| محرك الفحص | Python 3.12 stdlib خالص — 62 وحدة | `sentinel/` (62 ملفاً موثقة بـ `git ls-files 'sentinel/**'`) |
| طبقة الأداء | Python (actors/aio/columnar) | `perf/` (17 ملفاً) |
| المصادقة | NextAuth v4.24.15 (credentials, JWT sessions 12h) | `src/lib/auth.ts:48` |
| تشغيل التطبيق | `bun run dev` (:3000) / `bun run build` + standalone (:PORT) | `package.json` scripts |
| تشغيل المحرك | `python3 -m sentinel.cli scan|reproduce|report|doctor|benchmark` | `sentinel/cli.py` |
| الوكيل العكسي | Caddy (`:81` → app `:3000`) | `Caddyfile` |

## 2. سطح الـ API (19 مساراً — `git ls-files 'src/app/api/**'`)

- `auth/[...nextauth]` — تدفق NextAuth (signin/callback/signout).
- `bootstrap` GET/POST — إنشاء أول مالك للمنصة (مقفل ذرياً بـ PlatformLock، 409 بعد الإعداد).
- `me`, `audit` — بيانات المستخدم/سجل التدقيق (org-scoped).
- `orgs` (+`[id]`, `[id]/members`, `[id]/members/[id]`) — إدارة المنظمات والأعضاء (OWNER/MEMBER/VIEWER).
- `targets` (+`[id]`) — إدارة أهداف الفحص (رفض loopback/الشبكات الخاصة ما لم يكن demo).
- `scans` (+`[id]`, `[id]/findings`, `[id]/coverage`) — تشغيل الفحص وقراءة النتائج.
- `reports` (+`[id]`) — توليد التقارير (5 صيغ) وتنزيلها.
- `findings/[id]` — قراءة نتيجة واحدة.
- `v1/scans/[id]/twin` — التوأم الأمني (قراءة فقط، نفس سلسلة العزل).

**نمط التفويض الموحد**: `requireUser()` → `requireOrgAccess(user, orgId)` → وصول للمورد مُقيَّد بـ `orgId` في استعلام Prisma (مثال: `db.report.findFirst({where:{id, orgId}})` — `src/app/api/reports/[id]/route.ts:14`). غير الأعضاء يحصلون على 404 غير مميّز + سجل تدقيق.

## 3. المصادقة والجلسات (المحور 2)

- Credentials provider مع scrypt (`src/lib/passwords.ts`) — تحقق بتكلفة متساوية للبريد الموجود وغير الموجود (dummy hash — `auth.ts:76`).
- Rate limiting على البريد (10/15د) وعلى IP (50/15د) مع فشل مغلق `RATE_LIMITED` (`auth.ts:63-71`، `src/lib/rate-limit.ts` — نافذة منزلقة داخل الذاكرة، قيد عملية واحدة موثق).
- JWT session 12 ساعة (`auth.ts:48`); كوكيز NextAuth: `httpOnly`, `sameSite=lax` (افتراضي v4); `secure` يتبع HTTPS (البيئة الحالية HTTP — موثق كقيد نشر).
- رفض الإقلاع الإنتاجي بدون `NEXTAUTH_SECRET` (`auth.ts:40-45`) — مثبت بالبناء السلبي.

## 4. قاعدة البيانات (المحور 11)

- نماذج: User, Organization, Membership(OWNER/MEMBER/VIEWER + @@unique[userId,orgId]), Target, Scan, Finding(@@unique[scanId,engineId]), Report, AuditLog, TwinGraph, PlatformLock (`prisma/schema.prisma`).
- فهارس على كل مسارات الاستعلام الشائعة (orgId, orgId+createdAt, scanId...) — نفس الملف.
- لا توجد migrations dir — التدفق المعتمد `prisma db push` (موثق؛ لا يوجد مسار migrate في CI/التشغيل).
- استعلامات Prisma فقط (معلمات parameterized) — لا SQL خام في التطبيق (`grep -rn "queryRaw" src/` = صفر).

## 5. المهام الخلفية

- الفحوص تعمل كعمليات spawn خلفية داخل عملية التطبيق (`src/lib/engine.ts:304` — spawn بـ argv array بلا shell) مع سقف تزامن ومصالحة ذاتية `reconcileScan`.
- لا صفوف رسائل، لا cron، لا مهام مجدولة.

## 6. التخزين والملفات

- `SENTINEL_DATA_DIR` (افتراضي `saas-data/`): `scans/<scanId>/` (result.json/log.txt), `stores/<targetId>.db`, `reports/<scanId>-<ts36>.<ext>` (`engine.ts:54-59,614`).
- **لا توجد رفوعات ملفات إطلاقاً** — كل الملفات مولدة من الخادم بأسماء cuid/طوابع زمنية (لا مكوّن من المستخدم في أي مسار).
- تنزيل التقارير: قراءة من مسار محفوظ في DB + `Content-Disposition: attachment` + `nosniff` (`reports/[id]/route.ts:31-41`).

## 7. الشبكة والبروكسي (المحور 6)

- Caddyfile المستودع: `:81` → وكيل ثابت إلى `127.0.0.1:3000` + تمرير `X-Real-IP`. **لا يوجد أي اختيار upstream من المدخلات** (النسخة السابقة SSRF عبر `?XTransformPort` أزيلت كلياً — إثبات سلوكي في المحور 6).
- Caddy الحي في الحاضنة (`/app/Caddyfile`, root, PID 2): **لا يزال يحمل النسخة القديمة المصابة** — مثبت سلوكياً اليوم (canary عبر :81 وصل منفذاً داخلياً، ومن الواجهة العامة أيضاً) — انظر ENV-1 في RELEASE_GATE.

## 8. البناء وCI/CD (المحور 14)

- `bun run build` → standalone + نسخ static/public؛ حارس فشل مغلق بدون السر.
- `.github/workflows/ci.yml`: push/PR → frozen install → prisma generate → lint → typecheck → unit → integration (bash runner) → build → engine doctor + network policy + secret scan (النصف الثاني من الملف).
- لا Dockerfile في المستودع (`git ls-files | grep -i docker` = صفر).
- قيم CI: `NEXTAUTH_SECRET: "ci-only-secret-not-for-production"` — موسومة صراحة، ليست سراً.

## 9. الأسرار ومصادر الثقة (المحور 10)

- `.env` الوحيد: `DATABASE_URL` فقط (اسم متغير موثق؛ القيمة محلية، والملف مُتجاهَل في git — أُعيد التحقق بعد شذوذ الاقتطاع البيئي وأُصلح في هذه المهمة).
- `NEXTAUTH_SECRET`: من البيئة فقط، مرفوض غيابه إنتاجياً.
- المحرك: بصمات Ed25519 (توقيع التقارير) بمشتق HKDF-SHA256 من بذرة `os.urandom(32)` (محور RT-03/04 المُصلَح سابقاً).
- مستودع GitHub: **خاص الآن** (تحقق اليوم عبر API — كان عاماً في الجلسة السابقة).

## 10. التبعيات (المحور 13)

- مباشرة: next 16.4.2, react 19, next-auth 4.24.15, prisma 6.19.3, recharts 2.15.4, zod, tailwindcss… (`package.json`).
- overrides أمنية (من إصلاح GG-2): lodash ^4.17.23, source-map-js ^1.2.2, baseline-browser-mapping ^2.11.0, defu ^6.1.5, deepmerge-ts ^8.0.2.
- `bun install --frozen-lockfile` نظيف (667 حزمة، لا تغييرات) — قابلية إعادة إنتاج مثبتة.
- التفاصيل الكاملة في DEPENDENCY_REVIEW.md.

## 11. الاختبارات الموجودة (المحور 17)

| المجموعة | الملف | العدد الموثق آخر تشغيل |
|---|---|---|
| Unit (bun) | `tests/security.test.ts` | 21 |
| Engine + سياسة الشبكة (pytest) | `tests/test_network_policy.py`, `tests/test_engine_smoke.py` | 57 |
| Integration HTTP (bash runner) | `tests/api.integration.test.ts` | 12 |
| بطارية الإنتاج الحية | `scripts/qa_live_battery.py` | 33 |
| متصفح E2E | `scripts/greengate_browser_e2e.py` | 12 |
| عقد CLI | `scripts/qa_cli_contract.sh` | 5 |
| Doctor | `sentinel.cli doctor` | 19 |
| Benchmark (اصطناعي موسوم) | `benchmarks/ground_truth.json` + fixture v11 | P/R/F1=1.0 (38/0/0/37) |

الفجوات الموثقة: لا اختبارات حمل، لا fuzzing، لا اختبار خارجي (انظر TEST_MATRIX).

## 12. حدود الثقة وتدفق البيانات الحساسة

```
إنترنت ──> Caddy :81 (ثقة منخفضة؛ الوكيل الحي ضعيف = ENV-1)
        ──> Next.js app (ثقة متوسطة: جلسات مصادقة)
              ├──> Prisma/SQLite (ثقة عالية; عزل بالمستأجر في كل استعلام)
              ├──> spawn python engine (argv فقط؛ لا shell)
              │       └──> هدف الفحص (خارج الثقة؛ سياسة شبكة fail-closed في المحرك)
              ├──> saas-data/ (ملفات مولدة؛ أسماء من الخادم)
              └──> تقارير HTML (محتوى يحمل نصوصاً من الهدف) ──> iframe sandbox='' (المتصفح)
```

نقاط عبور الحدود: (1) مدخلات المستخدم → تحقق يدوي/zod في كل مسار؛ (2) ردود الهدف → تعقيم/ترميز في المحرك والتقارير + sandbox في العارض؛ (3) البيئة → config موثق؛ (4) الخادم → سجلات تدقيق لكل عملية حساسة (`src/lib/rbac.ts` audit()).
