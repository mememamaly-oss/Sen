# SENTINEL — DAST Platform (axes 1-18, final build v4.4.0)

منصة فحص اختراق تطبيقات الويب الآلي (DAST) — المحرك (Python stdlib نقي) + تطبيق
إدارة SaaS (Next.js). هذا المستودع مُنظّف تشغيلياً: كود المحاور 1-18 فقط.

## بنية المستودع

| المسار | الوصف |
|--------|-------|
| `sentinel/` | محرك الفحص الكامل — كل المحاور 1-18 (بما فيها `race/` و`symbolic/`) |
| `perf/` | طبقة أداء المحور-10 (actors / aio / columnar) — يستوردها `sentinel/infra.py` |
| `src/` | تطبيق SaaS (Next.js 16 + Prisma) — الواجهة والإدارة |
| `prisma/` | مخطط قاعدة بيانات التطبيق |
| `scripts/` | سكربتات التشغيل (بدء الخادم + بيانات العرض) |
| `Caddyfile` | بروكسي الإنتاج |

## تشغيل المحرك مباشرة (CLI)

```bash
python3 -m sentinel.cli scan <url> --out result.json --db store.db [opts]
python3 -m sentinel.cli reproduce --db store.db --finding F-xxx
python3 -m sentinel.cli report --db store.db --run-id <run> --format html --out report.html
python3 -m sentinel.cli compliance [--json]   # سجل خرائط OWASP/CWE/PCI لكل مكتشف
python3 -m sentinel.cli doctor
```

أعلام المحور-17/18 (اختيارية): `--race`, `--symbolic` (افتراضياً OFF).

كل مكتشف يحمل خريطة الامتثال الخاصة به (`compliance` في كل نتيجة داخل
result.json وفي كل تقرير — HTML/JSON/SARIF/EXECUTIVE/GLASS): OWASP Top 10
(2021 + النسخة النهائية 2025)، CWE، ومتطلب PCI DSS 6.4.2 (= 6.6 في
v3.2.1). وسم المصدر مصاحب لكل خريطة: `official` (الـCWE مذكور في قائمة
الفئة الرسمية — top10.owasp.org) أو `scope` (تصنيف تحريري معلن).

## تشغيل تطبيق SaaS

```bash
bun install
cp .env.example .env                       # + NEXTAUTH_SECRET = openssl rand -base64 32
bash scripts/pg_dev_start.sh               # عنقود PostgreSQL محلي (127.0.0.1:55432، بلا جذر وبلا docker)
bunx prisma migrate deploy               # ترحيلات حقيقية (ليست db push)
bash scripts/run_integration_tests.sh     # الجناح الكامل عبر الخادم الحقيقي
bun run dev                                # خادم تطوير :3000
# أو الإنتاج:
bun run build && bash scripts/start_prod_server.sh
python3 scripts/bootstrap_demo_data.py   # (اختياري) بيانات عرض عبر التدفق الحقيقي
```

قاعدة المنصة PostgreSQL (P2-D)؛ مخازن المحرك لكل هدف تبقى SQLite عمداً
(حتمية، ملف لكل هدف تحت `saas-data/stores`). للنشر: `docker-compose.yml`
(postgres:17) + `bash scripts/verify_postgres.sh`.

الصفحات العامة: `/` (هبوط) و`/docs` و`/docs/compliance` و`/demo` (فحص حقيقي
واحد ضد الـfixture المُدار) — المنصة نفسها خلف تسجيل الدخول مع حرس
جانب الخادم (`src/app/(app)/layout.tsx`).

CI: ملف واحد `.github/workflows/ci.yml` (خمس وظائف، منها فحص fixture حقيقي
على إعدادات الحملة نفسها + حارس انجراف سجل الامتثال) وقالب GitLab
`integrations/gitlab-ci/sen-scan.gitlab-ci.yml`.

المحرك يُستدعى من التطبيق عبر `src/lib/engine.ts` (subprocess CLI — `ENGINE_DIR`
افتراضياً جذر المستودع، قابل للتغيير بمتغير `SENTINEL_ENGINE_DIR`).

## فحص الأسرار قبل الالتزام

`pre-commit install` مرة واحدة — خطاف gitleaks (`.pre-commit-config.yaml`)
يفحص كل تغييرات staged قبل الالتزام.

## حذف عمداً في تنظيف 2026-10-23 (قابل للاستعادة من وسم `backup/pre-clean-2026-10-23`)

الاختبارات (tests)، fixtures، benchmarks، نتائج الحملات (campaign, saas-data,
audit-results)، أدلة التحقق (INDEPENDENT_*.md)، نسخ build-v400..v430 القديمة،
وثائق المحاور والأرشيفات (docs, PHASE_02, release-archives)، و~125 سكربت حملات.
