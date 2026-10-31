# SENTINEL — DAST Platform (axes 1-18, final build v4.4.0)

[![CI](https://github.com/mememamaly-oss/Sen/actions/workflows/ci.yml/badge.svg)](https://github.com/memamaly-oss/Sen/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v4.4.0-blue)](https://github.com/mememamaly-oss/Sen/releases)

منصة فحص اختراق تطبيقات الويب الآلي (DAST) — المحرك (Python stdlib نقي) + تطبيق
إدارة SaaS (Next.js). هذا المستودع مُنظّف تشغيلياً: كود المحاور 1-18 فقط.

كل نتيجة فحص موقّعة (Ed25519 فوق جذر Merkle فوق النتائج) وقابلة للتحقق
المستقل بلا أي كود من هذا المشروع — انظر «سجل الشفافية» أدناه.

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

CI: ملف واحد `.github/workflows/ci.yml` (تسع وظائف: التطبيق على PostgreSQL
حقيقي، المحرك، فحص الأسرار، فحص fixture حقيقي على إعدادات الحملة نفسها +
بوابة F1==1.0/TP==38/FP==0، حارس انجراف سجل الامتثال، هدف حقيقي
OWASP Juice Shop بأرضية مُلزِمة، شهادة قابلية إعادة الإنتاج بتشغيلين
مستقلين، سجل الشفافية، وتجربة الـAction كمستهلك خارجي) وقالب GitLab
`integrations/gitlab-ci/sen-scan.gitlab-ci.yml`، إضافة إلى فحص CodeQL
(يعمل عند التحول للعامة).

المحرك يُستدعى من التطبيق عبر `src/lib/engine.ts` (subprocess CLI — `ENGINE_DIR`
افتراضياً جذر المستودع، قابل للتغيير بمتغير `SENTINEL_ENGINE_DIR`).

## فحص الأسرار قبل الالتزام

`pre-commit install` مرة واحدة — خطاف gitleaks (`.pre-commit-config.yaml`)
يفحص كل تغييرات staged قبل الالتزام.

## استخدام المحرك كـ GitHub Action (سطر واحد في أي CI)

```yaml
- uses: mememamaly-oss/Sen@v4.5.0
  with:
    target: http://127.0.0.1:8080
    fail-on: high          # افشل المهمة عند وجود نتائج high فأعلى
```

المدخلات والمخرجات الكاملة وقيود المتصفح (Playwright): `docs/github-action.md`.

## سجل الشفافية والتحقق المستقل

كل نتيجة فحص غنيّة تحمل قسماً موقّعاً (`audit`): جذر Merkle فوق النتائج
(مع استبعاد الحقول الطائرة المعلنة) + توقيع Ed25519 فوق الهضم المركب.
سجل `transparency-log/log.jsonl` يضيف طبقة المشروع: سلاسل هاش مترابطة
موقعة بمفتاح المستودع المعلن `transparency-log/pubkey.hex`.

التحقق لا يحتاج أي كود من المشروع:

```bash
pip install cryptography
python3 tools/independent_verify.py verify-report result.json
python3 tools/independent_verify.py verify-log transparency-log/log.jsonl \
    --pubkey transparency-log/pubkey.hex
```

المحقق `tools/independent_verify.py` لا يستورد شيئاً من المحرك — أي خلل في
الموقّع لا يمكن أن يختبئ في محقق يشاركه الكود. المواصفة الكاملة:
`docs/transparency-log-format.md`.

## الترخيص

Apache-2.0 — انظر `LICENSE` (اختيار افتراضي ينتظر تأكيد المالك النهائي).

## ملفات المجتمع

`CONTRIBUTING.md` · `CODE_OF_CONDUCT.md` · `SECURITY.md` (الإفصاح المسؤول
عن ثغرات في الأداة نفسها) · قوالب Issues/PR تحت `.github/`.

## حذف عمداً في تنظيف 2026-10-23 (قابل للاستعادة من وسم `backup/pre-clean-2026-10-23`)

الاختبارات (tests)، fixtures، benchmarks، نتائج الحملات (campaign, saas-data,
audit-results)، أدلة التحقق (INDEPENDENT_*.md)، نسخ build-v400..v430 القديمة،
وثائق المحاور والأرشيفات (docs, PHASE_02, release-archives)، و~125 سكربت حملات.
