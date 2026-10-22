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
python3 -m sentinel.cli doctor
```

أعلام المحور-17/18 (اختيارية): `--race`, `--symbolic` (افتراضياً OFF).

## تشغيل تطبيق SaaS

```bash
bun install && bun run db:push   # تجهيز القاعدة
bun run dev                       # خادم تطوير :3000
# أو الإنتاج:
bun run build && bash scripts/start_prod_server.sh
python3 scripts/bootstrap_demo_data.py   # (اختياري) بيانات عرض عبر التدفق الحقيقي
```

المحرك يُستدعى من التطبيق عبر `src/lib/engine.ts` (subprocess CLI — `ENGINE_DIR`
افتراضياً جذر المستودع، قابل للتغيير بمتغير `SENTINEL_ENGINE_DIR`).

## حذف عمداً في تنظيف 2026-10-23 (قابل للاستعادة من وسم `backup/pre-clean-2026-10-23`)

الاختبارات (tests)، fixtures، benchmarks، نتائج الحملات (campaign, saas-data,
audit-results)، أدلة التحقق (INDEPENDENT_*.md)، نسخ build-v400..v430 القديمة،
وثائق المحاور والأرشيفات (docs, PHASE_02, release-archives)، و~125 سكربت حملات.
