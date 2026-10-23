# DEPENDENCY REVIEW — المحور 13 (2026-10-23)

## المنهجية
- `bun install --frozen-lockfile` (قابلية إعادة الإنتاج) — **نظيف: 667 installs، لا تغييرات**.
- `bun audit --prod` (سلسلة الإنتاج فقط) و `bun audit` (كامل الشجرة) — مخرجات حرفية أدناه.
- لا تحديثات واسعة: overrides موجّهة فقط (أصغر تغيير آمن — قاعدة التوجيه §6).

## النتيجة الحالية (مخرجات فعلية)

| الفحص | النتيجة |
|---|---|
| `bun audit --prod` | **"No vulnerabilities found" — صفر ثغرات في سلسلة الإنتاج** |
| `bun audit` (كامل) | 21 (15 high, 5 moderate, 1 low) — **سلسلة dev فقط** (eslint/babel/browserslist tooling) |

## سلسلة الإنتاج (مباشر، من package.json)
next 16.4.2 · react 19.x · next-auth 4.24.15 (آخر 4.x، إصلاح أمني CVE-2025-… سلسلة 4.24.x) · @prisma/client 6.19.3 · recharts 2.15.4 · zod 4.6.7 (غير مستخدم — I-05) · tailwind · lucide · framer-motion. الحزم المرسومة للعميل (recharts/framer/lucide) لا تصل نقاط تنفيذ ثغراتها المعروفة عبر مدخلات المستخدم (استخدامنا: رسوم بيانية ثابتة لمخرجات فحوصنا).

## Overrides الأمنية المفعلة (من إصلاح GG-2، أعيد التحقق اليوم)
| الحزمة | النطاق | المثبت | السبب (استشارة) |
|---|---|---|---|
| lodash | ^4.17.23 | 4.18.1 | GHSA-r5fr-rjxr-66jc (High، _.template code injection) عبر recharts — يُشحن للعميل |
| source-map-js | ^1.2.2 | 1.2.2 | GHSA-68fv-2mgg-jv7q (High، event-loop DoS) عبر postcss |
| baseline-browser-mapping | ^2.11.0 | 2.11.31 | GHSA-w5vr-8v7q-w6rv (Mod، DoS) |
| defu | ^6.1.5 | 6.1.7 | GHSA-737v-mqg7-c878 (High، proto pollution) |
| deepmerge-ts | ^8.0.2 | 8.0.2 | GHSA-ggr8-5vv4-36mx (High، stack exhaustion) |

توافق overrides مُثبت: `prisma db push` يعمل تحت deepmerge-ts 8 (اختبار فعلي)، البطارية الكاملة خضراء بعدها.

## الاستثناء الموثق (I-06)
الـ21 المتبقية كلها في سلسلة أدوات التطوير (eslint-config-next → babel/browserslist وغيرها): لا تُشحن في standalone ولا تُنفذ في الإنتاج. الاستثناء موقّع هنا ويعاد مراجعته في دورة التبعيات القادمة (لا يوجد مسار ترقية ضمن النطاقات لهذه الحزم بعد).

## مخطوطات التثبيت والسلامة
- `bun.lock` ملتزم ومتسق (frozen نظيف مرتين اليوم).
- لا `postinstall` خطيرة في الحزم المباشرة (مراجعة package.json scripts للحزم المضافة عبر overrides — أدوات بناء قياسية).
- بقايا: لا Dockerfile، لا مصادر حزم غير registry الافتراضي.
