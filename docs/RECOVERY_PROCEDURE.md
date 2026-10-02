# SENTINEL — Recovery Procedure (إجراء الاستعادة)

> **مُجرَّب فعليًا** — هذا الإجراء هو نفسه الذي نُفّذ في L1-R (rollback #4) وليس نظرية. النسخة المنفذة موثقة في `docs/gates/PHASE02_L1R_FINAL_GATE.md`.

## 0. متى تُنفّذ هذه الوثيقة؟

عند اكتشاف أي من:
- فقدان الوسم `v4.1.1` أو الفرع `release/v4.1.1` (`git rev-parse` يفشل).
- شجرة `/home/z/my-project` رُدّت لحقبة قديمة (مثال rollback #4: لا `src/`، لا `build-v411/`).
- `.git` تالف أو أُعيد لبناؤه بـ snapshot commits غريبة.
- اختلاف SHA256 لأي من الأرشيفين المرجعيين.

**القاعدة الذهبية**: لا تحذف شيئًا قبل توثيقه. لا تخمّن. الفروق تُسجَّل أولًا (مثل `docs/gates/PHASE02_L1_PREFLIGHT.md` في rollback #4).

## 1. مصادر الاستعادة (بالترتيب)

| الحالة | المصدر | الاستخدام |
|---|---|---|
| `.git` سليم | `git checkout main` (أو استخراج `git archive main`) | الحالة الكاملة |
| `.git` مفقود لكن الأرشيفان موجودان | `release-archives/SENTINEL-v4.1.1-{source,live-evidence}.tar.gz` | **المحرك + أدلة الفحص** (المحتوى المجمد). الـ SaaS يحتاج أرشيف الحالة الكاملة أو Git |
| أرشيف الحالة الكاملة موجود | `release-archives/SENTINEL-fullstate-<date>.tar.gz` | كل شيء (SaaS + محرك + أدلة + وثائق) |

**مواقع الأرشيفات**: مجلد `release-archives/` في جذر المشروع — **ملتزمة داخل git**، فتوجد في أي clone، وعلى القرص في `/home/z/my-project/release-archives/`.

## 2. التحقق من الأرشيفين (خطوة إلزامية أولى)

```bash
cd /home/z/my-project/release-archives
sha256sum -c SENTINEL-v4.1.1.sha256
# يجب: OK لكلا الملفين. القيم المرجعية الكاملة:
#   source  : f7c6d219ad0ee8fad29f51d776b59adf95fd4f3c2334fdb20568e17b719fcfbb
#   evidence: 93e883f8225982e8c6be890fa84812e0064060dec489fc7cf99268506bf2cc24
# فشل أي checksum = STOP (لا تُكمل، أبلغ فورًا)
```

## 3. التحقق من المحتوى قبل تثبيت Git (إثبات قبل التعليق)

```bash
# استخراج نظيف للمقارنة
mkdir -p /tmp/rv/src-archive /tmp/rv/ev-archive
tar -xzf release-archives/SENTINEL-v4.1.1-source.tar.gz      -C /tmp/rv/src-archive
tar -xzf release-archives/SENTINEL-v4.1.1-live-evidence.tar.gz -C /tmp/rv/ev-archive

# (أ) شجرة المحرك يجب أن تطابق الأرشيف بتّيًا (الفرق الوحيد المقبول:
#     build-v411/results/.doctor_v410.json.* — بقايا كتابة ذرية موثقة)
diff -r /tmp/rv/src-archive/SENTINEL-v4.1.1 /home/z/my-project/build-v411

# (ب) أدلة الفحص
diff -r /tmp/rv/ev-archive/gap-validation/results /home/z/my-project/gap-validation/results   # = 0
diff -r /tmp/rv/ev-archive/gap-validation/logs    /home/z/my-project/gap-validation/logs      # = 0

# (ج) إصلاح L0 (عزل المستأجرين) يجب أن يكون حاضرًا — لا يقبل الرجوع:
grep -n "requireOrgAccess" "src/app/api/findings/[id]/route.ts"    # موجود
grep -n "orgId: access.orgId" "src/app/api/findings/[id]/route.ts" # موجود
# وعدم وجود نمط: requireUser فقط + orgId من العميل مباشرة في where
```

## 4. إعادة بناء Git بصدق (عند فقدان `.git`)

**الممنوعات**: تزوير commit تاريخية/مؤلف/تاريخ · force rewriting · تعديل الأرشيفات · الادعاء باستعادة كائنات لا تملكها.

```bash
cd /home/z/my-project
# (أ) baseline anchor: المحتوى المجمد فقط (نفس تقسيم الـ baseline الأصلي)
git add build-v411 gap-validation
git commit -m "recovery: re-anchor verified SENTINEL v4.1.1 baseline (container rollback #N)
... وثّق داخل الرسالة: سلسلة الفقدان، SHA256 الكاملان، إثباتات diff،
    وأن هذا re-anchor صادق وليس استعادة حرفية للتاريخ المفقود ..."
BASELINE=$(git rev-parse HEAD)

# (ب) الوسم والفرع
git tag -a v4.1.1 -m "SENTINEL v4.1.1 — VERIFIED RECOVERED BASELINE
Content re-anchored from the SHA256-verified release archive (...)."
git branch release/v4.1.1

# (ج) إثبات التطابق البتّي (إلزامي قبل المتابعة)
git archive v4.1.1:build-v411 | tar -x -C /tmp/rv/tag-tree
diff -r /tmp/rv/tag-tree /tmp/rv/src-archive/SENTINEL-v4.1.1   # يجب = 0

# (د) الحالة الكاملة
#     تأكد أولًا أن .gitignore يستثني: node_modules/ .next/ db/ saas-data/scans/
#     saas-data/stores/ recovery-validation/ .l1r-recovery/ upload/ *.log
#     build-v411/results/.* tsconfig.tsbuildinfo live-targets/
git add -A
git commit -m "recovery: restore full SaaS + L0 state ... (rollback #N)"
```

## 5. إعادة بناء dependencies

```bash
cd /home/z/my-project
bun install                      # ~827 حزمة (7-60 ثانية حسب الكاش)
npx tsc --noEmit                 # يجب: 0 errors
npx eslint src --max-warnings 0  # يجب: نظيف
```

**فخ موثق (rollback #3/#4)**: النسخ القديمة قد تُحيي ملفات P0 الميتة الثمانية
(`src/components/saas/{bits,login-view,sentinel-app,views-admin,views-findings,views-reports,views-scans,views-targets}.tsx`) —
تُحذف مجددًا **بعد** إثبات صفر استيرادات (`grep -rE 'from "@/components/saas/(views-|login-view|sentinel-app|bits)' src/` = لا نتائج) مع نسخة احتياطية على القرص.

## 6. إعادة بناء DB (عبر مسارات حقيقية فقط — لا صفقات ملفقة)

```bash
cd /home/z/my-project
bun run db:push                  # ينشئ db/custom.db من prisma/schema.prisma
# ثم شغّل الخادم (القسم 7) ونفّذ عبر الـ API:
#   1) POST /api/bootstrap  → أول مستخدم = platform admin (admin@sentinel.local)
#   2) python3 scripts/bootstrap_demo_data.py --base http://localhost:3000
#      (يؤسس: admin + org "Sentinel SOC" + demo target + فحص محرك حقيقي + findings)
```

`.env` المطلوب (مسار محلي فقط، لا أسرار): `DATABASE_URL=file:/home/z/my-project/db/custom.db`

## 7. البناء والتشغيل

```bash
cd /home/z/my-project
rm -rf .next && bun run build    # نظيف من الصفر (typecheck مفعّل)
bun run start                    # الإنتاج على :3000 (standalone)
```

## 8. بوابات الانحدار الكاملة (كلها يجب أن تخضرّ)

| البوابة | الأمر | النتيجة المطلوبة |
|---|---|---|
| محرك: 102 اختبار | chunks: `python3 scripts/run_recovery_chunks_fg.py` (أو من clone مستخرج من الأرشيف) ثم merge + `python3 scripts/verify_recovery_v411.py` | **102/102** + تطابق أسماء/أعلام الحالات مع الأساس |
| Doctor | `cd <engine-tree> && python3 -m sentinel.cli doctor` | **15/15** |
| Benchmark ×3 | `python3 -m sentinel.cli benchmark --out <f>..` ×3 | **F1=1.000 · TP=38 · FP=0 · FN=0 · TN=35** ×3 (مطابقة بنيوية للأساس) |
| SaaS E2E | `python3 scripts/r3_e2e_orchestrator.py --port 3001` | **68/68** (قاعدة مؤقتة) |
| Tenant isolation | `python3 scripts/l0_isolation_orchestrator.py --port 3002` | **37/37** |
| Production API | `python3 scripts/l0_prod_verify.py --base http://localhost:3000` | **30/30** (يتطلب bootstrap_demo_data أولًا) |
| عدم تغير المحرك | `git diff v4.1.1 -- build-v411 gap-validation \| wc -c` | **= 0** |
| سلامة git | `git fsck --full` | نظيف |

**اختبار العزل الحاسم** (داخل 37/37 و30/30): Org A → Finding Org B = **404** بلا بيانات حساسة · Org A → Finding Org A = **200**.

## 9. اختبار الاستعادة النظيفة (Clean Reconstruction)

مرة واحدة بعد كل استعادة كبرى — في مجلد منفصل `recovery-validation/` دون الاعتماد على حالة `/home/z/my-project` المتغيرة (node_modules/db/.next):

1. **المحرك من الأرشيف**: `tar -xzf release-archives/SENTINEL-v4.1.1-source.tar.gz` → تشغيل 102/102 + Doctor + Bench ×3 من الاستخراج مباشرة.
2. **الـ SaaS من git**: `git clone /home/z/my-project recovery-validation/saas` → `bun install` + `db:push` + `rm -rf .next && bun run build` → E2E 68/68 + tenant isolation عبر منافذ مؤقتة (نسخ السكربتات مع تعديل مسار root فقط).
3. فشل أي بند → الاستعادة **BLOCKED** — لا إعلان نجاح.

## 10. الإغلاق

1. حدّث `release-archives/SENTINEL-v4.1.1-recovery-manifest.json` (commit الـ anchor/الحالة/التاريخ).
2. أنشئ/حدّث أرشيف الحالة الكاملة: `git archive --format=tar.gz -o release-archives/SENTINEL-fullstate-<date>.tar.gz main` + سجّل SHA256 في الـ manifest.
3. وثّق كل شيء في `docs/gates/` + worklog.
4. `git fsck --full` + worktree نظيف.
