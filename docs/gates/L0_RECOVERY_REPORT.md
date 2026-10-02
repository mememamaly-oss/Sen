# SENTINEL — PHASE 02 / L0 RECOVERY REPORT
## Recovery + Tenant Isolation Security Gate (المرحلة التمهيدية الإلزامية)

> **⚠️ RECOVERED BASELINE NOTE (أُضيف في L1-R بعد rollback #4)**: المراجع التاريخية في هذا التقرير (`30162f9`، `a24bc78`، `dd8334e`، وسم `v4.1.1` الأصلي `5dfa75d`) هي **git objects مفقودة الآن** — دُمّرت مع `.git` في rollback #4 (راجع `PHASE02_L1_PREFLIGHT.md` و`docs/RECOVERY_PROCEDURE.md`). الأساس الحالي المتحقق: tag `v4.1.1` الجديد (annotated) = `release/v4.1.1` = commit `184871e` «recovery: re-anchor verified SENTINEL v4.1.1 baseline» — **المحتوى مطابق بتّيًا لنفس الأرشيفين المذكورين أدناه** (SHA256 كما هي بلا تغيير). الحالة الكاملة المستعادة: commit `e106c1e` على `main`. كل ما وُثّق في هذا التقرير من محتوى وإثباتات ظل صحيحًا وأُعيد التحقق منه حيًّا في L1-R (انظر `PHASE02_L1R_FINAL_GATE.md`). لم يُمحَ أي شيء من الأصل — هذه الملاحظة إضافة فقط.

| البند | القيمة |
|---|---|
| التاريخ | 2026-10-01 (الجلسة) — 2026-10-02 UTC+3 اكتمل |
| الفرع | `phase/02-l0-recovery-security` (من `main` بعد re-anchor) |
| Re-anchor commit | `30162f9a78a00c28ea54a2096238e379659e0296` |
| Tag | `v4.1.1` (annotated، re-anchor #3 — انظر §4) |
| Release branch | `release/v4.1.1` (نفس الـ commit) |
| أرشيف المصدر | `release-archives/SENTINEL-v4.1.1-source.tar.gz` — **SHA256 `f7c6d219ad0ee8fad29f51d776b59adf95fd4f3c2334fdb20568e17b719fcfbb`** (1,263,577 bytes) — تحقق `sha256sum -c` = OK |
| أرشيف الأدلة الحية | `release-archives/SENTINEL-v4.1.1-live-evidence.tar.gz` — **SHA256 `93e883f8225982e8c6be890fa84812e0064060dec489fc7cf99268506bf2cc24`** (395,523 bytes) — تحقق `sha256sum -c` = OK |
| **الأساس غير القابل للتغيير** | **الأرشيفان أعلاه** (قرار موثّق بعد فقدان Git history — §3) |

---

## 1. الحادثة (Rollback #3)

بعد جلسة PHASE02-GAP-ANALYSIS (آخر سجل في worklog عند بدء L0)، أتلفت إعادة تشغيل الحاوية مجلد `.git` مرة ثالثة:

| العنصر | الحالة قبل L0 | الدليل |
|---|---|---|
| `v4.1.1` tag | **مفقود** (0 tags في المستودع) | `git tag -l` = فارغ |
| `release/v4.1.1` branch | **مفقود** (يوجد فقط `main`) | `git branch -a` |
| كائنات `7141c2d` (baseline سابق) و`3756d6a` (evidence سابق) | **غير موجودة** | `git cat-file -t` = Not a valid object |
| التاريخ الحالي | إعادة بناء: `Initial commit` + 29 snapshot commits برسائل UUID (30 commits) | `git log --oneline --all` |
| `/tmp/my-project/.git` | **غير موجود أيضًا** — الاسترجاع الحرفي من مساحة العمل الناجية مستحيل | فحص مباشر |
| Remote | لا يوجد (موثّق منذ التثبيت: النسخ محلي فقط) | `git remote -v` = فارغ |

**ما نجا سليمًا (مطابق بتّيًا):** شجرة العمل كاملة — `src/` (متطابقة مع مرآة `/tmp/my-project` — `diff -r` = 0)، `build-v411/` (113/113 ملفًا متطابقة مع أرشيف المصدر)، `gap-validation/{results,logs}` و`download/sentinel-v411-gap-closure` (متطابقة مع أرشيف الأدلة — 0 اختلاف)، `release-archives/` (SHA256 مطابق)، كل الأدلة والوثائق والسكربتات وworklog.

**ما فُقد وأُعيد إنشاؤه خلال L0 (كلها gitignored وقت الحادثة):** `node_modules` (bun install — 827 حزمة)، `.next` (بناء نظيف)، `db/custom.db` (db:push + بيانات عبر مسارات حقيقية فقط)، `saas-data/{scans,stores,reports}` (فحوصات محرك حقيقية).

## 2. تحقق المحتوى قبل أي تعديل (أثر ضد الأرشيفات — قبل re-anchor وقبل الإصلاح)

```
diff -r <source-archive-extract> /home/z/my-project/build-v411
  → الفرق الوحيد: "Only in build-v411/results: .doctor_v410.json.LxCyMV"
    (بقايا كتابة ذرّية من تشغيل Doctor قديم — ملف مؤقت مخفي، ليس من شجرة الأساس؛
     لم يُحذف — بقي على القرص وأُستثني من git عبر قاعدة تجاهل موثّقة)
diff -r <evidence-archive>/gap-validation/results  gap-validation/results  → 0
diff -r <evidence-archive>/gap-validation/logs     gap-validation/logs     → 0
diff -r <evidence-archive>/download/sentinel-v411-gap-closure ...          → 0
```

## 3. قرار الاسترجاع (وفق أمر L0 حرفيًا)

1. الاسترجاع الحرفي للتاريخ **مستحيل** (لا remote، الكائنات مفقودة، `/tmp` بلا `.git`).
2. سُجّل ذلك صراحةً (هذا المستند §1) — ولم يُنشأ أي commit أو tag تاريخي وهمي.
3. **الأرشيفان (SHA256 أعلاه) هما الأساس غير القابل للتغيير للمحتوى** — وهما سليمان بتّيًا.
4. أُعيد تعليق مراجع git عبر الآلية الموثّقة نفسها التي استخدمها `scripts/r3_git_rebuild.sh` بعد rollback #2 (re-anchor صادق بتوثيق كامل داخل رسالة الـ commit والـ tag — لا backdating ولا انتحال SHA تاريخي).

## 4. الـ Re-anchor (commit `30162f9`)

- استعادة تتبُّع git لشجرة الأساس المجمدة **بالمطابقة الكاملة للأرشيف**: إعادة تتبُّع 9 ملفات `.pyc` من ملفات الأساس الـ 12 (الباقي 3 متتبَّعة أصلًا)، وإلغاء تتبُّع الملف المؤقت الشارد (بقي على القرص + قاعدة تجاهل `build-v411/results/.*`).
- **الإثبات القاطع**: `git archive v4.1.1:build-v411` (استخراج شجرة الـ tag) `diff -r` مقابل استخراج الأرشيف المجمد → **متطابق بتّيًا**، و`git ls-tree -r v4.1.1 -- build-v411` = **113 ملفًا** (كما في المانيفست).
- `git tag -a v4.1.1` + `git branch release/v4.1.1` على `30162f9` مع رسالة توثّق: سلسلة الفقدان (5dfa75d → 7141c2d → rollback #3)، بصمات الأرشيفين، وأن الأرشيفين هما المرجع.

## 5. إصلاح اختلاف حالة إضافي مكتشف (State Divergence Repair)

- **الاكتشاف**: `tsc --noEmit` فشل بـ 3 أخطاء أنواع في `views-findings.tsx`/`views-scans.tsx` — وهي من مكونات P0 القديمة التي **حذفتها PHASE-01 رسميًا** («OLD P0 view components removed — preserved in git history» في worklog).
- **السبب**: rollback الحاوية أعاد كتابة `/home/z` بحالة قديمة ثم rsync `-a --update` من `/tmp` (الذي يحمل نسخًا قديمة من الملفات المحذوفة لاحقًا) **أعاد إحياء الملفات الثمانية المحذوفة** (نفس فخ mtime الموثّق في R3). آخر بناء ناجح (PHASE01-FIX) كان قبل هذا الإحياء — أي أن البناء كان سيفشل دون هذا الإصلاح.
- **التحقق**: صفر استيرادات لهذه الملفات في كل `src` (`rg 'from "@/components/saas/(views-|login-view|sentinel-app|bits)'` = لا نتائج) — كود ميت.
- **الإجراء**: حُذفت الملفات الثمانية مجددًا (استعادةً لحالة PHASE-01 المثبتة بالبوابات) مع **حفظ نسخ احتياطية** في `.l0-recovery/preserved-resurrected/`. النتيجة: `tsc = 0` و`eslint --max-warnings 0 = 0`.
- لا اختلافات حالة أخرى: `prisma/` و`docs/` وملفات الإعداد السبعة كلها متطابقة مع مرآة `/tmp`.

## 6. عدم ثبات البيئة أثناء البوابات (توثيق أمانة)

تعرّضت الجلسة لنوافذ «تجميد حاوية» متكررة (استدعاءات تعلّق ثم تُقتل عملياتها عند انتهال المهلة). عولج ذلك دون التأثير على صحة النتائج:
- كل خطوة محرك كُتبت مخرجاتها **إلى القرص** (ledger قابل للاستئناف لكل chunk + إعادة محاولة لكل chunk) — انتهى بالحساب الصارم 102/102 بدون تكرار/فقد/زيادة.
- benchmark #2/#3 أعيد تشغيلهما حتى اكتمال الملف الصالح؛ النتائج الثلاث متطابقة بنيويًا مع الأساس (البند §7).
- لم يُقبل أي نتيجة إلا من ملف مكتمل صالح JSON على القرص.

## 7. بوابات المحرك على الشجرة المعاد تعليقها (كلها من clone مستخرج من الـ tag نفسه)

الأدلة في `saas-data/l0-engine/` (doctor_recovery.json، bench_recovery_{1,2,3}.json، ledger.jsonl، tests_recovery.json):

| البوابة | النتيجة | المقارنة بالأساس المجمد (`gap-validation/results`) |
|---|---|---|
| Tests | **102/102** (9 chunks، strict ledger: لا تكرار/فقد/زيادة) | أسماء الحالات + أعلام ok **متطابقة حرفيًا** |
| Doctor | **PASS 15/15** | الحالات فحصًا بفحص متطابقة |
| Benchmark ×3 | **F1=1.000 · TP=38 · FP=0 · FN=0 · TN=35 · findings=190 · requests=1756 ×3** | كل الحقول متطابقة (boundary.by_category، coverage 90/90/0/100%، api_inventory=75، twin=78، param_intel=54) |
| **verify_recovery_v411.py** | **RECOVERY TEST: PASS** | — |

**إثبات عدم تغيّر المحرك بعد كل شيء** (بعد البناء وفحوصات SaaS وفحوصات الإنتاج التي شغّلت المحرك من الشجرة الرئيسية):
`git diff v4.1.1 -- build-v411 gap-validation` = **0 بايت** · الأرشيفان SHA256 OK · worktree ↔ الأرشيف المجمد متطابق بتّيًا · `sentinel.core.VERSION = "4.1.1"`.

## 8. الباقي غير المستعاد (قيود معروفة — لا تأثير على بوابات L0)

1. `gap-validation/tools/` (~617MB: MariaDB/PHP الخاصة بـ DVGA/DVWS): لم يتبق منها إلا ~20KB — **قابلة لإعادة الإنشاء** عبر `gap-validation/setup_*.sh` عند الحاجة لأي live-validation مستقبلي، وليست جزءًا من الأرشيف المجمد ولا من بوابات L0.
2. `remote git`: لا يوجد بعد — التوصية الدائمة: `git push <remote> v4.1.1 release/v4.1.1 main` فور توفر أي مستودع بعيد (RECOVERY_PROCEDURE §3).
3. لا يزال بإمكان أي rollback حاوية قادم إتلاف `.git` — الحماية الوحيدة المتاحة حاليًا هي الأرشيفان + SHA256 (وهذا كافٍ للاسترجاع الكامل كما أثبتت هذه الجلسة).
