# SENTINEL — Baseline Policy (سياسة الأساس)

> هذه الوثيقة **إلزامية** لكل جلسة عمل مستقبلية على SENTINEL. أي تعارض معها = توقف وتوثيق قبل المتابعة.

## 1. ترتيب مصادر الحقيقة (Source of Truth)

عند أي تعارض، الأولوية بالترتيب:

1. **أرشيفا الإصدار SHA256-verified** (`release-archives/SENTINEL-v4.1.1-{source,live-evidence}.tar.gz`) — للمحتوى المجمد (المحرك + أدلة الفحص).
2. **`release-archives/SENTINEL-v4.1.1-recovery-manifest.json`** — بيانات الأساس (SHAs، commit الـ anchor، الوسم، الفروع).
3. **Git** (tag `v4.1.1` + `release/v4.1.1` + `main`) — للتتبع والعمليات اليومية.
4. **`docs/gates/*` وتقارير المراحل** — للسجل التاريخي والقرارات.

**لا يُعتبر مصدر حقيقة**: `/tmp` (استُخدم مرة واحدة للاستعادة بعد rollback #4 — انتهى دوره)، شجرة عمل غير متحقق منها، أو أي نسخة «أحدث» بلا SHA موثق.

## 2. ما هو الثابت الذي لا يُلمس

| العنصر | القاعدة |
|---|---|
| `build-v411/` | للقراءة فقط على كل الفروع. `git diff v4.1.1 -- build-v411` = 0 دائمًا على `main` و`release/*` |
| `gap-validation/{results,logs}` | مجمدة — أدلة مرجعية للبوابات |
| الأرشيفان | SHA256 مسجل في 3 أماكن (`.sha256` + الـ manifest + `docs/releases/v4.1.1-baseline.md`) — تطابق الثلاثة إلزامي |
| Tag `v4.1.1` / `release/v4.1.1` | لا تحريك، لا حذف، لا force-push، لا إعادة تسمية |
| أرقام البوابات المجمدة | 102/102 · Doctor 15/15 · Bench ×3 F1=1.000 (38/0/0/35) · 68/68 · 37/37 · 30/30 — أي تغيير = كسر أساس يُبلَّغ عنه، لا يُخفى |

## 3. قواعد Git

1. **تاريخ صادق فقط**: لا انتحال تواريخ/مؤلفين، لا backdating، لا «استعادة» commit لا تملك كائناته. الـ re-anchor يُسمّى بما هو: `recovery: re-anchor verified ... baseline`.
2. **لا force-push ولا rewrite** على `main` / `release/v4.1.1` / الوسوم.
3. كل مرحلة عمل على **فرع مستقل** (`phase/...`) يُنشأ من آخر حالة متحققة على `main`.
4. قبل أي عمل: نفّذ preflight (القسم 4). إذا فشل → **STOP وسجّل** — لا «إصلاح صامت».
5. بعد أي commit كبير: تحقق أن `git fsck` نظيف وأن worktree نظيف.

## 4. Preflight الإلزامي لبداية أي جلسة

```bash
cd /home/z/my-project
git status                       # يجب أن يكون نظيفًا (أو الفروق موثقة ومقصودة)
git branch --show-current        # الفرع المتوقع للمرحلة
git rev-parse HEAD v4.1.1 release/v4.1.1   # الأخيران يجب أن يتطابقا
cd release-archives && sha256sum -c SENTINEL-v4.1.1.sha256   # يجب OK
cd .. && git diff v4.1.1 -- build-v411 gap-validation | wc -c   # يجب = 0
grep '"engine_version"' release-archives/SENTINEL-v4.1.1-recovery-manifest.json  # sentinel-core/4.1.1
```

**شرط التوقف**: أي بند أعلاه يخالف المتوقع (خاصة فقدها الوسم/الفرع أو اختلاف SHA256 أو diff ≠ 0) → لا تبدأ العمل؛ نفّذ `docs/RECOVERY_PROCEDURE.md` وأبلغ.

## 5. آلية النجاة من الرول باك (Rollback Resilience)

- **النظام المرجعي**: Git + الأرشيفان (داخل git) + الـ manifest + إجراء الاستعادة. لا اعتماد على `/tmp`.
- **الطبقة 1**: الأرشيفان ملتزمان في git — كل clone يحملهما.
- **الطبقة 2**: `release-archives/SENTINEL-fullstate-<date>.tar.gz` — أرشيف حالة كاملة (git archive للـ main النهائي) يُحدَّث عند إغلاق كل مرحلة؛ يستعيد **كل شيء** (حتى SaaS) بلا /tmp.
- **الطبقة 3**: إجراء الاستعادة الموثق خطوة بخطوة (docs/RECOVERY_PROCEDURE.md) — مجرَّب فعليًا (not theoretical).
- عند اكتشاف rollback جديد: لا تحذف شيئًا، لا تخمّن — وثّق الفروق أولًا ثم نفّذ إجراء الاستعادة.

## 6. أرقام لا تُدّعى بلا قياس

- أي ادعاء أداء/تغطية/قدرة يجب أن يكون له قياس محفوظ في `saas-data/` أو `docs/gates/` — نفس مبدأ L1 §14 (measurement not marketing).
- البوابات تعاد **كاملة** بعد أي استعادة (لا اكتفاء بـ«النتائج القديمة تكفي») — هذا ما يجعل الاستعادة قابلة للتحقق.
