# SENTINEL v4.1.0 — محرك سير العمل 2.0 (Workflow Branching & State Intelligence)

> المرجع التنفيذي لتطوير `workflow.py` — من سلاسل خطية إلى رسم بياني حقيقي بفروع وحالات.

## ما الجديد في v4.1.0

### 1. الرسم البياني الحقيقي (`build_graph`)

كل تدفق مُتعلَّم يُصدَّر كرسم بياني:

- **عقد الخطوات**: كل خطوة تحمل `id, kind, action, identity, preconditions,
  parameters, extracted_tokens, referenced_objects, state_before, state_after,
  impact_class, dependencies, provenance, confidence`
- **حواف نوعية**: `next` (خطية) · `branch` (شرطية — تحمل `condition` + `belief`)
  · `approval` (بوابة موافقة) · `cancel_of` · `rollback_of`
- **الاعتماديات**: `token` / `object` / `session` / `identity` لكل خطوة
- **أزواج الحالة لكل خطوة**: من لقطات العرض الحي أثناء المسير المُوجَّه
  (مثال: `''→'APP-0002 standard 1111 DRAFT'` ثم `DRAFT→APPROVED→EXECUTED`)

### 2. تمييز الاعتقاد في الحواف (belief)

| الحالة | المعنى |
|---|---|
| `observed` | مسير/baseline نفّذ هذا الخيار فعليًا |
| `declared` | النموذج يعلن الخيار ولم يُختر بعد |
| `inferred` | مسار مُكتشف (cancel/rollback) لم يُمارس — لا يُعرض كحقيقة |

### 3. مفردات مفصولة

| المفردة | أمثلة | الهجوم المرتبط |
|---|---|---|
| موافقة `APPROVE_RE` | approve, authoriz, signoff | approval_bypass |
| تراجع `ROLLBACK_RE` | rollback, revert, undo | rollback_abuse (+cross_state) |
| إلغاء `CANCEL_RE` | cancel, abort, void, reject | cross_state (الحالية) |
| تقييد `RESTRICTED_RE` | premium, verified, VIP, members only | unauthorized_branch |
| امتياز (قائمة) | admin only, manager | privilege (موجودة) |

## البطارية: من 8 إلى 13 معالجة

| # | الهجوم | الإثبات | الإصدار |
|---|---|---|---|
| 1 | step_bypass | العرض يكتسب كائن canary دون السابقة | v3.0.0 |
| 2 | out_of_order | معرّف اصطناعي يُنفَّذ | v3.0.0 |
| 3 | value_tamper | القيمة المبدلة تظهر في السطر المنفَّذ | v3.0.0 |
| 4 | duplicate | تكرارات العرض 1→2 | v3.0.0 |
| 5 | privilege | خيار admin يُنفَّذ بجلسة دنيا | v3.0.0 |
| 6 | cross_user | عرض المالك يكتسب السطر المنفَّذ | v4.0.0 |
| 7 | cross_object | كائن من نوع آخر يُنفَّذ | v4.0.0 |
| 8 | cross_state | كائن ملغى يُنفَّذ | v4.0.0 |
| 9 | **branch_bypass** | العرض يكتسب سطرًا يحمل قيمة الفرع المزوَّرة | **v4.1.0** |
| 10 | **unauthorized_branch** | عرض الجلسة الدنيا يُظهر الفرع المقيد منفَّذًا | **v4.1.0** |
| 11 | **approval_bypass** | كائن لم يُوافق عليه يُنفَّذ (زوج الحالة يثبت) | **v4.1.0** |
| 12 | **rollback_abuse** | كائن متراجع يُنفَّذ بقيمة canary المبدلة | **v4.1.0** |
| 13 | (إعادة replay محكومة بالـplanner) | بروتوكول JSON مفهوم فقط | v4.1.0/WS |

## قواعد الأمان الجديدة

1. **بوابة شرط مسبق قبل الجلسة**: البنية الغائبة (لا نمط branch-transfer، لا خطوة
   موافقة، لا مسار تراجع) = تخطٍّ صاخب **بدون أي طلب** — أبدًا لا تسجيل دخول مهدر.
2. **بوابة مخطط الهجمات الفورية**: كل هجوم يمر عبر `planner.gate()` قبل أي طلب —
   الهجوم المرفوض يُسجَّل `planner_blocked` ولا يُنفَّذ.
3. **مفردات تخريبية تتفوق دائمًا**: أي مسار يحمل delete/purge/wipe يُصنَّف
   DESTRUCTIVE بغض النظر عن ملاحظة المحرك (إصلاح أمني v4.1.0).

## أداة التحقق

`fixtures/flows_app.py`: معالج طلبات قروض (استمارات أهلية ← إنشاء ← موافقة ← تنفيذ
+ rollback) بنسختين — الهشة تحقق GT بـ8 فئات، والمحصّنة صامتة 100% (no_proof لكل
هجوم). الاختبارات: `unit_v41_workflow_graph_model` + `regression_v41_flows_battery`.
