# SENTINEL — PHASE 02 / L0 TENANT ISOLATION REPORT
## إغلاق ثغرة الوصول العابر للمستأجرين في `/api/findings/[id]`

> **⚠️ RECOVERED BASELINE NOTE (أُضيف في L1-R بعد rollback #4)**: هذا الإصلاح (requireOrgAccess + تحديد نطاق الاستعلام بـ access.orgId) **ناجٍ ومُتحقَّق حيًّا** في الاستعادة بعد rollback #4 — أُعيد إثبات هجماته كاملة (37/37 مؤقت + 30/30 إنتاج) في L1-R. المراجع التاريخية القديمة إن وردت أدناه مفقودة من git؛ المرجع الحالي: `src/app/api/findings/[id]/route.ts` كما هو في `main@e106c1e`.

| البند | القيمة |
|---|---|
| الملف المُصلَح | `src/app/api/findings/[id]/route.ts` (المسار الوحيد المُصاب) |
| نوع العيب | Broken Access Control — Tenant Isolation (OWASP A01:2021) |
| خطورة ما قبل الإصلاح | **CRITICAL** — قراءة كاملة لبيانات Findings عبر المستأجرين (evidence/verification/impact/reproduction) |
| الإصلاح | تمرير المسار عبر نقطة الاختناق الموثّقة `requireOrgAccess` + تحديد نطاق الاستعلام بـ `access.orgId` |
| الاختبارات الدائمة | `scripts/l0_tenant_isolation_test.py` (37 فحصًا) + `scripts/l0_prod_verify.py` (30 فحصًا) |

---

## 1. العيب الأمني بالتحديد (قبل الإصلاح)

`src/app/api/findings/[id]/route.ts` (النسخة قبل L0):

```ts
const user = await requireUser();                                  // مصادقة فقط
const orgId = String(req.nextUrl.searchParams.get("orgId") || ""); // من الـ query — يتحكم فيه المهاجم
if (!orgId) throw new ApiError(400, "orgId مطلوب");

const finding = await db.finding.findFirst({
  where: { id, orgId },                                            // ← orgId خام يدخل الاستعلام مباشرة
  ...
});
if (!finding) throw new ApiError(404, "الثغرة غير موجودة");
return NextResponse.json({ finding, scan, target, evidence, verification, impact, reproduction, ... });
```

**سيناريو الاستغلال**: أي مستخدم مصادق عليه (عضو Org A) يطلب:
`GET /api/findings/<findingId-of-OrgB>?orgId=<OrgB-id>`
→ `findFirst({ id: finding-of-OrgB, orgId: OrgB })` **يجد النتيجة** (المعرّفان متوافقان) → **200 + كامل الحزمة الحساسة**: سلسلة الأدلة (evidence)، سجل التحقق (verification)، تقييم الأثر (impact)، **وصفة إعادة الإنتاج (reproduction)** — أي أن مهاجمًا من منظمة يحصل على خريطة استغلال كاملة لمنظمة أخرى.

**لماذا لم يمسكه E2E؟** اختبار العزل القائم (`saas_e2e_test.py:367`) يمرر `orgId` الخاص بالمهاجم نفسه مع معرّف نتيجة الضحية → `findFirst` يعيد null → 404 → الاختبار ينجح **رغم الثغرة**. الثغرة تتطلب تمرير `orgId` الخاص بالضحية — وهو ما لم يختبره أحد قبل L0 (موثّق كـ D-Q5 في PHASE02_GAP_ANALYSIS).

## 2. السبب الجذري

المسار بُني في P0 بـ `requireUser()` + `orgId` خام، **متجاوزًا نقطة الاختناق الرسمية** `requireOrgAccess()` في `src/lib/rbac.ts:87` التي تفرضها كل المسارات الأخرى (targets/scans/reports/orgs/audit): (1) جلسة موثّقة، (2) **عضوية المنظمة من الجلسة** — غير الأعضاء يحصلون على 404 + سجل تدقيق `rbac.org_access_denied`، (3) الحد الأدنى للدور. الاعتماد على `orgId` القادم من المستخدم وحده يعني أن **المصادقة اشتُقت من هوية الجلسة بينما التفويض اشتُق من مدخلات الطلب** — خلط طبقتي الثقة.

## 3. الإصلاح بالتحديد (بعد L0)

```ts
const user = await requireUser();                                  // 1) المصادقة
const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
if (!orgId) throw new ApiError(400, "orgId مطلوب");

const access = await requireOrgAccess(user, orgId);                // 2) تفويض المنظمة من عضوية الجلسة
                                                                   //    (غير العضو → 404 + تدقيق)

const finding = await db.finding.findFirst({
  where: { id, orgId: access.orgId },                             // 3) المورد يجب أن ينتمي للمنظمة المصرّح بها
  ...
});
if (!finding) throw new ApiError(404, "الثغرة غير موجودة");        //    (غير موجودة «له» — بلا تمييز)
```

- `orgId` في الـ query لم يعد **منحة تفويض** — هو مجرد محدّد منظمة يُتحقق منه ضد عضوية الجلسة.
- السلوك عند الرفض: **404** — نفس convention النظام كله («404 non-members — indistinguishable from a non-existent org/resource») حتى لا يُكشف وجود المورد.
- عقد الـ API لم يتغير (نفس المعامل، نفس الاستجابات للمسارات المشروعة، نفس الأدوار: القراءة VIEWER+).

## 4. مصفوفة الهجوم (اختبارات دائمة — 37/37 PASS)

`scripts/l0_tenant_isolation_test.py` — يُشغَّل عبر `scripts/l0_isolation_orchestrator.py` (بناء إنتاج + قاعدة مؤقتة). كل الهويات والنتائج تُنشأ عبر **مسارات المنتج الحقيقية** (bootstrap → أعضاء → منظمات → demo target → فحصا محرك حقيقيان: 144+ نتيجة لكل منظمة — لا صفوف ملفّقة):

| # | السيناريو (P=عضو Org A فقط، R=عضو Org B فقط) | المتوقع | النتيجة |
|---|---|---|---|
| 1 | P → Finding A + `orgId=A` | ALLOW 200 + evidence/verification | ✅ PASS |
| 2 | R → Finding B + `orgId=B` | ALLOW 200 | ✅ PASS |
| **3** | **P + Finding تخص Org B + `orgId=B` (orgId الضحية الصريح — الأخطر)** | **DENY 404** | ✅ **PASS** (كان 200-leak قبل الإصلاح) |
| 4 | P + Finding B + `orgId=A` (orgId نفسه) | DENY 404 | ✅ PASS |
| 5 | R + Finding A + `orgId=A` (عكسي + orgId الضحية) | DENY 404 | ✅ PASS |
| 6 | R + Finding A + `orgId=B` (عكسي + orgId نفسه) | DENY 404 | ✅ PASS |
| 7 | مجهول + `orgId=A` / مجهول + `orgId=B` | DENY 401 | ✅ PASS ×2 |
| 8 | مصفوفة تعداد (7 تركيبات findingId×orgId: نتائج حقيقية/مفبركة × orgId ضحية/نفسه/مفبرك) | كلها 404، الجسم `{"error": ...}` فقط | ✅ PASS |
| 8b | نتيجة عابرة حقيقية vs معرّف غير موجود — عدم قابلية التمييز | نفس الكود (404) + نفس بنية الجسم `["error"]` | ✅ PASS |
| 9 | ضابط: Q (عضو المنظمتين مشروعًا) يقرأ نتائج المنظمتين | ALLOW 200 ×2 (لا فرط حجب) | ✅ PASS |
| 10 | RBAC: VIEWER في Org A يقرأ Finding A | ALLOW 200 (القراءة VIEWER+) | ✅ PASS |
| 11 | `orgId` مفقود → 400 · معرّف مهمل → 404 نظيف | 400 / 404 | ✅ PASS |
| 12 | التدقيق: محاولة R على Org A مسجلة في **تدقيق Org A** + محاولة P على Org B مسجلة في **تدقيق Org B** | `rbac.org_access_denied` | ✅ PASS ×2 |

**ما لا يمكن أن يُسرَّب عند الرفض** (مفحوص حرفيًا في كل استجابة رفض): existence، evidence، reproduction، verification، impact، metadata (fingerprint/engineId/createdAt/severity/confidence/risk/method/url/parameter)، ومعلومات المنظمة — الاستجابة مفتاح واحد `error` فقط، ولا يظهر معرّف منظمة الضحية في الجسم.

**حد معلوم وموثّق (ليس تسريبًا)**: رسالة الرفض تختلف بين «المنظمة غير موجودة» (غير عضو) و«الثغرة غير موجودة» (المورد ليس في منظمتك) — لكن أيًّا منهما لا تكشف شيئًا عن وجود المورد في منظمة أخرى: المهاجم يعرف مسبقًا عضويته هو؛ وكلا المسارين يمنعانه من التمييز بين «النتيجة موجودة في Org B» و«النتيجة غير موجودة إطلاقًا». التحليل الزمني (timing) خارج نطاق هذه البوابة — مسجّل كقيد.

## 5. التحقق على الإنتاج الحي (30/30 PASS)

`scripts/l0_prod_verify.py` ضد `http://localhost:3000` (بناء الإنتاج `BUILD_ID ZqosghoE3OZ-gSggjrxx6`، القاعدة الرئيسية بعد bootstrap حقيقي): **الاختبار الإلزامي حرفيًا** — جلسة Org A → نتيجة Org B (+`orgId=B`) → **404 وجسم `{"error":...}` فقط**؛ جلسة Org A → نتيجة Org A → **200 كاملة**؛ مع العكسي والمجهول والتعداد (3 تركيبات) وسجل التدقيق وصحة كل صفحات المنتج التسع + صفحة تفاصيل النتيجة. الأدلة المقننة (الحالات + الأجسام) في `saas-data/l0_prod_verify.json`.

## 6. التدقيق الأمني لبقية مسارات SaaS API (نفس الفئة)

المنهجية: قراءة كل route handler في `src/app/api/` والتحقق من: مصادقة؟ تفويض منظمة (عبر `requireOrgAccess`)? تحديد نطاق المورد بـ `access.orgId`? RBAC؟ — لا إعادة كتابة للمسارات السليمة.

| المسار | المصادقة | تفويض المنظمة | نطاق المورد | RBAC | الحكم |
|---|---|---|---|---|---|
| GET/POST `/api/targets` | requireUser | requireOrgAccess ✓ | `orgId: access.orgId` ✓ | POST: MEMBER+ ✓ | ✅ سليم |
| PATCH/DELETE `/api/targets/[id]` | requireUser | requireOrgAccess ✓ | requireTargetAccess (org+ملكية) ✓ | MEMBER+ وملكية ✓ | ✅ سليم |
| GET/POST `/api/scans` | requireUser | requireOrgAccess ✓ | org-scoped + requireTargetAccess ✓ | POST: MEMBER+ ✓ | ✅ سليم |
| GET/DELETE `/api/scans/[id]` | requireUser | requireOrgAccess ✓ | requireScanAccess (org-scoped) ✓ | إلغاء: ADMIN+/المنشئ ✓ | ✅ سليم |
| GET `/api/scans/[id]/findings` | requireUser | requireOrgAccess ✓ | requireScanAccess ✓ | VIEWER+ ✓ | ✅ سليم |
| GET `/api/scans/[id]/coverage` | requireUser | requireOrgAccess ✓ | requireScanAccess ✓ | VIEWER+ ✓ | ✅ سليم |
| **GET `/api/findings/[id]`** | requireUser | **كان مفقودًا** | **كان orgId خام** | — | 🔴 **كان المصاب — أُصلح في L0** |
| GET/POST `/api/reports` | requireUser | requireOrgAccess ✓ | org-scoped + requireScanAccess ✓ | POST: MEMBER+ ✓ | ✅ سليم |
| GET `/api/reports/[id]` | requireUser | requireOrgAccess ✓ | `findFirst({id, orgId: access.orgId})` ✓ | VIEWER+ ✓ | ✅ سليم (النمط المرجعي) |
| GET/POST `/api/orgs` | requireUser | عضويات المستخدم نفسه / إنشاء | — | منشئ المنظمة OWNER ✓ | ✅ سليم |
| GET `/api/orgs/[id]` | requireUser | requireOrgAccess ✓ | org-scoped ✓ | VIEWER+ ✓ | ✅ سليم |
| GET/POST `/api/orgs/[id]/members` | requireUser | requireOrgAccess ✓ | org-scoped ✓ | إضافة: ADMIN+، منح OWNER: OWNER فقط ✓ | ✅ سليم |
| PATCH/DELETE `/api/orgs/[id]/members/[mid]` | requireUser | requireOrgAccess(ADMIN) ✓ | `target.orgId !== access.orgId → 404` ✓ | حماية آخر OWNER ✓ | ✅ سليم |
| GET `/api/audit` | requireUser | requireOrgAccess ✓ | `orgId: access.orgId` ✓ | VIEWER+ ✓ | ✅ سليم |
| GET `/api/me` | requireUser | بيانات المستخدم نفسه | — | — | ✅ سليم |
| GET/POST `/api/bootstrap` | عام بالتصميم | — | — | يعمل فقط عند صفر مستخدمين (409 بعدها) ✓ | ✅ سليم بالتصميم |
| GET `/api` (الجذر) | عام (hello فقط) | — | — | — | ✅ خامل |
| `/api/auth/[...nextauth]` | NextAuth | — | — | — | ✅ سليم |

**النتيجة: ثغرة هذه الفئة كانت في مسار واحد فقط** (`/api/findings/[id]`) — وأُغلقت.

## 7. ملاحظات (code smells بلا دليل قابلية استغلال — لم تُغيَّر دون داعٍ وفق الأمر)

1. `orgId` يُمرَّر من الـ query/body في عقود المسارات المختلفة — آمن لأنه يُتحقق منه دائمًا عبر `requireOrgAccess` قبل أي استعلام؛ ملاحظة معمارية فقط (مستقبلًا: استخلاصه من السياق وحده عند أي إعادة تصميم للعقود).
2. `/api/reports/[id]` يقرأ المحتوى من `filePath` المخزن في قاعدة البيانات — المسار لا يأتي من الطلب (يضبطه جسر المحرك من `SENTINEL_DATA_DIR`) — لا مسار استغلال عبر الـ API.
3. رسالتا الرفض المختلفتان (منظمة/مورد) — انظر §4 (قيد موثّق، متوافق مع convention النظام).
4. تحليل timing خارج النطاق (قيد معلوم).
