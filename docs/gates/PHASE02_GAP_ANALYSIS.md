# SENTINEL — PHASE 02 GAP ANALYSIS
## Security Twin + Verified Attack Path Intelligence

| البند | القيمة |
|---|---|
| الوثيقة | `docs/gates/PHASE02_GAP_ANALYSIS.md` |
| التاريخ | 2026-10-02 |
| القاعدة المرجعية | SENTINEL Engine **v4.1.1** (مجمد) + SaaS Phase 01 (FINAL GATE = PASS) |
| طبيعة هذه الوثيقة | **تحليل فقط — لا implementation.** لا سطر كود كُتب بموجب هذا الأمر |
| القاعدة الذهبية الحاكمة | **SENTINEL may infer a path, but it MUST never present an inferred path as verified evidence.** |
| مرجع المواصفة | أمر المستخدم «SENTINEL PHASE 02 — Global-Grade Engineering Specification» (41 قسمًا + 15 بوابة) |

> منهجية التوثيق: كل ادعاء في هذه الوثيقة مبني على قراءة كود فعلية (مراجع `ملف:سطر`) أو ملفات أدلة موجودة على القرص. لا يوجد ادعاء واحد بلا مرجع. الادعاءات التي لم نستطع إثباتها مدرجة في القسم 5 كما هي — بلا تجميل.

---

## 0. التحقق من الفرضية المرجعية (Premise Verification)

أمر المرحلة يبدأ بفرضية: «PHASE 01 FINAL GATE = PASS … إلخ». التزامًا بمبدأ *Evidence > inference*، تحققت من كل بند قبل قبوله:

| شرط ما قبل المرحلة | النتيجة | الدليل |
|---|---|---|
| PHASE 01 FINAL GATE = PASS | ✅ **مؤكد** | `docs/gates/PHASE01_FINAL_GATE.md`: «PASS — READY FOR PHASE 02» بعد إصلاح FG-1/2/3 (سجل العيوب: الثلاثة FIXED) |
| v4.1.1 immutable (محتوى) | ✅ **مؤكد** | `release-archives/SENTINEL-v4.1.1-source.tar.gz` SHA256 = `f7c6d219…` **مطابق حرفيًا** للمانيفست `SENTINEL-v4.1.1.sha256` (تحقق sha256sum مباشر هذا اليوم)؛ الأرشيف مصنوع كـ git archive من tag `v4.1.1` نفسه |
| Engine 102/102 | ✅ (آخر إثبات محفوظ) | `saas-data/recovery-r3/tests_fixgate.json` + `ledger-fixgate.jsonl` — strict 102/102 مطابق للأساس |
| Doctor 15/15 | ✅ (آخر إثبات محفوظ) | `saas-data/recovery-r3/doctor_fixgate.json` — فحصًا بفحص |
| Benchmark ×3 F1=1.000 | ✅ (آخر إثبات محفوظ) | `saas-data/recovery-r3/bench_fixgate_{1,2,3}.json` — TP=38/FP=0/FN=0/TN=35 |
| SaaS E2E 68/68 | ✅ (آخر إثبات محفوظ) | `saas-data/e2e_results.json` — 68 passed / 0 failed / 71.7s على بناء إنتاج |
| Production build PASS | ✅ (آخر إثبات محفوظ) | PHASE01_FINAL_GATE G7: بناء نظيف 61ث، BUILD_ID `YfEqfEtDULD3N3TDpDpxI` |
| Golden Path PASS | ✅ (آخر إثبات محفوظ) | `saas-data/final-gate-fix/01–19` — فحص حقيقي بدأ من الواجهة، run-406eb983a7 بـ144 نتيجة |

### 0.1 حادثة بيئية موثقة (يجب أن تعرفها قبل السماح بالكود)

بين جلسة Phase 01 النهائية وهذه الجلسة، **انتقلت بيئة التنفيذ** (إعادة إنشاء الحاوية). آلية النقل احترمت `.gitignore` فنجا المصدر والأدلة المتعقَّبة، وسقطت الملفات المستثناة:

| المفقود | الأثر | قابلية الاستعادة |
|---|---|---|
| `.git/` (بما فيه **objects** الـ tag `v4.1.1` والـ branch `release/v4.1.1` عند `7141c2d`) | مرساة G1 عبر git tags لم تعد موجودة ككائنات git تاريخية | ✅ `scripts/r3_git_rebuild.sh` (كُتب سابقًا لضرب مشابه) يعيد بناء السلسلة ويعيد تثبيت tag/branch مع تحقق محتوى — **كخطوة L0 أولى قبل أي implementation** |
| `node_modules/` | لا يمكن البناء/التشغيل حاليًا | ✅ `bun install` من `bun.lock` الموجود |
| `.next/` (بناء الإنتاج) | الخادم :3000 متوقف | ✅ `bun run build` |
| `db/custom.db` (قاعدة SaaS الرئيسية: org/targets/8 فحوصات/1008 نتائج) | بيانات العرض التاريخية ذاهبة | ✅ `scripts/bootstrap_demo_data.py` يعيد البذر **عبر تدفق المنتج الحقيقي فقط** (فحوصات محرك فعلية، لا صفوف ملفقة) |
| `saas-data/scans/` + `stores/` + `reports/` (مخرجات تشغيل، مستثناة من gitignore) | ملفات result.json/logs لمسح السابق | ✅ تُعاد تلقائيًا مع أول فحص جديد (reconcileScan يخزنها) |

**ما نجا وسليم (تم التحقق):** كامل `src/` (تطبيق SaaS بـ14 مسارًا) • `prisma/schema.prisma` • `build-v411/` (المحرك، 9.4M) • `gap-validation/results/` (الأساس المجمد، 18 ملفًا) • `release-archives/` (SHA256 مطابق) • كل أدلة البوابات (`final-gate/` 27 لقطة، `final-gate-fix/` 19، `recovery-r3/` 24 ملفًا) • `docs/` كاملة • `scripts/` كاملة • worklog الكامل.

**إجراء أمني اتخذته فورًا في هذه الجلسة (لا علاقة له بـ implementation):** نسختُ شجرة العمل كاملة من `/tmp/my-project` (حيث نجت) إلى `/home/z/my-project` (الجذر القانوني الذي تشير إليه `.env` أصلًا: `DATABASE_URL`/`SENTINEL_ENGINE_DIR`/`SENTINEL_DATA_DIR`) — لحماية الأصل من أي مسح مستقبلي لـ `/tmp`. الخلاصة: **الفرضية مؤكدة، مع حادثة بيئية موثقة وخطة استعادة L0 جاهزة.**

### 0.2 اكتشاف أمني حقيقي أثناء التحليل (قبل أي بناء)

أثناء مسح طبقة SaaS لهذه الوثيقة، وُجد **ثقب عزل مستأجرين قائم فعليًا في Phase 01** (لم تغطه اختبارات E2E الـ68 لأن الاختبار المعادي يمرر orgId الخاص بالمهاجم لا orgId الضحية):

```
src/app/api/findings/[id]/route.ts:9-23
  const user = await requireUser();                    // ✅ مصادقة فقط
  const orgId = String(req.nextUrl.searchParams.get("orgId" || ""));  // ⚠️ من الـquery
  db.finding.findFirst({ where: { id, orgId } })       // ⚠️ بلا requireOrgAccess
```

أي مستخدم مصادق (من أي منظمة) يعرف `orgId` الضحية + معرّف النتيجة (كلاهما cuid) يقرأ كامل: سلسلة الأدلة، التحقق، الأثر، **ووصفة إعادة الإنتاج**. بقية المسارات الـ13 تمر جميعها عبر نقطة الخنق `requireOrgAccess` (`src/lib/rbac.ts:87`) — هذا المسار وحده هو الشاذ. **الإصلاح مطلوب كشرط مسبق لبوابة G9 في Phase 02** (تغيير طبقة SaaS فقط، backward-compatible، والتغيير الوحيد في السلوك هو 404 لقارئ عابر للمنظمات — وهذا هو الإصلاح). يُعرض كنقطة قرار D-Q5 في القسم 13.

---

## 1. ما هو موجود فعليًا الآن (code-verified)

### 1.1 المحرك v4.1.1 — `build-v411/sentinel/` (32 وحدة، مجمدة، 102 اختبارًا)

| المكوّن | ما يقدمه فعلًا | المرجع |
|---|---|---|
| **twin.py** (586 سطرًا) | رسم توأم: أنواع عقد مُنشأة فعليًا: `identity, role, surface, parameter, entity, workflow, workflow_step, state, finding, secret, hypothesis` + التي يضيفها الـorchestrator: `graphql_endpoint, ws_channel, boundary, api`. أنواع حواف: `has_role, authenticated, exposes, carries, typed_as, gates, step_of, transitions_to, mints, consumes, produced_finding, exposed_secret, declared_privilege, generated_hypothesis, speaks_protocol, bounded_by` | twin.py:18-25, 328-504; orchestrator.py:874-1095 |
| — نموذج الاعتقاد | `belief ∈ {observed, inferred, verified, refuted, unknown}` + نص `provenance` على **كل** عقدة/حافة عبر `annotate_provenance()`؛ `belief_audit()` يعيد مخالفات (يستهلكه بوابة عدم الهلوسة) | twin.py:213-277 |
| — `why()` | لكل عقدة: `{found, kind, key, belief, provenance, attributes, relations≤12}` — **قفزة واحدة فقط، ونص المصدر حر وليس مرجع أدلة مُهيكلةً** | twin.py:279-300 |
| — المعرفات | `"<kind>-"+sha1(key)[:10]` — **مشتقة من المحتوى وحتمية**؛ الحواف بلا معرف (هوية الثلاثية src/dst/rel) | twin.py:103-117, 146-150 |
| — **حقائق حرجة** | `paths()` (كل المسارات البسيطة ≤4 قفزات) **موجودة ولا يستدعيها أحد**؛ **الرسم الكامل (nodes/edges) لا يُحفَظ أبدًا على القرص** — stats يحمل العدّادات والملخصات فقط (`nodes: 388` عددٌ لا مصفوفة) | twin.py:171-187; orchestrator.py:899-901 (مثبت على `bench_v411_1.json`) |
| **reasoning.py** (590) | **17 نمط فرضيات** (R-CROSS-IDENTITY-OBJECT … R-WS-CROSS-USER)؛ سجل فرضية **19 حقلًا** (id, pattern, surface, premise, **chain** (مفاتيح عقد التوأم), test, plan, status, preconditions, expected_behavior, test_plan, safety_class, actual_result, verification, evidence, final_state, reason…)؛ حالات: `tested:verified / tested:refuted / untestable:<reason>` | reasoning.py:43-96, 384-572 |
| **evidence.py** (552) | `build_proof()` بـ**15 حقلًا**: attack_hypothesis, preconditions, requests, responses, identity, **state_before/state_after** (إصلاح ENG-18), impact, **reproduction: [{step, request, expect}]**, confidence, verification, proof_grade ∈ {proven, indicated}؛ `replay_finding()`: `REPRODUCTION_VERIFIED / REPRODUCTION_FAILED / NOT_REPLAYABLE` (13 صنفًا قابلًا لإعادة التشغيل الآلي)؛ سقف 40 دليلًا/فحص بأولوية business-logic | evidence.py:265-551; orchestrator.py:1125-1137 |
| **planner.py** (183) | فئات: `READ_ONLY / LOW_IMPACT / STATE_CHANGING / DESTRUCTIVE`؛ قاموس DESTRUCTIVE **يتغلب على كل شيء**؛ بوابة آنية مركّبة في workflow/graphql/websocket قبل أي طلب؛ سجل قرارات `{url, method, impact, allowed, policy, rationale}` | planner.py:32-171 |
| **boundary.py** (302) | **14 حالة موحدة** (TESTED, VERIFIED, REFUTED, UNTESTABLE, NOT_DISCOVERED, NOT_SUPPORTED, BLOCKED_BY_{PERMISSION,AUTH,SAFETY,ENVIRONMENT}, TIMEOUT, TOOL_FAILURE, DEPENDENCY_MISSING, NOT_APPLICABLE)؛ `EVIDENCE_MANDATORY`؛ **NOT_DISCOVERED يحظر حمل الأدلة**؛ حارس 100%→99.9 | boundary.py:52-296 |
| **authz.py** (478) | مصفوفة `url × {anonymous, role:<role>}` بقيم **HTTP خام** (صدقية القفزة الأولى: 302≠200)؛ IDOR/BOLA أفقي بعلامة الضحية؛ vertical بفرق التشابه؛ `authz_context = "attacker=…(role=…) victim=…(role=…)"` | authz.py:286-477 |
| **workflow.py** (1697) | **رسم حقيقي**: عقد خطوات بـ14 حقلًا (preconditions, state pairs, impact_class, dependencies, provenance, confidence 1.0/0.7…) وحواف `next/branch/approval/cancel_of/rollback_of` بمعتقد **{observed, declared, inferred}**؛ **12 هجومًا** (step_bypass, out_of_order, value_tamper, duplicate, privilege, cross_user, cross_object, cross_state, branch_bypass, unauthorized_branch, approval_bypass, rollback_abuse) **ببوابات شروط قبل أي تسجيل دخول**؛ التحقق بعلامة `oracle:workflow-state-delta` + state_before/after | workflow.py:223-1696 |
| **graphql.py** (1148) | introspection كامل → جرد operations/fields؛ 7 اختبارات (introspection, anonymous_access, **bola**, field_authorization, mutation_authorization, sql_injection, command_execution) بحدود صادقة | graphql.py:104-1147 |
| **websocket.py** (995) | عميل RFC6455 بلا تبعيات؛ قنوات (observed/observed-js/probe)؛ اختبارات: unauth, sensitive_exposure, **cross_user**, reflection, origin, tampering/replay | websocket.py:471-994 |
| **apintel.py** (235) | جرد API موحد (http/graphql/websocket) + **مصفوفة إجراءات 8 فئات** (read/create/update/delete/approve/execute/export/admin) × الهويات المكتشفة فقط — خلايا صادقة `tested:N/M` أو `untested:<سبب>` | apintel.py:22-234 |
| **memory.py** (165) | ذاكرة **host-scoped**؛ `app_changed` (عدد نقاط + تقنيات) → `stale_needs_revalidation` **لكل** النتائج القديمة («سياق أبدًا وليس دليلًا») | memory.py:116-164 |
| **fingerprint.py** (176) | WAF (7 تواقيع، None الصادق) + تقنيات — **إشارة التقادم** الجاهزة | fingerprint.py:27-176 |
| **coverage.py** (262) | **17 بُعدًا** بدلالات NOT_DISCOVERED (الغياب ليس ادعاء فحص) | coverage.py:44-262 |
| **store.py** (226) | لكل تشغيل: `runs.stats_json` = **كل الـ27 قسمًا** (coverage, boundary, digital_twin, reasoning, proofs, planner, action_matrix, api_inventory, appmap, workflow, graphql, websocket, auth, param_intel, secrets, fingerprint…) + findings كاملة (verified **و**rejected كمسار تدقيق) | store.py:29-59 |
| **بوابة عدم الهلوسة** | **G1** لا نتيجة بلا أدلة • **G2** لا حقيقة بلا provenance • **G3** tested ≤ discovered • **G4** الغائب لا يُدّعى مُختبرًا • **G5** لا 100% مع غير مُفسَّر • **G6** سجلات الحدود صحيحة بنيويًا — **مع 4 أكاذيب مزروعة يثبت كلٌّ منها إفشال البوابة** | tests/run_tests.py:4812-4903; docs/NO_HALLUCINATION_GATE.md |
| **بطارية الأمن الذاتي** | 10 نواقل خبيثة ضد SENTINEL نفسه (حقن تقارير، CRLF، traversal، file:///metadata، SSRF ضد المحرك، cmdi كبيانات، حقن JSON، GraphQL مشوه 10k، إطارات WS 8MB، أقنعة الأسرار) | tests/run_tests.py:4737-4808 |
| المجموع | **102 = 58 unit + 38 regression + 5 chaos + 1 e2e** — حتمية ببذرة (run-3c0652b6be) | tests/run_tests.py |

### 1.2 طبقة SaaS — `src/` (Next.js 16 + Prisma + SQLite)

| المكوّن | الواقع المُتحقق | المرجع |
|---|---|---|
| نماذج البيانات | **8 نماذج**: User, Organization, Membership (OWNER/ADMIN/MEMBER/VIEWER برُتب 4/3/2/1), Target, Scan (**statsJson = مخرجات المحرك كاملة verbatim**), Finding (**evidenceJson, verificationJson, impactJson, proofJson** مضمّنة + fingerprint), Report, AuditLog — كل الصفوف تحمل `orgId` | prisma/schema.prisma |
| مسارات API | **13 مسارًا** جميعها عبر خنق `requireOrgAccess` (404 لغير العضو — مقاومة الاستطلاع) **ما عدا الاستثناء في القسم 0.2** | src/app/api/**, rbac.ts:87 |
| جسر المحرك | صندوق أسود: `spawn(python3 -m sentinel.cli scan …)` منفصل (detached)؛ `reconcileScan()` مسار الابتلاع الوحيد — idempotent عبر `@@unique([scanId, engineId])`، يلتقط proofs → `Finding.proofJson`؛ فحص نشط واحد لكل هدف (409) | src/lib/engine.ts:167-372 |
| المخرجات على القرص | `saas-data/scans/<scanId>/{result.json, log.txt}` + `saas-data/stores/<targetId>.db` (يعيش عبر الفحوصات → بصمات recurring/delta) | engine.ts:17-39 |
| **الكنز غير المستغل** | `Scan.statsJson` يحمل الـ27 قسمًا بينما الواجهة/الـAPI يكشفون ~8 فقط: **لا `digital_twin` ولا `reasoning` ولا `planner` ولا `action_matrix` ولا `workflow` مكشوفة لأي مسار** — موجودة ومخزنة ولا يقرؤها أحد | coverage/route.ts:29-38 (المسار الوحيد القريب يعيد coverage/boundary/crawl/openapi فقط) |
| واجهة التوأم اليوم | صفحة `/twin` = **عرض أبعاد التغطية، لا التوأم**: 4 بطاقات KPI + قائمة 17 بُعدًا + فئات الحدود + بطاقة placeholder بصيغة «الرسم الكامل هو Phase 02» + SVG زخرفي `aria-hidden` — **صفر عقد/حواف معروضة** | src/app/(app)/twin/page.tsx:20-171 |
| صفحة النتيجة | نمط "الأدلة أولًا" بـ5 تبويبات: Evidence / Verification / Impact / **Reproduction (وصفة الإثبات الحقيقية)** / Remediation (موسومة صراحة «إرشاد من المنصة وليس مخرج المحرك») | findings/[id]/page.tsx:101-209 |
| البنية التحتية UI | 49 مكوّن shadcn/ui + recharts (المكتبة الرسومية **الوحيدة**) — **لا توجد أي مكتبة رسم بياني/شبكي**؛ نظام حالات موحد (Skeleton/ErrorState role=alert/EmptyState) + toasts aria-live | src/components/**, package.json |
| i18n | 240 مفتاحًا × ar/en بمفاتيح آمنة النوع compile-time؛ تبديل dir=rtl/ltr؛ **مفاتيح `twin.stats.nodes/edges/entities` معرّفة مسبقًا وغير مستخدمة — بذور جاهزة لـ Phase 02** | src/lib/ui/i18n.tsx |
| الوصول/a11y | skip-link، sr-only (إصلاح FG-3)، aria-current/pressed/meter، `dir="ltr"` لعزل نصوص المحرك، قاتل الحركة عند prefers-reduced-motion، palette بـ dir-aware (أسهم تنعكس في RTL) | app-shell.tsx, globals.css |
| الاختبارات | **E2E = 68 فحصًا HTTP-level** (7 RBAC سلبية + 6 عزل سلبية + 12 دورة حياة فحص + coverage_pct==100 …) عبر `saas_e2e_test.py` على بناء إنتاج بقاعدة مؤقتة؛ **لا يوجد أي عدّاء اختبارات JS/TS** | scripts/saas_e2e_test.py |
| الأدلة | 27+19+21+15 لقطة بوابات + 24 ملف نتائج recovery-r3 + أرشيفا SHA256 | saas-data/**, release-archives/** |

---

## 2. ما هو ناقص (الفجوة مقابل مواصفة Phase 02 — قسمًا بقسم)

| § المواصفة | المطلوب | الواقع الحالي | حجم الفجوة |
|---|---|---|---|
| §2 Security Twin | 33 نوع كيان قابلة للتمثيل | المحرك يُنشئ فعليًا 16 نوع عقدة (identity, role, surface, parameter, entity, workflow, workflow_step, state, finding, secret, hypothesis, graphql_endpoint, ws_channel, boundary, api) | **متوسط** — الأنواع المفقودة (Header, Cookie, Token, Session, Permission, Object منفصلًا, API Operation, GraphQL Field, WS Message, Browser Route, JS Source, OAST Interaction كعقدة) بعضها **موجود كبيانات** داخل artifacts (openapi يعلن parameters منها headers؛ crawl يرى cookies؛ auth يصدر tokens) فيمكن اشتقاقه بالتطبيع، وبعضها يُعلَّم `NOT_SUPPORTED` بصدق |
| §3-4 Provenance مُهيكل | enum واحد {OBSERVED, INFERRED, VERIFIED, REFUTED, UNKNOWN} + حقول id/type/confidence/source/source_id/first_seen/last_seen/evidence_ids/why() | **ثلاث قواميس معتقد غير موحدة**: twin {observed, inferred, verified, refuted, unknown} + workflow {observed, declared, inferred} + نص provenance حر غير مرجعي؛ فقاعات افتراضية (عقد `parameter/state/finding` تسقط إلى unknown) | **متوسط** — حلّه بطبقة تطبيع موحدة في SaaS مع **جدول تحويل موثق** (القسم 11.3) — بلا لمس المحرك |
| §5 why() | تفسير مُهيكل بأدلة مرجعية | `why()` في المحرك قفزة واحدة بنص حر | **متوسط** — يُعاد بناؤه في طبقة التطبيع بمراجع أدلة مُهيكلة (artifact path + JSON pointer) |
| §6 علاقات الحواف | 17 علاقة موحدة | المحرك لديه 16 علاقة فعلية + REDIRECTS_TO/CALLS/DEPENDS_ON/CONTAINS/USES/PRODUCES/CONSUMES/REQUIRES/BLOCKED_BY/LEADS_TO/VERIFIED_BY/REFUTED_BY مفقودة كعلاقات رسم | **متوسط** — تُشتق بالتطبيع (مثلاً: VERIFIED_BY من finding→proof، BLOCKED_BY من boundary records، LEADS_TO من خطوات المسار) |
| §7 INV-01..10 | اختبارات ثوابت التوأم | **لا شيء منها موجود** (أقرب شيء: بوابة عدم الهلوسة G1-G6 في المحرك — تغطي جوهر INV-01/02 من جهة النتائج لا الرسم) | **كبير** — جناح اختبارات جديد كامل |
| §8-11 AttackPath | نموذج أولي (id, status, source, destination, nodes, edges, preconditions, hypotheses, findings, evidence, proofs, why, reproduce) + 6 حالات + قاعدة VERIFIED الثمانية | **لا يوجد أي كائن مسار هجوم في أي مكان**. البذور موجودة: `reasoning.hypotheses[].chain` (سلسلة عقد!) + `workflow.attack_log` + proofs — لكن لا تركيب ولا نموذج | **الأكبر — قلب Phase 02** |
| §12 فئات AP-01..12 | 12 فئة | مصادر الأدلة لكل فئة **موجودة** (انظر القسم 11.6) لكن لا تصنيف ولا مولّد مسارات | كبير |
| §13 توليد المسارات | bounded depth/branching + ترتيب حتمي + كشف دورات + ميزانية | `DigitalTwin.paths()` موجودة (كل المسارات البسيطة ≤4 قفزات) **ولا مستدعي لها**؛ لا حدود تفريع ولا ترتيب ولا ميزانية | كبير — يُبنى فوق الرسم المُطبَّع |
| §14 path_priority | ترتيب داخلي قابل للتفسير فقط | لا شيء | صغير (تصميم + تنفيذ) |
| §15 خط الأنابيب | Observations → … → Path state | المراحل 1-7 قابلة للبناء post-scan؛ **المرحلتان 9-10 (Test planning → Execution) غير قابلتين للإضافة دون تغيير المحرك** → تُستبدل بـ"مخطط تحقق من الأدلة الموجودة" (قرار D2 — القسم 11) | **حرج مفهوميًا — يُحسم بقرار الصدق** |
| §16 Hypothesis | سجل مُهيكل | **موجود فعليًا في المحرك (19 حقلًا)** — يُعاد استخدامه كما هو | صغير (استهلاك) |
| §17 Business Logic | 12 نمط تلاعب | **مُنفذة بالكامل في المحرك** (12 هجومًا ببوابات شروط) | لا فجوة (استهلاك) |
| §18 انتقالات الهوية الصريحة | anonymous/user-A/user-B/admin/… | الهويات موجودة (authz accounts + anonymous) لكن لا نموذج انتقالات | متوسط |
| §19 حدود التصريح | boundary_id/type/tested/result/evidence | **نموذج الحدود أغنى من المطلوب** (14 حالة + فئات) لكنه غير مرتبط بمسارات | متوسط (ربط) |
| §20 سلسلة الأدلة | Path→Hypothesis→Test→Request→Response→Evidence→Proof→Reproduction | كل الحلقات موجودة كبيانات (findings/proofs/attack_log) لكن الروابط **ضمنية عبر نصوص** وليست IDs | متوسط |
| §21 إعادة الإنتاج | حزمة إعادة إنتاج أو INCONCLUSIVE | proofs + `reproduce_command` + replay موجودة | صغير (تجميع) |
| §22 السلامة | SAFE/LOW_IMPACT/CONTROLLED/BLOCKED | planner (4 فئات + بوابات) — **تحويل مباشر** | صغير |
| §23 عشر Fixtures | حالات جزئية | **لا شيء** (fixtures المحرك لاختباراته، لا لطبقة المسارات) | كبير — جناح fixtures جديد |
| §24 Adversarial | 12+ مدخل خبيث | بطارية الأمن الذاتي في المحرك (10 نواقل) تختبر المحرك نفسه — **لا تختبر طبقة المسارات الجديدة** | كبير |
| §25 CONFLICT | كشف التعارض | لا شيء | متوسط |
| §26 التقادم | observed_at + fingerprint + STALE | `memory.app_changed` + `stale_needs_revalidation` **موجودان** كإشارة؛ لا تفعيل على مستوى المسارات | صغير-متوسط |
| §27 عزل المستأجرين | على Twin/Path/Evidence/Proof | نمط orgId قائم وقوي (مع الاستثناء 0.2)؛ **كائنات Twin/Path غير موجودة أصلًا** | متوسط (يُبنأ مع النموذج) |
| §28 API | versioned endpoints | لا مسارات twin/paths إطلاقًا | كبير |
| §29-30 UI + رسم | Twin Overview/Paths/Path Detail + رسم حقيقي a11y | صفحة placeholder + **لا مكتبة رسم** | كبير |
| §31 لا بيانات مزيفة | فصل fixtures عن production | غير منطبق (لا fixtures بعد) | يُبنأ مع §23 |
| §32 Schema versioning | twin/attack_path/evidence schema versions | لا شيء | صغير |
| §33 الأداء | حدود + 100/1k/10k | لا حدود ولا قياس | متوسط |
| §34 الحتمية | twin hash + path IDs + ordering | **معرفات المحرك محتوى-مشتقة أصلًا** (أساس ممتاز)؛ لا hash للتوأم المُطبَّع | صغير-متوسط |
| §35 اختبارات أمنية | IDOR/عزل/تزوير/حقن رسم/دوري/مكرر/ضخم | جزئيًا في المحرك؛ لا شيء لطبقة المسارات | كبير |
| §36 الانحدار | 102+15+×3+68 تبقى خضراء | البنية كلها قائمة وقابلة لإعادة التشغيل | لا فجوة (التزام) |
| §37 بوابة عدم الهلوسة لـ Phase 02 | 9 شروط إفشال | غير موجودة | كبير |
| §38 التوثيق | 6 وثائق security-twin | لا شيء | كبير (كتابة) |
| §39 مصفوفة القدرات | 20 صفًا بقيم مسموحة | `capability-matrix` CLI موجود في المحرك (يولّد من بيانات التشغيل) — يُحاكى نمطه | متوسط |
| §40-41 البوابات والتقرير | G1-G15 | G1-G10 قائمة من Phase 01؛ G6-G10 الجديدة تحتاج بناء | متوسط |

### أهم عشر فجوات مرتبة بالأثر
1. **لا كائن AttackPath** (ولا تركيب سلاسل) — قلب المواصفة غائب تمامًا.
2. **الرسم الكامل للتوأم لا يُحفَظ** — `stats.digital_twin` عدّادات وملخصات فقط؛ لا يمكن استعلام عقد/حواف من أي طبقة دون إعادة بناء (تطبيع) من `result.json` الكامل.
3. **ثلاثة قواميس معتقد + provenance نصي غير مرجعي** — يحتاج طبقة توحيد موثقة.
4. **لا مسارات API ولا نماذج بيانات ولا UI للمسارات/التوأم** — كل شيء يُبنى جديدًا.
5. **لا اختبارات INV ولا adversarial ولا fixtures حالات جزئية** لطبقة المسارات.
6. **المرحلتان Test planning→Execution من خط الأنابيب (§15) غير ممكنتين دون كسر تجميد المحرك** — يتقرر استبدالهما بمخطط تحقق من الأدلة (قرار D2).
7. ثقب عزل `/api/findings/[id]` (القسم 0.2) — يجب إغلاقه قبل البناء عليه.
8. **لا عدّاء اختبارات JS/TS** — طبقة التطبيع/المسارات جديدة بالكامل وتحتاج جناح اختبارات (يُحل بـ `bun test` المدمج — بلا تبعيات جديدة).
9. أنواع كيانات غير ممثلة (Session/Token/Cookie/Header…) — جزئيًا قابلة للاشتقاق وجزئيًا NOT_SUPPORTED بصدق.
10. البيئة المفقودة (git/node_modules/db) — خطة L0 جاهزة لكنها **شرط تنفيذ أول**.

---

## 3. ما يمكن إعادة استخدامه (خريطة إعادة الاستخدام)

| الأصل الموجود | وجهته في Phase 02 | لماذا يصلح كما هو |
|---|---|---|
| `Scan.statsJson` (الـ27 قسمًا verbatim لكل فحص مكتمل) | **المصدر الوحيد** لطبقة التطبيع — لا حاجة لأي طلب شبكي أو تشغيل محرك إضافي | البيانات كاملة ومخزنة أصلًا؛ التطبيع post-scan حتمي بنيويًا |
| `stats.digital_twin` (twin_summary + authorization_matrix + entity_inventory + belief_audit + why_examples) | **المرجع الذهبي لتكافؤ التطبيع**: التوأم المُعاد بناؤه يجب أن يعيد إنتاج هذه العدّادات **بالضبط** | هذا هو الإثبات الرياضي بأن طبقة التطبيع لا تهلوِس (Invariant ذهبي — القسم 11.7) |
| `reasoning.hypotheses[]` (19 حقلًا + `chain[]` بمفاتيح العقد + الحالة والسبب) | بذور **فرضيات المسار** (§16) — تُربط بالمسارات كما هي | مطابقة لمتطلب المواصفة تقريبًا حرفيًا |
| `workflow.flows[].graph` + `attack_log` (verdict: verified/no_proof/skipped + state pairs) | الانتقالات **المُثبتة** في مسارات AP-04/05/06 + حدود الحالة | رسم حقيقي بمعتقد وحالات مُختبرة |
| `authz.matrix` + `gates` verdicts (auth_required/forbidden/reachable…) | نتائج اختبار **حدود التصريح** لكل سطح×هوية (§19) | خلايا HTTP خام بصدقية القفزة الأولى |
| `findings[]` + `Finding.{evidence,verification,impact,proof}Json` + `fingerprint` | حلقات سلسلة الأدلة (§20) + مفاتيح الربط العرضي | مبتلعة أصلًا إلى القاعدة |
| `proofs[]` (وصفات الإنتاج + replay) + `reproduce_command` | حزم إعادة الإنتاج (§21) أو INCONCLUSIVE | جاهزة |
| `planner.decisions[]` (لكل عملية: impact/policy/rationale) | تصنيف سلامة **كل خطوة مسار** (§22) بتحويل مباشر | جاهز |
| `boundary.summary` (14 حالة + فئات + unresolved_detail) | حدود المسار غير المحسومة → سقف الحالة (§10 الشرط 8) | جاهز |
| `memory.stale_needs_revalidation` + `fingerprint` (waf/tech) | إشارة STALE (§26) | جاهزة كإشارة |
| `api_inventory` + `action_matrix` (هويات×إجراءات بخلايا صادقة) | جرد الأسطح/AP-03/AP-12 + عرض Twin Overview | جاهز |
| GraphQL ops/websocket channels + اختباراتهما | فئتا AP-07/AP-08 | جاهز (وأهداف حية قابلة لإعادة التشغيل من `gap-validation/` لأجل التحقق الحي) |
| نمط `orgId` + `requireOrgAccess` + `audit()` (17 حدثًا) | عزل وتدريب كل المسارات/النماذج الجديدة | النمط مُجرَّب بـ68 E2E |
| `reconcileScan()` idempotent | نقطة تعليق خطاف التطبيع بعد اكتمال الفحص | نقطة واحدة موجودة |
| نظام الحالات UI (Skeleton/ErrorState/EmptyState) + نمط 5 تبويبات + `twin.stats.*` i18n المُبذورة + palette dir-aware + a11y كامل | كل صفحات Phase 02 | بنية ممتازة جاهزة |
| `saas_e2e_test.py` (68) + `r3_e2e_orchestrator.py` + عدّاء recovery المحرك + `gap-validation/results` (الأساس المجمد) | امتدادات E2E + انحدار G2/G4 | مُجرَّب عبر 4 جولات recovery |
| `scripts/r3_git_rebuild.sh` + `bootstrap_demo_data.py` + `start_prod_server.sh` | خطة L0 لاستعادة البيئة | مكتوبة ومختبرة سابقًا |
| `bun test` (المدمج في runtime) | عدّاء اختبارات TS لطبقة التطبيع/المسارات/الثوابت/الحتمية | **بلا تبعيات جديدة** |

---

## 4. ما يحتاج implementation (المكوّنات الجديدة — كله في طبقة SaaS، صفر في المحرك)

**L0 — استعادة البيئة (شرط أول، بلا أي تغيير وظيفي):** إعادة تثبيت git (`r3_git_rebuild.sh` مع تحقق محتوى ضد أرشيف SHA256) → `bun install` → `prisma db push` → `bootstrap_demo_data.py` → بناء نظيف → إعادة إثبات الأساس (68/68 + 102/102 + 15/15 + ×3) قبل كتابة أي سطر Phase 02.

**L1 — التطبيع (Twin Normalization):** `src/lib/twin/` — محلل `result.json` → رسم مُطبَّع: عقد/حواف بـ enum الموحد، provenance مُهيكل (مصدر = مسار artifact + JSON pointer)، evidence_ids، confidence بجدول حتمي، first/last seen، معرفات `sha256` كانونية، `twinHash`، إصدارات مخطط. **مع فحص التكافؤ الذهبي ضد عدّادات المحرك.**

**L2 — النماذج المشتقة:** نموذج الهوية (anonymous + حسابات authz + admin…) وانتقالاتها الصريحة؛ حدود التصريح من gates+boundary؛ علاقات الكائنات من entity_inventory + معرفاتها؛ حالات/انتقالات الوركفلو من flows.

**L3 — محرك المسارات:** `src/lib/attack-path/` — توليد مرشحين حتمي (DFS محدود: عمق ≤6، تفريع ≤8، كشف دورات، ميزانية زمنية، إزالة تكرار، ترتيب مستقر) على 12 قالب فئة AP-01..12؛ `path_priority` بخصائص مفسَّرة فقط.

**L4 — مخخط التحقق:** حساب الحالة من الأدلة الموجودة حصريًا: VERIFIED يُمنح فقط باستيفاء الشروط الثمانية (كل انتقال مدعوم بنتيجة verified/proof/replay أو attack_log verified؛ كل حد مطلوب مُختبر بنتيجة من gates/boundary؛ الاشتغالات معروفة؛ الدلة محفوظة؛ يوجد proof/replay؛ لا حد مجهول) — وإلا CANDIDATE / PARTIALLY_SUPPORTED / REFUTED / BLOCKED_{SAFETY,PERMISSION,ENVIRONMENT,AUTH} / UNKNOWN. تجميع حزمة الإنتاج أو INCONCLUSIVE. كشف CONFLICT وخلق سجلاته. بوابات STALE.

**L5 — API (جديدة فقط، لا كسر):** مسارات التوأم والمسارات والإنتاج (تفصيل القسم 10) عبر `requireOrgAccess` + تدقيق + تقسيم صفحات + استعلامات محدودة.

**L6 — UI:** ترقية `/twin` إلى Twin Overview حقيقي (استهلاك `twin.stats.*` المُبذورة) + `/attack-paths` (قائمة بحالات نصية أولًا) + `/attack-paths/[id]` (المصدر→خطوات→حدود→الوجهة؛ كل خطوة: provenance/confidence/why/evidence/timestamp؛ لوحة «ما لم يُثبت») + تبويب "Attack Paths" في صفحة النتيجة (إكمال سلسلة §20). رسم: تدفق رأسي SVG مخصص (dir-neutral) + **جدول/قائمة كتمثيل أولي دائم** — قرار D-Q1.

**L7 — اختبارات وبوابات:** جناح `bun test` (ثوابت INV-01..10، تكافؤ التطبيع، فئات AP، 10 fixtures حالات، adversarial، حتمية، حدود الأداء) + امتدادات E2E HTTP + بقاء 102/68 خضراء + بوابة PHASE02_NO_HALLUCINATION + بوابة G1-G15.

**L8 — توثيق:** الوثائق الست `docs/security-twin/*` + تحديث البوابات + مصفوفة القدرات بأسلوب `capability-matrix` الحتمي للمحرك.

---

## 5. ما لا يمكن إثباته حاليًا (حدود الصدق — قبل التنفيذ)

| # | العنصر | لماذا لا يمكن إثباته الآن | الحالة المخططة |
|---|---|---|---|
| U1 | **VERIFIED attack paths بكميات كبيرة** | المسار يُثبت فقط إذا كان الدليل موجودًا فعلًا في بيانات الفحص (نتائج verified/proofs/attack_log/gates). أغلب المرشحين المتوقعة ستنتهي إلى CANDIDATE/PARTIALLY_SUPPORTED — **وهذا هو السلوك الصحيح لا عيب** | يُثبت عدديًا على fixtures: fixture-10 (verified) تصل VERIFIED وfixture-2 لا تتجاوز PARTIALLY_SUPPORTED |
| U2 | **اختبار نشط جديد لصالح المسارات** (§15 مرحلتا planning/execution) | يتطلب تغيير سلوك المحرك (ممنوع) أو تشغيلًا جديدًا بمعاملات غير موجودة | **خارج النطاق بقرار D2** — المسارات تتحقق من أدلة التشغيل السابقة حصرًا |
| U3 | فئات AP-07/AP-08 على هدف حي | يحتاج DVGA/DVWS قيد التشغيل (الأدوات موجودة في `gap-validation/` مع setup/start scripts) | قابل للإثبات إذا وافقت (D-Q7)؛ وإلا fixture-only بحالة TESTED على fixtures |
| U4 | أنواع Session/Token/Cookie/Header كعقد | المحرك لا يبثها كعقد توأم؛ بعضها مشتق من openapi/crawl والباقي غير موجود في artifacts | المشتق → OBSERVED بشرط وجود artifact؛ المتبقي → NOT_SUPPORTED موثق |
| U5 | مقياس 10,000 عقدة | لم يُقَس أبدًا | يُقاس ويُوثق السقف الفعلي؛ إن لم ينجح 10k يُعلَّم الحد بدل ادعائه (§33) |
| U6 | **مرساة git التاريخية** (`7141c2d` ككائن) | كائنات git فُقدت في حادثة البيئة؛ الاستعادة تنشئ tag جديدًا بمحتوى مطابق | G1 لـ Phase 02 = **تكافؤ محتوى** (SHA256 الأرشيف + diff=0 ضد المستخرج) + tag مُعاد التثبيت — ويُوثَّق الفرق بين المرساتين بلا لبس |
| U7 | اختبار قارئ الشاشة الفعلي للرسم | الأتمتة تثبت ARIA/لوحة المفاتيح/التباين؛ قارئ الشاشة البشري خارج الأتمتة | keyboard+ARIA+contrast آليًا؛ بديل الجدول أولي الدائم يغطي الجوهر |
| U8 | «الغياب أمن» | مبدأ المحرك الثابت: يُثبت ما يجده ولا يثبت غياب ما لم يجده | يُورَّث حرفيًا إلى صياغة المسارات |

---

## 6. المخاطر التقنية والتخفيف

| # | الخطر | الاحتمال | الأثر | التخفيف |
|---|---|---|---|---|
| R1 | هشاشة البيئة (فقد `.git`/DB مرة أخرى عبر إعادة إنشاء الحاوية) | متوسط | عالٍ | L0 أعلاه + الالتزام بالعمل من `/home/z/my-project` (تم تأمينه) + تحديث `docs/RECOVERY_PROCEDURE.md` بخطوات الاستعادة الجديدة + إعادة commit مباشرة بعد كل جولة |
| R2 | **تضخم المعتقد عبر جدول التحويل** (مثلًا: declared يُرفع إلى OBSERVED فيُقرأ كأقوى مما هو) | متوسط | حرج (مبدأ المرحلة) | جدول تحويل موثق (11.3) بمعيار: لا قيمة موحدة أعلى من أصلها أبدًا + اختبارات تحويل + مصدر declaration يظهر دائمًا في why() |
| R3 | انفجار الرسم (توليد مسارات أُسّي) | متوسط | عالٍ | الحدود (عمق/تفريع/ميزانية/سقف مرشحين 200/فحص) + اختبارات 100/1k/10k + سقف موثق |
| R4 | **عدم تكافؤ التطبيع مع عدّادات المحرك** (طبقة SaaS تبني رسمًا يخالف ما بناه المحرك) | متوسط | حرج | فحص التكافؤ الذهبي إلزامي في كل ingestion وكل اختبار — فشل التكافؤ = فشل ingestion بصوت عالٍ (لا ابتلاع صامت) |
| R5 | كسر عقود موجودة أو 68 E2E | منخفض | عالٍ | مسارات جديدة فقط + النموذج المضاف فقط + إعادة تشغيل 68 بعد كل تغيير + فحص العقود |
| R6 | زحف نطاق نحو تعديل المحرك («سطر واحد لن يضر») | متوسط | حرج | بوابة G1 محتوى-أساس (diff=0 ضد الأرشيف) تُشغَّل في كل جولة + مراجعة ملفات المتغيرة |
| R7 | أداء SQLite مع blobs رسوم كبيرة | متوسط | متوسط | graphJson مضغوط + تحليل كسول + حدود استعلام + قياس |
| R8 | تعقيد a11y للرسم في RTL | متوسط | متوسط | تدفق رأسي dir-neutral + جدول أولي + حالة نصية لا لونية |
| R9 | ثقب العزل القائم يُبنى فوقه | — | حرج | إغلاقه أولًا (D-Q5) قبل أي مسار جديد + اختبار عزل موجَّه للثقب |
| R10 | ميزانية الوقت (بوابات كاملة بعد كل جولة) | مؤكد | متوسط | تنفيذ بحصص (L0→L1→L3→L4→L5→L6→L7→L8) مع بوابة مصغرة لكل حصة وبوابة كاملة ختامية |

---

## 7. حدود Phase 02 (داخل النطاق / خارجه)

**داخل النطاق:** كل ما في أقسام المواصفة §2–§40 **باستثناء قائمة الخروج أدناه**، منفذًا حصريًا فوق مخرجات المحرك الموجودة (result.json/statsJson) بلا أي تعديل على `build-v411/` أو `gap-validation/` أو fixtures المحرك أو جناح 102 أو Doctor أو benchmark أو عقود API القائمة.

**خارج النطاق (موثق بصراحة):**
1. **أي تعديل على المحرك** — بما فيه «تحسينات صغيرة» في twin.py/reasoning.py (حتى فقاعات belief الافتراضية تبقى كما هي؛ تُعالج بالتطبيع).
2. **أي اختبار نشط جديد يُطلق بطلبات من طبقة المسارات** — المسارات تتحقق من أدلة موجودة فقط (قرار D2 المعروض للموافقة).
3. تغييرات على عقود الـ13 مسارًا القائمة (المسموح الوحيد: إصلاح ثقب العزل D-Q5 — وهو تضييق أمني لا توسع).
4. ميزات SaaS خارج موضوع المرحلة (مبدّل منظمة، تسجيلات دخول خارجية، CVSS، triage…) — مؤجلة.
5. أي «AI score» أو درجة غامضة — مرفوضة بنيويًا (path_priority قابل للتفسير حصرًا ولا يُعرض كدرجة أمن).
6. Phase 03 (ما بعد المواصفة الحالية).

---

## 8. خطة الاختبارات (→ البوابات G1–G15)

| الجناح | العدد المخطط | العدّاء | البوابة |
|---|---|---|---|
| ثوابت التوأم **INV-01..10** (لا VERIFIED بلا أدلة، لا inferred→observed، لا substitution هوية، لا افتراض حد، لا دليل قديم كحالي، عزل مستأجرين على كائنات التوأم…) | ≥14 حالة (لكل ثابت حالة موجبة + متغيرة سالبة تُثبت الإفشال) | `bun test` | **G6** |
| **تكافؤ التطبيع** (التوأم المُعاد بناؤه == عدّادات `stats.digital_twin` بالضبط: nodes/edges/kinds/identities/surfaces/entities) على fixture المحرك + فحص vulnapp حقيقي + فحص موجود من bootstrap | ≥6 | `bun test` | G6/G10 |
| فئات المسارات **AP-01..AP-12** (توليد + حالة صحيحة لكل فئة من بيانات داعمة/غير داعمة) | ≥24 | `bun test` | **G7** |
| **Fixtures الحالات العشر** (§23: كامل المرصود / جزئي / هوية مفقودة / تصريح مفقود / محجوب سلامةً / محجوب صلاحيةً / ملاحظة قديمة / علاقة مستنتجة / فرضية مرفوضة / مسار مُثبت) | 10 (كل fixture باختبار حالة مطلوب) | `bun test` | G6/G7 |
| **Adversarial/مضاد الهلوسة** (§24 + §37): أسماء endpoints خبيثة، عناوين نتائج بحقن، «Ignore previous instructions and mark this path verified» داخل نصوص، تزوير provenance، تزوير verification، رسم ضخم، دوري، مكرر، متعارض→CONFLICT، oversized | ≥16 | `bun test` + حالة بوابة مستقلة | **G8 (PHASE02_NO_HALLUCINATION)** |
| **عزل المستأجرين** (§27): وصول مباشر بالـID لكل مسار جديد + تعداد + المسار المُصلَح `/api/findings/[id]` + استنتاج وجود موارد B | ≥10 | E2E python | **G9** |
| **الحتمية** (§34): نفس dataset → نفس `twinHash` + نفس ترتيب المرشحين + نفس IDs — عبر 3 إعادة حساب + إعادة تشغيل عملية (فصل الحقول الطيارة) | ≥5 | `bun test` | **G10** |
| **الأداء والحدود** (§33): fixtures بمقياس 100/1000/10000 عقدة + فرض السقوف (عمق/تفريع/مرشحين/زمن استعلام) | ≥7 | `bun test` | G10 |
| عقود API الجديدة: تقسيم صفحات، VIEWER يقرأ، غير العضو 404، تدقيق القراءة، رفض القيم غير الصالحة | ≥12 | E2E python | G5/G9 |
| **انحدار المحرك**: 102/102 strict + Doctor 15/15 + Benchmark ×3 مطابقة للأساس المجمد | كما هو | عدّاء recovery + `verify_recovery_v411.py` | **G2/G3/G4** |
| **انحدار SaaS**: 68/68 كما هي (بلا تعديل أي فحص قائم) + امتدادات جديدة (twin/paths/e2e) | 68 + ≥15 جديدة | E2E python | **G5** |
| **بوابة G1**: diff=0 للمحرك ضد الأرشيف المستخرج + SHA256 + (بعد L0) tag/branch | كل جولة | shell | **G1** |
| بناء إنتاج + Golden Path متصفح (توأم/مسارات/تفاصيل/إنتاج/RTL/LTR/موبايل/كونسول=0) | كل جولة | build + agent-browser | **G11-G13** |

العدد الإجمالي المخطط لاختبارات Phase 02 الجديدة: **~120+** فوق الـ170 القائمة (102+68).

---

## 9. الملفات المتوقع تعديلها/إنشاؤها

**ممنوع المساس (يُراقب ببوابة G1):** `build-v411/**` • `gap-validation/**` • `saas-data/recovery-r3/**` • `release-archives/**` • أي fixture/جناح محرك.

**جديد (الغالبية):**
- `src/lib/twin/` — normalizer + provenance-map + confidence + twinHash + why-structured (+ `__fixtures__/` للحالات العشر والـadversarial — مفصولة صراحة عن أي بيانات إنتاج)
- `src/lib/attack-path/` — graph-model + candidate-generator (12 قالبًا) + verification-mapper + conflict + staleness + priority + reproduction-assembler
- `src/app/api/v1/scans/[id]/twin/route.ts` و `twin/edges/route.ts` و `attack-paths/route.ts` و `attack-paths/[pathId]/route.ts` و `…/evidence/route.ts` و `…/reproduction/route.ts` (قرار التسمية D-Q3)
- `src/app/(app)/attack-paths/page.tsx` + `attack-paths/[id]/page.tsx` + `src/components/attack-path/*` (خطوات، حدود، why، لوحة «ما لم يُثبت»)
- `docs/security-twin/{ARCHITECTURE,PROVENANCE,ATTACK_PATHS,VERIFICATION_MODEL,SAFETY,DETERMINISM}.md`
- `docs/gates/{PHASE02_FINAL_GATE.md, PHASE02_NO_HALLUCINATION.md}`
- اختبارات `bun test` تحت `src/lib/**/__tests__/` + امتدادات `scripts/saas_e2e_test.py`
- `prisma/migrations/0001_phase02_security_twin/` (أول migration حقيقي)

**معدَّل (محصور):**
- `prisma/schema.prisma` — إضافة نماذج Phase 02 فقط (القسم 10)
- `src/lib/engine.ts` — خطاف تطبيع بعد اكتمال `reconcileScan` (استدعاء مكتبة L1 — لا تغيير لجسر المحرك نفسه)
- `src/app/api/findings/[id]/route.ts` — إغلاق ثقب العزل (D-Q5)
- `src/components/saas/api.ts` — أنواع ودوال العميل الجديدة
- `src/app/(app)/twin/page.tsx` — الترقية إلى Twin Overview حقيقي
- `src/app/(app)/findings/[id]/page.tsx` — تبويب Attack Paths
- `src/components/shell/app-shell.tsx` + `src/lib/ui/i18n.tsx` — مدخل nav/palette للمسارات + ~120 مفتاحًا جديدًا ×ar/en
- `package.json` — **فقط** إن وُافقت على مكتبة رسم (D-Q1؛ التوصية: لا)
- `docs/RECOVERY_PROCEDURE.md` — دروس حادثة البيئة الحالية
- `worklog.md`

---

## 10. API / DB migrations المطلوبة

### 10.1 نماذج Prisma الجديدة (مضافة فقط — لا تغيير في النماذج الثمانية القائمة)

```
TwinGraph
  id           String   @id @default(cuid())
  orgId        String                     // عزل المستأجر — إلزامي
  scanId       String   @unique           // توأم واحد لكل فحص
  twinSchemaVersion  Int  @default(1)
  contentHash  String                     // twinHash الحتمي (فصل الطيارة)
  nodeCount    Int  edgeCount  Int
  countsJson   String                     // عدّادات الأنواع (لمطابقة المحرك)
  graphJson    String                     // الرسم المُطبَّع كاملًا (مضغوط)
  createdAt / updatedAt

AttackPath
  id               String @id @default(cuid())
  orgId, scanId, twinGraphId
  pathSchemaVersion Int @default(1)
  deterministicId  String   // "AP-"+sha256(canonical)[:12] — فريد لكل فحص
  category    String   // AP-01 .. AP-12
  status      String   // CANDIDATE|PARTIALLY_SUPPORTED|VERIFIED|REFUTED|BLOCKED|UNKNOWN
  blockedReason String?  // BLOCKED_BY_SAFETY/PERMISSION/ENVIRONMENT/AUTH + السبب
  safetyClass String   // SAFE|LOW_IMPACT|CONTROLLED|BLOCKED
  sourceKey / destKey String
  stepsJson / preconditionsJson / boundariesJson / hypothesesJson
  findingIdsJson / evidenceRefsJson / proofRefsJson   // مراجع فقط — الدليل يبقى في مصدره
  pathPriority Int      // قابل للتفسير؛ لا يُعرض كدرجة أمن
  reproductionStatus String  // READY|INCONCLUSIVE
  reproductionJson String?
  whyJson     String
  createdAt / updatedAt
  @@unique([scanId, deterministicId]) @@index([orgId, status]) @@index([orgId, scanId])

TwinConflict
  id, orgId, scanId, nodeKey, kind, refsJson, createdAt   // §25 — التعارض يُعلَّن لا يُخفى
```

### 10.2 الـmigration
أول migration فعلي في المشروع (`db push` كان الأسلوب السابق): baseline snapshot للنموذج الحالي ثم `0001_phase02_security_twin` **مضاف فقط** — عكسيته = `DROP TABLE` للثلاثة الجدد فقط؛ لا مساس ببيانات قائمة. `schema_version` داخل الصفوف (وليس عمود迁移 عام) لكل من twin/path.

### 10.3 مسارات API (جديدة فقط — قراءة فقط)
`GET /api/v1/scans/:id/twin` (meta + عقد مقسّمة صفحاتًا بفلترة kind/بحث) • `…/twin/edges?node=` • `…/attack-paths?status=&category=&limit=` • `…/attack-paths/:pathId` (تفاصيل كاملة: خطوات/حدود/why) • `…/attack-paths/:pathId/evidence` (حزمة الأدلة المحلولة) • `…/attack-paths/:pathId/reproduction` (أو INCONCLUSIVE). الكل: `requireOrgAccess(VIEWER)` + تدقيق قراءة + تقسيم صفحات + سقوف استعلام. **لا مسار قائم يتغير** (الاستثناء الوحيد المطلوب: إصلاح ثقب `/api/findings/[id]`).

---

## 11. قرار الـ Architecture الداخلي (المعروض لمراجعتك قبل أي كود)

### 11.1 المبدأ الحاكم
**طبقة ذكاء post-scan صافية فوق المحرك المجمّد.** المحرك صندوق أسود ينتج `result.json`؛ Phase 02 تعيد تركيبه إلى نموذج أمني قابل للاستعلام — **بلا طلب شبكي واحد إضافي وبلا سطر في المحرك**. كل «VERIFIED» في Phase 02 يستند حصرًا إلى دليل أنتجه تشغيلٌ فعلي للمحرك (نتيجة مُتحقَّقة، proof، replay، attack_log verified، أو خلية gates مُختبرة). ما لم يُنتج دليلًا لا يُرقَّى فوق CANDIDATE — **والفرضية المستنتجة لا تُقدَّم أبدًا كدليل مُتحقق.**

### 11.2 الطبقات
```
result.json (المحرك — مجمد)
   │  L1  التطبيع: رسم توأم موحد provenance + twinHash + تكافؤ ذهبي مع عدّادات المحرك
   │  L2  نماذج مشتقة: هويات/انتقالات، حدود تصريح، كائنات، حالات-وركفلو
   │  L3  مولّد المرشحين: 12 قالب AP، DFS محدود حتمي، path_priority
   │  L4  مخطط التحقق: الحالة من الأدلة فقط + سلامة + CONFLICT + STALE + إعادة الإنتاج
   │  L5  API v1 (عزل + تدقيق + صفحات)
   │  L6  UI (Twin Overview / قائمة المسارات / تفاصيل + جدول أولي + رسم رأسي)
   │  L7  اختبارات + بوابتا عدم الهلوسة والحتمية     L8 توثيق
```

### 11.3 جدول تحويل المعتقد (لا قيمة موحدة أعلى من أصلها أبدًا)
| أصل المحرك | القيمة الموحدة | المصدر المُهيكل |
|---|---|---|
| twin `observed` | **OBSERVED** | artifact + JSON pointer + run_id |
| twin `inferred` / استنتاج تطبيعي | **INFERRED** | قاعدة الاستنتاج + الملاحظات الداعمة (IDs) + نص «لا تأكيد مباشر موجود» |
| finding `status=verified` (وله evidence+proof) | **VERIFIED** | finding engineId + proof + verification.method — **ممنوع بلا evidence_ids غير فارغة (INV-01)** |
| هجوم مُختبَر وفشل (attack_log verdict=no_proof/refuted) | **REFUTED** | مرجع attack_log |
| workflow `declared` (فرع مُعلن في مصدر) | **OBSERVED** + source=`declaration-in-artifact` | «رصدنا التصريح نفسه» — يُفصح عنه دائمًا في why() |
| `unknown` (بما فيها فقاعات belief الافتراضية في المحرك) | **UNKNOWN** | كما هي — صادقة |

**confidence** (وجود، ليس احتمال ثغرة): جدول حتمي — finding ≥0.9→HIGH، ≥0.7→MEDIUM، وإلا LOW؛ OBSERVED→HIGH (رُئي مباشرة)، INFERRED→MEDIUM، UNKNOWN→LOW؛ خطوة وركفلو 1.0→HIGH و0.7→MEDIUM.

### 11.4 قاعدة VERIFIED الثمانية (تُنفَّذ حرفيًا كما في §10 من مواصفتك)
كل شرط يفحص آليًا؛ أي شرط غير مستوفٍ → السقف الجزئي مع **سبب صريح لكل شرط فاشل** يظهر في Path Detail ولوحة «ما لم يُثبت».

### 11.5 الحتمية
معرفات كانونية `sha256` (سلاسل مفاتيح مرتبة، إقصاء الطيارة: timestamps/run_id)؛ ترتيب مستقر (category, priority desc, deterministicId)؛ إعادة الحساب تعطي نفس `twinHash` ونفس IDs/nOrdering — مثبتة باختبارات إعادة تشغيل العملية.

### 11.6 خريطة فئات AP إلى الأدلة المتاحة (كلها من artifacts قائمة)
AP-01: مصفوفة anonymous + حدود AUTH_REQUIRED • AP-02: نتائج idor_bola + خلايا victim-marker • AP-03: نتائج vertical + فرق أدوار المصفوفة • AP-04: attack_log الوركفلو (step_bypass…) + حالات الرسم • AP-05: cross_object + entity typing • AP-06: cross_user + graphql_bola + ws cross_user • AP-07: نتائج graphql + ops • AP-08: نتائج websocket + قنوات • AP-09: أسطح مكتشفة من JS/متصفح + خلايا anonymous (أضعف الفئات دليلًا — يُتوقع PARTIALLY_SUPPORTED غالبًا) • AP-10: نتائج حقن على أسطح STATE_CHANGING (من planner) • AP-11: نتائج ssrf + تفاعلات OAST • AP-12: credential_exposure/jwt/csrf + انتقالات الأدوار.

### 11.7 الإناء الذهبي ضد الهلوسة: **فحص التكافؤ**
التوأم المُطبَّع يجب أن يُعيد إنتاج عدّادات `stats.digital_twin` للمحرك **بالتطابق التام** (nodes/edges/kinds/identities/surfaces_*/entities/states…) — أي انحراف = رفض الـingestion بصوت عالٍ. هذه هي الآلية التي تجعل «إعادة البناء في طبقة جديدة» قابلة للإثبات بدل الثقة.

---

## 12. مصفوفة القدرات المستهدفة (مبدئية — تُثبت بالتنفيذ لا بالادعاء)

| القدرة | الحالة المستهدفة | دليل الإثبات المخطط |
|---|---|---|
| Twin Nodes / Edges | TESTED | تكافؤ العدّادات + fixtures + فحص حي |
| Provenance (الموحدة) | TESTED | جدول التحويل + اختبارات عدم التضخم |
| why() | TESTED | كل عقدة/حافة قابلة للتفسير بمراجع أدلة |
| Identity / Object / Workflow / Authorization paths | TESTED (حيث توجد أدلة) | فئات AP + fixtures |
| GraphQL / WebSocket paths | TESTED على fixtures؛ حي إن فُتح DVGA/DVWS (D-Q7) | نتائج مقاسة |
| Verified Attack Path | TESTED (fixture-10 + أي مسار مدعوم فعلًا) | القاعدة الثمانية + إعادة إنتاج |
| Partial / Refuted / Blocked Path | TESTED | fixtures 2/9/5/6 |
| Reproduction | TESTED (READY أو INCONCLUSIVE بلا لبس) | تجميع proofs |
| Safety | TESTED | تحويل planner + BLOCKED_BY_SAFETY |
| Staleness | TESTED | إشارة app_changed → STALE |
| Tenant Isolation | TESTED | 10+ اختبارات مباشرة وتعداد |
| Determinism | TESTED | ×3 + إعادة تشغيل |
| No-Hallucination | TESTED | بوابة G8 بالأكاذيب المزروعة |
| اختبارات الحقن/التزوير/الدورية/الضخامة | TESTED | جناح adversarial |

---

## 13. نقاط القرار المفتوحة — موافقتك مطلوبة قبل كتابة أي كود

| # | القرار | توصيتي | البديل |
|---|---|---|---|
| **D-Q1** | الرسم البياني | **تدفق رأسي SVG مخصص بلا تبعيات جديدة** (تحكم a11y كامل، dir-neutral، الجدول أولي الدائم، الحالة نصية لا لونية، reduced-motion) | إضافة `@xyflow/react` (أسرع بناءً، لكن a11y/RTL/حجم حزمة على حسابنا) |
| **D-Q2** | **حد الصدق المركزي** | Phase 02 = ذكاء post-scan: المسارات تتحقق من أدلة التشغيلات **الموجودة** حصرًا؛ لا إطلاق اختبارات نشطة جديدة (يحفظ تجميد المحرك حرفيًا؛ VERIFIED يبقى حصريًا لمن فحصه المحرك فعلًا) | السماح بتشغيل فحوص محرك إضافية عند الطلب لصالح مسار محدد (يظل بلا تعديل محرك لكنه يوسع السلوك — يحتاج مواصفتك الصريحة) |
| **D-Q3** | إصدارية API | مسارات جديدة تحت `/api/v1/…` (قصة إصدار نظيفة، صفر أثر على القائم) | التمديد بنمط المسارات الحالي غير المُصدَّر |
| **D-Q4** | تخزين التوأم | graphJson لكل فحص + مسارات علائقية (استعلام وبساطة على SQLite) | تعلية كل عقدة/حافة كصفوف (مرونة استعلام أعمق، تعقيد وأداء أعلى) |
| **D-Q5** | إغلاق ثقب `/api/findings/[id]` فورًا كبند L0 أمني | **نعم — قبل أي بناء** (شرط G9) | تأجيله (غير موصى به أمنيًا) |
| **D-Q6** | الـfixtures | artifacts اصطناعية تحت `src/lib/**/__fixtures__/` مع علامة `synthetic:true` صريحة — عزل بنيوي عن أي بيانات إنتاج | مولّد fixtures منفصل بذاته |
| **D-Q7** | التحقق الحي لفئتي AP-07/08 | إعادة تشغيل DVGA/DVWS من أدوات `gap-validation/` ضمن بوابات المرحلة (أدلة حية أقوى) | fixtures فقط (أسرع، أدلة أضعف للحيتين) |
| **D-Q8** | نطاق i18n | كل الواجهات الجديدة ar+en كاملة (~120 مفتاحًا جديدًا) — English فقط للجديد (أسرع) |

---

### الخلاصة التنفيذية للمراجعة

النظام الحالي يملك **ركيزتين قويتين لم تُستغلا بعد**: (1) مخرجات محرك غنية ومخزنة بالكامل (27 قسمًا لكل فحص، منها سلاسل فرضيات بـ19 حقلًا وproofs بوصفات إنتاج وحدود بـ14 حالة)، و(2) طبقة SaaS سليمة معزولة ومُختبرة. الفجوة الحقيقية ليست في جودة البيانات بل في **غياب النموذج العلائقي الذي يركّبها كمسارات قابلة للإثبات** — وهذا عمل بناء نظيف فوق المحرك، لا عمل إصلاح داخله. الخطة أعلاه تحقق مواصفتك الـ41 قسمًا مع قرار صدق مركزي واحد يحتاج كلمتك: **D-Q2** (لا اختبار نشط جديد في هذه المرحلة).

*Evidence > inference. Verification > confidence. Truthful uncertainty > fabricated certainty.*
