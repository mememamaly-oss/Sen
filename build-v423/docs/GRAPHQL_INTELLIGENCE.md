# SENTINEL v4.1.0 — محرك GraphQL الذكي

> المرجع التنفيذي لـ `graphql.py` — GraphQL من فئة أولى: اكتشاف، نمذجة، اختبار آمن، حدود صادقة.

## خط الأنابيب

```
DISCOVER → MODEL (introspection) → TEST (planner-gated) → PROVE → BOUNDARY
```

### الاكتشاف
1. **ملاحظ**: نقاط النهاية ذات مسارات graphql-الشكل في خريطة الزحف
2. **JS**: روابط fetch/axios المستخرجة ثابتًا
3. **استقصاء**: قائمة معروفة حتمية (`/graphql`, `/api/graphql`, `/graphql/v1`, `/gql`)
   بطلب `{__typename}` — الاستجابة يجب أن تحمل مفتاح `data` (استجابة JSON خطأ
   وحدها ليست دليلًا — تطبيقات REST ترسل `{"errors":[...]}` أيضًا)

### النمذجة (introspection)
- الاستقصاء الكامل عبر المحرك الموثَّق → جرد العمليات: queries/mutations مع
  أشكال الوسائط وأنواع الإرجاع والحقول القابلة للاختيار
- **الانعكاس معطّل** → حد `UNTESTABLE schema unavailable` — لا ادّعاء، لا تخطٍّ صامت

### البطارية (كلها request → response → verification)

| الاختبار | الإثبات | التصنيف |
|---|---|---|
| وصول مجهول | استعلام **حساس** يُجيب دون مصادقة (الاستعلام العام ليس عيبًا — لا تأثير ملفق) | READ_ONLY |
| BOLA | هوية دنيا تستعلم عن معرّف الهوية الرئيسية والماركر حاضر في الاستجابة | READ_ONLY |
| تفويض حقلي | حقول حساسة التسمية (password/ssn/token) في إجابة الكائن الخاص | READ_ONLY |
| تفويض mutation | mutation ينفَّذ دون امتيازه (بيانات بلا أخطاء) | **STATE_CHANGING** — بوابة planner + `--logic-active` |
| انعكاس مكشوف | المخطط قابل للقراءة (finding منخفض — سياسة قابلة للتقرير) | معلوماتي |

### قواعد الأمان
- الـmutations التخريبية الاسم (delete/destroy/purge) → حد `BLOCKED_BY_SAFETY` —
  لا تُرسل أبدًا
- 401/"not authenticated" على mutation → حد `UNTESTABLE authentication required`
  (لم يُمارس — ليس ادّعاء رفض)
- كل طلب عبر محرك الطلبات القياسي (النطاق + إعادة المحاولة + التقييد)

### الحدود المسجَّلة (أمثلة فعلية من fixtures)
```
graphql/gql/partial          UNTESTABLE   introspection disabled — inventory cannot be learned
graphql/bola  gql/safe       TESTED       cross-identity query refused (authorization holds)
graphql/mutation gql/safe    UNTESTABLE   authentication required — not exercisable
graphql/mutation gql/vuln    (finding)    graphql_mutation_authorization VERIFIED
```

## التوأم الرقمي
كل نقطة GraphQL تصبح عقدة `graphql_endpoint` (provenance: observed) تربطها حافة
`speaks_protocol` بسطحها — ومولّد الفرضيات يولّد `R-GQL-BOLA` و`R-GQL-MUTATION-AUTHZ`
**فقط** عند وجود العقدة (لا تخمين بأن GraphQL قد يوجد).

## أداة التحقق
`fixtures/gql_app.py` — ثلاثة توائم (هش: 5 فئات GT · محصّن: introspection فقط ·
جزئي: 0 findings + حد UNTESTABLE). الاختبار: `regression_v41_graphql_battery`.
