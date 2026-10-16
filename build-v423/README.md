# SENTINEL v4.1.1 — Live Gap Closure: GraphQL (DVGA) + WebSocket (DVWS)

> **DISCOVER → MODEL → PLAN → TEST → VERIFY → PROVE → CLASSIFY BOUNDARY → REPORT**
>
> SENTINEL يعرف التطبيق، ويعرف ما اكتشفه، وما اختبره، وما لم يستطع اختباره،
> ولماذا — ولا يدّعي تغطية أو إثباتًا لم يحدث فعليًا.

## الحكم النهائي (v4.1.1)

| البوابة | القيمة |
|---|---|
| الاختبارات | **102/102** (97 v4.1.0 + 5 إضافات v4.1.1 مُلتقطة حيًا — تشمل بوابة عدم الهلوسة) |
| Doctor | **15/15** |
| Benchmark | **F1 = 1.000 ×3** (TP=38 / FP=0 / FN=0 / TN=35 · طلبات متطابقة ×3) |
| الحتمية | confusion + listings + الأبعاد الـ17 + planner/reasoning/boundary + أزواج إثبات الحالة — متطابقة ×3 |
| أهداف حية مصرّح بها | WebGoat · WebWolf · ginandjuice.shop · Juice Shop · **DVGA (GraphQL) · DVWS (WebSocket)** |

## ما الجديد في v4.1.1 — إغلاق الفجوتين المعلّقتين (WAIVED → CLOSED)

فجوتا v4.1.0 المعلّقتان (GraphQL/WebSocket حيًا) أُغلقتا بأهداف تدريبية
> مصرّح بها ومعزولة محليًا، والاختبار الحي كشف وأصلح **عيوبًا حقيقية في
> SENTINEL نفسه** لم تكن الـ fixtures لتكشفها:

1. **GraphQL على DVGA**: 25 نتيجة فريدة (2 CRITICAL: SQLi + تنفيذ أوامر ·
   2 HIGH: BOLA + تصريح mutation) · 29 اختبار GraphQL · قاعدة البيانات
> نجت من الفحص. من الإصلاحات: Content-Type · إسناد Int للمعاملات ·
   selection sets للـ mutations · custom scalars · إسقاط المعاملات
   الإلزامية · إسناد الهوية (القراءة الذاتية ليست BOLA).
2. **WebSocket على DVWS**: **12/12 قناة مكتشفة من JavaScript** — نمط
   `var wsUri = "ws://host:8080/path"; new WebSocket(wsUri)` حيث يستمع
   خادم WS على منفذ مختلف عن أصل HTTP (8888/8080) — 77 اختبارًا عبر 86
   اتصالًا · 3 انعكاس رسائل MEDIUM (أحدها داخل سياق HTML) · 9 CSWSH
   LOW · إثبات cross-user يدوي بعلامة مزروعة (dVws_cross_user_proof.json).
3. **canary الانعكاس أبجديًا [a-z0-9] فقط**: قناة /command-execution في
   DVWS تُلحق الرسالة الخام بـ `shell_exec('ping -c 3 ' . $msg)` — الكناري
   الآن عاجز بالبناء في سياقات shell/المسارات/القوالب.
4. **بوابات المسارات التدميرية مركزية** (V411-DISC-SAFE): /start_over في
   DVGA يعيد تهيئة قاعدة البيانات بـ GET مجرد — أُمسكت حيًا بعد أن دمّرت
   هويات الاختبار منتصف الفحص؛ البوابات الآن تغطي الزاحف والخط الأساسي
   والمتصفح والمخطط الفوري، و/setup.php في DVWS تحت نفس البوابات.
5. **V411-COV**: سبب التخطي يُنشر إلى بُعد endpoint في التغطية (لم يعد
   في سجل الحدود فقط).

## ما الجديد في v4.1.0 (الفئة الأولى للحدود والتغطية)

1. **محرك حدود المعرفة** (boundary.py): 14 حالة موحّدة لكل ما لم يُختبر ولماذا،
   مع حارس يمنع ادّعاء 100% غير المدعوم.
2. **التغطية متعددة الأبعاد**: 17 بُعدًا قابلًا للتدقيق (endpoint/parameter/
   identity/authorization/workflow/branch/state/graphql/websocket/...) —
   والغياب بيان NOT_DISCOVERED لا ادّعاء اختبار.
3. **سير العمل 2.0**: رسم بياني حقيقي (فروع/موافقات/تراجع/حالات + اعتماديات
   وأزواج حالة لكل خطوة) و**4 هجمات جديدة**: branch_bypass · unauthorized_branch
   · approval_bypass · rollback_abuse (البطارية 13).
4. **GraphQL من فئة أولى**: اكتشاف + introspection + BOLA/حقول/mutations/مجهول —
   كلها request→response→verification.
5. **WebSocket من فئة أولى**: عميل RFC 6455 بلا تبعيات + بوابة نطاق قبل أي
   اتصال + تصنيف بروتوكول وحد protocol_not_understood صادق.
6. **التوأم الرقمي 2.0**: كل عقدة/حافة تحمل belief + provenance، و`why()` يجيب
   "لماذا يعتقد SENTINEL هذا؟".
7. **الاستدلال 2.0**: سجلات فرضيات منظمة بالكامل مع سبب صريح لكل نتيجة
   (verified/refuted/untestable) + 7 أنماط جديدة.
8. **الإثبات 2.0**: `reproduce --replay` يعيد تنفيذ الإثبات من محرك نظيف —
   REPRODUCTION_FAILED بالسبب يُسجَّل ولا يُخفى أبدًا.
9. **مخطط الهجمات الفوري**: كل هجوم يمر بالبوابة قبل أي طلب، وسجل القرارات
   محفوظ — والمفردات التخريبية تتفوق على أي إشارة تصنيف.
10. **مصفوفة الهوية×الإجراء + الجرد الموحد للـAPI** (REST/OpenAPI/GraphQL/WS).
11. **ذاكرة أمنية** عبر الجولات (معزولة لكل تطبيق؛ التغيير يُبطل الافتراضات
    القديمة؛ الذاكرة سياق وليست دليلًا أبدًا).
12. **بطارية أمن ذاتي**: هدف خبيث يهاجم SENTINEL (حقن تقارير، SSRF ضد
    SENTINEL نفسه، إطارات 8MB) — وكل شيء ينجو ويُهرَّب ويُرفض.
13. **بوابة عدم الهلوسة**: 6 قواعد قابلة للتنفيذ، والأكاذيب المزروعة تفشلها.

## البدء السريع

```bash
unzip sentinel-4.1.1-source.zip -d sentinel && cd sentinel
python3 sentinel/cli.py doctor                          # 15/15
python3 sentinel/cli.py scan https://target.example/ \
    --auth-user user --auth-pass pass --db results/t.db  # فحص موثّق
python3 sentinel/cli.py capability-matrix --db results/t.db  # مصفوفة القدرات (مولّدة)
python3 sentinel/cli.py reproduce --finding F-xxxx --db results/t.db --replay  # إعادة إنتاج حية
python3 sentinel/cli.py report --db results/t.db --format html --out r.html --ci  # عقد خروج 0/1/2/3
```

## الوثائق (docs/)

INSTALLATION_GUIDE · USER_GUIDE · API_CLI_REFERENCE · THREAT_MODEL ·
SECURITY_MODEL · KNOWN_LIMITATIONS · SUPPORTED_ENVIRONMENTS · RELEASE_POLICY
+ v4.1.0: BOUNDARY_MODEL · WORKFLOW_V2 · GRAPHQL_INTELLIGENCE ·
WEBSOCKET_INTELLIGENCE · COVERAGE_V2 · NO_HALLUCINATION_GATE · PROOF_ENGINE_V2

## الاستخدام المصرّح به فقط

أداة اختبار أمني نشطة — استخدمها فقط على أنظمة تملكها أو تملك تصريحًا خطيًا
باختبارها. كل فحص حي في حملة الإصدار كان على أهداف مصرّح بها رسميًا
(WebGoat/WebWolf/PortSwigger labs/Juice Shop).
