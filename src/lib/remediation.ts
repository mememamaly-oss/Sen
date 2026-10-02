// Platform-side remediation guidance catalog, keyed by engine finding type.
// NOTE: This is PLATFORM guidance (P0) — it is NOT engine output. The engine's
// own evidence (evidence / verification / impact) is always shown alongside,
// and the UI labels this section as guidance provided by the platform.

export type Remediation = {
  title: string;
  summary: string;
  steps: string[];
};

const CATALOG: Record<string, Remediation> = {
  sql_injection: {
    title: "SQL Injection",
    summary: "المدخل يغيّر تقييم استعلام SQL من جهة الخادم — أثبته المحرك بأوراكل تفاضلي غير تدميري.",
    steps: [
      "استخدم Prepared Statements / Parameterized Queries حصريًا — لا تركيب سلاسل SQL مع مدخلات المستخدم.",
      "طبّق تحقق صارم من نوع وطول المدخل (allowlist) قبل أي استخدام في الاستعلام.",
      "أزل صلاحيات غير ضرورية من حساب قاعدة البيانات (least privilege) وعزّل مستخدم DB لكل خدمة.",
      "أضف WAF كطبقة مساندة فقط — ليست علاجًا جذريًا.",
    ],
  },
  nosql_injection: {
    title: "NoSQL Injection",
    summary: "المدخل يغيّر دلالات استعلام NoSQL (مثل معاملات $ في MongoDB).",
    steps: [
      "تحقق من بنية المدخل صراحةً (schema validation) وارفض المفاتيح التي تبدأ بـ $.",
      "استخدم مكتبات ORM بمدخلات مُعاملة بدل بناء الاستعلامات يدويًا.",
      "قيّد صلاحيات مستخدم قاعدة البيانات وعطّل التشغيل الجانبي للسيرفر (server-side JS) إن لم يلزم.",
    ],
  },
  xss_reflected: {
    title: "Reflected XSS",
    summary: "قيمة المدخل تعود إلى الاستجابة دون ترميز آمن وتصل إلى سياق تنفيذ في المتصفح.",
    steps: [
      "رتّب المخرجات حسب السياق (HTML/JS/URL/CSS) باستخدام ترميز مناسب لكل سياق.",
      "استخدم CSP صارمة (default-src 'self') لتقييد أي سكربت خارجي/مضمّن.",
      "اعتمد مكتبات قوالب تهرّب تلقائيًا (auto-escaping) وتجنب innerHTML مع مدخلات غير موثوقة.",
    ],
  },
  xss_stored: {
    title: "Stored XSS",
    summary: "مدخل يُخزَّن ثم يُعرض دون ترميز لمستخدمين آخرين.",
    steps: [
      "نقّح المدخل عند التخزين (sanitize) ورتّبه عند العرض (encode) — الطبقتان معًا.",
      "طبّق CSP وأفعّل HttpOnly على الكوكيز الفعالة.",
      "راجع كل مسارات العرض المحتملة للبيانات المخزّنة (ويب، بريد، API).",
    ],
  },
  path_traversal: {
    title: "Path Traversal",
    summary: "مسار ملف مبني من مدخل المستخدم يسمح بالخروج من المجلد المسموح.",
    steps: [
      "لا تبنِ مسارات ملفات من مدخل المستخدم — استخدم معرّفات تُربط بجدول مسارات داخلي.",
      "إن كان لا بد: طبّع المسار (realpath) وتحقق من بقائه داخل الجذر المسموح.",
      "شغّل الخدمة بمستخدم محدود وقيّد صلاحيات نظام الملفات (chroot/containers).",
    ],
  },
  open_redirect: {
    title: "Open Redirect",
    summary: "معامل توجيه يقبل URL خارجي دون تحقق — قابل للاستخدام في تصيّد موثوق.",
    steps: [
      "اعتمد قائمة سماح (allowlist) للنطاقات المسموح بإعادة التوجيه إليها.",
      "استخدم مسارات داخلية (رسم خرائط ثابتة) بدل تمرير URL كامل من العميل.",
      "أظهر النطاق الهدف للمستخدم قبل التنفيذ عند إعادة التوجيه الخارجية.",
    ],
  },
  csrf: {
    title: "Cross-Site Request Forgery",
    summary: "نموذج/عملية تغيير حالة لا تتحقق من أصل الطلب.",
    steps: [
      "أضف SameSite=Lax/Strict على الكوكيز وأرفق رمز CSRF لكل عملية تغيير حالة.",
      "تحقق من Origin/Referer في الخادم كطبقة إضافية.",
      "استخدم رؤوس مخصصة (X-Requested-With) مع توكنات غير قابلة للتخمين.",
    ],
  },
  ssrf: {
    title: "Server-Side Request Forgery",
    summary: "الخادم يجلب URL يتحكم به المهاجم — وصول محتمل لخدمات داخلية/metadata.",
    steps: [
      "اعتمد allowlist للنطاقات/البروتوكولات (http/https فقط) وحظر عناوين IP الخاصة و169.254.169.254.",
      "عطّل إعادة التوجيه التلقائية أو أعد التحقق من كل قفزة.",
      "أخرج الطلبات عبر بوابة شبكية معزولة بسياسة خروج صارمة.",
    ],
  },
  xxe: {
    title: "XML External Entity (XXE)",
    summary: "محلل XML يسمح بكيانات خارجية — قراءة ملفات/SSRF محتملة.",
    steps: [
      "عطّل DTDs والكيانات الخارجية في المحلل (feature disallow-doctype-decl).",
      "استخدم JSON بدل XML حيث أمكن.",
      "حدّث المكتبة وتحقق من إعداداتها الافتراضية بعد كل ترقية.",
    ],
  },
  ssti: {
    title: "Server-Side Template Injection",
    summary: "مدخل يُنفَّذ كجزء من قالب من جهة الخادم.",
    steps: [
      "افصل البيانات عن القوالب: مرّر المدخلات كمتغيرات، لا كجزء من نص القالب.",
      "استخدم محركات قوالب بوضع sandbox/auto-escape.",
      "قلّل الصلاحيات وأزل الوظائف الخطرة من بيئة التنفيذ.",
    ],
  },
  command_injection: {
    title: "Operating System Command Injection",
    summary: "مدخل يصل إلى أمر نظام دون تهريب مناسب.",
    steps: [
      "تجنّب تنفيذ أوامر نظام من مدخلات المستخدم كليًا — استخدم مكتبات لغة بدل CLI.",
      "إن كان ضروريًا: مرّر المعاملات كمصفوفة argv (لا سلسلة shell) مع allowlist صارمة.",
      "شغّل بأقل صلاحية وافصل التنفيذ في بيئة معزولة.",
    ],
  },
  jwt_security: {
    title: "JWT Security",
    summary: "مشكلة في التحقق من التوكن (خوارزمية، توقيع، انتهاء صلاحية).",
    steps: [
      "ثبّت الخوارزمية في الخادم ( HS256 أو RS256) وارفض alg:none وأي تبديل خوارزمية.",
      "تحقق من التوقيع + انتهاء الصلاحية + الجمهور (aud) + المُصدر (iss) في كل طلب.",
      "استخدم مفاتيح طويلة عشوائية ودوّرها، ولا تثق بالتوكن من مصادر غير موثوقة.",
    ],
  },
  cors_misconfig: {
    title: "CORS Misconfiguration",
    summary: "سياسة CORS تسمح بأصول غير موثوقة أو بمرور الاعتمادات.",
    steps: [
      "حدّد Allowlist صريحة للأصول — لا تعكس Origin تلقائيًا ولا تستخدم * مع الاعتمادات.",
      "لا تفعّل Allow-Credentials إلا للأصول الموثوقة الضرورية.",
      "راجع الرؤوس المكشوفة (Expose-Headers) وقلّلها للحد الأدنى.",
    ],
  },
  missing_security_headers: {
    title: "Missing Security Headers",
    summary: "رؤوس أمان أساسية غير موجودة في الاستجابة.",
    steps: [
      "أضف: Content-Security-Policy، X-Content-Type-Options: nosniff، X-Frame-Options/CSP frame-ancestors.",
      "أضف: Strict-Transport-Security مع max-age مناسب وReferrer-Policy: strict-origin-when-cross-origin.",
      "طبّقها مركزيًا (middleware/proxy) واختبرها تلقائيًا في CI.",
    ],
  },
  credential_exposure: {
    title: "Credential / Secret Exposure",
    summary: "بيانات سرية (مفاتيح، توكنات) مكشوفة في الاستجابة أو الملفات الثابتة.",
    steps: [
      "أزل السر من المصدر فورًا ودوّره (rotation) بافتراض تسربه.",
      "انقل الأسرار إلى متغيرات بيئة/خزنة أسرار ولا تضمّنها في ملفات تُقدَّم للعميل.",
      "أضف فحص أسرار (pre-commit + CI) لمنع التسريب مستقبلًا.",
    ],
  },
  host_header_injection: {
    title: "Host Header Injection",
    summary: "قيمة Host غير محقّقة تُستخدم في بناء روابط/كاش.",
    steps: [
      "تحقق من Host مقابل allowlist وأرجع 400 لغير المعروف.",
      "لا تبنِ URLs مطلقة من رأس Host — استخدم إعدادًا خادميًا ثابتًا.",
      "عطّل بروكيل الكاش المعتمد على Host غير المحقّق.",
    ],
  },
  http_response_header_injection: {
    title: "HTTP Response Header Injection (CRLF)",
    summary: "مدخل يسمح بحقن أسطر جديدة في رؤوس الاستجابة.",
    steps: [
      "ارفض/نقّح CR وLF من كل مدخل يصل إلى الرؤوس.",
      "استخدم مكتبات إعداد رؤوس آمنة ترميز تلقائيًا.",
      "راجع الاستجابات المُعادة (redirects) تحديدًا.",
    ],
  },
  server_banner_disclosure: {
    title: "Server Banner Disclosure",
    summary: "بصمة تقنية مكشوفة في رؤوس/رسائل الخطأ تسهّل الاستهداف.",
    steps: [
      "أزل/غيّر Server وX-Powered-By وأي بصمة إصدار.",
      "وحّد صفحات الأخطاء (بدون stack traces) في الإنتاج.",
      "قلّل المعلومات المفيدة للمهاجم إلى الحد التشغيلي الأدنى.",
    ],
  },
  vulnerable_js_dependency: {
    title: "Vulnerable JS Dependency",
    summary: "مكتبة أمامية بإصدار معروف الضعف.",
    steps: [
      "حدّث المكتبة إلى إصدار مصحّح (راجع advisory).",
      "أضف فحص SCA (npm audit/Dependabot) إلى CI.",
      "إن كان الترقية مؤجلة: قيّم القابلية الفعلية للاستغلال وعوّضها بـ CSP/WAF مؤقتًا.",
    ],
  },
  idor_bola: {
    title: "IDOR / BOLA",
    summary: "كائن يُعاد لمستخدم غير مالكه — غياب تحقق تخويل على مستوى الكائن.",
    steps: [
      "طبّق تحقق تخويل لكل كائن (هل المستخدم الحالي مالكه/مصرّف له؟) في كل نقطة وصول.",
      "استخدم معرّفات غير متسلسلة (UUID) — ليست حماية بذاتها لكنها ترفع كلفة التعداد.",
      "غطِّ المسار باختبارات تخويل آلية (هذا ما يفعله المحرك في authz probing).",
    ],
  },
  graphql_introspection_enabled: {
    title: "GraphQL Introspection Enabled",
    summary: "مخطط GraphQL قابل للاستعلام بالكامل في الإنتاج.",
    steps: [
      "عطّل introspection في الإنتاج (إلا للاستخدام الداخلي الموثوق).",
      "طبّق تحقق تخويل على مستوى الحقول والـ resolvers.",
      "قيّد depth/complexity للاستعلامات لمنع DoS.",
    ],
  },
  graphql_field_authorization: {
    title: "GraphQL Field Authorization",
    summary: "حقل يُعاد دون تحقق تخويل مناسب.",
    steps: [
      "أضف تحقق تخويل داخل resolver كل حقل حساس (وليس فقط على مستوى الاستعلام).",
      "قسّم المخطط لحسابات أدوار مختلفة عند الحاجة.",
      "اختبر تغطية التخويل آليًا عبر أدوار متعددة.",
    ],
  },
  graphql_mutation_authorization: {
    title: "GraphQL Mutation Authorization",
    summary: "عملية كتابة قابلة للتنفيذ دون صلاحية كافية.",
    steps: [
      "تحقق من التخويل داخل كل mutation resolver قبل أي تغيير حالة.",
      "سجّل عمليات الكتابنة الحساسة (audit trail).",
      "طبّق حدود معدل (rate limiting) على الـ mutations.",
    ],
  },
  graphql_bola: {
    title: "GraphQL BOLA",
    summary: "كائن GraphQL يُعاد/يُعدَّل عبر معرّف دون ملكية.",
    steps: [
      "تحقق من الملكية في resolver لكل كائن مُعاد.",
      "لا تعتمد على معرّفات متسلسلة وحدها.",
      "غطِّ بمسح تخويل آلي متعدد الأدوار.",
    ],
  },
  graphql_anonymous_access: {
    title: "GraphQL Anonymous Access",
    summary: "واجهة GraphQL متاحة دون مصادقة.",
    steps: [
      "افرض المصادقة على مستوى المسار (route) بالكامل.",
      "أعد مخططًا عامًا محدودًا إن كانت بعض الحقول عامة عمدًا.",
      "راقب الاستعلامات المجهولة وسجّلها.",
    ],
  },
  graphql_sql_injection: {
    title: "GraphQL SQL Injection",
    summary: "مدخل GraphQL يصل إلى SQL دون معالجة.",
    steps: [
      "استخدم parameterized queries في كل resolver.",
      "تحقق من أنواع المدخلات (schema types) وارفض القيم غير المتوافقة.",
      "لا تبنِ SQL ديناميكيًا من أسماء الحقول/المعاملات.",
    ],
  },
  graphql_command_execution: {
    title: "GraphQL Command Execution",
    summary: "مدخل GraphQL ينفَّذ كأمر نظام.",
    steps: [
      "أزل تنفيذ الأوامر من resolvers نهائيًا.",
      "استخدم مكتبات لغة آمنة، وشغّل بأقل صلاحية.",
      "راقب استعلامات غير معتادة الشكل.",
    ],
  },
  websocket_cross_user_access: {
    title: "WebSocket Cross-User Access",
    summary: "قناة WebSocket تسمح لمستخدم بمشاهدة بيانات مستخدم آخر.",
    steps: [
      "اربط هوية الجلسة بالاتصال عند الـ upgrade وتحقق من التخويل لكل اشتراك/غرفة.",
      "لا تعتمد على معرّفات يرسلها العميل للانضمام لقنوات المستخدمين.",
      "سجّل الاشتراكات الحساسة واختبرها عبر حسابين مختلفين.",
    ],
  },
  websocket_message_reflection: {
    title: "WebSocket Message Reflection",
    summary: "الخادم يعيد بث الرسائل لمستلمين غير مقصودين.",
    steps: [
      "عنون الرسائل إلى مستلم محدد مع تحقق تخويل على كل رسالة.",
      "لا تكرر البث للقناة العامة دون فلترة.",
      "اختبر التدفق بحسابين متوازيين.",
    ],
  },
  websocket_origin_not_enforced: {
    title: "WebSocket Origin Not Enforced",
    summary: "الاتصال يُقبل من أي أصل (CSWSH).",
    steps: [
      "تحقق من رأس Origin عند الـ upgrade مقابل allowlist.",
      "أضف مصادقة مخصصة لقناة WS (توكن قصير العمر).",
      "أغلق الاتصالات غير المطابقة فورًا.",
    ],
  },
  websocket_sensitive_data_exposure: {
    title: "WebSocket Sensitive Data Exposure",
    summary: "بيانات حساسة تمر عبر القناة دون تقييد وصول.",
    steps: [
      "قلّل البيانات المرسلة إلى ما يحتاجه المستلم فقط.",
      "طبّق تخويلًا لكل نوع رسالة.",
      "استخدم TLS إلزامي للقناة (wss://).",
    ],
  },
};

export function remediationFor(type: string): Remediation {
  return (
    CATALOG[type] ?? {
      title: type,
      summary: "إرشاد عام من المنصة لهذا النوع من النتائج.",
      steps: [
        "راجع سلسلة الأدلة وتحقق من قابلية الاستغلال في سياقك.",
        "طبّق مبدأ التحقق من المدخلات والتخويل على مستوى الكائن لكل مسار متأثر.",
        "أضف اختبار انحدار آلي لهذه الثغرة بعد المعالجة (أعد الفحص للتأكد).",
      ],
    }
  );
}
