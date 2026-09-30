# مرجع CLI و REST — SENTINEL v4.0.0

## أوامر سطر الأوامر

### `sentinel scan <target>`
| العلم | الوظيفة |
|---|---|
| `--allow-private` | السماح بالنطاقات الخاصة (أهداف مختبِر مصرّح بها فقط) |
| `--max-pages N` | سقف صفحات الزحف |
| `--timeout S` | مهلة كل طلب بالثواني |
| `--no-crawl` | تعطيل الزحف (استخدم مع `--openapi-spec`) |
| `--seed` | بذرة الحتمية (نفس البذرة + نفس الهدف = نفس الفحص) |
| `--db PATH` | قاعدة نتائج SQLite (تُنشأ/تُلحق تلقائيًا) |
| `--out PATH` | تقرير JSON للفحص |
| `--auth-user/--auth-pass` | بيانات الدخول (نموذج) |
| `--auth-url` | صفحة الدخول الحاملة للنموذج |
| `--auth-user-field/--auth-pass-field` | حقلا اسم المستخدم/كلمة المرور في النموذج |
| `--auth-success-marker` | نص يتوقع ظهوره بعد النجاح (بوابة صارمة اختيارية) |
| `--auth-token/--auth-header/--auth-scheme` | وضع Token (Bearer/JWT/API-key) |
| `--auth-validate-url` | عنوان يُجلب بالتوكن لإثبات أنه يفتح بابًا مغلقًا |
| `--authz-accounts FILE` | ملف الحسابات المتعددة → محرك التفويض الكامل |
| `--openapi-spec PATH/URL` | مواصفة OpenAPI/Swagger لتزريع السطح (DISC-13) |
| `--no-openapi` | تعطيل استكشاف مستندات المواصفات تلقائيًا |
| `--workflow` | تعلم سير العمل (وضع آمن) |
| `--logic-active` | تفعيل بطارية الهجوم الثمانية (تحذير صريح + تصريح) |
| `--oast {auto,local,public}` | قناة التأكيد الخارج للنطاق |
| `--no-oast` | تعطيل OAST كليًا |
| `--no-browser` / (افتراضي: مفعّل) | محرك المتصفح/DOM |
| `--vault PATH --vault-key-file KEY` | تسليح خزنة بيانات الاعتماد أثناء الفحص |
| `--no-secrets` | تعطيل مسح كشف بيانات الاعتماد |

### `sentinel doctor`
15 فحصًا: runtime/dns/egress/tls/scope/detectors/strategy/sqlite/repair/browser/auth/oast/intelligence/vault/workflow.

### `sentinel findings --db`
عرض النتائج عبر الفحوصات (فلاتر: run/type/risk/status).

### `sentinel report --db --format …`
| الصيغة | الاستخدام |
|---|---|
| `html` | التقرير التقني (ذاتي الاكتفاء: تغطية، سطح غير مختبر، نتائج بمعرفات، إعادة إنتاج، مرشحون مرفوضون) |
| `executive` | JSON للإدارة: وضع الخطر، الأثر التجاري، أصول متأثرة، بوابة CI |
| `glass` | لوحة عربية RTL بأسلوب الزجاج (iOS-style) |
| `sarif` | SARIF 2.1.0 لرفع GitHub code scanning |
| `--ci` | exit 1 عند وجود critical/high (سياسة البوابة) |

### `sentinel twin --db [--full]`
التوأم الرقمي: العقد/الحواف بأنواعها + الإسقاطات (مصفوفة التفويض، جرد الكيانات).

### `sentinel reproduce --finding F-xxxx --db`
ملف الإثبات الكامل لنتيجة واحدة + وصفة إعادة الإنتاج.

### `sentinel serve --host --port --db [--token]`
REST + لوحة الويب. **ربط غير loopback يتطلب `--token` إلزاميًا.**

### `sentinel vault …`
`keygen --out` · `init --vault --key-file --org` · `status` · `list` · `report`
· `export --record` · `audit` · `authorize --new-key` · `revoke --key-id`
· `purge [--all]`.

### `sentinel benchmark`
مسح الـfixture المرفق ومقابلته بـ Ground Truth (73 صفًا) — نفس الأمر الذي
يُنتج أرقام الجودة في كل إصدار.

### `sentinel repair-demo`
عرض قواعد الإصلاح الذاتي (self-repair ops rules) عمليًا.

## واجهة REST

كل المسارات تحتاج `X-Auth-Token: <token>` إذا شُغّل الخادم بـ `--token`:

| المسار | الطريقة | الوظيفة |
|---|---|---|
| `/api/health` | GET | حالة الخدمة + عدد الفحوصات الجارية |
| `/api/scans` | POST | إطلاق فحص (JSON: target/allow_private/max_pages/timeout/seed) → 202 + run_id |
| `/api/scans/{id}` | GET | حالة فحص حي |
| `/api/runs[?limit]` | GET | سجل الفحوصات |
| `/api/runs/{id}` | GET | فحص واحد بكل إحصاءاته |
| `/api/runs/{id}/sarif` | GET | SARIF لفحص واحد |
| `/api/findings[?run_id&type&min_risk&status&limit]` | GET | نتائج مفلترة |
| `/api/stats` | GET | ملخص شامل + recurring + latest_delta |

## رموز الخروج

| الرمز | المعنى |
|---|---|
| 0 | اكتمال العملية |
| 1 | فشل بوابة CI (وجود critical/high مع `--ci`) أو خطأ تشغيلي |
| 2 | خطأ في الوسائط/المدخلات |
