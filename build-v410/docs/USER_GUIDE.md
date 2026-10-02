# دليل مستخدم SENTINEL v4.0.0

من "فحص صفحة والعثور على ثغرة" إلى "فهم التطبيق كاملًا ثم إثبات الأثر".

## الفكرة في سطر واحد

SENTINEL يبني **توأمًا رقميًا أمنيًا** للتطبيق (هويات، أدوار، أسطح، معاملات،
كيانات، حالات، سير عمل) ثم يولّد **فرضيات هجوم** ويختبرها — ولا يُصدر أي Finding
إلا بإثبات قابل لإعادة الإنتاج.

## دورة العمل الكاملة

```
Install → Doctor → Configure target → Authentication → Scan
       → Review findings → Open evidence → Reproduce → Export SARIF
```

### 1) فحص الجاهزية
```bash
python3 sentinel/cli.py doctor
```

### 2) فحص مجهول (أسرع بداية)
```bash
python3 sentinel/cli.py scan https://target.example/ \
  --db results/target.db --out results/scan.json
```
- `--db` يحفظ كل شيء (يعمل على قواعد بيانات متعددة عبر الزمن).
- `--out` يصدّر تقرير JSON للفحص.

### 3) فحص مُصادَق (نموذج دخول)
```bash
python3 sentinel/cli.py scan https://target.example/ \
  --auth-user USER --auth-pass 'PASS' \
  --auth-url https://target.example/login \
  --auth-user-field username --auth-pass-field password \
  --db results/target.db --out results/scan.json
```
- يبدأ ENGINE الجلسة قبل الاكتشاف فتصبح صفحات ما بعد الدخول ضمن السطح.
- جلسة مفقودة أثناء الفحص؟ يكتشفها الـwatchdog ويعيد الدخول تلقائيًا (تحتاج
  تكرار الدخول الحقيقي؟ راقب `stats.auth`).

### 4) فحص مُصادَق (Token/JWT على REST APIs)
```bash
TOKEN=$(curl -s -X POST https://api.example/login -d '{...}' | jq -r .token)
python3 sentinel/cli.py scan https://api.example/ \
  --auth-token "$TOKEN" --auth-header Authorization --auth-scheme Bearer \
  --auth-validate-url https://api.example/whoami \
  --db results/api.db --out results/api.json
```

### 5) تفويض متعدد المستخدمين (IDOR/BOLA + مصفوفة الأدوار)
جهّز ملف حسابات (انظر `benchmarks/authz_accounts.json` كمثال):
```json
{"login_url": "/login", "user_field": "uid", "pass_field": "passw",
 "accounts": [
   {"name": "admin", "role": "admin", "username": "a", "password": "x",
    "marker": "admin@target", "object_id": "1001"},
   {"name": "bob",   "role": "user",  "username": "b", "password": "y",
    "marker": "bob@target",   "object_id": "2002"}]}
```
```bash
python3 sentinel/cli.py scan https://target.example/ \
  --auth-user a --auth-pass x --auth-url .../login \
  --authz-accounts accounts.json \
  --db results/target.db --out results/scan.json
```
الناتج: مصفوفة دور × نقطة نهاية + كشف IDOR/التصعيد الرأسي — بلا أي Finding
بلا دليل ملكية.

### 6) سير العمل ومنطق الأعمال (الوضع النشط)
```bash
# تعلم فقط (آمن دائمًا — الوضع الموصى به للأهداف الحية):
python3 sentinel/cli.py scan ... --workflow

# بطارية الهجوم الثمانية (تغيّر حالة التطبيق — يتطلب تصريحًا صريحًا):
python3 sentinel/cli.py scan ... --workflow --logic-active
```
`--logic-active` يفعّل: تخطي خطوة، إعادة ترتيب، تكرار/إعادة إرسال، تغيير قيمة،
عبور مستخدم، عبور كائن، عبور حالة، تجاوز صلاحية — وكلها لا تُثبت إلا عبر
"عدّالة حالة" (state oracle) يقرأها المحرك من التطبيق نفسه.

### 7) مراجعة النتائج
```bash
python3 sentinel/cli.py findings --db results/target.db          # كل النتائج
python3 sentinel/cli.py twin --db results/target.db --full      # التوأم الرقمي
```

### 8) فتح إثبات finding واحد وإعادة إنتاجه
```bash
python3 sentinel/cli.py reproduce --finding F-a93c789266 --db results/target.db
```
يُصدّر ملف الإثبات الكامل: الفرضية، الشروط المسبقة، الطلبات، الاستجابات،
الحالة قبل/بعد، الأثر، التحقق، وصفة إعادة الإنتاج خطوة بخطوة، ودرجة الثقة.

### 9) التقارير والتصدير
```bash
python3 sentinel/cli.py report --db results/target.db --format html       --out r.html
python3 sentinel/cli.py report --db results/target.db --format executive  --out exec.json
python3 sentinel/cli.py report --db results/target.db --format glass      --out glass.html   # عربي RTL
python3 sentinel/cli.py report --db results/target.db --format sarif      --out r.sarif
python3 sentinel/cli.py report --db results/target.db --format sarif --ci --out r.sarif      # بوابـة CI
```
- `--ci` يُرجع exit 1 عند وجود نتائج critical/high — اربطه مباشرة بخط CI/CD.

### 10) واجهة REST + لوحة الويب
```bash
python3 sentinel/cli.py serve --host 127.0.0.1 --port 8899 --db results/target.db
# من خارج الجهاز (إلزامي التوكن):
python3 sentinel/cli.py serve --host 0.0.0.0 --token 'SECRET' --db results/target.db
```
المسارات: `/api/health` · `/api/scans` (POST) · `/api/scans/{id}` · `/api/runs` ·
`/api/runs/{id}` · `/api/runs/{id}/sarif` · `/api/findings` · `/api/stats` — وكلها
تتطلب `X-Auth-Token` عند تمرير `--token`.

### 11) خزنة بيانات الاعتماد (Vault)
```bash
python3 sentinel/cli.py vault keygen --out owner.key
python3 sentinel/cli.py vault init --vault secrets.vault --key-file owner.key --org 'شركتك'
python3 sentinel/cli.py scan ... --vault secrets.vault --vault-key-file owner.key
python3 sentinel/cli.py vault list   --vault secrets.vault --key-file owner.key  # أقنعة فقط
python3 sentinel/cli.py vault report --vault secrets.vault --key-file owner.key  # كشف كامل للمالك (مُدقَّق)
python3 sentinel/cli.py vault purge  --vault secrets.vault --key-file owner.key --all
```
القيم الخام لا تظهر أبدًا في أي تقرير أو قاعدة بيانات — فقط داخل الخزنة المشفرة
(ChaCha20 + HMAC)، والكشف الكامل للمالك فقط ويسجَّل في سجل تدقيق مشفر.

## كيف أقرأ النتائج؟

- **Finding مُثبت (verified)**: تجاوز تحققًا مستقلًا (إعادة إرسال / عدّالة /
  تفاضل). كل الأرقام قابلة للتدقيق من الإثبات.
- **مرشح مرفوض (rejected candidate)**: اقترحه كاشف ثم كذّبه التحقق — يظهر في
  التقارير ضمن "audit trail" لأن الشفافية تشمل الإخفاقات.
- **تغطية <100%**: يعرض التقرير كل نقطة نهاية لم تُختبر وسبب ذلك — لا ادعاء
  كاذب بالاكتمال أبدًا.
- **OAST**: تفاعلات خارجة النطاق تُنسب للطلب الذي حمل الحمولة فقط.

## القيم الأمنية الثلاثة (لا تُخالف أبدًا)

1. **لا Finding بلا إثبات أثر** — التخمين لا يتحول أبدًا إلى نتيجة.
2. **الأفعال المغيّرة للحالة خلف علم صريح** (`--logic-active`)، والمدمِّرة محجوبة دومًا.
3. **الأسرار لا تظهر خامًا** في أي مخرجات — أقنعة + خزنة مشفرة.
