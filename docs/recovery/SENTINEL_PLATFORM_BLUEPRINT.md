# SENTINEL PLATFORM — مخطط التحوّل من محرك إلى منتج
**الوثيقة:** BLUEPRINT v1.0 (P0 Spec) — أساس مرحلة المنتج
**التاريخ:** 2026-10-01
**الحالة:** مسودة بانتظار تصديق المنسّق (7 قرارات مفصلية في القسم 13)
**المرجعية:** تقييم المنسّق الاستراتيجي (7 محاور) + حالة v4.1.1 + شجرة v4.1.0 المغلقة على القرص

---

## 0. القرار الاستراتيجي — لماذا المنتج الآن، ولماذا ليس محركات جديدة

**القرار مُصادَق عليه من المنسّق:** المحرك وصل إلى مرحلة "لا ينقصه شيء أساسي للبيع ضمن نطاقه الموثق". الفجوة القائمة ليست فجوة محرك، بل فجوة **مُنتَج**: Dashboard، Cloud/SaaS، Multi-tenant، تجربة عميل، Deployment.

هذا التقرير يُحوّل ذلك القرار إلى مواصفة قابلة للبناء ببوابات قبول قابلة للفحص — بنفس منهجية بوابات v4.x (لا إغلاق مرحلة قبل استيفاء بواباتها).

### 0.1 الخندق التنافسي الذي يجب أن يحميه المنتج (وليس أن يخفيه)

معظم الماسحات التجارية تبيع **ضجيجًا**: قوائم نتائج بطول آلاف بدون إثبات. ما بَنَاه SENTINEL خلال v2.x–v4.1 هو العكس تمامًا:

| ما يمتلكه SENTINEL اليوم (مُثبَت بالبوابات) | ما يعنيه تجاريًا |
|---|---|
| كل finding حالة `verified` فقط مع evidence + replay قابل لإعادة الإنتاج | صفر إجهاد False-Positive للمراجع — أعلى شكوى مشتري أدوات DAST |
| بوابة No-Hallucination + سجلات `UNTESTABLE / NOT_SUPPORTED / BLOCKED` مع سبب لكل حد | تقرير أمان يُصدَّقه المدقق — يمكن الدفاع عنه أمام إدارة/عميل/جهة تفتيش |
| Proof Engine v2 (state_before/after) + verification rounds + confidence | "كيف أثبتّموه؟" لها إجابة آلية مُوثَّقة لكل نتيجة |
| Coverage 2.0 + Boundary Model | "ما الذي لم تختبروه ولماذا؟" — سؤال لا يجرؤ المنافس على عرضه |
| استراتيجية Wilson LB + ذاكرة فشل + repair | التحسن عبر الفحوصات المتكررة دون تدخل |

**القاعدة التصميمية رقم 1 للمنتج (غير قابلة للتفاوض):**
> طبقة العرض في المنصة **مُصيِّر (Renderer) خالص لمخرجات المحرك**. يحظر على أي شاشة أو تقرير أو إحصائية أن تُولِّد أو تُعدِّل أو "تجمّل" أي ادعاء أمني غير صادر من المحرك. انتهاك هذه القاعدة في أي PR = رفض بنيوي.

هذه القاعدة تنقل بوابة No-Hallucination من المحرك إلى المنتج كله — وهي رسالة البيع المركزية: **"كل ادعاء مربوط بدليله، وكل فجوة ظاهرة بشفافية"**.

### 0.2 لماذا لا محركات جديدة الآن (تأكيد تحليل المنسّق)

- قيمة المحرك الإضافية لكل أسبوع تطوير إضافي الآن **متناقصة حدّيًا** (تغطية المصفوفة أُغلقت على 4 أهداف حية + أهداف تدريبية).
- قيمة المنتج لكل أسبوع تطوير **صاعدة حادّة**: المحرك قوي لكن غير قابل للشراء من فريق غير تقني اليوم.
- الاستثناء الوحيد المعتمد: **أتمتة WebSocket Cross-User** (القسم 10) — لأنها فجوة في مصفوفة ادعاء قائمة (`authz` عبر WS)، لا محركًا جديدًا.

---

## 0.3 حالة البيئة الحالية — شفافية كاملة قبل البدء

فحص قرص بيئة البناء (`/home/z/my-project/`) يعطي الصورة التالية:

| العنصر | الحالة على القرص |
|---|---|
| شجرة `build-v410/` (المحرك v4.1.0) | ✅ موجودة كاملة: 30+ وحدة (graphql.py 596 سطر، websocket.py 534 سطر، boundary، reasoning، twin، memory، coverage، oast، vault، proof engine) + fixtures + tests + 19 مستندًا |
| أدلة الإغلاق v4.1.0 | ✅ موجودة: 97/97 اختبار، doctor 15/15، Benchmark F1=1.000 ×3، 4 أهداف حية، الحزم في `download/` |
| عمل جلسة v4.1.1 (DVGA GraphQL + DVWS WebSocket) | ⚠️ **غير محفوظ على هذا القرص** — لا يوجد `build-v411/` ولا دليل DVGA/DVWS، والكود لا يحوي مستخرج `wsUri` ولا بوابة المنفذ، وسجل العمل ينتهي عند إغلاق v4.1.0 |

**التبعات:** وفق رواية الجلسة السابقة (التي شهدتَها): DVGA/GraphQL اكتمل بـ26 نتيجة مؤكدة، وCross-user على DVWS أُثبت **يدويًا**. هذه النتائج صحيحة كدليل witnessed، لكنها غير قابلة لإعادة الإنتاج من هذا القرص — وهذا يخالف معيار الإثبات القابل لإعادة الإنتاج الذي بُني عليه المشروع كله.

**المطلوب قبل التفرع إلى v5 (بوابة P0-0):**
1. **الخيار الموصى به:** رفع شجرة v4.1.1 الكاملة (كود + أدلة DVGA/DVWS) من بيئتك إلى `upload/` → أدمجها وأعيد تشغيل البوابات المختصرة (اختبارات + doctor + benchmark ×1) للتحقق من التكامل.
2. الخيار البديل: إعادة تطبيق فروق v4.1.1 (مستخرج `wsUri` + بوابة المضيف-مع-المنفذ) على شجرة v4.1.0 هنا وإعادة بوابات 15 خطوة كاملة على DVGA/DVWS — أبطأ لكنه يعيد كل شيء إلى حالة موثقة ذاتيًا.

> **القاعدة:** لا يبدأ بناء المنتج فوق نسخة غير موثقة. المنصة ستستدعي المحرك كمكتبة — أي انحراف نسخة سينتقل إلى كل فحص عميل.

---

## 1. نقطة الانطلاق الحقيقية — ماذا يوجد لدينا فعلًا (ولا يحتاج بناءً من الصفر)

فحص الكود أظهر أن **نواة طبقة المنتج موجودة مسبقًا** في v4.1.0 — وهذه نقطة انطلاق أقوى بكثير مما في تقييم "يحتاج بناء":

| مكوّن قائم | ما يقدمه للمنصة | جاهزيته |
|---|---|---|
| `api.py` (319 سطر، stdlib) | خادم HTTP + **لوحة تحكم HTML أولية** + 7 نقاط نهاية: `health`, `runs`, `runs/{id}`, `findings` (فلترة cross-run), `stats`, `POST /scans` (202 + خيط خلفي), `scans/{id}` + مصادقة token/loopback | البذرة الصحيحة — تُطوَّر إلى Platform API v2 |
| `orchestrator.py` (1293 سطر) | دورة فحص كاملة قابلة للاستدعاء كمكتبة: `launch_scan(store, target, max_pages, allow_private, timeout, seed, strategy_path, oast)` | ✅ جاهز — المنصة تستدعيه مباشرة، بلا subprocess |
| `core.py` | `EventBus` (تيار أحداث مُهيكل للبث الحي) + نموذج Finding غني (`evidence[]`, `verification{method,rounds,confidence}`, `authz_context`, `state_before/after`, fingerprint للمقارنة بين الفحوصات) | ✅ جاهز |
| `store.py` + `stats` | حفظ runs/findings + **إحصائيات recurring + latest delta** (أساس شاشة "ما الجديد منذ الفحص السابق؟") | ✅ جاهز |
| `report.py` | تقارير HTML / SARIF / executive JSON / تقرير عربي PDF — المنصة تكتفي بتخزينها وربطها بالتنزيل | ✅ جاهز |
| `vault.py` | خزنة بيانات اعتماد مشفّرة + سجل تدقيق استخدام — أساس Credential Management للمنصة | ✅ جاهز (يُغلَّف بـ envelope encryption) |
| `cli.py` | `scan / benchmark / doctor / repair-demo` — يبقى واجهة CI/خبراء، والمنصة توازيه للعملاء | ✅ جاهز |
| `fixtures/vulnapp.py, ws_app.py, gql_app.py` | أهداف اختبار مدمجة = بيئة Demo فورية للمنصة نفسها (تجربة "من GitHub إلى أول finding في 5 دقائق") | ✅ جاهز |

**الاستنتاج الهندسي:** المنتج ليس مشروعًا أخضر؛ هو **طابقٌ ثانٍ فوق أساس مسلَّح**: نُضيف طبقة `platform/` (Auth/Orgs/Queue/Streaming/API v2/UI) تستدعي المحرك كمكتبة عبر `launch_scan` — والمحرك نفسه **لا يُمَسّ** (يبقى stdlib بنفس بواباته).

---

## 2. المعمارية المستهدفة

### 2.1 مبدأ الفصل الصارم (Engine ≠ Platform)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SENTINEL PLATFORM (جديد)                     │
│  تبعيات مسموحة: FastAPI, SQLAlchemy, Alembic, uvicorn, argon2-cffi  │
│                                                                     │
│  ┌───────────────┐   ┌──────────────┐   ┌─────────────────────────┐ │
│  │  api (uvicorn) │   │ worker ×N    │   │ web UI (SPA مُجمَّعة)   │ │
│  │  REST v2 + SSE │←──┤ استدعاء      │   │ يُخدَم كملفات ثابتة     │ │
│  │  JWT/API-keys  │DB │ launch_scan() │   │ من نفس حاوية api       │ │
│  └───────┬───────┘   └──────┬───────┘   └─────────────────────────┘ │
│          │      Postgres (+RLS) + queue-as-table                    │
└──────────┼──────────────────────────────────────────────────────────┘
           │  استيراد مكتبة (نفس العملية في worker) — بلا subprocess
┌──────────▼──────────────────────────────────────────────────────────┐
│                     SENTINEL ENGINE v4.1.x (كما هو)                 │
│  pure-stdlib، بواباته (tests/doctor/benchmark/no-hallucination)     │
│  لا يتغير أي سطر فيه إلا عبر بواباته الخاصة                         │
└─────────────────────────────────────────────────────────────────────┘
```

**لماذا هذا الفصل؟**
- المحرك أثبت قابلية نشر بصفر تبعيات (ميزة CI والعملاء التقنيين) — يجب ألا تُكسر بتبعيات المنصة.
- المنصة تحتاج بالضرورة إطار ويب حقيقي، ترحيلات مخطط، تجميع اتصالات، وتشفير كلمات مرور بمعايير حديثة — كتابتها stdlib يدويًا = إطار عمل مُرتجل غير قابل للتدقيق أمنيًا، وهذا عكس ثقافة المشروع.
- عزل الفشل: ترقية المنصة لا تُعيد اختبار المحرك، وترقية المحرك لا تلمس المنصة إلا عبر عقد API داخلي مُوثَّق.

### 2.2 الطوبولوجيا حسب المراحل

| المرحلة | الطوبولوجيا | ملاحظات |
|---|---|---|
| **P1 (MVP)** | حاوية `api+ui` + حاوية `worker` + `Postgres` — docker-compose واحد | صندوق واحد يخدم عميلًا واحدًا أو عدة مؤسسات؛ queue داخل Postgres (جدول + `SELECT … FOR UPDATE SKIP LOCKED`) — **بلا Redis** |
| **P2** | `worker ×N` + مجدول + quotas | نفس compose؛ التوسع أفقيًا بزيادة نسخ worker |
| **P3 (SaaS)** | + Redis، + K8s (Helm)، + autoscale للـ workers، + Prometheus/Grafana، + S3-مثل للتخزين | عندها فقط تُضاف التعقيدات السحابية |

**قرار مفصلي #5 (قسم 13):** queue-as-table في P1/P2 بدل Redis — أقل قطعة متحركة، ويكفي حتى عشرات الفحوصات المتزامنة، مع مسار ترقية موثّق إلى Redis دون تغيير عقد المنصة.

### 2.3 البث الحي لتقدّم الفحص: SSE (وليس WebSocket)

- `EventBus` في المحرك يُنتج أحداثًا مُهيكلة أصلًا → الـ worker يكتبها إلى `scan_events` → `GET /api/v2/scans/{id}/events` يبثها **SSE**.
- لماذا SSE وليس WebSocket لمنصة SENTINEL نفسها؟ اتجاه واحد (سيرفر→متصفح)، يعمل عبر كل الـ proxies/CDNs بلا ترقية بروتوكول، إعادة اتصال تلقائية مدمجة في المتصفح، و`Last-Event-ID` يعطي استئنافًا بعد انقطاع مجانًا. المحرك يبقى سيد WebSocket — لفحص الأهداف، لا لخدمة لوحة التحكم.
- احتياط التصيّر: نفس الأحداث متاحة polling عبر `GET /scans/{id}` (نمط v1 الحالي) للأدوات التي لا تدعم SSE.

---

## 3. نموذج البيانات (PostgreSQL — كامل، جاهز للترحيل بـ Alembic)

> الهرم: `Org → Project → Target → Scan → Finding` + هوية/صلاحيات/أتمتة/تدقيق. الحقول القادمة من المحرك تُستورد كما هي (قاعدة المُصيِّر الخالص)؛ حقول المنصة (triage، التعيين…) منفصلة بوضوح.

```sql
-- الهوية والمؤسسات ---------------------------------------------------
CREATE TABLE users (
  id              UUID PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,              -- argon2id
  name            TEXT NOT NULL DEFAULT '',
  is_platform_admin BOOLEAN NOT NULL DEFAULT false,
  totp_secret     TEXT,                       -- P2 (2FA)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at   TIMESTAMPTZ
);

CREATE TABLE orgs (
  id          UUID PRIMARY KEY,
  name        TEXT NOT NULL,
  slug        TEXT UNIQUE NOT NULL,
  plan        TEXT NOT NULL DEFAULT 'free',   -- free | pro | enterprise (P3)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_members (
  org_id      UUID NOT NULL REFERENCES orgs(id)    ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('owner','admin','analyst','viewer')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

-- الأصول -------------------------------------------------------------
CREATE TABLE projects (
  id          UUID PRIMARY KEY,
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE targets (
  id            UUID PRIMARY KEY,
  project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  url           TEXT NOT NULL,
  -- إثبات التفويض (قسم 9): لا فحص بدون attestation موقّعة
  ownership_proof_kind TEXT,                  -- dns_token | meta_tag | manual_attest | local_lab
  ownership_verified_at TIMESTAMPTZ,
  attested_by  UUID REFERENCES users(id),
  scope_config JSONB NOT NULL DEFAULT '{}',   -- يُترجم إلى ScopeRule المحرك (allowed_hosts, denied_paths, allow_private…)
  last_scanned_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- بيانات الاعتماد (تُبنى فوق vault.py) ---------------------------------
CREATE TABLE credentials (
  id          UUID PRIMARY KEY,
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  target_id   UUID REFERENCES targets(id) ON DELETE CASCADE,   -- NULL = مشترك
  label       TEXT NOT NULL,                  -- "user-a (victim)" / "admin" / "ws-attacker-b"
  kind        TEXT NOT NULL,                  -- form_login | http_basic | bearer | api_key | ws_cookie | ws_subprotocol | ws_first_message | ws_query_token
  role_hint   TEXT,                           -- victim | attacker | admin | anonymous (لتغذية أزواج cross-user)
  ciphertext  BYTEA NOT NULL,                 -- envelope-encrypted JSON (بيانات الاعتماد الخام لا تُعاد أبدًا عبر API)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- الفحوص ---------------------------------------------------------------
CREATE TABLE scans (
  id            UUID PRIMARY KEY,
  target_id     UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  project_id    UUID NOT NULL,
  org_id        UUID NOT NULL,
  status        TEXT NOT NULL CHECK (status IN
                  ('draft','queued','running','analyzing','completed','failed','cancelled','timeout')),
  config        JSONB NOT NULL,               -- {max_pages, timeout, seed, profiles, credential_refs[], allow_private:false…}
  engine_run_id TEXT,                         -- "run-xxxx" من المحرك (الربط التشغيلي)
  engine_version TEXT,
  triggered_by  UUID REFERENCES users(id),
  trigger       TEXT NOT NULL DEFAULT 'manual', -- manual | scheduled | api | ci
  progress_pct  INT NOT NULL DEFAULT 0,
  current_phase TEXT,
  error         TEXT,
  started_at    TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_events (                    -- البث الحي + السجل التشغيلي
  id      BIGSERIAL PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  t       TIMESTAMPTZ NOT NULL,
  kind    TEXT NOT NULL,                      -- phase | progress | finding | log | warning | cancelled
  data    JSONB NOT NULL
);
CREATE INDEX ix_scan_events_scan ON scan_events (scan_id, id);

-- النتائج: استيراد حرفي من مخرجات المحرك + حالة مراجعة من المنصة ---------
CREATE TABLE findings (
  id            UUID PRIMARY KEY,
  scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  org_id        UUID NOT NULL, project_id UUID NOT NULL, target_id UUID NOT NULL,   -- denormalized للفلترة وRLS
  engine_finding_id TEXT NOT NULL,             -- "F-xxxx"
  fingerprint   TEXT NOT NULL,                 -- بصمة المحرك = مفتاح التتبع بين الفحوصات (new/regression/fixed)
  type          TEXT NOT NULL, severity TEXT NOT NULL,
  url TEXT, method TEXT, parameter TEXT,
  confidence    REAL,
  verification  JSONB,                         -- {method, passed, rounds, confidence, notes}
  evidence      JSONB,                         -- [{kind, detail}] كما أصدرها المحرك
  authz_context TEXT, state_before TEXT, state_after TEXT,
  raw           JSONB NOT NULL,                -- finding.to_dict() كاملة — مصدر العرض الوحيد (قاعدة المُصيِّر)
  first_seen_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ,
  -- حالة المراجعة (من المنصة؛ لا تمس مخرجات المحرك):
  triage_status TEXT NOT NULL DEFAULT 'open'
                CHECK (triage_status IN ('open','in_review','accepted_risk','false_positive','fixed')),
  assigned_to   UUID REFERENCES users(id),
  notes         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_findings_org_sev  ON findings (org_id, severity);
CREATE INDEX ix_findings_fp       ON findings (org_id, fingerprint, last_seen_at DESC);

-- التقارير والأتمتة والتدقيق -------------------------------------------
CREATE TABLE reports (
  id UUID PRIMARY KEY,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  org_id UUID NOT NULL,
  kind TEXT NOT NULL,                          -- html | sarif | executive | pdf_ar
  storage_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,                    -- "sk_a1b2" للعرض في القائمة
  key_hash TEXT NOT NULL,                      -- sha256 للمفتاح الكامل
  scopes TEXT[] NOT NULL DEFAULT '{scans:read,findings:read}',
  last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhooks (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  url TEXT NOT NULL, secret TEXT NOT NULL,     -- توقيع HMAC للحمولة
  events TEXT[] NOT NULL,                      -- {scan.completed, finding.verified, …}
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE webhook_deliveries (
  id BIGSERIAL PRIMARY KEY,
  webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event TEXT NOT NULL, payload JSONB NOT NULL,
  status TEXT NOT NULL,                        -- pending | delivered | failed
  attempts INT NOT NULL DEFAULT 0, next_retry_at TIMESTAMPTZ,
  response_code INT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (                       -- append-only (انظر 4.2)
  id BIGSERIAL PRIMARY KEY,
  org_id UUID, actor UUID, actor_kind TEXT NOT NULL DEFAULT 'user', -- user | api_key | system | worker
  action TEXT NOT NULL,                        -- member.invited, target.created, scan.started, credential.used, finding.triaged…
  object_type TEXT, object_id TEXT,
  ip TEXT, user_agent TEXT, data JSONB,
  t TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE quotas (
  org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  max_concurrent_scans INT NOT NULL DEFAULT 1,
  max_scans_per_month  INT NOT NULL DEFAULT 10,
  max_targets          INT NOT NULL DEFAULT 3,
  retention_days       INT NOT NULL DEFAULT 90
);

CREATE TABLE schedules (                       -- P2: الفحص الدوري
  id UUID PRIMARY KEY,
  target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  org_id UUID NOT NULL,
  cron TEXT NOT NULL,                          -- cron بالتوقيت المحلي للمؤسسة
  config JSONB NOT NULL,
  next_run_at TIMESTAMPTZ, last_run_id UUID,
  active BOOLEAN NOT NULL DEFAULT true
);
```

**قرارات مقصودة في هذا المخطط:**
- `findings.raw` يحمل `to_dict()` الكاملة: العرض يقرأ منه حصريًا → إضافة حقول محرك مستقبلًا لا تكسر الواجهة (المُصيِّر يعرض ما يعرفه ويتجاهل ما لا يعرفه بأمان).
- `fingerprint` من المحرك = أساس شاشة **Delta بين الفحوصات** (جديد/متكرر/أُصلح) بلا منطق مطابقة مُعاد اختراعه.
- `scan_events` تخدم SSE والسجل التشغيلي معًا — مصدر حقيقة واحد.
- لا يوجد أي جدول يسمح للمنصة بـ"تحسين" نتيجة: حقول المحرك للقراءة فقط بعد الاستيراد، وtriage منفصل تمامًا.

---

## 4. تعدد المستأجرين والعزل (Multi-tenancy)

### 4.1 النموذج: قاعدة مشتركة + `org_id` + **RLS كخط دفاع ثانٍ إلزامي**

```sql
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON findings
  USING (org_id = current_setting('app.org_id')::uuid);
-- نفس السياسة على: projects, targets, scans, scan_events, credentials, api_keys, webhooks, reports, schedules
```

- **الخط الأول:** كل استعلام API يُقيَّد بـ `org_id` من الجلسة/المفتاح (لا يصل SQL إلى قاعدة البيانات أبدًا بلا org سياق).
- **الخط الثاني:** RLS في Postgres نفسه — حتى لو تسلل استعلام بلا قيد، الصفوف الأخرى غير مرئية.
- **الخط الثالث:** مفاتيح الحاويات/التخزين مسارية (مسارات prefixes بـ org_id) بحيث لا يصل تقرير مؤسسة إلى مؤسسة أخرى عبر الرابط.

**لماذا مشترك-DB وليس schema-per-tenant؟** عند نطاق عشرات→مئات المؤسسات: الترحيلات الجماعية (alembic واحد)، النسخ الاحتياطي الموحد، ومراقبة واحدة. schema-per-tenant يُعاد تقييمه في P3 فقط إن طلب عميل Enterprise عزلًا تنظيميًا (عندها: خيار نشر مستقل له).

### 4.2 اختبار العزل كبوابة إصدار (وليس أمنية شفافة)

بوابة **P1-G4** (قسم 12): اختبارات آلية سالبة:
1. مستخدم Org-B يطلب `GET /api/v2/findings/{id-of-org-A}` → **404** (ليس 403 — لا تسريب وجود).
2. مفتاح API من Org-B يستعلم قائمة scans بـ filter يخص Org-A → صفر نتائج.
3. محاولة `POST /scans` على `target_id` تابع لـ Org-A → 404.
4. تسليم webhook مُوقَّع لا يمكن إعادة استخدامه عبر مؤسسة.
5. فحص كامل لقاعدة البيانات بعد التشغيل: لا سياسة RLS معطلة على أي جدول مستأجر.
6. **Dogfooding:** تشغيل محرك SENTINEL نفسه على API المنصة (وضع `allow_private` على lab) — وحدة authz تختبر BOLA عبر حدود org_id — المنتج يفحص نفسه بأدواته (يصبح هذا بندًا دائمًا في بوابات كل إصدار منصة).

---

## 5. RBAC — مصفوفة الصلاحيات (P1: owner+viewer فقط، الكامل في P2)

| الفعل | owner | admin | analyst | viewer |
|---|:---:|:---:|:---:|:---:|
| دعوة/إزالة أعضاء وتغيير أدوارهم | ✅ | ✅ | ❌ | ❌ |
| إنشاء/تعديل/حذف المشاريع والأهداف | ✅ | ✅ | ✅ | ❌ |
| إدارة بيانات الاعتماد (vault) | ✅ | ✅ | ✅ | ❌ |
| بدء/إيقاف الفحوصات | ✅ | ✅ | ✅ | ❌ |
| عرض النتائج والتقارير وتنزيلها | ✅ | ✅ | ✅ | ✅ |
| Triage النتائج (قبول مخاطرة/FP/إصلاح) + التعيين | ✅ | ✅ | ✅ | ❌ |
| إنشاء/إبطال API Keys وWebhooks | ✅ | ✅ | ❌ | ❌ |
| قراءة Audit Log | ✅ | ✅ | ❌ | ❌ |
| حذف المؤسسة / نقل الملكية / إدارة الخطة | ✅ | ❌ | ❌ | ❌ |

قواعد تنفيذية:
- التطبيق في **طبقة خدمة واحدة** (`platform/authz.py` — decorator يفحص `role × action × scope`) + اختبارات سالبة لكل خلية ❌ في المصفوفة (بوابة P2-G2). لا تفويض "مبعثر" داخل نقاط النهاية.
- `viewer` **لا يرى محتوى بيانات الاعتماد أبدًا** (ولا أي دور — القيم المشفرة تُستخدم داخليًا فقط؛ API يُرجع metadata فقط).
- آخر `owner` في مؤسسة لا يمكن تخفيضه/إزالته (حماية قفل ذاتي).

---

## 6. دورة حياة الفحص داخل المنصة

### 6.1 آلة الحالة

```
draft ──▶ queued ──▶ running ──▶ analyzing ──▶ completed
             │          │            │
             │          ▼            ▼
             └──────▶ cancelled ◀───┤
                        │           ▼
                        └──────▶ failed / timeout
```

| الانتقال | المُنفِّذ | شرط |
|---|---|---|
| draft→queued | api | تصديق التفويض على الهدف + quota متاح + اكتمال config |
| queued→running | worker | استئجار الصف (`FOR UPDATE SKIP LOCKED`) ثم استدعاء `launch_scan()` |
| running→analyzing | worker | انتهى الفحص → استيراد findings + توليد التقارير + حساب delta مقابل الفحص السابق |
| أي حالة→cancelled | api/worker | تعاوني: علم في الصف؛ المحرك يفحصه عند نقاط التوقف الطبيعية (بين endpoints) — لا يُقتل بالقوة إلا بعد مهلة أمان |
| analyzing→completed | worker | كتابة summary + إرسال webhook `scan.completed` |

**ملاحظة تشغيلية:** الإلغاء التعاوني يمر عبر نفس نقاط التوقف التي يستخدمها المحرك لبوابات scope — نفس نمط الأمان الذي أثبت نفسه على DVGA (`/start_over`): **لا تُنفَّذ خطوة مدمِّرة لمجرد أنها في الطريق؛ حتى الإيقاف يمر من بوابة**.

### 6.2 سير العمل داخل الـ worker

```python
# platform/worker.py — الاستدعاء كمكتبة (القرار: لا subprocess)
from sentinel import orchestrator, store as engine_store   # استيراد مباشر

def run_scan_job(scan_id):
    scan = load_scan(scan_id)                              # + تعيين org_id لجلسة RLS
    target_cfg = build_engine_config(scan)                 # config المنصة → معاملات launch_scan + ScopeRule
    creds   = vault.open_refs(scan.config["credential_refs"])   # فك تشفير عند الاستخدام فقط + سجل استخدام في audit
    events  = []
    def on_event(ev):                                      # جسر EventBus → scan_events (SSE)
        persist_event(scan_id, ev); maybe_update_progress(scan_id, ev)

    result = orchestrator.launch_scan(
        store=engine_store.Store(per_org_db_path(scan)),
        target=scan.target.url, max_pages=cfg.max_pages, timeout=cfg.timeout,
        seed=cfg.seed, strategy_path=..., allow_private=cfg.allow_private,   # false دائمًا إلا للمعاملات المعتمدة
        event_hook=on_event)                               # (نقطة تعديل وحيدة مطلوبة في المحرك: hook موجود أصلًا في EventBus)

    import_findings(scan, result)                          # استيراد حرفي + fingerprint → delta
    generate_reports(scan)                                 # html / sarif / executive / pdf_ar
    emit_webhook("scan.completed", summary(scan))
```

### 6.3 Quotas (P2) وحدود الموارد

- فحوصات متزامنة لكل org (افتراضي 1 في free) — الرفض بـ 429 مع `Retry-After`.
- فحوصات شهرية، أهداف، مدة احتفاظ (تنظيف مجدول للتقارير والـ findings القديمة مع إبقاء fingerprint-counts للتاريخ).
- حد زمني صلب لكل فحص من config (`timeout` الكلي) → حالة `timeout` مع حفظ ما تحقق (نتائج جزئية + سبب الإيقاف — لا نلغي ما أثبتناه).
- عزل موارد: worker pool مستقل لكل org في P3 (soft limit عبر semaphores)؛ الشبكة: خروج الفحص من worker عبر نطاق شبكي معزول (قسم 9.3).

---

## 7. واجهة API v2 (تبني فوق v1 الموجودة — v1 تبقى للـ CLI)

```
# الهوية ---------------------------------------------------------------
POST /api/v2/auth/register        # user + org افتراضية (owner) — لا تسجيل مفتوح في نشر المؤسسات (invite-only mode)
POST /api/v2/auth/login           # → {access(JWT 15m), refresh(7d)} + rate-limit + قفل تدريجي
POST /api/v2/auth/refresh
POST /api/v2/auth/logout
GET  /api/v2/me                   # المستخدم + مؤسساته وأدواره

# المؤسسات والأعضاء -----------------------------------------------------
GET  /api/v2/orgs
GET/PATCH /api/v2/orgs/{org}
GET/POST   /api/v2/orgs/{org}/members          # دعوة بالبريد (P2: رابط موقّع)
PATCH/DELETE /api/v2/orgs/{org}/members/{user} # تغيير دور / إزالة
GET  /api/v2/orgs/{org}/audit                  # owner/admin

# المشاريع والأهداف ------------------------------------------------------
GET/POST /api/v2/projects ; GET/PATCH/DELETE /api/v2/projects/{p}
GET/POST /api/v2/projects/{p}/targets
PATCH/DELETE /api/v2/targets/{t}
POST /api/v2/targets/{t}/verify-ownership      # dns_token | meta_tag → {verified: bool, method}

# بيانات الاعتماد --------------------------------------------------------
GET/POST /api/v2/orgs/{org}/credentials        # metadata فقط (label/kind/role_hint/timestamps)
PATCH/DELETE /api/v2/credentials/{c}           # PATCH يستبدل ciphertext — القيم لا تُقرأ أبدًا عبر API

# الفحوص ------------------------------------------------------------------
POST /api/v2/targets/{t}/scans                 # 202 {scan_id} — يفحص التفويض + quota قبل القبول
GET  /api/v2/scans?project&status&trigger&limit&cursor
GET  /api/v2/scans/{id}                        # status/progress/phase/summary/error
POST /api/v2/scans/{id}/cancel                 # idempotent
GET  /api/v2/scans/{id}/events                 # SSE (Last-Event-ID للاستئناف)
GET  /api/v2/scans/{id}/findings               # نتائج هذا الفحص + delta مقابل السابق (new/regression/fixed)
GET  /api/v2/scans/{id}/coverage               # تغطية ما اختُبر وما لم يُختبر ولماذا (من Coverage 2.0)

# النتائج (عبر الفحوصات) ---------------------------------------------------
GET  /api/v2/findings?severity&type&triage&assigned&search&cursor
GET  /api/v2/findings/{id}                     # كل الأدلة + replay + الحدود — جسم صفحة التفاصيل
PATCH /api/v2/findings/{id}                    # triage فقط: {triage_status, assigned_to, notes}

# التقارير -----------------------------------------------------------------
POST /api/v2/scans/{id}/reports                # {kind: html|sarif|executive|pdf_ar} → 202 {report_id}
GET  /api/v2/reports/{id}/download             # روابط موقعة قصيرة العمر

# الأتمتة ------------------------------------------------------------------
GET/POST /api/v2/orgs/{org}/api-keys ; DELETE /api/v2/api-keys/{k}
GET/POST /api/v2/orgs/{org}/webhooks ; PATCH/DELETE /api/v2/webhooks/{w}
GET  /api/v2/orgs/{org}/quotas                  # الاستخدام الحالي مقابل الحدود

# التشغيل ------------------------------------------------------------------
GET  /api/v2/admin/health                       # لعمليات النشر/healthchecks (لا يحتاج auth؛ بلا أي معلومات حساسة)
```

قواعد عامة: كل مسار (عدا auth/admin-health) يتطلب `Authorization: Bearer` أو `X-API-Key`؛ كل استجابة قائمة تستخدم cursor pagination؛ كل كائن يجمع `org_id` من السياق — **أبدًا من جسم الطلب** (منع tampering عبر الجسم).

---

## 8. تجربة المستخدم — الواجهة كمواصفة (الأسئلة السبعة جوهر المنتج)

### 8.1 الصفحات

| الصفحة | المحتوى الجوهري |
|---|---|
| Login / Register | بسيطة؛ P2: 2FA |
| Overview | بطاقات مؤسسات/مشاريع + مؤشرات: آخر فحص، نتائج مفتوحة حسب الخطورة، اتجاه أسبوعي (delta) |
| Project → Targets | جدول أهداف + حالة التفويض (⚠️ لا فحص قبل التحقق) + آخر فحص لكل هدف |
| New Scan (wizard من 3 خطوات) | اختيار الهدف → إعدادات (عمق/ملفات/بيانات اعتماد مرجعية) → **شاشة تصديق التفويض** → تشغيل |
| Scan Live | شريط طور + تيار أحداث SSE حي + findings تظهر لحظيًا مع شارة حالة كل واحدة + زر Cancel |
| Findings (قائمة) | فلاتر خطورة/نوع/حالة triage/بحث؛ أعمدة: خطورة، نوع، موقع، حالة التحقق، أول/آخر رصد، triage |
| **Finding Detail** | انظر 8.2 — قلب المنتج |
| Coverage & Boundaries | ما اختُبر، ما لم يُختبر ولماذا (UNTESTABLE/NOT_SUPPORTED/BLOCKED بأسبابها) — شاشة لا يملكها المنافس |
| Scan History | تاريخ الفحوص + مقارنة أي فحصين (delta عبر fingerprint) |
| Settings | أعضاء وأدوار، API Keys، Webhooks، بيانات اعتماد، quotas |

### 8.2 صفحة Finding Detail — تعبئة حرفية من مخرجات المحرك الحالية

مواصفة المنتج التي رسمها المنسّق ("وجدنا مشكلة BOLA عالية الخطورة…") تتحقق بعرض الحقول **الموجودة أصلًا** في `core.Finding` + مخرجات المحرك — بلا اختراع أي محتوى جديد:

| سؤال العميل | مصدره الحرفي في المحرك (اليوم) |
|---|---|
| **أين؟** | `url`, `method`, `parameter`, `authz_context` (أي ثنائية دور/ضحية أنتجت الدليل) |
| **لماذا هذه ثغرة؟** | `type` + شرح الصنف الثابت من كتالوج report.py + فرضية reasoning التي أنتجت الاختبار (hypotheses) + Boundary Model لماذا تجاوز الطلب الحد المسموح |
| **كيف أثبتها SENTINEL؟** | `verification {method, passed, rounds, confidence, notes}` + قائمة `evidence[]` (kind → شرح) + للفئات ذات الحالة: `state_before`/`state_after` (Proof Engine v2) |
| **ما الطلب الذي أعاد إنتاجها؟** | Proof/replay من ملف الإثبات → زر "نسخ كـ cURL" + عرض HTTP خام + زر "إعادة التشغيل" (replay مراقب داخل نطاق scope فقط) |
| **ما التأثير؟** | `severity` + نص الأثر لكل صنف (من نفس مصدر التقارير التنفيذية) + ما تمكن منه فعليًا (الإثبات يصف الأثر المُلاحَظ لا النظري) |
| **كيف أصلحها؟** | توصية الإصلاح لكل صنف (نفس مصدر report.py) + إرشاد التحقق بعد الإصلاح (إعادة فحص موجه) |
| **ما الذي لم نستطع اختباره؟** | ربط لشاشة Coverage: الفجوات التي تخص هذا الـ endpoint/الصنف بأسبابها + حدود معروفة ذات صلة — **ميزة بيع لا عيبًا يجب إخفاءه** |

عناصر إضافية: شريط ثقة (confidence)، سجل أول/آخر رصد، حالة triage + التعيين + التعليقات (من حقول المنصة)، و"سلسلة الإثبات" (evidence chain) كسهم: طلب أصلي → تحوير → استجابة → إعادة تحقق → verdict.

### 8.3 لغة الواجهة

- **عربية + إنجليزية من اليوم الأول** (i18n مدمج: مفاتيح ترجمة، لا نصوص مضمّنة). التقارير: HTML/PDF عربي موجود أصلًا في المحرك (تقارير AR جاهزة) — تنسجم مع سوق المنطقة.
- دعم RTL كامل في الواجهة العربية (بما فيه اتجاه جداول الأدلة والسجلات).

### 8.4 قاعدة "المُصيِّر الخالص" في الواجهة

كل مكوّن عرض يقرأ من `findings.raw` / مخرجات المحرك فقط. إن غاب حقل (مثلاً proof قديم النسخة) تُعرض بطاقة "غير متوفر في هذا الفحص (نسخة محرك X)" — **لا تُركَّب بيانات ولا تُخفى الفجوة**.

---

## 9. أمن المنصة نفسها — النموذج القانوني والتقني

منصة فحص أمني سحابية هدفٌ عالي القيمة (تحتوي بيانات اعتماد عملاء + خريطة ثغراتهم + قدرة إطلاق فحوص). أمنها ليس ميزة بل شرط بقاء.

### 9.1 الإذن القانوني قبل الفحص (Authorization Attestation)

- **لا فحص على أي هدف بدون تفويض موثق**: تحقق ملكية عبر `dns_token` (سجل TXT عشوائي) أو وسم `meta` — أو `manual_attest` في نشر self-hosted مع تسجيل المُصادِق في audit.
- نشر SaaS: التحقق التقني إلزامي لكل نطاق جديد (وإعادة تحقق دورية)؛ نطاق لا يملك دليل ملكية = لا يدخل جدول الأهداف أصلًا.
- كل فحص يسجل: من صادق، متى، بأي طريقة، على أي نطاق بالضبط (scope_config مجمد snapshot مع الفحص) — ذراع دفاع قانوني للعميل ولنا.

### 9.2 حماية بيانات الاعتماد

- Envelope encryption: مفتاح بيانات لكل org يُشفَّر بمفتاح رئيسي من `SENTRY_MASTER_KEY` (env / KMS في P3)؛ `vault.py` الحالي يبقى طبقة التشفير الداخلية.
- القيم **لا تُعاد عبر API أبدًا** (metadata فقط)؛ كل استخدام داخلي يُسجَّل في audit (من/أي فحص/أي هدف) — نفس انضباط سجل vault الحالي (`vault_audit_*.json`) مرفوعًا إلى مستوى المنصة.
- فك التشفير يحدث في ذاكرة الـ worker عند لحظة الاستخدام فقط؛ لا تُكتب القيم في أي log/event/تقرير (redaction إلزامي في طبقة الأحداث).

### 9.3 عزل حركة الفحص

- الفحوص تخرج من الـ workers عبر نطاق شبكي منفصل (في السحب: egress via NAT مخصص يمكن تقييده بنطاق الأهداف المصرح بها فقط).
- حافظة "قرص سحابي" (SSRF إلى metadata الخدمة) محجوبة أصلًا في المحرك (`allow_metadata_svc=false` افتراضيًا) — تبقى كذلك في المنصة مهما كان الإعداد.

### 9.4 تقوية المنصة

- كلمات المرور argon2id + قفل تدريجي بعد محاولات فاشلة + rate-limit على login/scan-launch/report-generation.
- JWT قصير العمر + تدوير refresh + إبطال فوري للجلسات عند تغيير الدور.
- API Keys: تُخزَّن hashed، تُعرض مرة واحدة عند الإنشاء، scopes دنيا بالافتراض، انتهاء صلاحية إلزامي للـ enterprise.
- Webhooks: توقيع HMAC-SHA256 بطابع زمني (نمط GitHub) + إعادة محاولة backoff.
- Audit log: append-only (REVOKE UPDATE/DELETE) + تصدير SIEM في P4.
- التقارير المنزلة: روابط موقعة قصيرة العمر (15 دقيقة) وليست مسارات مباشرة.
- **بوابة إصدار دائمة:** كل إصدار منصة يُفحص بمحرك SENTINEL نفسه (وضع lab على API المنصة) — نتائج BOLA/التصريح عبر حدود org تدخل بوابات الإصدار كشرط فشل حاد.

---

## 10. الفجوة التقنية الأولى: أتمتة WebSocket Cross-User Authorization

### 10.1 الحالة الراهنة (كما استقرت في جلسة v4.1.1)

- Cross-user عبر WebSocket **أُثبت يدويًا** على DVWS (وصلة A/B بندين، استخراج مرجع كائن من اتصال الضحية، إعادة إرساله عبر اتصال المهاجم).
- ما لم يُثبت بعد: قدرة **محرك SENTINEL نفسه** على تنفيذ الدورة كاملة آليًا عبر نموذج مصادقة WebSocket معلن — والفجوة هنا في طبقة "أزواج بيانات الاعتماد + نماذج مصادقة WS"، وليست في عميل WS (العميل RFC6455 موجود ومُختبر: 55 اختبارًا).

### 10.2 التصميم: `ws_cross_user` كوحدة داخل محرك authz (وليس محركًا جديدًا)

**المدخلات المعلنة في config الفحص:**

```json
{
  "ws_cross_user": {
    "enabled": true,
    "endpoint": "ws://target:8080/socket",        // أو مُستخرَج آليًا من JS (wsUri)
    "auth_model": "first_message",                 // cookie | subprotocol | first_message | query_token
    "credential_pair": {"ref_victim": "cred-a", "ref_attacker": "cred-b"},
    "observe": {"max_messages": 50, "window_s": 10},
    "object_ref_extractors": ["json_path:$..id", "json_path:$..channel", "regex:\\b(room|sess|uid):([^\\s]+)"]
  }
}
```

**نماذج مصادقة WS الأربعة المدعومة** (تُبنى فوق عميل RFC6455 الحالي):

| النموذج | آلية الحقن في الاتصال | أمثلة واقعية |
|---|---|---|
| `cookie` | ترويسة `Cookie` في مصافحة الترقية | تطبيقات الجلسات الكلاسيكية (DVWS) |
| `subprotocol` | `Sec-WebSocket-Protocol: <token>` في المصافحة | بوابات token-aware (بعض بوابات API) |
| `first_message` | أول رسالة JSON بعد الاتصال تحمل token الهوية | تطبيقات chat/realtime الحديثة |
| `query_token` | المعامل في URL: `ws://…/?token=` | سريعة الانتشار رغم ضعفها (تسجل في اللوجات) |

**الخوارزمية (الدورة الكاملة — بنفس تعريف الدليل الذي أقره المنسّق):**

```
1. اكتشاف     → wsUri من JS (مستخرج v4.1.1) أو config صريح
2. اتصال A    → connect + مصادقة الضحية A بالنموذج المعلن → 101 وحدها لا تكفي:
                يجب أن تصل رسالة ترحيب/ack تثبت هوية الجلسة (وإلا: UNTESTABLE{reason})
3. مراقبة     → جمع مراجع الكائنات (ids/channels/rooms) خلال نافذة observe
                من رسائل A الواردة — كل مرجع يُسجَّل مع رسالته الأصلية (transcript)
4. اتصال B    → اتصال جديد كامل بمفاتيح المهاجم B + نفس النموذج
5. إعادة الإرسال → لكل مرجع كائن يخص A: إرسال رسالة استعمال/اشتراك عبر اتصال B
6. التفاضل    → VERIFIED   : استقبل B بيانات A أو تلقى تأكيد فعل (response يحمل
                             محتوى/معرف كائن A) — مع transcript ثنائي الاتجاه كامل
                REFUTED    : رفض صريح (error/قclose 4xxx) أو تجاهل متكرر عبر ≥3 محاولات
                UNTESTABLE : تعذر توثيق هوية A أو B، أو لا مراجع كائنات قابلة للاستخدام
7. الأدلة     → transcript كامل (اتجاه، طول، مقتطف) لكل اتصال + بصمة كل رسالة مُعاد
                إرسالها + snapshots حالة قبل/بعد حيث ينطبق (Proof Engine v2)
8. النتيجة    → Finding{type: "ws_cross_user_authz", authz_context: "A(victim)→B(attacker)",
                evidence: transcript, verification: {method:"ws_replay_differential", rounds}}
```

**قواعد أمان خاصة بالوحدة (موروثة من دروس DVGA/DVWS):**
- بوابات المسارات المدمرة (النمط المكتشف مع `/start_over`) تطبَّق على قائمة الرسائل القابلة لإعادة الإرسال: رسائل تحمل أفعال reset/purge/delete تُستبعد من replay إلا في وضع lab صريح.
- بوابة المضيف-مع-المنفذ (إصلاح v4.1.1): التحقق أن wsUri يستهدف نفس مضيف الهدف (المنفذ مسموح بالاختلاف) — منع انجرار الفحص إلى خدمة أخرى.
- حد أقصى لرسائل replay لكل اتصال (افتراضي 10) + backoff — لا إغراق للهدف.

### 10.3 خطة الإثبات (بوابات P1.5)

| # | البوابة | معيار النجاح |
|---|---|---|
| 1 | Fixture ثابتة | توسيع `fixtures/ws_app.py`: ثغرة cross-user واحدة + **سالبة آمنة** (رفض صريح) + حالة لا-مراجع (→ UNTESTABLE) |
| 2 | اختبارات وحدة | دورة كاملة آلية على الـ fixture: VERIFIED/REFUTED/UNTESTABLE بالضبط حسب الحقن — و"101 فقط" تُفشل الاختبار بنيويًا |
| 3 | انحدار المحرك | suite كاملة + doctor + benchmark ×3 بلا تراجع (F1 كما هو) |
| 4 | إثبات حي DVWS | دورة كاملة آلية على DVWS بنموذجي مصادقة على الأقل (cookie + first_message) — من حالة نظيفة، مع بقاء قاعدة بيانات الهدف سليمة |
| 5 | التوثيق | تحديث WEBSOCKET_INTELLIGENCE.md + CAPABILITY_MATRIX + KNOWN_LIMITATIONS — ورفع حالة Cross-user من "يدوي" إلى "آلي (نماذج: cookie/subprotocol/first_message/query_token)" مع ذكر ما بقي يدويًا إن وجد |

---

## 11. النشر والتغليف — من GitHub إلى Dashboard

### 11.1 الهدف التجريبي المعلن

```bash
git clone https://github.com/<org>/sentinel-platform.git && cd sentinel-platform
cp .env.example .env          # عدّل SECRET_KEY / MASTER_KEY / POSTGRES_PASSWORD
docker compose up -d          # ← الأمر الوحيد
# افتح http://localhost:8080 → سجّل → أنشئ مشروعًا → أضف الهدف → فحص → نتائج
```

### 11.2 docker-compose.yml (P1 — مربوط بالبوابات)

```yaml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: sentinel_platform
      POSTGRES_USER: ${POSTGRES_USER:-sentinel}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set in .env}
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-sentinel}"]
      interval: 5s
      retries: 12

  migrate:
    build: .
    command: alembic upgrade head
    env_file: .env
    depends_on:
      db: {condition: service_healthy}
    restart: "no"

  api:
    build: .
    command: >
      sh -c "alembic current &&
             uvicorn platform.app:app --host 0.0.0.0 --port 8080 --workers 2"
    env_file: .env
    volumes:
      - reports:/data/reports            # تقارير مولدة + ملفات إثبات
    ports: ["8080:8080"]
    depends_on:
      db: {condition: service_healthy}
      migrate: {condition: service_completed_successfully}
    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request as u;assert u.urlopen('http://127.0.0.1:8080/api/v2/admin/health').status==200"]
      interval: 10s
      retries: 12

  worker:
    build: .
    command: python -m platform.worker        # حلقة: استئجار صفوف + تنفيذ + أحداث
    env_file: .env
    volumes:
      - reports:/data/reports
    depends_on:
      db: {condition: service_healthy}
      migrate: {condition: service_completed_successfully}
    deploy:
      replicas: ${WORKER_REPLICAS:-1}

volumes: {pgdata: {}, reports: {}}
```

`Dockerfile` متعدد المراحل: مرحلة بناء الواجهة (node) → مرحلة تشغيل python-slim تحمل الحزمة + الملفات الثابتة المُجمَّعة فقط. صورة واحدة تخدم api وworker (أوامر مختلفة) — أقل انحرافًا بين البيئات.

### 11.3 الترقية والترحيل

- كل تغيير مخطط عبر **Alembic** حصريًا (لا DDL يدويًا)؛ الترقية = `git pull && docker compose up -d` (migrate يعمل تلقائيًا كشرط مسبق).
- سياسة توافق: كل ترحيل يُختبر رقيًا (upgrade) وهبوطًا (downgrade) في CI؛ لا ترحيل مدمّر دون إصدار رئيسي + تعليمات تصدير.
- نسخ احتياطي: `pg_dump` المجدول + snapshot لمجلد `reports/` — وإجراء استعادة مُختبَر (بوابة P3: استعادة كاملة على بيئة نظيفة خلال RTO معلن).

---

## 12. خارطة الطريق والبوابات (لا تُغلق مرحلة قبل بواباتها)

> الوحدة الزمنية هنا "جلسة بناء" (نفس إيقاع v2.x–v4.x). التقديرات تشمل التحقق والتوثيق، لا الكتابة فقط.

### P0 — الأساس (1 جلسة، بعد تصديق هذه الوثيقة)
**النطاق:** إعادة مزامنة شجرة v4.1.1 (بوابة P0-0) → إعادة هيكلة المستودع monorepo: `sentinel/` (كما هو) + `platform/` (حزمة جديدة) + `web/` (SPA) + `deploy/` → هيكل FastAPI عامل بـ `/admin/health` + Alembic أولي + compose من 11.2 يعمل → CI (lint + اختبارات المنصة + بوابات المحرك كما هي).

| بوابة | المعيار |
|---|---|
| P0-0 | شجرة v4.1.1 مدمجة + suite المحرك + doctor + benchmark ×1 أخضر (على بيئة نظيفة) |
| P0-1 | `docker compose up -d` على VM نظيفة → كل healthchecks خضراء خلال 90 ثانية |
| P0-2 | CI يشغل اختبارات المنصة وبوابات المحرك معًا؛ فشل أي منهما يمنع الدمج |

### P1 — MVP قابل للعرض (3–5 جلسات)
**النطاق:** Auth (register/login/JWT) + org واحد تلقائي لكل مستخدم (owner) + مشاريع/أهداف + التفويض (`manual_attest` في self-hosted) + فحص حقيقي كامل عبر worker يستدعي `launch_scan()` + بث SSE حي + Findings (قائمة/تفاصيل بالأسئلة السبعة 8.2) + تقارير html/sarif/pdf_ar للتنزيل + تاريخ وdelta + i18n عربي/إنجليزي.

| بوابة | المعيار |
|---|---|
| P1-G1 | E2E على VM نظيفة: تسجيل → مشروع → هدف (fixture `vulnapp.py` مدمجة) → فحص → نتائج حية على الشاشة → تنزيل تقرير — **بلا أمر تقني واحد بعد compose up** |
| P1-G2 | Cancel يعمل خلال ≤5 ثوانٍ من الضغط، والحالة النهائية `cancelled` مع حفظ ما تحقق؛ إعادة تشغيل الفحص بنفس seed تعطي نفس النتائج (determinism المحرك منقولًا للمنتج) |
| P1-G3 | عرض Finding Detail يجيب حرفيًا على الأسئلة السبعة من `findings.raw` (مراجعة شاشة-بشاشة مقابل مصدر البيانات — قاعدة المُصيِّر) |
| P1-G4 | اختبارات عزل org (قسم 4.2 بنود 1–5) + فحص SENTINEL-على-المنصة: صفر verified findings حرجة على API المنصة نفسها |
| P1-G5 | suite المنصة خضراء + suite المحرك بلا تراجع + demo script "5 دقائق من clone إلى أول finding" مُختبر فعليًا |

### P1.5 — أتمتة WS Cross-User (1–2 جلسة) — بوابة المنسّق الأخيرة على المحرك
النطاق والبوابات: القسم 10.3 كاملًا (fixture → وحدة → انحدار → DVWS حي → توثيق).

### P2 — الفرق والأتمتة (3–4 جلسات)
**النطاق:** RBAC الكامل (4 أدوار) + دعوات الأعضاء + API Keys + Webhooks (تسليم موقّع بretry) + Quotas + Schedules (cron) + Audit UI + عزل worker لكل org + Postgres في compose الإنتاجي مع RLS مُفعّل.

| بوابة | المعيار |
|---|---|
| P2-G1 | كل خلية ❌ في مصفوفة RBAC لها اختبار سالب أخضر (5×9) |
| P2-G2 | Webhook: تسليم موقّع صحيح + retry/backoff بعد فشل مُفتعل + تحقق التوقيع عند المستقبِل |
| P2-G3 | Quotas: رفع 429 مجدولًا عند التجاوز + لا تجاوز تزامن حتى مع طلبات متزامنة (اختبار سباق) |
| P2-G4 | Schedule يطلق فحصًا في الدقيقة المحددة (بتوقيت org) + إشعار نتيجة webhook |
| P2-G5 | حمل: 10 فحوصات متزامنة على 2 workers بلا أخطاء وبلا تسريب مقابض؛ مراجعة استهلاك ضمن حدود |

### P3 — SaaS تشغيلي (4+ جلسات)
**النطاق:** Stripe (خطة/فوترة) + OIDC SSO (قبل SAML) + Helm/K8s مع autoscale للـ workers + Prometheus metrics + Grafana لوحات + إجراء نسخ/استعادة مُختبَر + KMS للمفاتيح + تصليب أمني خارجي (اختبار اختراق للمنصة نفسها) + onboarding مؤسسي.

| بوابة | المعيار |
|---|---|
| P3-G1 | استعادة كامل لنسخة احتياطية على بيئة نظيفة خلال RTO المعلن + تحقق سلامة البيانات (بصمات findings مطابقة) |
| P3-G2 | فشل worker أثناء فحص → إعادة جدولة تلقائية، دون فقد findings مثبتة قبل الفشل |
| P3-G3 | اختبار الاختراق الخارجي: لا حرج/عالٍ مفتوح على المنصة؛ كل متوسط له خطة معالجة بمهلة |
| P3-G4 | تسجيل عميل تجريبي ذاتي (self-serve) من الصفر حتى أول تقرير منزَّل دون تدخل بشري |

### P4 — التكاملات (2–3 جلسات)
Jira (إنشاء issue لكل triage) + Slack/Teams إشعارات + GitHub/GitLab (SARIF إلى code scanning — الأساس موجود) + CI examples (GitHub Actions) + تصدير SIEM (syslog/CEF) + MCP/AI agents (لاحقًا).

| بوابة | المعيار |
|---|---|
| P4-G1 | SARIF يُرفع لـ GitHub code scanning من CI مباشرة (وثيقة + قالب action مُختبر) |
| P4-G2 | Jira issue يُنشأ من Finding بضغطة، ويربط بمعرّفها، ويُحدَّث عند تغير triage |

### 12.1 نطاق مضاد (Anti-scope — ما لن نفعله عمدًا)

- **لا محركات كشف جديدة** في P1–P3 إطلاقًا (استثناء وحيد: P1.5 لأنه مصفوفة ادعاء قائمة).
- لا SAML/SCIM قبل دخول أول عميل Enterprise يطلبه (P3 يكتفي بOIDC).
- لا schema-per-tenant قبل طلب تنظيمي ملزم.
- لا نشر K8s قبل P3 (compose يخدم حتى مئات المستخدمين بجدارة).
- لا "تحسين" أو تلخيح آلي لنصوص الأدلة في الواجهة — العرض الحرفي فقط.

---

## 13. القرارات السبعة المنتظرة للتصديق (تُنهي P0 فور ردّك)

| # | القرار | التوصية | البديل |
|---|---|---|---|
| 1 | **مكدس المنصة**: FastAPI + SQLAlchemy + Alembic + Postgres، والمحرك يبقى stdlib كمكتبة تُستدعى داخليًا | ✅ موصى به | استمرار stdlib للمنصة = إطار مُرتجل غير قابل للتدقيق |
| 2 | **الواجهة**: SPA (Vite + React + TypeScript) تُجمَّع وتُخدَم من حاوية api نفسها | ✅ موصى به | Next.js مستقل (حاوية إضافية + تعقيد نشر P1) |
| 3 | **البث الحي**: SSE مع fallback polling | ✅ موصى به | WebSocket (تعقيد بلا حاجة — الاتجاه واحد) |
| 4 | **تعدد المستأجرين**: قاعدة مشتركة + RLS + طبقة API إلزامية | ✅ موصى به | schema-per-tenant (مؤجل لEnterprise P3+) |
| 5 | **الطابور**: queue-as-table في Postgres (بلا Redis حتى P3) | ✅ موصى به | Redis مبكرًا (قطعة متحركة إضافية بلا حاجة) |
| 6 | **تسلسل البدء**: إعادة مزامنة شجرة v4.1.1 أولًا (بوابة P0-0) ثم البناء | ✅ موصى به | البدء من v4.1.0 الموجودة هنا وإعادة تطبيق فروق v4.1.1 لاحقًا (أبطأ وأكثر مخاطرة) |
| 7 | **الترقيم**: المحرك يواصل 4.x؛ المنصة تبدأ 0.x؛ "SENTINEL Platform 1.0" عند إغلاق P1 | ✅ موصى به | ترقيم موحد (يربط دورات إصدار المحرك بالمنصة قسرًا) |

**ملاحظة الختام:** أي بند من هذه الوثيقة قابل للتعديل قبل بدء P0؛ بعد بدء التنفيذ يصبح تغيير القرارات 1–5 تغييرًا معماريًا يتطلب جلسة إعادة تأسيس — لذلك صُممت لتُقرأ بدقيقة وتُصادَق بسطر واحد لكل قرار.

