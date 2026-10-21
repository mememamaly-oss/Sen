# HONEST BOUNDARIES — SENTINEL v4.3.0+

**One file with every declared limit. No limit is hidden, glossed, or
discovered later by an adversary. Each entry carries its mitigation and the
order that produced it.** (Arabic summary at the end.)

## 1. SSRF Guard Limitation (RT-01 TOCTOU — DNS rebinding)

The ORD-001-REMAND fix (commit 68f616a) implements the supervisor's
Option A: the engine resolves each target ONCE per request, validates every
answer against the RT-01 guard, and pins the transport to the validated
address; the original hostname rides in Host (http) and in SNI +
certificate hostname validation (https). The check-then-connect race is
closed within one request lifecycle. DECLARED RESIDUAL:

- Between two SEPARATE requests the resolver may still return different
  answers; each request re-validates independently at pin time
  (fail-closed), so no request can ever CONNECT to an unvalidated address.
- A rogue system resolver can still DENY SERVICE (answer with garbage) but
  cannot route the engine to an unvalidated target.
- DNS answers with multiple addresses: the pin deterministically selects
  the lowest (version, numeric) safe address; a mixed public+private answer
  is REJECTED entirely (any-unsafe = reject).

**Mitigation:** do not scan targets in untrusted DNS environments; treat
resolver availability as scan infrastructure, not as an attack surface.

## 2. Request-Body Sanitization (ORD-001-REMAND item 3)

`sanitize_request_body` (commit b48a2da) redacts sensitive keys
(password, passwd, secret, token, credit_card, cvv, ssn) in
form-urlencoded and JSON journals, and omits binary/multipart bodies
>= 1KB as `[BINARY_BODY_OMITTED_FOR_SECURITY]`. DECLARED LIMITS, exactly
as ordered:

- **< 1KB binary/multipart bodies are journaled VERBATIM** — the ordered
  exception. A small multipart form carrying a password WOULD still be
  journaled. This is the supervisor's specification, not an oversight.
- Non-listed content types (text/plain, XML, vendor JSON, ...) are journaled
  verbatim — the ordered families were form-urlencoded + JSON + binary +
  multipart only. A future family must extend `SENSITIVE_BODY_KEYS` /
  `_BINARY_CONTENT_TYPES` explicitly.
- RESPONSE bodies stay verbatim by design — they are the verification
  evidence pairs (out of the ordered scope).
- Redaction is journal-side only; the WIRE request is never modified.

**Mitigation:** operators scanning with credential-bearing forms should
pass credentials via the auth engine (headers are redacted since RT-05),
not inside multipart bodies.

## 3. Keypair Seed Policy (RT-03/RT-04 — commit e4d9159)

- Pre-remand reports signed with short seeds can no longer be RE-DERIVED;
  their embedded public keys still VERIFY their existing signatures
  (verification never derives).
- Unseeded derivations (`None`) draw a fresh `os.urandom(32)` key per call:
  unforgeable, but unreproducible (N7: no reproducibility claim) — the
  honest trade, chosen over the old publicly-known `"unseeded"` key.
- The seed floor (>= 32 bytes) rejects operator seeds at BOTH the CLI
  parse and the crypto layer; the suite harness pads its historical short
  case labels in ONE visible point (the same opt-out pattern as the
  request budget) — the operator path is never padded.

## 4. Bench Anchor Migration (RT-03/RT-04 consequence)

The bench seed grew `"benchmark-fixed-seed"` (21 bytes) ->
`"bench430" x 8` (64 chars), so the bench `run_id` necessarily changed
(run-3c0652b6be -> run-d6b26b92d0). The structural families
(path_tuples / norm_url_tuples / struct_meta) are IDENTICAL to the
accepted record — zero verdict changes; requests=7162 matches the prior
station runs exactly. `norm_url` strips the port by design: the bench
fixture binds an ephemeral port per run (ENG-20), so the port is run
plumbing, never target identity.

## 5. Suite Harness Boundaries (standing, re-declared)

- Shared fixed ports: 17 fixture ports are each shared by exactly two
  cases; a chunk is one process and daemon fixture servers accumulate
  until it exits — same-chunk pairs are separated BY CONSTRUCTION in the
  gate plan. A single-process full-suite run is structurally impossible.
- The regression harnesses opt out of the request budget and the seed
  floor in ONE visible point each (documented in-file) — the
  operator-facing defaults are never weakened.

---

## الملخص العربي

ملف واحد يعلن كل حد صراحةً: (1) حرس SSRF يثبّت الاتصال على العنوان
المُحلَّل والمُتحقَّق منه — البقايا: بين طلبين منفصلين قد يتغير جواب
المُحلِّل، لكن كل طلب يتحقق باستقلال قبل الاتصال (fail-closed)؛ محلّل
خبيث يستطيع تعطيل الخدمة لا توجيه المحرك. (2) تطهير أجسام الطلبات:
الأجسام الثنائية/multipart الأصغر من 1KB تُسجَّل حرفياً — هذا هو
الاستثناء المأمور به حرفياً؛ الأنواع غير المدرجة تُسجَّل حرفياً؛ أجسام
الاستجابات تبقى (قيمة التحقق). (3) سياسة البذرة: تقارير ما قبل
الإصلاح لا يمكن إعادة اشتقاقها (مفاتيحها العامة تظل تتحقق)؛ بلا بذرة
= مفتاح عشوائي لكل استدعاء (غير قابل للتزوير، بلا ادعاء تكرار). (4)
مرساة البنش انتقلت لـ run_id جديد لتغيّر البذرة المأمور — بصفر تغيير
في الأحكام (IDENTICAL). (5) حدود أدوات السويت: المنافذ الثابتة
المشتركة تفصل بين الأجزاء بحكم البناء؛ التشغيل الكامل في عملية واحدة
مستحيل بنيوياً.
