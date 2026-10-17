# SENTINEL v4.1.0 — محرك الإثبات 2.0 (Proof Engine v2)

> المرجع التنفيذي لتطوير `evidence.py` — حزمة الإثبات الكاملة + إعادة التشغيل الحية.

## حزمة الإثبات (كل نتيجة مثبتة)

```
finding_id · vulnerability class · target · endpoint · identity · preconditions
· requests · responses (evidence chain) · state_before · state_after (ENG-18)
· object identifiers · impact (grade + statement) · verification (method/rounds)
· reproduction (خطوات بشرية مرتبة) · confidence · provenance · safety classification
```

الجديد في v4.1.0:

- **فئات v4.1 الكاملة**: profiles تأثير لـ branch_bypass / unauthorized_branch /
  approval_bypass / rollback_abuse + فئات GraphQL الخمس + فئات WebSocket
  (قواعد SARIF: SEN-BL-009..012, SEN-GQL-001..005, SEN-WS-001..002)
- **سلاسل الإثبات GraphQL/WS**: request → response → verification كسلسلة واحدة
  (زوج الحالة = الاستعلام والاستجابة)

## إعادة التشغيل الحية (`--replay`)

```bash
sentinel reproduce --finding F-ab12cd34ef --db results/x.db --replay
```

يعيد تنفيذ إثبات النتيجة **من محرك نظيف** (لا جلسة مستعارًة، لا حالة سابقة) عبر
**الكاشف نفسه + خط التحقق نفسه** — ليس فحصًا مبسطًا:

| النتيجة | المعنى | كود الخروج |
|---|---|---|
| `REPRODUCTION_VERIFIED` | فئة الثغرة نفسها أعادت التثبيت على محرك نظيف | 0 |
| `REPRODUCTION_FAILED` | أعيد التشغيل ولم يُعد الإنتاج — **السبب مسجَّل ولا يُخفى** (الهدف تغيّر أو النتيجة سياقية) | 1 |
| `NOT_REPLAYABLE` | الفئة تحتاج سياق وقت المسح (سلاسل منطق الأعمال تحتاج اعتمادات المسح) — وصفة يدوية موصى بها | 1 |

قاعدة الصدق: الفشل **يُسجَّل ولا يُخفى أبدًا** — `REPRODUCTION_FAILED` مع سبب
صريح هو مخرج مشروع، وليس عيبًا في التقرير.

## نطاق الأتمتة (موثَّق بصدق)

- **قابل لإعادة التشغيل آليًا**: 13 فئة على مستوى الطلب (sqli/xss/traversal/
  redirect/ssrf/crlf/xxe/cmdi/csrf/nosql/jwt/hostheader/ssti)
- **تقييد OOB (مهم)**: المتغيرات **العمياء** من هذه الفئات (cmdi/xxe/ssrf
  المثبتة عبر استدعاء خارج النطاق) لا تُعاد إنتاجها آليًا — القناة الخارجية
  مسلحة وقت المسح ولا يحملها ملف الإثبات؛ النتيجة الصادقة عندها هي
  `REPRODUCTION_FAILED` بسبب "القناة الخارجية غير مسلحة في وضع إعادة التشغيل"
  (لا يُخفى أبدًا). المتغيرات ذات واجهة الاستجابة (انعكاس/خطأ/اختلاف
  استجابة) تُعاد إنتاجها آليًا (مثال حي: SQLi الحرجة في Juice Shop).
- **تدفقات الإصدار POST**: نتائج مثل jwt-login تحتاج بيانات نموذج لا يحملها
  سجل الطلب المصغر في الإثبات — الإعادة **الآلية** قد تُخفق بسبب "سياق"
  بينما **الوصفة اليدوية** (لكل خطوة: طلب + متوقع) هي القناة الكاملة.
- **NOT_REPLAYABLE بنيويًا**: منطق الأعمال وIDOR — يستنسخان عبر سياق الجلسة/
  المسح؛ الوصفة اليدوية في ملف الإثبات هي القناة (كل خطوة: طلب + متوقع)
- **سقف ملفات الإثبات (40/فحص)**: `reproduce` يخدم نتائج الأعلى أولوية أولًا
  (منطق الأعمال ← التفويض/الأسرار ← الباقي أبجديًا) — موثق في
  KNOWN_LIMITATIONS بند 0؛ كل النتائج تبقى محفوظة بأدلتها في القاعدة.

## الاختبار
`unit_v41_replay`: إعادة تشغيل حية على نتيجة XSS حقيقية من vulnapp → VERIFIED؛
سطح مختفٍ → FAILED بسبب؛ منطق أعمال → NOT_REPLAYABLE بسبب.
