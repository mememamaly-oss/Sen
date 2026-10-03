# SENTINEL — STATE.md

**One honest file with the full picture. No marketing. If a claim is not
backed by a number or a committed artifact, it does not belong here.**

- Last updated: 2026-10-03 (UTC) — round 2: v4.2.2 (DETECT-06 numeric-comment family, doLogin fixed & live-VERIFIED), comparison frame delivered, addendum package; pending external verification
- Maintained by: the engineering agent. **Update protocol: after every work round, refresh sections 1/4/5/6 with real numbers, bump this date, commit, push.**
- Audience: future engineering sessions (context is lost between sessions), the supervisor, and any future buyer performing due diligence.

---

## 1. What is built and PROVEN (with numbers)

**Engine** — pure-Python-stdlib DAST engine (`sentinel/`, ~30 modules), current version **4.2.2**
(`build-v422/` is the canonical live engine; v4.2.1 and earlier are frozen).
- Verification by **re-execution**: a finding is VERIFIED only by re-issued
  requests against the live target (17 explicit type branches, fail-closed on
  unlisted types since v4.2.0). No finding is verified by description.
- **Request journal (v4.2.1)**: passive raw capture of every request as issued
  (including session cookies) + final response after redirects, per-scan
  isolation, bounded (6000 entries / 4000-char bodies, honest dropped counter).
  Proven passive: 194=194 verdict tuples identical v4.2.0 vs v4.2.1 on the same
  fixture; 42/42 proof request_ids resolve to complete raw pairs.
- Gates as of v4.2.2: tests **104/104** (103 + the DETECT-06 discriminating
  case), doctor **15/15**, benchmark **x3 deterministic** (F1 1.000 =
  38/0/0/37, run-3c0652b6be — the numeric-comment family added +106 fixture
  requests and ZERO verdict changes).
- **bench-adv v11 discriminates the fix set** (the stock 73-case bench is
  proven blind — see section 2): v4.1.1 = 38/2/0/35, F1 **0.9744** (2 FPs:
  csrf@/vuln/subscribe-echo, nosql@/api/nosql-lockout) vs v4.2.0+ = 38/0/0/37,
  F1 1.000 — same fixture/seed/run-id, x3 bit-identical.

**L1 Security Twin** — normalization + provenance layer (`src/lib/twin/`),
branch `phase/02-l1-twin` (merged into main's tree).
- Suite **195/195** after the four supervisor-ordered fixes; **210/210** with
  the five real v4.2.1 live scans in REAL_FILES; determinism x3 across all 11
  fixtures; two tamper-attack batteries (E13, E14) all caught.

**SaaS platform** — Next.js multi-tenant console (orgs/members RBAC, audit
log, scan lifecycle, HTML/SARIF reports, AR/EN i18n, dark/light).
- L0 tenant-isolation suite passed; E2E flows verified with committed
  screenshots (`saas-data/final-gate*/`).

**Live evidence campaign (2026-10-03)** — engine v4.2.1 against the declared
authorized targets only, within each target's declared authorization.
- 5 reachable targets scanned: demo.testfire.net, ginandjuice.shop,
  testasp.vulnweb.com, testaspnet.vulnweb.com, google-gruyere.appspot.com.
- **171 findings packaged raw** + 5 engine-rejected candidates listed for
  transparency, in `INDEPENDENT_VERIFICATION_PACKAGES.md` (577 KB, repo root)
  — every finding carries type, URL+parameter, engine verdict, evidence chain,
  raw request/response pairs verbatim from the journal, and a reproduction
  recipe. The generator formats; it never evaluates.
- Strong-class live hits (active-evidence findings, 22 of 171):
  - SQLi boolean-oracle: ginandjuice `/catalog?category` (TRUE 17111B vs FALSE
    9426B body differential); testasp x5; testaspnet x2
  - XXE blind-OOB: ginandjuice `/catalog/product/stock` (2 live webhook
    interactions from the target's infrastructure)
  - DOM XSS with real browser execution probe: ginandjuice `/blog/` (source=
    search → sink=document.write; window.__SENTINEL_XSS__ set in live DOM)
  - Reflected XSS variant-battery: testfire x4, ginandjuice x2 (incl. Angular
    {{expression}}), testasp x1, gruyere x1
  - CRLF header injection: ginandjuice (x-sentinel-probe header split)
  - CSRF triple-control (baseline/cross-origin-replay/malformed-control):
    ginandjuice `/catalog/cart`
  - Open redirect: ginandjuice; Path traversal: testasp
- Earlier local-lab rounds (WebGoat, WebWolf, Juice Shop, DVGA, DVWS):
  committed under `build-v41*/results/live_v41/` and `gap-validation/`.

---

## 2. Limits of the "proof" — read before trusting anything

**Where the proof is REAL (re-execution, strong family):** SQLi (error oracle +
boolean body-differential, PATH A/B/C), XXE (OOB interaction), DOM XSS (browser
execution probe), reflected XSS (6-vector battery incl. WAF-resistant shapes),
SSTI (fresh-expression numeric evaluation), IDOR/BOLA (cross-account matrix on
lab targets), CSRF (three-control), header injection, open redirect, path
traversal. For these classes a VERIFIED verdict means the engine re-issued the
attack and observed the differential/execution/callback again.

**Where the proof is thin, weak, or caveated — stated plainly:**

0. **Authorization discipline (standing rule, adopted 2026-10-03):** two
   external targets submitted outside the declared list ([REDACTED-THIRD-PARTY-DOMAIN] = ATIB bank,
   [REDACTED-THIRD-PARTY-DOMAIN] = Jumhouria Bank — both real Libyan production banks) were REFUSED
   after passive identification only; no payloads sent, engine never started.
   The engine runs on an external target only with proven user control of the
   asset (challenge-response) or declared authorization from the owner. This
   rule exists to keep the 171-package evidence chain admissible and the
   campaign on the legal side of the line.
1. **149 of the 171 live findings are passive/low classes** (96
   missing_security_headers, 34 server_banner, 18 tech_banner, 1
   vulnerable_js_dependency, 1 …). They are true but near-worthless as
   capability proof. The campaign's real substance is the 22 strong-class
   findings. Do not quote "171 findings" as if they were 171 exploits.
2. **The stock benchmark's F1=1.000 is PROVEN BLIND** (it certified the broken
   v4.1.1 engine identically to the fixed one — supervisor's finding, confirmed
   with data). The ONLY admissible benchmark evidence is bench-adv v11 (v4.1.1
   0.9744 vs v4.2.0+ 1.000). F1=1.000 on the stock 73 cases must never be
   cited as fix evidence.
3. **All live-target verdicts are engine-self-judged.** The packages exist so
   an external party can adjudicate; **no external party has adjudicated any of
   them yet.**
4. **testfire doLogin: a live MISS on v4.2.1 — FIXED in v4.2.2, proven live.**
   The v4.2.1 battery carried the string-quote SQLi family only; during the
   2026-10-03 campaign the target drifted (string shape neutralized while
   `1' OR 1=1--` still bypassed) and the engine honestly reported nothing.
   v4.2.2 adds the numeric-comment family (DETECT-06, detector + verifier
   PATH C'); the re-scan VERIFIED doLogin (conf 0.95) with BOTH differentials
   in the evidence chain and raw pairs in
   INDEPENDENT_VERIFICATION_ADDENDUM_v422.md. NOTE the target flaps between
   states (three timestamped windows documented in the addendum) — the
   unit/mechanism proofs are the stable discriminators, the live scan records
   whichever state answers.
5. **xss_dom packages carry browser execution steps, not journaled HTTP
   pairs**; XXE verdicts rest on OOB interaction records (public webhook
   channel), not response bytes. Both are marked as such in the file.
6. **Replay caveat:** raw pairs carry the scan session's cookies (demo/test
   accounts on authorized test sites). A reviewer replaying them may need a
   fresh authorized session of their own.
7. **VF-03 honest limitation:** not bench-discriminable through the current
   detector (detect.py already enforced the ≥max(200B, 25%) body-diff guard in
   BOTH builds); proven at mechanism level + on live targets only.
8. **No external benchmark has been run** (no OWASP/PortSwigger official suite,
   no third-party pentest report, no CVE-mapped corpus).

---

## 3. Fixes applied and their evidence

**Engine VF-01..04 (v4.2.0, `intel.py`/`workflow.py`)** — fail-closed unlisted
types; evidence chains must be real (no auto-minted verification records
counting as evidence); PATH A replay tightening (≥max(200B, 25%)); workflow
findings require a captured proof protocol (ValueError otherwise).
Evidence: bench-adv v11 2-FP delta (x3 deterministic), mechanism probes
(`results/probe_vf_mechanisms_v{411,420}.jsonl` — e.g. VF-01a v411 VERIFIED
0.98 fail-open vs v420 CANDIDATE 0.30 fail-closed), docs
`VERIFICATION_FIXES_v420.md` incl. the "what this does NOT prove" block.

**L1 four fixes (commit 1f4c35a, supervisor ruling 2026-10-03)**
1. `verifiedClaimIsSound` was dead code (zero callers) → now the gate inside
   `why()`, the single construction path; sourceRefs-laundering loophole
   closed; VERIFIED without evidence refs fails closed to UNKNOWN.
2. `hasEvidence` was vacuous (auto-minted verification node always satisfied
   it) → now requires the finding's OWN captured chain (minus the
   verification record). Real v4.2.0 data unaffected (all 136 findings carry
   non-empty chains — verified before implementing).
3. INV-05 was findings-only + raw-only → now covers hypotheses AND the stored
   path (twin's own evidence graph). Proven by E14: 11/11 stored-path pass +
   3 tamper attacks (verification flipped / hypothesis resolution flipped /
   chain stripped) all CAUGHT.
4. CONFLICT was automatic demotion → now demotion only with captured
   counter-evidence; vacuous rejection preserves the VERIFIED claim
   (hypothesis conflicts keep demotion — a tested:refuted resolution IS an
   engine test by construction, documented).
Evidence: suite 195/195; new fixture F11 (vacuous-rejection golden), F10 golden
honestly re-frozen (hash follows content); determinism x3; 210/210 with real
v4.2.1 scan data.

**v4.2.1 request journal (commits 185ac26 + 7bf3cae)** — passivity gate
194=194 verdict tuples identical; 42/42 proofs resolve; first version of the
gate caught fixture-state contamination and was fixed to
fresh-instance-per-engine (the gate discriminates, by design).

---

## 4. Gaps discovered live (not papered over)

- ~~SQLi numeric-comment family absent~~ **FIXED in v4.2.2** (2026-10-03,
  supervisor-ordered): detector + verifier + discriminating test + gates +
  live doLogin VERIFIED. See CHANGELOG v4.2.2 and
  INDEPENDENT_VERIFICATION_ADDENDUM_v422.md.
- **testphp.vulnweb.com + testhtml5.vulnweb.com unreachable** (shared host
  44.228.249.3 TCP timeouts; the other five targets answered from the same
  egress in the same window). Retry pending host recovery.
- **Container fragility:** rollbacks #1–#13 have repeatedly wiped `download/`
  and untracked state (6 escape-pod bundles died undownloaded) and gutted
  `.gitignore` 3+ times. Mitigated since 2026-10-03: GitHub is the primary
  durable copy; tracked content + git anchors have survived every event.
- **VF-03 not bench-discriminable** (see section 2.7) — mechanism + live only.

---

## 5. What has NOT happened yet (as of this file's date)

1. **External independent verification of the 171 packages.** No external
   judge — human or tool — has ruled on any finding. The supervisor's own
   review of INDEPENDENT_VERIFICATION_PACKAGES.md (in progress) is the first
   semi-independent pass; it is not external confirmation. The comparison
   frame (order 3) is READY but has processed only the synthetic sample —
   no real external list exists yet.
2. **L2 Attack Paths** — not started. The differentiating layer of the
   architecture remains unbuilt (blocked per supervisor ruling until the fix
   set landed; the fixes have landed, L2 remains untouched).
3. ~~SQLi numeric-comment battery~~ — implemented and proven in v4.2.2
   (2026-10-03). The comparison frame for external verifiers
   (scripts/compare_external_findings.py + worked example) is also delivered;
   it awaits a REAL external list to compare against.
4. **testphp/testhtml5 scans** — not run (outage).
5. **Any customer, buyer, pilot, or market contact. Zero revenue.** Any
   valuation (including the 1–4M range discussed) is a hypothesis conditional
   on external verification + a real buyer — neither exists.

---

## 6. Save status (updated every round)

- **PRIMARY (durable): GitHub — `github.com/mememamaly-oss/Sen` (private).**
  Last verified push: main **73fb547** (2026-10-03, mirror-clone proof: refs +
  HEAD tree + fsck identical to source). Refs on GitHub: 5 branches (main,
  phase/02-l1-twin, release/v4.1.1, release/v4.2.0, release/v4.2.1), 4 tags
  (v4.1.1, v4.2.0, v4.2.1 annotated, recovery/l1-candidate-2026-10-02).
  Local-only commits after 73fb547 (STATE.md + worklog task 10) are pending
  push — the 24h PAT was used inline only and is gone; **pushing requires a
  fresh PAT from the repo owner.**
- **Local:** full repo at `/home/z/my-project` (git-tracked content + all
  anchors survive every rollback). Escape pod bundle regenerated per round
  into `download/` (dies with each container rollback — r4 is current).
- **PAT security:** the 2026-10-03 token was command-line-inline only, never
  written to disk, config, or any commit; the owner was instructed to revoke
  it. Future pushes use the same inline-only protocol.

---

## ملخص عربي صادق (Arabic honest summary)

ما هو مبني ومُثبت بالأرقام: محرك فحص DAST بإعادة تنفيذ حقيقية (v4.2.1،
اختبارات 103/103، مرجعِية bench-adv v11 تُميّز الإصلاحات: v4.1.1 = F1
0.9744 بخطأين إيجابيين مقابل v4.2.0+ = 1.000)، طبقة Twin أمنية مع إصلاحات
المشرف الأربعة (195/195 و210/210 على بيانات حقيقية)، منصة SaaS كاملة
باختبارات عزل، وحملة حية على 5 أهداف مُصرّح بها أنتجت 171 حزمة أدلة خام
(577KB) — كل حزمة تحمل الطلب والاستجابة كما أُرسلا حرفيًا.

حدود البرهان بصراحة: 149 من الـ171 سباقًا سلبيًا (ترويسات/لافتات) — الجوهر
الحقيقي 22 حالة قوية فقط؛ درجة F1=1.000 في المرجع القديم عمياء ومُثبت
عماؤها ولا تُستشهد أبدًا؛ جميع أحكام الأهداف الحية أصدرها المحرك نفسه ولم
يحكم عليها أي طرف خارجي بعد؛ فجوة حية موثقة سابقًا (عائلة SQLi numeric-comment غائبة) أُصلحت في v4.2.2
بإثبات حي: doLogin أصبحت VERIFIED بدليل خام مع توثيق صادق لتذبذب حالة الهدف؛
هدفان (testphp/testhtml5) ما زالا معطلين. إطار مقارنة نتائج المحقق الخارجي
جاهز لكن لم يُقارن به إلا المثال الاصطناعي بعد.

ما لم يحدث بعد: التحقق الخارجي المستقل (لا قاضي حكم)، L2 Attack Paths
(لم تبدأ)، إصلاح فجوة SQLi، إعادة فحص الهدفين المعطّلين، وأي عميل أو مشترٍ
أو إيراد — لا شيء. أي تقييم مالي (بما فيه نطاق 1–4 مليون) فرضية مشروطة
بتحقق خارجي ومشترٍ حقيقي، وكلاهما غير موجود.

حالة الحفظ: الأصل الدائم على GitHub (github.com/mememaly-oss/Sen، آخر دفعة
مُتحقَّق منها 73fb547). هذا الملف نفسه والتزامات ما بعده تنتظر PAT جديدًا
للدفع. تُحدَّث هذه الوثيقة بعد كل جولة وتُدفع معها.
