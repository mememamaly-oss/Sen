# SENTINEL — STATE.md

**One honest file with the full picture. No marketing. If a claim is not
backed by a number or a committed artifact, it does not belong here.**

- Last updated: 2026-10-08 (UTC) — round 17: **v4.3.3 GraphQL STORED-XSS +
  FIELD-SUGGESTIONS batteries — DVGA leg complete, THE OWASP CAMPAIGN CLOSES
  AT 6/6** (WrongSecrets, OWASP Benchmark, DVWA, Mutillidae, NodeGoat,
  DVWS+DVGA). Against DVGA's own 22 official solutions the GraphQL layer had
  two live-caught gaps: no write->read oracle (stored XSS through mutations,
  solution #12 — proven manually first with raw urllib, then built as
  _stored_xss_battery: additive-write mutations only, fresh-marker 2-round
  verification, the marker key riding the first non-slot String arg) and no
  field-suggestion probe (solution #8 — a typo DERIVED from a real
  introspected field answers 'Did you mean <field>?'; the escaped-quote form
  was live-caught and fixed). LIVE RECORD: 30/30 findings VERIFIED (the five
  baseline GraphQL classes + xss_stored + graphql_field_suggestions — a NEW
  finding type), zero false positives, destructive mutations never exercised,
  DoS-class solutions excluded by design. Gates: 205/206 covered (+1
  RED-proven discriminating case on the new /gql/dvga fixture twin; the same
  1 documented environmental exclusion) + doctor 17/17 + bench x3 IDENTICAL
  38/0/0/37 @4784 ZERO regressions. Round 16 before it: v4.3.2 WS-ACTIVE. **v4.3.2 WS-ACTIVE — the WebSocket
  message battery (DVWS campaign, app 6/6 part 1)** — the engine observed WS
  channels but never SENT attack payloads through the message channel: the
  baseline v4.3.1 scan of DVWS returned 58 passive-only findings, ZERO
  strong-class, while the target carries nine message-borne vulnerabilities
  (red-team-proven the same day with raw-socket probes, zero engine code).
  Built: channel-builder bindings harvested from the target's own page JS
  (JSON templates + per-key base64/percent transforms + raw sends + literal
  triggers, object-chain bound — the csrf.php same-var two-template page
  fixed by nearest-preceding-assignment resolution), the seven-family active
  battery (sql_pair 2-round byte-stable differential, sql_error signature,
  cmdi canary, ssti/code_injection 42-oracle, lfi passwd signature, xss
  reflection, xss_stored write->read roundtrip — every verdict re-executed
  on a FRESH connection, echo replies excluded from execution oracles), the
  ONE destructive-vocabulary gate for every message phase (battery refused
  /change-password but the v4.1 elicitation still sent hellos there —
  live-caught by the discriminating test), and the per-family fresh
  connection (the Ratchet server closes the socket on null replies — a
  per-channel client went permanently deaf mid-sweep). LIVE RECORD: 10/10
  strong-class VERIFIED on the real target (sql x2, cmdi, code_injection —
  NEW TYPE, ssti, lfi, xss x3, stored xss), the parameterized control
  silent, /change-password zero-message blocked, zero false positives, 113
  battery sends on 11 channels. Gates: 204/204 covered (+1 RED-proven
  discriminating case; 1 case excluded with a documented runner-only
  environmental stall that also hangs pristine v4.3.1 and passes standalone)
  + doctor 17/17 + bench x3 IDENTICAL 38/0/0/37 @4784 ZERO regressions.
  DVGA (app 6/6 part 2) follows. Round 15 before it: v4.3.1 GTP-12. **GTP-12 THE PERFECT-PRECISION PUSH — v4.3.1, measured** — the supervisor's order "أصلح الدقة لـ200% وارفع الكشف لأعلى نسبة عالمية بعقلية الردتيم والبلوتيم ومعايير التشفير العسكري" executed: **precision 100.00% (0 FP across all 2,740 tests) / recall 68.90% / F1 0.8159 / FPR 0.000%** — eight live-caught defect families fixed (GTP-12a transformation-aware echo neutralization — the 6 verified path_traversal FPs on SECURE crypto servlets were the engine measuring ITS OWN percent-encoded/last-char-stripped payload echo; GTP-12b the weakrand PRNG-disclosure oracle — 218/218 vulnerable servlets disclose a non-CSPRNG class in the response text, 0/275 secure do, weakrand 13.8%→92.66%; GTP-12c the artifact TRUNCATION leg + three-tier block oracle — a verified FileOutputStream sink pointed at passwordFile.txt zeroes it (open-no-write), the round-4 "write-amplification bound" is broken, hash 0%→89.15% and crypto 0%→52.31%; GTP-12e the writability hoist — the check was nested inside the exists-DIFFERS branch and never ran for its own family, pathtraver 30.1%→38.35%; GTP-12f the spec-drift body channel — the servlets read their OWN test-name form param while the spec declares decoys; GTP-12g the off-boundary discriminator — AES/GCM with an 8-byte tag collides with the DES length curve exactly, a 15-byte probe separates them (25 intermediate FPs killed) + abort-on-failed-truncate (the stale-line FP); GTP-12h the constant-digest family — 20 hash servlets hash a hardcoded 'bob', the algorithm is still identifiable by digest length + input-independence; eval mapping fix for weak_hash/weak_crypto). Gates: suite **204/204** (199 + 5 new discriminating GTP-12 cases) + doctor 17/17 + local bench ×3 IDENTICAL 38/0/0/37 F1=1.000 @4784 run-3c0652b6be (zero regressions) + the full ground truth re-measured END-TO-END twice (12 no-crawl chunks, 298,576 requests, 1,032 VERIFIED active findings; per-category recall: hash 89.15%, weakrand 92.66%, sqli 76.10%, xss 75.61%, cmdi 61.11%, ldapi 55.56%, crypto 52.31%, securecookie 52.78%, xpathi 40.00%, pathtraver 38.35%, trustbound 34.94%). All 8 eval rounds committed under build-v430/results/owsp/benchmark/ (round1 RED baseline recall 28.98% → definitive 68.90% @ precision 1.000). Round 14 before it (2026-10-07): v4.3.0, the first ground-truth push.
- Maintained by: the engineering agent. **Update protocol: after every work round, refresh sections 1/4/5/6 with real numbers, bump this date, commit, push.**
- Audience: future engineering sessions (context is lost between sessions), the supervisor, and any future buyer performing due diligence.

---

## 1. What is built and PROVEN (with numbers)

**Round 9 — maximum internal test (أقصى اختبار داخلي، not external verification).**
Supervisor order trace 1a10860055030c15. All artifacts under
`build-v423/results/maxtest/` + `scripts/maxtest/`:
- **Coverage**: Juice Shop 20.2.0 (node22, local) — 114 findings vs 29 pre-round:
  SQLi VERIFIED on `/rest/products/search?q=` (SQLITE_ERROR db_error + status_oracle),
  credential_exposure VERIFIED on `/rest/memories`, js:static surface 2→96 endpoints
  (SPA backtick-template extraction), authz matrix 3 accounts × 25 endpoints, honest
  IDOR-FP kill via fresh-victim verify. L2: 1 path VERIFIED. L3: sql_version_oracle
  VERIFIED live (control 21571B/30B, version 21571B/30B — was scope-blocked 0/0).
  WebGoat 8.2.2 (java, local) — the lesson surface extracted from the app's own jar
  form templates + lesson-context priming; **9 sql_injection VERIFIED live on the real
  lessons** (assignment5a ×3 params, attack10 15699B/286B, attack8/9 ×4,
  SqlInjectionAdvanced 6a) + 11 L2 paths VERIFIED + session stable (failed_reauths
  3944→0). WebWolf 8.2.2 — 31 verified (anonymous surface).
- **Twelve engine defects fixed red→green** (unit_max01..unit_max11 in the suite):
  MAX-01 token validation closed-door proof; MAX-02 authz token_validate_url
  resolution; MAX-03 SQLITE_ERROR/Oracle/.NET/pgsql error signatures; MAX-05
  OpenAPI path-template instantiation + PATH render + plain-"id" IDOR param;
  MAX-06 SPA template-literal endpoint extraction; MAX-07 impact --allow-private
  flag (localhost L3 was wholly scope-blocked); MAX-08 SQL-family version
  predicates; MAX-09/09b paren-closing SQLi battery + PATH D2 verification +
  journal-separated L3 template ranking; MAX-10a/b logout self-preservation
  (crawler + passive gates) + cookie-diet re-auth retry; MAX-11 bare-Endpoint
  query-string preservation.
- **Self-verification**: independent re-derivation (zero-trust, fresh code) 6/6
  MATCH (`rederivation_report.md`); attack-the-tool battery 4/4 PASS (hostile
  result JSONs, L3 destructive-smuggle REFUSED ×6, hostile-HTTP fuzz, report
  injection escaped); isolation/secrets PASS (PAT untracked, .env gitignored,
  journals carry only own-session cookies, credential evidence masked).
- **Gates after all fixes**: 142/142 (11 fresh chunks) + doctor 17/17 + bench ×3
  identical 38/0/0/37 run-3c0652b6be @2185 reqs (+241 = the paren battery, ZERO
  verdict changes) + verdict-diff vs frozen v4.2.2 NONE.

**Engine** — pure-Python-stdlib DAST engine (`sentinel/`, ~30 modules, 16 active
detectors + 2 chain phases), current version **4.3.3** (`build-v430/` is the
canonical live engine; v4.2.2 and earlier are frozen).
- Verification by **re-execution**: a finding is VERIFIED only by re-issued
  requests against the live target (19 explicit type branches, fail-closed on
  unlisted types since v4.2.0). No finding is verified by description.
- **Request journal (v4.2.1)**: passive raw capture of every request as issued
  (including session cookies) + final response after redirects, per-scan
  isolation, bounded (6000 entries / 4000-char bodies, honest dropped counter).
- Gates as of v4.2.3: tests **110/110** (104 + the six v4.2.3 discriminating
  cases), doctor **15/15**, benchmark **×3 deterministic** (F1 1.000 =
  38/0/0/37, run-3c0652b6be, 1959 requests = v422's 1944 + 15 for the
  DETECT-17 path battery) and **verdict-level diff vs frozen v4.2.2: NONE** —
  every fixture finding bit-stable, zero new false positives.
- **bench-adv v11 discriminates the fix set** (the stock 73-case bench is
  proven blind — see section 2): v4.1.1 = 38/2/0/35, F1 **0.9744** (2 FPs:
  csrf@/vuln/subscribe-echo, nosql@/api/nosql-lockout) vs v4.2.0+ = 38/0/0/37,
  F1 1.000 — same fixture/seed/run-id, x3 bit-identical.
- **v4.2.3 mechanism probes** (`build-v423/results/probe_v423_gaps.jsonl`):
  the same five gap/FP scenarios through the FROZEN v4.2.2 engine (read-only
  import) vs v4.2.3 — v4.2.2 misses both stored-XSS shapes and the URL-path
  traversal and wrongly VERIFIES both false positives; v4.2.3 verifies the
  three gaps and rejects both FPs. Raw records, generator never evaluates.

**L1 Security Twin** — normalization + provenance layer (`src/lib/twin/`),
branch `phase/02-l1-twin` (merged into main's tree).
- Suite **195/195** after the four supervisor-ordered fixes; **210/210** with
  the five real v4.2.1 live scans in REAL_FILES; determinism x3 across all 11
  fixtures; two tamper-attack batteries (E13, E14) all caught.

**L2 Attack Path Intelligence (v4.3.0)** — `build-v423/sentinel/apath.py`,
the layer ABOVE the engine (L0) and the twin (L1): strings VERIFIED findings
into complete attack paths through the seven supervisor-defined links
(Identity → Entry → Action → Object → Authorization → State → Impact).
- **The decisive rule is enforced in code and tested**: a path equals its
  weakest link; EVERY link must trace to verified evidence (finding record /
  raw journal entry / twin row / scan artifact, each with a substring-
  verifiable excerpt); any inferred link → the WHOLE path is INFERRED and the
  weak links are named. Rejected/unverified/banner findings never seed.
- Pure projection over the serialized scan report (zero requests, no engine
  imports, deterministic). Wired additively: orchestrator.report() emits
  `attack_paths` on every scan; CLI `apaths`; doctor check 16.
- Gates: **121/121** (110 engine + 10 L2 discriminating + 1 live-caught
  regression), doctor **16/16**, bench **×3 identical** 38/0/0/37 (L2 adds
  zero requests), verdict-diff vs frozen v4.2.2 **NONE**.
- **Live verification on 4 authorized targets — 20 paths: 18 VERIFIED /
  2 INFERRED, ALL on fresh-live evidence (round 7: zero projections)**,
  every link carrying a cited evidence excerpt, ALL journal
  cross-checks passed (excerpt ⊆ cited raw entry of THAT run's journal):
  - ginjuice: round-7 TARGETED fresh live scan (run-1738d74ba4, 451.9s,
    395 live req/resp pairs, freshness window PASS) — 9 paths incl. **2
    CHAINS VERIFIED** (xss_dom → tokenless cross-site state change;
    xss_reflected → same), every hop citing THIS run's journal; all 7
    seed findings re-verified live with IDENTICAL finding IDs (surface
    fingerprints are deterministic)
  - testasp: 6 VERIFIED (round-6 fresh scan, re-confirmed), gruyere2:
    2 VERIFIED + xss_stored honestly INFERRED (round-6 fresh scan,
    re-confirmed); testaspnet: round-7 targeted fresh scan — ReadNews SQLi
    VERIFIED + xss_stored honestly INFERRED (weak link: impact)
  - **not-fresh-verified register (honesty contract):** testaspnet
    Comments.aspx?id SQLi did NOT re-verify fresh — public-target content
    drift collapsed the TRUE-condition body 23962B→14880B (FALSE side
    byte-identical 13310B in both runs), differential 10652B/44% →
    1570B/10.5%, below the anti-FP threshold max(200B, 25%); the engine
    honestly declined; raw probe pairs preserved in the fresh journal
  - freshness confirmation matrix (scripts/l2_reconfirm_fresh.py, zero
    requests): all 4 targets — apaths rebuild byte-identical, single-scan
    journal windows (443–829s), 0 stale entries, citations literal;
    embedded in the report
  - artifacts: `build-v423/results/l2_live_report.md` (per-link raw
    request/response blocks, per-hop evidence, freshness matrix,
    not-fresh-verified register) + `live_v430/l2_freshness_confirmation.json`;
    round-6 projection files archived under
    `live_v430/archive_round6_projections/`

**L3 Proven Real Impact (v4.4.0)** — `build-v423/sentinel/impact.py`, the
layer ABOVE L2. For every attack path: ONE safe minimal-benign live probe
proving what the attacker ACTUALLY reaches at the end. 12 discriminating
tests (121 → 133), doctor check 17 (impact_layer), CLI `impact` (pure plan
by default; `--execute` is the only path that ever issues L3 requests —
the scan pipeline NEVER calls this layer).
- **The decisive rules, enforced in code and tested**: an impact is VERIFIED
  only via a confirming fresh probe from THIS run's own journal; reasoned-
  only → INFERRED; attempted-but-unconfirmed → PROBE_FAILED with the measured
  numbers; no safe probe exists → NOT_SAFE_TO_PROVE with the honest Arabic
  label (غير قابلة للإثبات الآمن). Safety ceiling fail-closed: SQLi =
  tautology controls + version predicates + a 2-digit ladder over DB metadata
  only; XXE/traversal = benign allowlisted files (hostname/passwd/hosts/
  win.ini) only; state change = ONE additive cart-add in OUR OWN session with
  a hostile Origin header; NEVER a destructive action, never a secret file,
  never a victim session. أُثبتت القدرة، لم تُستغَل.
- **LIVE run on the 4 authorized targets (2026-10-05): 20 impact plans /
  12 VERIFIED / 7 PROBE_FAILED / 1 INFERRED** — ginjuice 5V (own-session
  CSRF state change w/ hostile Origin; CRLF fresh-header split; open redirect
  landed on OUR OAST channel — 1 recorded interaction; DOM XSS execution
  attr_inject_onload; and the **xss_dom→csrf chain VERIFIED with BOTH legs
  fresh**), testasp 5V (4 SQL version oracles incl. both Login.asp
  auth-bypass surfaces + a win.ini read), testaspnet 1V (ReadNews version
  oracle: control pair 30554B/13444B, version pair 30608B/13552B, digit
  ladder measured null — the MSSQL version string starts with a letter),
  gruyere2 1V (traversal /etc/passwd: the fresh read shares real passwd
  lines with the original proving read).
- Every honest failure is in the register with its measured numbers
  (`results/l3_impact/l3_impact_report.md` + per-target probe journals /
  plans / assessments under `results/l3_impact/<target>/`).
- **5 live-caught product defects fixed with the L3 suite green after each**
  (see section 4): the executor dropped every query string (Parameter field
  order); str.replace corrupted cross-pair payload placement; stale
  __VIEWSTATE silently rejected (WebForms needs the submit-button field);
  traversal false-verified on shared ERROR-page boilerplate; the SQL
  template could derive from the FALSE-side vector.

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
5. **THE TRADE-OFF, stated plainly (discovered 2026-10-03/04, IV13+IV14):**
   the engine is tuned for PRECISION and this costs RECALL, in both directions:
   - **False negatives (missed real vulns):** the IV13 independent round found
     THREE real vulnerabilities the engine missed live — testaspnet stored
     XSS (tbComment; the reflected battery ships the endpoint's STALE
     __VIEWSTATE and 500s), gruyere stored XSS via signup uid (renders only on
     LATER requests — a reflected-only design is structurally blind), gruyere
     URL-path traversal (the battery was param-bound only). All three FIXED
     in v4.2.3 with discriminating tests — but they were missed for the whole
     campaign, and more like them may exist.
   - **False positives (over-claimed verdicts):** two engine-VERIFIED claims
     were wrong — ginandjuice /catalog?searchTerm "Angular XSS" (the canary
     landed inside a <script> string, which Angular never interpolates —
     verified anyway by v4.2.2) and testasp tfSearch/tfUName/tfUPass "SQLi"
     (a generic IIS 500 with NO DB error string verified as CRITICAL via
     PATH B's bare-5xx acceptance). Both mechanisms FIXED in v4.2.3
     (DETECT-15/VR-14 + VF-04); the tfSearch endpoint itself is REAL SQLi
     (reconfirmed live 2026-10-03 20:43 UTC with a boolean body-differential).
     The v4.2.3 live re-scan then demonstrated the VF-04 cost exactly as
     predicted (section 2.9): tfSearch landed REJECTED — PATH B correctly
     refused (no DB string) and PATH A did not reproduce inside the scan
     window — i.e. a live FALSE NEGATIVE accepted in exchange for killing the
     over-claim. tfUPass on the same page VERIFIED through a REAL oracle
     (oracle:or-bodydiff-2round) — real SQLi the whole time, now honestly
     channeled.
   - Net reading: F1 1.000 on the fixture means the engine agrees with the
     fixture — NOT that it agrees with reality. The only admissible recall
     evidence is independent verification (which found 3 gaps + 2 FPs in one
     round). Treat unverified-coverage claims accordingly.
6. **xss_dom packages carry browser execution steps, not journaled HTTP
   pairs**; XXE verdicts rest on OOB interaction records (public webhook
   channel), not response bytes. Both are marked as such in the file.
7. **Replay caveat:** raw pairs carry the scan session's cookies (demo/test
   accounts on authorized test sites). A reviewer replaying them may need a
   fresh authorized session of their own.
8. **VF-03 honest limitation:** not bench-discriminable through the current
   detector (detect.py already enforced the ≥max(200B, 25%) body-diff guard in
   BOTH builds); proven at mechanism level + on live targets only.
9. **VF-04 honest cost — MATERIALIZED LIVE:** PATH B now requires a DB error
    STRING. The v4.2.3 re-scan of testasp proved the trade: tfSearch (a REAL
    endpoint per IV14 raw evidence) landed REJECTED because its 500 carries
    no DB text and the boolean oracle did not reproduce in that window —
    candidate signal remains visible (rejected_candidates, conf 0.15).
    Deliberate precision-first trade per supervisor order 3, now with a live
    instance on record.
10. **No external benchmark has been run** (no OWASP/PortSwigger official suite,
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

**v4.2.3 (2026-10-04, supervisor orders 2+3)** — the three IV13 gaps + the two
adjudicated false-positive mechanisms. Evidence: six discriminating unit tests
(110/110 suite), mechanism probe `results/probe_v423_gaps.jsonl` (frozen v4.2.2
vs v4.2.3 on identical input: 3 misses -> VERIFIED, 2 over-claims -> REJECTED),
gates ×3 deterministic with verdict-level diff vs frozen v4.2.2 = NONE, and the
live re-scan (see section 5). Raw IV14 adjudication evidence:
`build-v423/results/iv14_evidence/` (stdlib-only probes, zero SENTINEL code).

---

## 4. Gaps discovered live (not papered over)

- ~~SQLi numeric-comment family absent~~ **FIXED in v4.2.2** (2026-10-03,
  supervisor-ordered): detector + verifier + discriminating test + gates +
  live doLogin VERIFIED. See CHANGELOG v4.2.2 and
  INDEPENDENT_VERIFICATION_ADDENDUM_v422.md.
- ~~Stored XSS structurally invisible~~ **FIXED in v4.2.3**: DETECT-16
  two-step flow (fresh form round-trip with rotating __VIEWSTATE/CSRF →
  canary submit → render-surface re-fetch with persistence control).
  Live-proven on BOTH surfaces: gruyere /saveprofile uid (VERIFIED,
  run-228ffb67c9) AND testaspnet /Comments.aspx tbComment (VERIFIED,
  run-3d6cf53f93 — re-test:fresh-canary-resubmit, marker survived the
  independent second fetch). Getting there took a SECOND live iteration,
  recorded honestly: the first v4.2.3 re-scan (2026-10-03 22:32) still
  missed testaspnet because ASP.NET WebForms routes the postback through the
  clicked submit button's name=value pair — POST answered 200 and silently
  discarded the comment. Fix: _StoredFormParser captures submit buttons as
  ride-along fields; full gate cycle re-run after (110/110, doctor 15/15,
  bench x3 identical, verdict-diff vs frozen v4.2.2 = NONE), then the
  re-scan verified.
- ~~URL-path traversal unprobed~~ **FIXED in v4.2.3**: DETECT-17 path battery
  from the target root + crawled directory prefixes. Live-proven on gruyere
  (VERIFIED: /<inst>/..%2f×4 etc%2fpasswd).
- **testphp.vulnweb.com + testhtml5.vulnweb.com unreachable** (shared host
  44.228.249.3 TCP timeouts; the other five targets answered from the same
  egress in the same window). Retry pending host recovery.
- **demo.testfire.net unreachable in the round-4 re-gate window** (DNS
  resolves to 65.61.137.117 but HTTP+HTTPS both socket-timeout, checked
  2026-10-03 23:0x UTC; v4.2.2's scan a day earlier succeeded — 37 verified).
  The stop-line re-gate therefore covers 4/5 targets live; testfire's engine
  path is asserted unchanged by the gate (verdict-level diff vs frozen
  v4.2.2 = NONE on the full fixture suite, which contains the testfire-class
  ASP/JSP shapes). A re-scan lands the moment the host answers again.
- **Container fragility:** rollbacks #1–#13 have repeatedly wiped `download/`
  and untracked state (6 escape-pod bundles died undownloaded) and gutted
  `.gitignore` 3+ times. Mitigated since 2026-10-03: GitHub is the primary
  durable copy; tracked content + git anchors have survived every event.
- **VF-03 not bench-discriminable** (see section 2.8) — mechanism + live only.
- ~~L2 rotating-cookie citation bug~~ **FIXED in v4.3.0 (round 6)**: the live
  cross-checks caught the identity builder excerpting the cookie header of
  the LAST proving request while citing the FIRST — on ginandjuice the AWS
  load-balancer cookie (AWSALB) ROTATES between requests, so 13 excerpts
  were not literal slices of their cited journal entries (evidence-integrity
  violation; a second, harness-side false-negative from json.dumps escaping
  was also found and fixed). Fix: the cookie value is kept PAIRED with the
  request id it was seen in — excerpt and citation always come from the same
  entry. Discriminating regression test `unit_l2_identity_citation_rotating_cookie`
  (reproduces the live shape synthetically; RED on the old code, GREEN on the
  fix); all four targets' paths regenerated; ALL cross-checks now pass. The
  live-check discipline caught a real defect the 10 unit tests missed —
  which is exactly what live verification is for.
- **L3 round 8 (2026-10-05): FIVE live-caught product defects, all fixed with
  the discriminating suite (133/133) green after each, then the full gate
  cycle re-run green at the end:**
  1. **Executor dropped every query string** — `Parameter(name, value,
     location)` was passed with the wrong field order (location is the
     SECOND dataclass field); every GET probe went out URL-less (the
     testaspnet oracle answered 200/0B pages). Caught by comparing the
     engine's rendered URL against a direct request.
  2. **str.replace corrupted cross-pair payload placement** — replacing a
     param value by global substring hit the FIRST same-value pair (the
     tbComment payload landed under `__EVENTTARGET=sentinel`). Fix: exact
     pair-swap helpers (`_swap_query_value`/`_swap_body_value`) that touch
     only the target pair, preserving every other byte.
  3. **Stale `__VIEWSTATE` silently rejected + missing submit-button field**
     — a WebForms postback replays the scan-journal body only when the
     button field (`btnSend`) rides along AND the hidden fields are FRESH.
     Fix: the planner prefers real-form entries (submit-button heuristic),
     drops `__*` pairs from the planned bytes, and the executor harvests a
     live GET before every stored_resubmit. (The app filtering the
     `<img onerror>` comment TODAY was measured honestly: PROBE_FAILED.)
  4. **Traversal false-VERIFIED on error pages** — the shared-marker rule
     matched the DOCTYPE of two identical 500 pages. Fix: the fresh read
     must be 2xx, and the planner/assessor both anchor to 2xx proving
     entries. (This was a caught FALSE verification — the class of bug the
     whole discipline exists to prevent.)
  5. **SQL template could derive from the FALSE-side vector** (control_true
     == control_false → guaranteed failure), and an arbitrary same-shape
     entry could land the oracle on a different page. Fix: TRUE-form
     normalization + a pick ranked by 2xx-first, then anchored to the
     finding's own TRUE-side size, then quoted-shape.
  Also fixed live: the CRLF split value may carry the merged next-header
  tail (`; Secure; HttpOnly`) — confirmation now accepts the expected value
  as a prefix; the redirect probe builds from the L0 verification entry
  (ginjuice's linkback UI only renders while a search is active) and
  exercises the page's own location-assigning anchor once.

---

## 5. What has NOT happened yet (as of this file's date)

0. **Round-9 honest open gaps (internal test, not external verification):**
   Juice Shop login-form params invisible (Angular-rendered form — the login-SQLi
   challenge stays unproven); basket BOLA probed but not claimed (victim-marker
   oracle needs identity markers; basket JSON carries UserId only); WebGoat XSS
   lessons produced no findings (attack1 params are quiz answers; DOM lessons need
   the browser chain); DVGA original repo deleted from GitHub (Node re-engine fork
   retained; needs PostgreSQL — not yet run); NodeGoat needs MongoDB; DVWS and
   Mutillidae need portable PHP; crAPI needs Docker (no root/docker in this env).
   These are recorded as coverage gaps, not claims.

1. **Genuinely external verification of any finding.** Rounds 3–4 ran an
   INDEPENDENT-TOOLCHAIN verification (stdlib-only, zero SENTINEL code, blind
   target selection) that confirmed 10 findings, exposed 3 real gaps + 2
   engine over-claims — all now fixed and re-proven — but it was executed by
   the same agent. **No third party (human pentester or external scanner) has
   ruled on any finding yet.** The comparison frame
   (scripts/compare_external_findings.py) is ready; runs against the agent's
   own independent list: IV13 round 6 confirmed / 3 real gaps / 17
   unconfirmed, then the round-4 re-run against the v4.2.3 re-gate scans:
   **10 confirmed / 0 gaps / 13 unconfirmed** (the three fixed gaps now match
   — two via the documented xss-bridge, one via instance-ID path
   normalization; both normalizations are transparent in the report and in
   the matcher source).
2. ~~L2 fresh re-scans of testaspnet + ginjuice~~ **DONE IN ROUND 7 (targeted
   mode)**: full-site re-scans still do not fit the 600s window (936s/620s),
   but the supervisor-ordered solution ran: TARGETED fresh live scans of
   exactly the attack-path surfaces through the shipped pipeline (discovery
   seeded to those surfaces; `stats.crawl.targeted_mode` records seeds and
   keep-rules inside each result file). ginjuice: all 7 seeds re-verified
   live. testaspnet: 2/3 seeds re-verified; the Comments.aspx?id SQLi is
   honestly NOT fresh-verified (content drift — see the register in section
   1); it stays out of the fresh L2 until the target's comment volume (and
   therefore the boolean differential) recovers above the anti-FP
   threshold. A full-site fresh scan of each remains desirable when a
   >600s window exists; the round-6 projections are archived, not deleted.
3. **testfire L2 paths** — blocked by the same target network outage recorded
   in section 4 (HTTP+HTTPS socket timeout, re-checked in round 6); re-scan
   when the host answers.
4. **The unconfirmed residue.** After the IV14 adjudication (searchTerm =
   engine FP — now dropped from the verified list; tfSearch = real endpoint,
   engine now records it as an honest rejected candidate; Templatize = real,
   re-VERIFIED live) and the round-4 re-gate, the comparison frame counts 13
   unconfirmed SENTINEL-only strong claims. A genuinely external list still
   needs to rule on them.
5. **testphp/testhtml5 scans** — not run (host outage persists, see section 4).
6. **Any customer, buyer, pilot, or market contact. Zero revenue.** Any
   valuation (including the 1–4M range discussed) is a hypothesis conditional
   on external verification + a real buyer — neither exists.

---

## 6. Save status (updated every round)

- Round-12 (2026-10-06, app 4/6 Mutillidae): ALL content committed locally (6b5662d -> 33238e4). PUSH BLOCKED — the session PAT is revoked (401 on all four auth channels, the rounds-3/4 pattern). A fresh PAT from the supervisor completes: push + ls-remote confirm.

- **Round 10 (2026-10-05, OWASP campaign app 1/6):** WrongSecrets round committed
  (5 defects OWSP-01..05 + 5 tests + gates + artifacts); push + ls-remote confirm
  executed at round close (see git log for the exact sha).

- **PRIMARY (durable): GitHub — `github.com/mememamaly-oss/Sen` (private).**
  Last verified push (ls-remote, 2026-10-03 round 2): main = release/v4.2.2 =
  v4.2.2{} (peeled) = **9bc4e95** = local HEAD. Refs on GitHub: 6 branches
  (main, phase/02-l1-twin, release/v4.1.1, release/v4.2.0, release/v4.2.1,
  release/v4.2.2), 5 tags (v4.1.1, v4.2.0, v4.2.1, v4.2.2 annotated,
  recovery/l1-candidate-2026-10-02). Earlier round: 73fb547 also landed
  (STATE.md 9cb88e3 + tasks 10/11). The round-2 PAT was inline-only; the
  owner should revoke it once the round is accepted.
- **Local:** full repo at `/home/z/my-project` (git-tracked content + all
  anchors survive every rollback). Escape pod bundle regenerated per round
  into `download/` (dies with each container rollback — r4 is current).
- **PAT security:** the 2026-10-03 token was command-line-inline only, never
  written to disk, config, or any commit; the owner was instructed to revoke
  it. Future pushes use the same inline-only protocol.
- **Round 3 (2026-10-03, IV13 independent verification):** report + 12
  evidence JSONs + comparison outputs committed locally (b367fdb, then 1e2159f
  and the relabeled bac2013). Push attempted with the round-2 PAT: REJECTED
  (token revoked as instructed); .gitignore restored from HEAD after another
  environment gutting (rollback-#13 pattern).
- **Round 4 (2026-10-04):** v4.2.3 engine + six discriminating tests + gates
   (110/110, doctor 15/15, bench x3 identical, verdict-diff vs frozen v4.2.2
   = NONE) + IV14 adjudication evidence + the live re-gate (4/5 targets green,
   testfire env-down; raw scans in build-v423/results/live_v423/ + regate
   diff JSON + comparison re-run) committed locally, tag v4.2.3 + release
   branch ready. Push was blocked only by the PAT value (session continuation
   lost the inline token, never written to disk per protocol).
- **Round 5 (2026-10-04, PUSH EXECUTED):** two supervisor PATs arrived inline.
   The first (len-93, format-valid, ...50pN) was REJECTED by GitHub itself:
   401 Bad credentials on all four auth schemes (git oauth2-URL, Bearer,
   token, basic) — the token value was dead at GitHub's end (revoked/expired);
   recorded in worklog task 16, commit 3b618be. The second PAT (fresh) worked:
   push landed main a3f2ae4..3b618be (5 commits: b367fdb IV13 round, 1e2159f
   state, bac2013 evidence relabel, 174ab6e v4.2.3, 3b618be worklog-16) +
   release/v4.2.3 (174ab6e) + tag v4.2.3 (annotated 6b724cd -> 174ab6e).
   **ls-remote CONFIRMED**: remote main = 3b618be = local, release/v4.2.3 =
   174ab6e, v4.2.3 peeled = 174ab6e, all prior refs intact (7 branches, 6
   tags). This STATE.md update is the post-push round-5 commit on top.
- **Round 6 (2026-10-04, L2 BUILT — freeze lifted by supervisor order):**
  commit 5b2eede (built in the pre-collapse continuation, recovered intact
  from GitHub after rollback #14, pushed) + commit f933549 (live verification
  + citation-integrity hotfix + regenerated paths + evidence report), both
  verified on GitHub by ls-remote. Tag v4.3.0 (f35fc2a → 8e70625) + release
  branch release/v4.3.0 landed; main closed the round at 8e70625 (ls-remote
  confirmed; rollback #15 then gutted the local tree — recovered again from
  GitHub at the start of round 7, zero files lost). The round-6 PAT is
  inline-only (never on disk); owner revokes at round acceptance.
- **Round 7 (2026-10-04, L2 EVIDENCE MADE 100% FRESH-LIVE):** incremental
  pushes, each ls-remote-confirmed: 053c6aa (ginjuice targeted fresh scan —
  9/9 paths re-proven live incl. both chains), cf7277a (testaspnet targeted
  fresh scan — honest 2/3 + the measured drift record), 52029ed (evidence
  report regenerated from fresh journals + freshness matrix + register),
  77c8e39 (full gate cycle green after the replacement), then this STATE.md
  + worklog-20 commit. Engine code UNCHANGED all round (the scans ran the
  shipped v4.3.0 pipeline; only discovery scoping was applied in-process
  and recorded inside the result files). The round-7 PAT is inline-only
  (never on disk); owner revokes at round acceptance.
- **Round 8 (2026-10-05, L3 PROVEN REAL IMPACT — supervisor order
  trace 1a107bbe20c548bd):** the L3 tests had been drafted in the pre-
  collapse continuation (uncommitted 609-line insertion); this round built
  `sentinel/impact.py` (~760 lines) to their spec, wired CLI `impact` +
  doctor check 17, then LIVE-executed on the 4 authorized targets with
  5 live-caught defects fixed (section 4) and the L3 suite green after
  each. Final register: 20 impact plans / 12 VERIFIED / 7 PROBE_FAILED /
  1 INFERRED. Full gate cycle re-run green (133/133, doctor 17/17, bench
  ×3 identical 38/0/0/37 @ 1959 reqs, verdict-diff vs frozen v4.2.2 NONE).
  Artifacts: results/l3_impact/ (per-target journals/plans/assessments +
  combined report) + scripts/l3_live_probe.py, l3_build_report.py.
  Push + ls-remote confirmation recorded in the worklog at round close.
  The round-8 PAT is inline-only (never on disk); owner revokes at
  round acceptance.

---

## ملخص عربي صادق (Arabic honest summary) — الجولة 15

ما هو مبني ومُثبت بالأرقام الآن: محرك فحص DAST بإعادة تنفيذ حقيقية (v4.3.1)
حقق على مرجعية OWASP Benchmark الكاملة (2,740 اختبارًا مُوسومًا) **دقة 100.00%
(صفر إنذار زائف عبر كل الاختبارات) مع استدعاء 68.90% وF1 = 0.816** — من 43.04%
بدقة 99.02% في الجولة السابقة. الفئات: weakrand 92.66% (أوراكل الإفصاح —
الاستجابة نفسها تُسمّي المولّد العشوائي الضعيف)، hash 89.15% (سلسلة الاقتطاع:
بالوعة كتابة مُصدَّقة تُصفّر ملف الأثر قبل كل مسبار، ثم مطابقة MD5/SHA-1
المحسوبة محليًا ضد السطر المقروء عبر بديلة قراءة ملفات مُصدَّقة)، crypto
52.31% (أوراكل ثلاثي الطبقات لحجم الكتلة + مسبار الحدّ غير المتضاعف الذي يفصل
DES عن AES/GCM تصادمًا تامًا في منحنى الأطوال)، sqli 76.10%، xss 75.61%،
pathtraver 38.35% (رفع فحص قابلية الكتابة من التداخل الخاطئ).

حدود البرهان بصراحة: 440 فائتًا متبقيًا (sqli 65، xss 60، cmdi 49، trustbound
54، pathtraver 82، crypto 62 — منها عائلة الثابت التشفيري غير القابلة للفك
صندوقيًا، hash 14، weakrand 16 — أشكال بلا نص إفصاح)؛ عائلة الثابت في crypto
مُوثّقة كمُقيدة وليست مغطاة؛ البيئة (لا docker → crAPI معلّق؛ حاويات تُمحى
باستمرار → GitHub هو الأصل الدائم).

حالة الحفظ: محليًا ملتزم ومدفوع إلى GitHub (github.com/mememamaly-oss/Sen) بعد
كل جولة مع تحقق ls-remote. هذا الملف نفسه يُحدَّث بعد كل جولة.
