# SENTINEL — STATE.md

**One honest file with the full picture. No marketing. If a claim is not
backed by a number or a committed artifact, it does not belong here.**

- Last updated: 2026-10-07 (UTC) — round 14: **THE GROUND-TRUTH PUSH (ادفع الحقيقة الأرضية) — v4.3.0, measured** — the supervisor's order "fix everything, >85% per category, a globally competitive tool" executed to its honest end for this round: the GTP detector line (11 categories, from 4), 4 live measurement rounds on the full OWASP Benchmark 2,740-test ground truth, and 16 more live-caught engine defects fixed (GTP-03b entity-encoded markers + the exists_oracle verifier branch + the >8B gate + the writability axis; GTP-04b ENV-ARRAY + DIRECT-EXEC cmdi batteries with OOB twins; GTP-05b proportional xpath margin; GTP-06b LDAP fresh wildcard (** 500s on ApacheDS); GTP-07b securecookie attribute TOKENS; GTP-08b trustbound context window + GTP-08c phase budgets 640/1024→4096; GTP-09b stateless RNG sampling — the jar replay AND the harvest, bisected over five bench runs after it cost 8 business_logic FNs on the local fixture; GTP-09b jrand 17→20-digit parse; GTP-11 JDBC/HSQLDB signatures; OWSP-36 cookie payload breaking-char encoding). **Measurement of record** (gated engine 155/155 + doctor 17/17 + bench ×3 IDENTICAL 38/0/0/37 @4784, ZERO regressions vs v4.2.6): precision **99.02%** / recall **43.04%** / F1 **0.600** / FPR 0.45% across 11 categories — per-category recall: sqli 76.1%, xss 75.6%, cmdi 61.1% (was 0), ldapi 55.6% (was 0), securecookie 52.8% (was 0), xpathi 40.0% (was 0), pathtraver 30.1% (was 0), trustbound 34.9% (was 0), weakrand 13.8% (was 0 — the LCG chain prediction works live against the real JVM: predicted '5308017114732453' observed '5308017114732453', all 25 Math.random tests caught; the relation family is implemented but did not fire live this round; nextInt/nextFloat shapes documented NOT RECOVERABLE), hash/crypto 0% — the chain design validated end-to-end on a controlled pair but BOUNDED on this target by the app's write amplification (every request appends to passwordFile.txt; the read primitive's window is the first 1000 bytes; the scanner's own battery traffic exhausts the window before the post-battery phase runs; the digest never appears in any response) — recorded as the honest not-covered bound. Scan-of-record discipline: 12 no-crawl spec chunks × 228 tests (benchmark_v430_nocrawl.sh; the reaper kills detached scans and the 600s call ceiling forced the chunk grid) + benchmark_merge_chunks.py + benchmark_eval.py; all five eval rounds committed under build-v430/results/owsp/benchmark/ (eval_v430_gtp_round1 = the RED baseline: recall 28.98%, precision 83%, 84 FPs). Round 13 before it (2026-10-07): engine v4.2.6, NodeGoat, campaign 5/6.
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
detectors), current version **4.2.3** (`build-v423/` is the canonical live engine;
v4.2.2 and earlier are frozen).
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

## ملخص عربي صادق (Arabic honest summary)

**جولة 11 (حملة OWASP — التطبيق 3/6: DVWA):** نُشر DVWA 3.x محليًا (PHP 8.5.8
ثابت + MariaDB 11.4.5 بمساحة المستخدم، مستوى الأمان low، والمصادقة مفعّلة —
المحرك يسجّل الدخول بنفسه). اكتُشفت وعُولجت **ثمانية عيوب حية** أحمر→أخضر
(OWSP-13..20)، أخطرها **عيب أمان الفاحص نفسه (OWSP-15)**: طلبُ الأساس على
نموذج تغيير كلمة المرور غيّر كلمة admin إلى الفارغ (أثبتته قاعدة البيانات
بصمة d41d8cd9) — الآن زوج كلمة المرور/التأكيد لا يُرسل متساويًا أبدًا،
والبصمة بقيت 5f4dcc3b سليمة بعد الفحص الكامل. **النتيجة النهائية: كل فئات
الثغرات القابلة للحقن على المستوى المنخفض VERIFIED** — حقن SQL ×3 (منها
العمياء عبر أوراكل انعكاس الوجود الجديد)، XSS عاكس/مخزن/DOM، رفع ملفات غير
مقيّد (multipart + فحص خدمي، دون إرسال أي ملف تنفيذي أبدًا)، حقن أوامر
(OOB)، اجتياز مسار، SSRF (OOB)، إعادة توجيه، وCSRF كمرشحين صادقين غير
مُثبتين لأن الإثبات يتطلب commit مدمّرًا يمنعه حارس الأمان بتصميم. البوابات:
164/164 + doctor 17/17 + مرجعية ×3 متطابقة (صفر تغيير أحكام) + فرق أحكام
مقابل v4.2.2 = لا شيء.

ما هو مبني ومُثبت بالأرقام: محرك فحص DAST بإعادة تنفيذ حقيقية (v4.2.3، 16
كاشفًا نشطًا، اختبارات 133/133، doctor 17/17، مرجعية ×3 متطابقة تمامًا
38/0/0/37 مع صفر تغيير أحكام مقابل v4.2.2 المجمّدة)، طبقة Twin أمنية
بإصلاحات المشرف الأربعة (195/195 و210/210)، طبقة L2 لذكاء مسارات
الهجوم (v4.3.0)، **طبقة L3 للأثر الحقيقي المُثبَت (v4.4.0)** — مفصولة
أدناه —، منصة SaaS كاملة باختبارات عزل، وحملة حية على 5 أهداف مصرّح بها
أنتجت 171 حزمة أدلة خام (577KB).

طبقة L3 (الأثر الحقيقي المُثبَت، أمر المشرف trace 1a107bbe20c548bd):
لكل مسار هجوم، مسبار واحد آمن بسيط يثبت ماذا يصل إليه المهاجم فعلًا في
نهاية المسار — لا وصفًا بل قياسًا حيًا من تشغيل نفسه. القاعدة الحاسمة
(مفروضة في الكود ومُختبرة): الأثر يُوثَّق VERIFIED فقط بمسبار حي مؤكِّد
من دورة التشغيل نفسها؛ الاستنتاج وحده يبقى INFERRED؛ المحاولة الفاشلة
تُسجَّل PROBE_FAILED بأرقامها المقاسة؛ ولا إثبات آمن موجود →
NOT_SAFE_TO_PROVE بالعبارة الصادقة «القدرة مستنتَجة، غير قابلة
للإثبات الآمن». سقف الأمان fail-closed في الكود: SQLi = عبارات تحكم
ومسندات الإصدار فقط (لا استخراج بيانات أبدًا)، XXE/الاجتياز = ملفات
حميدة من قائمة نافية فقط، تغيير الحالة = إضافة سلة واحدة في جلستنا
نحن برأس معادٍ — أُثبتت القدرة، لم تُستغَل. التنفيذ الحي على الأهداف
الأربعة: 20 خطة أثر / 12 VERIFIED / 7 PROBE_FAILED / 1 INFERRED،
كل فشل بأرقامه، ولا برهان مزيف واحد — بما فيها سلسلة xss_dom→csrf
كاملة الرجلين حيًا، وهبوط متصفح على قناة OAST الخاصة بنا. خمسة عيوب
منتج حقيقية اصطادها الاختبار الحي وأُصلحت جميعًا (منها توثيق كاذب
اكتُشف وأُبطل قبل الاعتماد) ثم أعيدت البوابات كاملة خضراء.

المقايضة المكتشفة — نقرّ بها بصراحة كاملة: المحرك مضبوط للدقة وهذا يكلفه
الاستدعاء في الاتجاهين. (1) فجوات حقيقية فاتته في الحملة: XSS مخزنة في
testaspnet (تعليق tbComment — البطارية أرسلت __VIEWSTATE قديمًا ففشل الطلب
500)، وXSS مخزنة في gruyere عبر التسجيل (تُعرض في طلب لاحق فقط — تصميم
انعكاسي فقط أعمى بنيويًا عنها)، واجتياز مسار في مسار URL لـ gruyere
(البطارية كانت محصورة بالمعاملات). الثلاث أُصلحن في v4.2.3 باختبارات تمييزية
(تفشل على v4.2.2 وتنجح على v4.2.3) وأُعيد إثباتها حيًا: فحص gruyere الجديد
يكتشف الفجوتين (xss_stored + path_traversal بحالة VERIFIED بدليل خام)،
وفحص testaspnet الجديد يوثّق XSS المخزنة في tbComment (run-3d6cf53f93،
إعادة تقديم كناري حيّ نجا من الجلب الثاني المستقل). وللوصول هناك احتاج
الأمر تكرارًا حيًا ثانيًا نقرّ به: الفحص الأول (22:32) فوّتها لأن WebForms
يوجّه الحدث عبر زر الإرسال name=value — أجاب POST بـ200 وتجاهل التعليق
صامتًا؛ أُصلح ذلك (أزرار الإرسال تصحب الطلب) وأُعيدت البوابات كاملة ثم
نجح الفحص. (2) ادعاءات خاطئة صدّقها المحرك: searchTerm في ginandjuice
(التعبير داخل
<script> لا تقيّمه Angular أبدًا — أُصلح DETECT-15/VR-14 وسقط الادعاء من
قائمة الموثّق حيًا) وtfSearch في
testasp (خطأ 500 عام بلا نص قاعدة بيانات صُدّق كـ SQLi حرجة عبر PATH B —
أُصلح VF-04 ليتطلب نص خطأ فعليًا). المفارقة الصادقة: نقطة tfSearch نفسها
حقيقية (أُعيد تأكيدها حيًا بفارق بولياني فعلي في 2026-10-03) — وكان الحكم
الصحيح ممكنًا لكن عبر القناة الخطأ؛ وبعد الإصلاح هبطت في الفحص الحي كمرشّح
مرفوض مرئي (سلبية كاذبة حية مقبولة عمدًا مقابل قتل المبالغة — توثيق القسم
2.9)، بينما رُقّي tfUPass إلى موثّق عبر أوراكل بولياني حقيقي.

L2 — ذكاء مسارات الهجوم (v4.3.0)، بُني فوق المحرك والتوأم بأمر المشرف
ورفعِ التجميد: الوحدة apath.py تصل الثغرات الموثّقة في مسارات كاملة عبر
الحلقات السبع (هوية ← مدخل ← فعل ← كائن ← تصريح ← حالة ← أثر)، والقاعدة
الحاسمة مفروضة في الكود ومُختبرة: المسار يساوي أضعف حلقة فيه — كل حلقة
تتتبع دليلًا موثّقًا (سجلّ طلب خام / سجل ثغرة / صف توأم / أثر فحص)، وأي
حلقة مستنتجة تُنزل المسار كله إلى INFERRED وتُسمّى بصراحة. الإثبات بعد
الجولة السابعة (أمر المشرف: برهان حي طازج، لا إسقاط فوق سجلات):
**20 مسارًا على 4 أهداف مصرّح بها (18 VERIFIED / 2 INFERRED بصدق —
كلاهما XSS مخزنة حيث الثبات مُثبت والتنفيذ غير مُبرهَن)، وكل مسار
يستند الآن إلى أزواج طلب/استجابة أُرسلت فعلًا إلى الهدف الحي في فحصه
المذكور atop كل قسم في التقرير**. فحصا testasp وgruyere طازجان أصلًا
وأُعيد تأكيدهما (إعادة بناء حتمية بايت-باطباق، نافذة مجلة واحدة لكل
فحص، صفر مدخلات متقادمة)، وفحصا ginjuice وtestaspnet استُبدل إسقاطهما
بفحص موجّه طازج لأسطح المسارات فقط عبر خط الأنابيب المُشحن نفسه مع
توسيع نطاق الاكتشاف مُسجّلًا داخل كل ملف: ginjuice (run-1738d74ba4،
395 زوجًا حيًا في 452ث) أعاد إثبات البذور السبع كلها بمعرفات النتائج
نفسها والسلسلتان المركّبتان VERIFIED وكل قفزة فيهما موثقة بمجلة هذا
الفحص (ترويسات date داخل نافذته)، وtestaspnet (run-4fe17c44cc، 546
زوجًا حيًا في 493ث) أثبت اثنتين من ثلاث بذور. ومسار واحد سُجّل بصراحة
في سجل «لم يُتحقق طازجًا»: SQLi في Comments.aspx — انجراف محتوى الموقع
العام قلّص جسم شرط TRUE من 23962B إلى 14880B (جانب FALSE متطابق
بايت-باطباق 13310B في الفحصين) فهوى الفارق البولياني من 10652B/44% إلى
1570B/10.5% تحت عتبة مضاد الإيجابيات الزائفة max(200B, 25%) — فرفض
المحرك شهادته بصدق، والمجسّان الطازجان محفوظان في المجلة (req-045e4187
/ req-54e20175)، ولا برهان طازج زائف. وجميع الفحوص المتقاطعة ناجحة
(كل مقتطف شريحة حرفية من إدخال مجلة الفحص الطازج المُشار إليه)،
ومصفوفة تأكيد الطزاجة مدمجة في التقرير، وملفا إسقاط الجولة 6 مؤرشفان
لا محذوفان. والانضباط أثبت نفسه حيًا في الجولة 6: الفحوص المتقاطعة
اكتشفت خلل استشهاد حقيقيًا (كوكي AWSALB يتجدد بين الطلبات) فأُصلح
باحتبار انحدار تمييزي وأُعيدت البوابات كاملة، وبعد استبدال الإسقاطات
بالبرهان الطازج أعيدت دورة البوابات كاملة مجددًا: 121/121 + doctor
16/16 + مرجعية ×3 متطابقة 38/0/0/37 + صفر تغيير أحكام مقابل v4.2.2
المجمّدة.

حدود البرهان بصراحة: 149 من الـ171 سلبيًا؛ F1=1.000 على المرجع المحلي تعني
اتفاقًا مع المرجع لا مع الواقع — الدليل الوحيد المقبول على الاستدعاء هو
تحقق مستقل، وهو نفسه (أدوات مستقلة بيد نفس الوكيل) وجد 3 فجوات + خطأين
إيجابيين في جولة واحدة؛ لا قاضي طرف ثالث بعد؛ خط التوقف أُنجز بحدود
البيئة: 4/5 أهداف أعيد فحصها حيًا خضراء (الفجوات الثلاث VERIFIED،
المبالغتان سقطتا، صفر إيجابيات كاذبة جديدة — regate_v421_vs_v423.json)
وtestfire معطّل شبكيًا في نافذة الإعادة (البوابة تؤكد عدم تغيّر أحكامه)؛
إطار المقارنة بعد إعادة التشغيل: 10 مؤكدة / 0 فجوات / 13 غير مؤكدة؛
testphp/testhtml5 ما زالا معطلين؛ لا عميل ولا مشترٍ ولا إيراد — أي تقييم
مالي فرضية مشروطة بتحقق خارجي حقيقي ومشترٍ، وكلاهما غير موجود.

حالة الحفظ: الأصل الدائم على GitHub (github.com/mememamaly-oss/Sen).
الجولات 2–6 مدفوعة ومؤكدة بـls-remote (v4.2.2 ثم v4.2.3 ثم v4.3.0
بوسمها وفرعها)، والجولة 7 (البرهان الطازج) دُفعت تباعًا فور كل إنجاز
كما أُمر: فحص ginjuice الطازج (053c6aa) ثم فحص testaspnet الصادق
(cf7277a) ثم تقرير الأدلة المتجدد من المجلات الطازجة مع مصفوفة الطزاجة
وسجل عدم التحقق (52029ed) ثم البوابات الكاملة الخضراء (77c8e39) —
ودفعة STATE.md وworklog هذه تالية. التوكن inline-only لم يُكتب على
القرص قط؛ يُبطله المالك عند قبول الجولة.
