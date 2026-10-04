# SENTINEL — STATE.md

**One honest file with the full picture. No marketing. If a claim is not
backed by a number or a committed artifact, it does not belong here.**

- Last updated: 2026-10-04 (UTC) — round 6 CLOSED: **L2 ATTACK PATH INTELLIGENCE BUILT, LIVE-VERIFIED, GATES GREEN, PUSHED** (v4.3.0, commits 5b2eede + f933549, main verified by ls-remote). 21 attack paths on 4 authorized targets (19 VERIFIED / 2 INFERRED by the weakest-link rule; every link evidence-cited; ALL journal cross-checks passed). One live-caught citation bug (rotating AWSALB cookie) fixed with a discriminating regression test; full gate cycle re-run green: 121/121 + doctor 16/16 + bench ×3 identical 38/0/0/37 + verdict-diff vs frozen v4.2.2 = NONE. Remaining open: testfire re-scan when the host recovers; tag v4.3.0.
- Maintained by: the engineering agent. **Update protocol: after every work round, refresh sections 1/4/5/6 with real numbers, bump this date, commit, push.**
- Audience: future engineering sessions (context is lost between sessions), the supervisor, and any future buyer performing due diligence.

---

## 1. What is built and PROVEN (with numbers)

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
- **Live verification on 4 authorized targets — 21 paths: 19 VERIFIED /
  2 INFERRED**, every link carrying a cited evidence excerpt, ALL journal
  cross-checks passed (excerpt ⊆ cited raw entry, entry exists):
  - ginjuice: 9 paths incl. **2 CHAINS VERIFIED** (xss_dom → tokenless
    cross-site state change; xss_reflected → same) — per-hop evidence
  - testasp: 6 VERIFIED (incl. both Login.asp SQLi oracles), gruyere2:
    2 VERIFIED + xss_stored honestly INFERRED (execution not demonstrated);
    testaspnet: 2 VERIFIED + xss_stored honestly INFERRED
  - per-target provenance is stamped in every file (`l2_source`): gruyere2 +
    testasp = fresh v4.3.0 live scans; testaspnet + ginjuice = v4.3.0
    projection over their REAL v4.2.3 live journals (this environment kills
    background processes and caps calls at 600s; those scans measured 936s/
    620s; engine verdict-identical per gates; equivalence proven on testasp)
  - artifact: `build-v423/results/l2_live_report.md` — per-link raw request/
    response blocks, per-hop evidence, honesty banner per INFERRED path

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

---

## 5. What has NOT happened yet (as of this file's date)

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
2. **L2 fresh re-scans of testaspnet + ginjuice in THIS environment.** L2
   itself is BUILT, gated and live-verified (see section 1) — but the fresh
   v4.3.0 re-scan could only be hosted for gruyere2 (430s) and testasp
   (505s): this environment generation kills background processes between
   tool calls and caps foreground calls at 600s, while the testaspnet scan
   measured 936s and ginjuice 620s (v4.2.3 re-gate). For those two targets
   the L2 paths are a v4.3.0 projection over their REAL v4.2.3 live journals
   (same findings, same raw requests, zero new requests; engine
   verdict-identical per the gate's verdict-level diff; projection≈pipeline
   equivalence proven on testasp which has both). A fresh re-scan of each
   lands the moment a >600s execution window exists; the projection files
   are marked `l2_source` and are honest about their provenance.
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
  verified on GitHub by ls-remote (main = f933549 at the time). Incremental
  push discipline honored: the L2 build landed on GitHub before the live
  round began; the hotfix round landed immediately after its gates went
  green. Remaining for the round: tag v4.3.0 + release branch + this STATE.md
  push. The round-6 PAT is inline-only (never on disk); owner revokes at
  round acceptance.

---

## ملخص عربي صادق (Arabic honest summary)

ما هو مبني ومُثبت بالأرقام: محرك فحص DAST بإعادة تنفيذ حقيقية (v4.2.3، 16
كاشفًا نشطًا، اختبارات 121/121، doctor 16/16، مرجعية ×3 متطابقة تمامًا
38/0/0/37 مع صفر تغيير أحكام مقابل v4.2.2 المجمّدة)، طبقة Twin أمنية
بإصلاحات المشرف الأربعة (195/195 و210/210)، **طبقة L2 لذكاء مسارات
الهجوم (v4.3.0)** — مفصولة أدناه —، منصة SaaS كاملة باختبارات عزل، وحملة
حية على 5 أهداف مصرّح بها أنتجت 171 حزمة أدلة خام (577KB).

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
حلقة مستنتجة تُنزل المسار كله إلى INFERRED وتُسمّى بصراحة. الإثبات:
21 مسارًا على 4 أهداف مصرّح بها (19 VERIFIED / 2 INFERRED بصدق —
كلاهما XSS مخزنة حيث الثبات مُثبت والتنفيذ غير مُبرهَن)، منها سلسلتان
مركّبتان VERIFIED في ginandjuice (XSS ← تغيير حالة عابر للمواقع بلا
توكن، كل قفزة بدليلها)، وجميع الفحوص المتقاطعة ناجحة (كل مقتطف شريحة
حرفية من إدخال السجل المُشار إليه). والانضباط أثبت نفسه حيًا: الفحوص
المتقاطعة اكتشفت خلل استشهاد حقيقيًا (كوكي موازن الأحمال AWSALB يتجدد
بين الطلبات فاقتُطع المقتطف من طلب وأُشير لآخر — 13 خرقًا في ginjuice)
فأُصلح باختبار انحدار تمييزي (أحمر ← أخضر) وأُعيدت دورة البوابات كاملة:
121/121 + doctor 16/16 + مرجعية ×3 متطابقة + صفر تغيير أحكام. حدود
البيئة موثقة بلا تجميل: فحصا testaspnet (936ث) وginjuice (620ث) لا
يستضيفهما هذا الجيل من البيئة (يقتل الخلفية ويحدّ الطلبات بـ600ث)،
فمساراتهما إسقاط v4.3.0 فوق سجلاتهما الحية الحقيقية من حملة v4.2.3
(نفس الطلبات الفعلية، صفر طلبات جديدة، تكافؤ الإسقاط مع خط الأنابيب
مُثبت على testasp الذي يملك النسختين) — وكل ملف موسوم بمصدره l2_source.

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
الجولات 2–5 مدفوعة ومؤكدة بـls-remote (v4.2.2 ثم v4.2.3 كاملة)،
وجولة 6 (L2) مدفوعة تباعًا فور كل إنجاز كما أُمر: بناء L2 (5b2eede) ثم
التحقق الحي + الإصلاح (f933549) — ويليها وسم v4.3.0 وفرع الإصدار
ودفعة STATE.md هذه. التوكن inline-only لم يُكتب على القرص قط؛ يُبطله
المالك عند قبول الجولة.
