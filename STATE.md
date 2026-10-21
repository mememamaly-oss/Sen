# SENTINEL — STATE.md

**One honest file with the full picture. No marketing. If a claim is not
backed by a number or a committed artifact, it does not belong here.**

- Last updated: 2026-10-22 (UTC) — round 25: **ORD-003 CLOSED END-TO-END — AXIS-18, the Symbolic Execution Engine: constraint extraction from application responses -> exact stdlib-only solving -> gated payload generation -> engine-sent verification -> Merkle+Ed25519 signed results, built as a purely additive package (sentinel/symbolic/, six modules each <300 lines: models/parser/solver/gates/integration/__init__) behind --symbolic (default OFF; without the flag the package is never imported — bomb-tested), with THE FOUR REGISTRATION POINTS as the only coupling surface (parse_constraints / solve_constraints / generate_payload / verify_and_sign — the package imports stdlib + itself, never the engine; sender and url_gate INJECTED).** Semantic decisions encoded in the atom suite: numeric solutions = minimal satisfying integers (age > 18 -> 19); strings deterministic ((prefix|enum|varname)+"123" extended by the 456789 cycle: len(password)>=8 -> "password123", startswith "admin" AND len>10 -> "admin123456"); "unsatisfiable" (infeasible SET) vs "contradiction" (ONE compound declaration defeating itself) as distinct honest boundaries; closed boundary vocabulary (…/tautology/complex_solver_unavailable/unresolvable_reference) — the solver never raises on unsolvable input. Signatures: Merkle-SHA256 evidence chain + RFC-8032 Ed25519 in pure stdlib arithmetic, externally verifiable from the EMBEDDED public key (recompute root AND signature; six tamper variants all rejected); THREE real crypto defects caught and fixed DURING the build (int-times-bytes keypair confusion; _encodepoint dropping y-bits 249..254; on-curve equation sign) and the clamp/scalarmult/encode primitives validated against the RFC 8032 test-1 vector (the sign path is domain-separated, so signature bytes differ from the vector BY DESIGN — disclosed). STATION CHAIN with the rollback story recorded, not hidden: the local container was found rolled back ~20 rounds (rollback #14 — the prerequisite verification against the LOCAL tree read FALSE: no build-v430/race/axis17/wire/worklog-91..113 anywhere); AXIS-18 was first built M1-RED-proven (12/12 failing) + M2/M3 green on the last real LOCAL baseline (v4.2.2) — preserved on branch axis18/draft-on-rolledback-v422 (6dcfe27) — then the push REJECTED because GitHub main (5349e47) carried the ENTIRE missing timeline (RT-fixes, AXIS-14, AXIS-17, ORD-002-WIRE CLOSED — the prerequisite was TRUE on GitHub; the local copy was the victim). AXIS-18 was TRANSPLANTED onto the recovered baseline (d99c3e7 pure additions -> bc2bc29 wiring) and re-gated from scratch on THAT tree: M-suite 20/20 (10 mandated + 2 live end-to-end through the full SentinelScanner incl. the flag-OFF bomb test and the flag-ON chain 400->"len(password) >= 8"->"password123"->engine-sent verify->200 activated->signed->report section->external verification + 8 hostile atoms). FINAL GATE (all fresh, their exact tools and anchors): pytest 230 passed + 10 skipped in 294.36s (their 230 incl. the 6 wire; the AXIS-18 20 execute at import under the house @case protocol) + bench x3 run-d6b26b92d0 (38,0,0,37) @7162/199 gt=0373baf9 — their bench_structural_compare vs the accepted anchor run-3c0652b6be: ALL IDENTICAL, MUTUAL x3, COMPARE_RC=0 (zero verdict changes — purely additive PROVEN on the recovered baseline) + doctor 19/19 (17 + symbolic_engine + symbolic_signature) + scope-edge 6/6 x3 digest c2916ba3b060f40b (station anchor intact) + THE ORDERED 4313: suite 19x227 = 4313/4313, dedup 226/226 covered (the single exclusion is the documented runner-only env stall) + live --symbolic smoke on the real fixture (scan behavior unchanged; 8 sources analyzed; honestly ZERO constraints extracted — vulnapp carries no validation prose, no guessing, no false positives; the symbolic_analysis section IS in the deposited doc, the race-pattern conditional copy). Evidence pack: build-v430/results/axis18/ (GATE_LOG + 30-file SHA256SUMS). Honest limits: the solver is deliberately bounded (linear comparisons/lengths/string shapes/enums/cross-refs; non-linear arithmetic answers complex_solver_unavailable — the honest limit of a stdlib solver); extraction covers a curated unambiguous pattern vocabulary only; "activated" (original validation error absent AND status < 400) is a path-activation fact, NOT a severity classification — AXIS-18 adds NO finding types and touches NO verifier branches by design; no with-flag benchmark mode was ordered (the with-flag proof is the live e2e + smoke, per the order's own gate list). The program: STOPPED at the ordered gate — awaiting the supervisor's approval before anything further.
- Round 24 (2026-10-21): **ORD-002-WIRE CLOSED END-TO-END — the race package WIRED into the real scan path (INTEGRATION, not a new axis): --race arms the AXIS-17 battery during a normal scan, and without the flag the package is never even imported (constraint 4, pinned by a fresh-subprocess no-load proof).** The wiring, purely additive and confined to the allowed surfaces (sentinel/race/ byte-identical — empty diff, zero package logic anywhere in it): CLI flags --race / --race-parallel N (default 10, fail-closed 1..64) / --race-variance F (default 0.005s) on BOTH scan and benchmark with a loud state-changing warning + pre-validation; ScanConfig race plumbing (defaults OFF); the orchestrator trigger _run_race_battery — register() once via the four registration points (bus / per-probe _RaceJournalProxy journal / planner_gate / signer), sensitive-endpoint selection over the ordered six categories (تحويل/دفع/حذف/تعديل/سحب/نقل — word-boundary vocabulary over path AND query), wire_plan per endpoint, the engine's real classify_operation as the planner gate (DESTRUCTIVE always rejected; --race is the operator's explicit permission for state-changing probes; every decision logged in the planner's own audit trail), the axis-14 signer (merkle over evidence_chain + compound 0x00 digest + ed25519 via proof primitives, keypair = audit.derive_keypair over the run seed), race_condition Findings (verified, HIGH, timing-variance evidence + signature evidence), honest request accounting, and the report section "race_analysis" ONLY when --race ran. Station chain: M1 RED 0/6 uniform wiring-absent pattern (digest 410f98849d26dd2e, 0c70076) -> M2 GREEN 6/6 (41a17cf098813c73, c8387f4) + full pytest 230 passed (224 prior + 6 test_wire_*) -> GATE on 322c316 (839a120): pytest 230 in 304.21s + bench x3 WITHOUT --race (38,0,0,37) run-d6b26b92d0 ALL IDENTICAL vs anchor run-3c0652b6be MUTUAL x3 COMPARE_RC=0 + bench x3 WITH --race same (38,0,0,37) with the section IN THE DEPOSITED DOC (probed=10: 4 destructive_blocked + 6 empty_parameter, race_requests=0 — every sensitive point on the fixture is transfer-family, honestly blocked by the package's own internal vocabulary gate BEFORE any send; ALL IDENTICAL vs anchor COMPARE_RC=0 — the live no-regression proof in BOTH modes) + doctor 17/17 + scope-edge 6/6 x3 digest c2916ba3b060f40b (station anchor intact). FIVE defects caught by the RED->GREEN loop and the gate itself, all fixed pre-commit and disclosed: (1) sensitive selection missed path-slash word boundaries; (2) successive probes collide on race-0000 rids in the shared engine journal — _RaceJournalProxy namespaces keys "race:" under the same JOURNAL_MAX=6000 discipline, and the wing now counts race requests by journal keys (the engine's own active batteries legitimately probe the same discovered forms — server counters cannot isolate the battery, caught live); (3) discovery records GET endpoints without their query string — the probe lost ?mode=reseed so the planner gate never saw the OWSP-21 destructive command; query params are rebuilt onto the probe URL per the engine's own _render doctrine; (4) an all-failed probe (10x404) produced race_detected=True — failure timings are not race evidence: wiring-level ok>0 gate, disclosed in section.finding_gates; (5) post-signature mutation of the section entry broke external axis-14 verification — entries are now pure res.to_dict() signed units with wiring decisions in a separate key; plus the gate-observability fix (the bench out-doc never carried the scan report's race section — 322c316, conditional so no-race docs keep their byte shape). Honest limits: the /transfer, /delete and /withdraw categories are NEVER probed (the package's own internal vocabulary list — ORD-002's literal delete/transfer order — blocks them before any send; the planner-gate layer is load-bearing for query-routed destructive commands, proven by wire case 4 on /update?mode=reseed). The program: STOPPED at the ordered gate — awaiting the supervisor's approval before anything further.
- Round 23 (2026-10-21): **AXIS-17 CLOSED END-TO-END — the Race Condition Detection Engine: TOCTOU/race exposure via concurrent requests and timing-variance analysis, built as a purely additive standalone package under the five-station gates with the standing discipline (every station committed+pushed+ls-remote MATCH YES at the moment of proof, rule #1).** The package: sentinel/race/ — __init__ 76 / engine 214 / analysis 135 / gates 228 / models 177 / integration 249 lines (all under the ordered 300-line ceiling; stdlib-only inside the package by the literal order — threading/http.client/time/json/hashlib, NO urllib even: URL splitting is manual text parsing, fail-closed on bad shapes; NO re: word boundaries via translate). The four registration points exist as the single integration surface and everything is INJECTED, never imported (the ordered test_no_engine_import scans the source: zero `from sentinel.` outside sentinel.race itself): journal (the engine's literal journal format with RT-05-redacted headers + item-3-redacted bodies), planner_gate (the engine's real classify_operation injected from outside), signer (axis-14's Merkle+Ed25519 recipe from the engine's own audited primitives, injected), bus (RaceProbe events). Station chain: M1 RED 0/10 uniform ModuleNotFoundError (digest 148849cf7043dee7) -> M2 GREEN 10/10 (17ebb3f1c2aaf4a7; two defects caught by the RED->GREEN loop itself and fixed pre-commit: models._coerce KeyError front-load, and case-9 re-isolated via 'setup' — engine-planner DESTRUCTIVE yet absent from race's internal list, so the rejection provably flows through the planner gate alone) -> M3 ATOMS 8/8 (5f0917fded934a76; two more real defects caught by the atoms and fixed pre-commit: the signer used to append to evidence_chain AFTER signing — which would invalidate the signature against the merkle-rooted published chain; and the reset fixture closed the raw socket while keep-alive refs kept the kernel socket alive so the client saw neither FIN nor RST — live-diagnosed with an isolated Errno-104 proof, then close_connection=True+flush+SO_LINGER(0)) -> the signature atom proves EXTERNAL verification from published fields alone (rebuild root + digest, ed25519_verify passes; a tampered request_count FAILS verification — the signature is load-bearing) -> M4 R3 (all fresh by order): suite 4313/4313 (19x227, dedup 227/227 exact, AGG_RC=0; the single-process full experiment reproduced its documented 226/227 port-collision artifact — the chunked gate is the record, as at ORD-001) + pytest 224/224 in 264.57s (the prior 214 + the 10 new) + doctor 17/17 + bench x3 all run-d6b26b92d0 (38,0,0,37) P/R/F1=1.0 @7162 requests, findings=199, gt=0373baf92a92dce2 — structural compare vs the accepted anchor run-3c0652b6be: path/norm-url/struct ALL EQ x3, MUTUAL x3 IDENTICAL, COMPARE_RC=0, VERDICT-DIFF vs the frozen record: NONE (the live additivity proof — the purely additive package changed NOTHING in the engine's scan behavior) -> M5 GATE (this round): scope-edge 6/6 x3 digest c2916ba3b060f40b byte-identical to the station anchor + evidence pack results/axis17/ (GATE_LOG + 29-file SHA256SUMS: RED/GREEN/ATOMS digests, 19 chunk JSONs, bench x3, scope-edge x3). Honest limits declared: (a) the redaction policy inside race/gates.py is a LITERAL COPY of the engine's RT-05+item-3 policy — a future engine policy change must update this copy manually (the single declared divergence point); (b) analysis implements the supervisor's LITERAL contract (mutating-group variance < 0.005s decides; unbiased sample variance, disclosed); (c) [SUPERSEDED by round 24: the package is now wired via ORD-002-WIRE — this line records the round-23 standing state]; (d) timings enter tests as class quanta, never raw ms — digests carry no timing or port values; (e) IPv6 only in bracket form, raw multi-colon hosts rejected fail-closed. The program: STOPPED at the ordered gate — no next axis starts without the supervisor's approval.
- Round 22 (2026-10-21): **ORD-001 CLOSED END-TO-END — the red-team remand: the three open items closed red/green on the same tree with every fix committed+pushed+ls-remote MATCH YES the moment it was proven (rule #1; e4d9159/68f616a/b48a2da).** Item 1 (RT-03/RT-04 crypto seed entropy): the run seed is os.urandom(32) hex (256-bit; core.new_run_id), the Ed25519 keypair is HKDF-SHA256 (RFC 5869, stdlib hmac, domain-separated salt+info) over the FULL >=32-byte material, and ANY seed under 32 bytes is REJECTED fail-closed at BOTH the CLI parse and the crypto layer (audit.SeedPolicyError) — the live RED reproduced the original audit exactly (a date-seeded report's key recovered from a YYYYMMDD dictionary in 2,484 candidates, then a findings-ERASED forged report VERIFIED TRUE by the external cryptography recipe) and the fix leaves the attack with ZERO candidates (a date-seeded report cannot even be signed); Axis-14 replay determinism preserved byte-identically (same seed -> same signature; proven against two independent HKDF implementations). Item 2 (RT-01 TOCTOU): the supervisor's Option A — the engine resolves ONCE, validates EVERY answer, pins the transport to the validated address, and keeps the original hostname in Host + SNI + certificate hostname validation (https never breaks TLS SNI); the live RED showed the engine FETCHING an EVIL listener's body through the second resolution, the GREEN leaves the rebind answer rejected at the pin with evil_hits=0. Item 3 (request bodies): sanitize_request_body in _journal_put — form/JSON sensitive keys -> [REDACTED] (structural walk + regex fallback), binary/multipart >= 1KB -> [BINARY_BODY_OMITTED_FOR_SECURITY], < 1KB verbatim per the ordered exception; the journal now carries the request SHAPE on both sides (headers since RT-05, bodies since this round), never the secrets. FINAL GATE (fresh, full): suite 4313/4313 (19x227, dedup 227/227 exact, port-collision-safe partition after the honest diagnosis that 17 fixture ports are each shared by exactly two cases — the platform's chunked design is structural, not stylistic) + doctor 17/17 + bench x3 ALL IDENTICAL vs the accepted anchor run-3c0652b6be (path/norm-url/struct families EQ, ZERO verdict changes; the seed's ordered growth moved the anchor run_id to run-d6b26b92d0, disclosed) + pytest 214/214 (206 + 8 new remand battery) + scope-edge 6/6 x3 digest c2916ba3b060f40b (station anchor intact) + red-team battery 5/5 standing + 3/3 new proofs, all GREEN. New standing tools persisted (the prior session left its chunk plan only in /tmp — wiped by rollback #2): scripts/rt03_seed_entropy_proof.py, scripts/rt01_toctou_proof.py, scripts/rt_body_journal_proof.py, scripts/bench_structural_compare.py, scripts/owsp/remand_gate.py. Every declared limit lives in docs/HONEST_BOUNDARIES.md (new). Honest notes inside the gate log: the single-process full-suite experiment measured 226/227 (the port-collision artifact — the chunked gate is the record; the one failing bind PASSED in its chunk), and one latent fixture wart repaired (missing b prefix, line 10998, disclosed). The program: ORD-002 may proceed on this record.
- Round 21 (2026-10-20): **AXIS-14 CLOSED END-TO-END — the independently-auditable report: every enriched report carries a Merkle root over its verified findings + an Ed25519 public key + a signature, so ANY external auditor verifies EVERY result with OPEN tools (openssl / python cryptography) and NO code access — the competitive property neither Burp Suite nor OWASP ZAP carries (the supervisor's literal order).** New module sentinel/audit.py BUILT ON the closed axes (axis-8's Ed25519+Merkle primitives; axis-11's SeededPRNG for the deterministic keypair) — never reimplementing. The declared VOLATILE_KEYS (notes/durations/stats) stripped recursively at every depth so timing-bearing content can never move the root; the empty set = the declared constant sha256(b''); the signed message = sha256(run_id \x00 root \x00 count \x00 header_canonical); the literal recipe embedded in every report AND docs/AUDIT_VERIFICATION.md. Station chain M1 RED 0/16 (uniform ModuleNotFoundError, digest f653209f) -> M2 GREEN 16/16 (6fa44ea679143cb7) + bench x3 STRUCTURALLY IDENTICAL (the live additivity proof) -> M3 ATOMS 3/3 (deac91875fa4fbc5: 45 planted cycles x2 byte-identical + bit-flip sensitive, 133 independent references, 40 adversarial exactly 12+10+8+6+4 — THE LYING REPORT class caught by the external auditor in all ten; the honest trust-model limit pinned: a consistent forgery needs the out-of-band key) with TWO fail-closed engine hardenings declared (list-only findings; NUL-byte rejection in raw fields — the encoding-overlap attack) -> M4 R3 six digests IDENTICAL x3 -> M5 GATE: 4313/4313 fresh cache-wiped + 17/17 + bench x3 IDENTICAL + the closed axes fresh (85 pytest + 8 digests DIGEST_MATCH) + scope-edge 6/6 digest c2916ba3 + red-proof + anchor a08828ee intact. Full-report reproducibility: same seed -> same run_id -> same root -> same signature (pinned e2e over two independent real scans). The program remains: axes 15 (CI/CD developer API) and 16 (OWASP Benchmark 95%+ with the documented Burp/ZAP comparison), EACH awaiting the supervisor's approval after its predecessor's M5 (the standing stop rule).
- Round 20 (2026-10-20): **AXIS-13 CLOSED END-TO-END — the modern vulnerability battery: six recent-CVE-class detectors (JWT algorithm confusion + none-acceptance, GraphQL batching, request-smuggling BY TIMING, mass assignment, prototype pollution), all built under the five-station gates with the standing discipline.** New engine module sentinel/modernsec.py (pure stdlib — the RSA public key reconstructed from the JWKS n/e by a minimal DER encoder; NO key material ever stored in a finding — the proof is the differential) + the four registration points (evidence/report/intel VR-29..34/orchestrator lazy wiring). MANDATORY differential everywhere: no differential -> no finding, only an honest boundary (TESTED_NEGATIVE / UNTESTABLE / OBSERVED_ANOMALY / NOT_DISCOVERED) — zero probes when preconditions are missing. Station chain M1 RED 0/20 (uniform ModuleNotFoundError, digest 6eef4f89) -> M2 GREEN 20/20 (dfa89987ee824c13) -> M3 ATOMS 3/3 (fb6eafe1bfd8c721: 48 planted cycles x2 passes byte-identical + bit-flip sensitive, 100 independent references, 40 adversarial exactly 12+10+8+6+4 — the lying-target class caught by the VR fail-closed in all ten) -> M4 R3 six digests IDENTICAL x3 -> M5 GATE: 4313/4313 fresh cache-wiped + doctor 17/17 + bench x3 run-3c0652b6be (38/0/0/37) F1=1.0 @7162/199 gt 0373baf92a92dce2 STRUCTURALLY IDENTICAL vs the accepted record — the LIVE no-regression proof (the six new detectors fired ZERO findings on WAVSEP) + the closed axes fresh (65 pytest + all six digests DIGEST_MATCH) + scope-edge 6/6 digest c2916ba3 with red-proof and the anchor a08828ee intact. The program: docs/SPEC_AXES_13_16.md (banked verbatim supervisor order) — axes 14 (Merkle+Ed25519 auditable report), 15 (CI/CD developer API), 16 (OWASP Benchmark 95%+ with the documented Burp/ZAP comparison) remain, EACH awaiting the supervisor's approval after its predecessor's M5 (the standing stop rule). HONEST LEDGER CATCH-UP (this file's rounds 20-25 gap): external-round-2 (X0-X3), axes 11-12, and final-round-1 (F0-F3, the first REAL external scan on scanme.nmap.org) are fully committed and evidenced in CHANGELOG.md + worklog tasks 82-85 — they were ledgered there, not here; no silent gaps.
- Round 19 (2026-10-14): **TRUSTBOUND CLOSED — the
  recall-push campaign now at FOUR categories at 100.00% (sqli, xss, cmdi,
  trustbound), precision 1.0000 across ALL (zero FP), covered-set recall
  90.33% -> 94.31% at F1 0.9707.** trustbound 38.55% -> 100.00% (83/83 TP,
  0 FN, 0 FP) on a fresh full 12-chunk re-run of the TB engine cc142b3 —
  447,834 requests, 1,498 active findings ALL VERIFIED, zero rejected;
  machine-checked ZERO regressions (every other category TP/FP and test
  lists byte-identical vs the cmdi-close eval, cross-class 54=54 identical,
  FP 0 across ALL). The seven root-cause fixes, each RED->GREEN with full
  gates, live minispec, and immediate commit+push+ls-remote (986735e the
  live-proven diagnosis first): TB-1a the self-named VALUE channel
  (35 of the 51 FNs — tcid-value 20 + raw-query-string 10 + map-read 5,
  5f1bbe4), TB-1b the header-NAME channel + the declared-nonstandard-header
  race (4, 89a2d48), TB-1c the sacrificial-tail marker for the 17-test
  last-char-mangle family (25cc789), TB-2 the all-params pass — the 01617
  wrong-param-pick (b33f2b7), TB-3a the resolver name-channel ungated (7,
  07d0db6), TB-3b the header-tcid-VALUE channel (4, c6d80f7), TB-3c the
  cookie-value channel (1 — 01876 the last, cc142b3). The battery now
  covers every diagnosed read channel: param (first+all), selfnamed,
  resolver_name, segment_name (fallback), header_tcid, header_name, cookie
  — each with plain + conditional sacrificial-tail variants and a
  channel-aware VR-25. Session context: the environment was rebuilt from
  scratch (JDK + Maven + BenchmarkJava re-cloned/rebuilt, CSV byte-identical,
  war 4,541 classes); the Tomcat 9.0.85 core verified structurally complete
  (stock 637 files, 32 lib jars, ServerInfo 9.0.85 — no re-download needed);
  stack smoke green. The assembly scripts' overwrite flaw (a complete
  artifact could be replaced by a partial download/extraction) fixed FIRST
  per the supervisor's item-0 order: tomcat_guard.sh — verified artifacts
  are never written over; the official Apache SHA-512 gates the tarball;
  extraction is temp-dir + structural-verify + atomic swap. Gates fresh this
  round: suite 4313/4313 (19/19, c00 preserved cached 227/227 per the
  supervisor's order, the other 18 re-run), doctor 17/17, bench x3
  STRUCTURALLY IDENTICAL 38/0/0/37 @7161. One display-level bug live-caught
  in tb_close_eval.py (tuple-vs-list stringification printed a spurious
  cross-class DIFFERS on identical data) — fixed, re-run clean. Per-close
  report: build-v430/results/owasp/trustbound_category_close.md; scan +
  eval: build-v430/results/owsp/benchmark/{benchmark_scan_tb_close.json,
  eval_tb_close_full.json}. Remaining covered-set FNs (73): weakrand 16,
  hash 14, securecookie 14, ldapi 14, crypto 6, xpathi 9 (pathtraver 17
  sits outside the strict covered set; with it the all-category FN total is
  90). Round 18 before it: **THE RECALL-PUSH CAMPAIGN — sqli,
  xss, and cmdi ALL CLOSED at 100.00% recall on the full OWASP Benchmark
  ground truth (2,740 labeled tests), precision 1.0000 across ALL categories
  (zero FP), covered-set recall 86.35% -> 90.33% at F1 0.9492.** The closes,
  each with its own RED->GREEN differential test, full gates, live minispec
  proof, and immediate individual commit+push+ls-remote: sqli 76.10% ->
  100.00% (272/272; SQ-1 resolver POST-form name-channel + SQ-2 callable-sink
  control), xss 75.61% -> 100.00% (246/246; XS-1 resolver name-channel, XS-2
  last-char-mangle sacrificial-tail, XS-3 the crossover), cmdi 59.52% ->
  100.00% (126/126; CM-1 the dead twin-callback harvest — form-tagged twin
  iids + one combined poll window + form-aware VR-11 replay; CM-2 the absent
  name-channel battery — three nc OOB forms riding the param NAME on renamed
  clones, self-identifying oob-<12hex> iids embedded in the payload-name,
  nc-replay VR; CM-2b the wall-time fix — the LOCAL-channel poll budget
  0.15s -> 0.0, live-caught when chunk 00458_00686 blew the scan budget).
  Every close re-ran the FULL 12-chunk benchmark (390,703 requests on the
  cmdi close) with machine-checked ZERO regressions: every other category's
  TP/FP and test lists byte-identical, cross-class 54=54 identical, FP 0
  across ALL. Full taxonomy tables + per-close reports:
  build-v430/results/owsp/{sqli,xss,cmdi}_category_close.md; evals under
  build-v430/results/owsp/benchmark/eval_*_close_full.json. Session-baseline
  repair on record: the previous session's "token lost git-protocol access"
  diagnosis was WRONG — the origin URL had been environment-rewritten to
  mememaly-oss/Sen (owner typo); fixed to mememamaly-oss/Sen. Remaining
  covered-set FNs (124): trustbound 51, weakrand 16, hash 14, pathtraver 17,
  securecookie 14, ldapi 14, crypto 6, xpathi 9. Round 17 before it (2026-10-08): v4.3.3 GraphQL STORED-XSS +
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

**Round 21 (2026-10-20) — AXIS-14 CLOSED: the independently-auditable report, zero regressions.**
The report layer: merkle_root over the verified findings (leaf = sha256(canonical JSON), volatile keys stripped recursively at every depth; pairwise sha256(L||R) dup-last-on-odd; empty = sha256(b'')); the keypair derived deterministically from the run seed (same seed = same run_id = same root = same signature — pinned e2e over two independent real scans); the signature = Ed25519 (RFC 8032, axis-8 primitives) over sha256(run_id \x00 root \x00 count \x00 header_canonical); the literal open-tools recipe (python cryptography + openssl pkeyutl with the hand-built SPKI PEM) embedded in every report AND docs/AUDIT_VERIFICATION.md. Verified live: the external-auditor flow (independent recompute -> root match -> signature verify) and the lying-report class (tampered after signing — all ten forms caught). Honest trust-model limit pinned: a fully consistent forgery needs the out-of-band public key. Two fail-closed hardenings: findings must be a LIST; NUL bytes rejected in raw fields (the encoding-overlap attack). Gates: suite 4313/4313 fresh (c03=285s c07=211s), doctor 17/17, bench x3 STRUCTURALLY IDENTICAL @7162/199 gt 0373baf92a92dce2, scope-edge 6/6 digest c2916ba3 + red-proof, anchor a08828ee intact. Deposits: results/axis14/ (9 evidence files + SHA256SUMS, 11 files verify OK) + the gate/bench logs.

**Round 20 (2026-10-20) — AXIS-13 CLOSED: the modern vulnerability battery, six families, zero regressions.**
Per-family at the M5 gate: jwt_algorithm_confusion (SEN-JWT-002, HIGH, proven — RS/HS confusion, the verifier accepts an HS256 token signed with the PUBLIC key PEM body while rejecting the corrupted control), jwt_none_acceptance (SEN-JWT-003, HIGH, proven — the verifier honors alg=none with an empty signature while rejecting the corrupted original; both-accepted -> OBSERVED_ANOMALY, never a finding), graphql_batching_enabled (SEN-GQL-008, LOW, indicated — arrays of read-only ops execute, rate-limit-bypass surface), http_request_smuggling (SEN-SMK-001, MEDIUM, indicated — CL+TE raw-socket timing pair, threshold max(3x control, 500ms), quantized classes desync/below-threshold/rejected-ambiguous, pipeline corruption NEVER attempted), mass_assignment (SEN-MA-001, HIGH, proven — a privilege-shaped param with a FABRICATED canary value persisted via state-oracle on the scan's OWN session objects, never a real privilege), prototype_pollution (SEN-PP-001, HIGH, proven — __proto__ merge + reflection oracle; the DOM variant declared out of the default scope). All six carry VR-29..34 fresh-replay branches in the fail-closed verifier. Gates: suite 4313/4313 (fresh, cache-wiped, the heavies c03=285s c07=211s), doctor 17/17, bench x3 STRUCTURALLY IDENTICAL @7162/199 gt 0373baf92a92dce2, scope-edge 6/6 digest c2916ba3 + red-proof, anchor a08828ee intact. Deposits: results/axis13/ (7 evidence files + SHA256SUMS, verify OK) + results/gate_axis13_dfa89987.log + bench log. Pre-existing NOT rebuilt (the spec 0.2 disclosure): jwt_security issuance (DETECT-18/VR-15) + graphql_introspection_enabled (SEN-GQL-001).

**Round 19 (2026-10-14) — trustbound CLOSED at 100.00%, zero regressions.**
Per-category recall at precision 1.0000 (fresh full 12-chunk run on the TB
engine cc142b3, campaign honesty rules, machine-checked zero-regression vs
the cmdi close): trustbound 100.00% (83/83 — from 32/83 = 38.55%), joining
sqli/xss/cmdi at 100.00%; covered-set recall 90.33% -> 94.31%, F1 0.9707,
FP 0 across ALL categories. The close merged 447,834 requests across 12
chunks (+57,131 vs the cmdi close = the 7-channel trustbound battery:
param first+all, selfnamed, resolver_name, segment_name, header_tcid,
header_name, cookie — each plain + conditional sacrificial-tail); 1,498
active findings ALL VERIFIED, zero rejected; the trustbound TP set = the
cmdi-close TP+FN union EXACTLY, cross-class 54=54 identical, every other
category's counts AND test lists byte-identical (tb_close_eval.py, rc=0).
The seven fixes (TB-1a/1b/1c/2/3a/3b/3c — see the header and
results/owasp/trustbound_category_close.md for the full 51-FN taxonomy)
each shipped earlier with RED->GREEN differential units, full gates, live
minispec proof, and immediate individual commit+push+ls-remote. Gates
re-proven fresh at the close: suite 4313/4313 (c00 preserved cached
227/227), doctor 17/17, bench x3 STRUCTURALLY IDENTICAL 38/0/0/37 @7161.
The remaining FN inventory: covered-set 73 (weakrand 16, hash 14,
securecookie 14, ldapi 14, crypto 6, xpathi 9) + pathtraver 17 outside the
strict covered set = 90 across all 11 categories.

**Round 18 (2026-10-13/14) — the recall-push campaign, PROVEN at 100% on three
categories.** Per-category recall at precision 1.0000 (fresh full 12-chunk
runs, campaign honesty rules, machine-checked zero-regression vs the prior
close): sqli 100.00% (272/272), xss 100.00% (246/246), cmdi 100.00% (126/126);
covered-set recall 90.33%, F1 0.9492, FP 0 across ALL categories. The cmdi
close merged 390,703 requests across 12 chunks; 1,447 active findings ALL
VERIFIED, zero rejected. The remaining FN inventory (124, by category):
trustbound 51, pathtraver 17, weakrand 16, hash 14, securecookie 14, ldapi 14,
crypto 6, xpathi 9. Every fix shipped with a staged differential test
(RED on the unpatched engine recorded, GREEN after), full gates (suite
19/19, doctor 17/17, bench x3 structurally identical 38/0/0/37), a live
minispec on the running BenchmarkJava 8b67a88 stack, and the complete diff
pasted into worklog.md as the text backup.

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

- **ROLLBACK #14 (2026-10-22, the round's defining event — recorded in full):**
  the local container had been rolled back ~20 rounds (to the v4.2.2-era
  tree f2d41e8): every local trace of rounds 5..24 (RT-fixes, AXIS-14,
  AXIS-17, ORD-002-WIRE, worklog 91..113, STATE rounds 5..24) was GONE
  from disk while GitHub main (5349e47) carried it all. The session first
  verified ORD-003's prerequisite FALSE against the local tree and built
  AXIS-18 on the stale baseline; the push rejection exposed the truth.
  Mid-session, the environment rolled back TWICE more (a branch checkout
  vanished; git index/working-tree incoherence; a push reported
  "up-to-date" while the remote ref lagged). Mitigation per standing
  protocol: every step committed and pushed to GitHub immediately; the
  stale-baseline draft preserved on its own branch for audit; main never
  force-pushed. The final tree was re-gated from scratch on the recovered
  baseline — no number in this round comes from the stale tree.
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

0. **The extension program (axes 15-16) — registered, NOT built (docs/SPEC_AXES_13_16.md):**
   axis 15 (the CI/CD developer API surface — the stable semver surface with
   the literal exit-code contract 0/1/2), axis 16 (the OWASP Benchmark push from
   the committed round-19 baseline — full-set 93.64% = TP 1325 / FN 90 of 1415
   vulnerable, at precision 1.0000 — to 95%+ with the documented Burp/ZAP
   comparison). EACH awaits the supervisor's approval after its predecessor's
   M5 — the standing stop rule; no silent starts.

1. **Round-9 honest open gaps (internal test, not external verification):**
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

- **Round 5 save-state entry (2026-10-22, AXIS-18 / round-25):** work
  secured on GitHub as it happened (the rollback-#14 protocol): branch
  axis18/draft-on-rolledback-v422 @ 6dcfe27 (the complete stale-baseline
  build incl. its own evidence + ledgers, kept for audit); branch
  axis18-real @ bc2bc29+ (transplant onto 5349e47 + gates + ledgers);
  main UNTOUCHED at 5349e47 until this gate's merge. Round-4 PAT used
  inline-only per protocol (never on disk/config/commits).

- **Round 27 (2026-10-16, Axis-3 mounted — PCS):** supervisor order:
  Part A bank the round-26 axis-1 .log deposits + Part B axis-3 under the
  M1–M5 station protocol. 8TH CONTAINER ROLLBACK on arrival (full-snapshot
  to the IV13 era: worklog 923, build-v430 absent, download/ absent,
  /tmp wiped) — standard realignment executed (fetch on the session PAT,
  six-fold redundancy proof of the stale f2d41e8 chain, reset --hard
  e42d4bb, .env restored untracked, 11/11 tags). PART A BLOCKED, AWAITING
  RULING: the three round-26 files (gate/bench_3c0652b6be.log,
  axis1_digest.log — created under the round-26 no-commit freeze, never
  committed anywhere) were DESTROYED by the 8th rollback before the
  banking order arrived; byte-identical banking is impossible. Their
  sha256sums are on record (2dd59286…/1f08a73e…/85f39fe9…). Options
  presented: (a) accept the already-banked axis-2 M5 deposits (committed
  e42d4bb, same gate contract on the superset tree) as the durable
  closure evidence, (b) regenerate axis1_digest.log from the committed
  axis-1 JSONs (content reproducible, marked regenerated), (c) fresh
  axis-1-shaped gate re-run with new .log deposits. Dev-time reference
  work (declared): pip install blake3 (the official package) used ONLY as
  a validation oracle — the pure-Python implementation validated 0
  mismatches over 30 vectors + 200 random; committed code has zero new
  dependencies. Station M1 (RED): tests/test_axis3_pcs.py — 28 cases
  H3_01..H3_28 covering §3.1–§3.8 + the --atoms battery (3a 12,000
  events / 3b 1,000 datasets / 3c 500 schedules / 3d 80 adversarial
  stores / 3e 500 histories) — executed BEFORE implementation: **0/28,
  digest 9190527d4eb85234** (results/axis3/axis3_RED.json), committed
  "axis3: red" and pushed immediately. M2 (GREEN): sentinel/blake3.py +
  sentinel/pcs.py implemented — 28/28, digest ec1626c7e0cd1809; the
  merge-laws battery caught ONE REAL module defect (VectorClock merge
  dropped zero-valued components from the second argument, breaking
  commutativity — fixed); five test-side bugs also fixed and documented.
  M3 (atoms): 3a 12,000 events/16,574 direct edges/1,999 transitive
  samples ZERO violations; 3b 1,000 datasets/32,248 leaves every proof
  verifies + every bit flip detected + 25 full 256-bit sweeps zero
  escapes; 3c 500/500 schedules converge + 100 law triples; 3d 80/80
  forgeries caught (100%, zero escapes, five classes); 3e 500 histories/
  25,930 read_at checks 0 wrong — chain digest 0ce206c1ad60caba. M4
  (determinism): R3 triple-run identical digests ec1626c7e0cd1809 (the
  M3 CHANGELOG ledger line was missed by a failed text anchor and banked
  honestly at the M4 commit). M5 (gate, CLOSURE): full gate fresh on
  the axis-3 tree — suite 4313/4313 (19/19 chunks 227/227), doctor
  17/17, bench ×3 38/0/0/37 F1=1.0 @7161/199 run-3c0652b6be structurally
  identical tuple-by-tuple — zero core drift; mandated .log deposits +
  SHA256SUMS committed (gate_axis3_3c0652b6be.log, bench_axis3_3c0652b6be.log).
  Station chain: 604f56c (M1) -> 025d368 (M2) -> 363c6a0 (M3) ->
  ff65a85 (M4) -> M5. AXIS 3 CLOSED end-to-end. Axis 4 (channel
  synthesis per the phase-2 roadmap) queued pending the supervisor's
  reply.


- **Round 26 (2026-10-15, Axis-2 mounted — station protocol M1–M5):**
  supervisor amendment: every clean station commits isolated and pushes
  immediately (no waiting for the axis end); any push failure = stop and
  report. Pre-work: 7th UUID noise commit (41036fd) proof-checked (six
  oob-* markers only, parent = 1bc184b) and discarded per precedent.
  Station M1 (RED): tests/test_axis2_statemachine.py — the 24-case table
  H2_01..H2_24 literally (S/s0/Σ, δ literal-8 + atomic rejection, C1–C6,
  Λ∈ℝ⁴ + Σw=1 + V∈[0,1] + weight effects, A* golden/admissible/consistent,
  replay/verify_invariants/interface/Γ, 14-category boundary log, digest
  stability) + the --atoms M3 battery — executed BEFORE implementation:
  **0/24, digest 10bd2caf36e107be** (results/axis2/axis2_RED.json),
  committed "axis2: red" and pushed immediately. M2 (GREEN):
  sentinel/statemachine.py implemented §2.1–§2.8 — 24/24 first-shot,
  digest 9634780aa1712d12 (one test-side keyword-arg bug caught in
  pre-run review; no implementation defects). M3 (atoms): the exhaustive
  3a/3b/3c battery **431/431 checks** (3a 126 state atoms, 3b 182
  transition atoms incl. all 48 illegal pairs, 3c 123 value atoms),
  digest 9217f3b19e1d7e79 — two bugs caught were in the battery's own
  tooling, module innocent, suite digest regression-checked unchanged.
  M4 (determinism): R3 triple-run identical digests 9634780aa1712d12
  (RUN2/RUN3 byte-identical files). M5 (gate, CLOSURE): full gate fresh
  on the axis-2 tree — suite 4313/4313 (19/19 chunks 227/227), doctor
  17/17, bench ×3 38/0/0/37 F1=1.0 @7161/199 run-3c0652b6be
  structurally identical tuple-by-tuple vs the accepted record — zero
  core drift; mandated .log deposits + SHA256SUMS committed
  (gate_axis2_3c0652b6be.log, bench_axis2_3c0652b6be.log). Every station
  committed isolated + pushed immediately + ls-remote-verified:
  e2655fa (M1) → 3bc547c (M2) → 85e760b (M3) → 3ccc802 (M4) → M5.
  AXIS 2 CLOSED end-to-end. Axis 3 (PCS: BLAKE3/MessagePack/Lamport/
  Merkle/CRDT/MVCC per the phase-1 roadmap) queued pending the
  supervisor's reply.

- **Round 25 (2026-10-15, Axis-1 mounted — the 12-axis spec program
  begins):** supervisor order: mount the axes one by one, red/green tests
  first, full gate, immediate push, wait for the reply between axes.
  Axis 1 (execution-graph engine) landed: sentinel/xgraph.py (spec §1.1–§1.8
  complete — W1–W6 validation, Kahn Θ(V+E), layered decomposition, BSP
  parallel executor with barrier-proven supersteps, O(1) COW forks,
  speculative branching with argmax-V merge, adaptive pruning
  k_adaptive=⌈⌈log₂|V|⌉·(1+ε)⌉ into the 14-category boundary log,
  snapshot/restore with semantic digests) + a STANDALONE 22-case suite
  (not @case-registered — the 4313 contract untouched by construction).
  RED 0/22 executed first; the W-condition tests then caught two REAL
  validate() defects (Kahn mutating the shared indeg array corrupting the
  W3 source count; reachability BFS walking predecessors) — fixed; GREEN
  22/22; R3 triple-run digests identical (cc84a91a…). Full gate fresh on
  the mounted tree: suite 19/19 = 4313/4313, doctor 17/17, bench ×3
  38/0/0/37 F1=1.0 @7161/199 STRUCTURALLY IDENTICAL (run-3c0652b6be) —
  zero drift, machine-proven. A 4th environment UUID noise commit
  (443a3a1) was proof-checked and discarded pre-work (7614ee5 precedent).
  Hot-path rewiring deferred to phase-1 close (axes 1+2+3+12). Axis 2
  queued pending the supervisor's reply. PAT inline-only, owner revokes
  on acceptance.

- **Round 24 (2026-10-15, cleanup file CLOSED — supervisor closure
  order + the 5th rollback):** local release/v4.1.1 (2d5ce2f) deleted
  after fresh proof (main-ancestor, 0-ahead, tag v4.1.1 at tip); the 4
  phantom refs a mid-turn 5th container rollback resurrected
  (phase/02-l1-twin, release/v4.2.0/v4.2.1/v4.2.2 — tips identical to
  the task-58 ratified deletions) re-proven and re-deleted, completing
  the sanctioned state. Realignment per protocol: fetch → 6-part
  redundancy proof fresh on the same stale commit f2d41e8 (1 unique
  commit; parent in main; iv_out byte-identical; worklog byte-exact
  prefix; .env identical — 100% redundant, matching the ratified
  task-58 audit) → reset --hard 5fd9301, .env restored untracked,
  NO backup branch re-created (would resurrect a ref the ratified
  order removed). Tags restored 11/11. FLAGS CLOSED BY RULING: the 4
  remote archive/* branches = KEEP (final); the remaining task-54
  classes (owsp, evidence generators, tags, report outputs) = KEEP
  (final). END STATE: local branches = main only; remote = main + 4
  kept archive/*; zero history rewrites. Records-only commit; full
  gate fresh on the engine-identical tree per protocol; PAT
  inline-only, owner revokes on acceptance.

- **Round 23 (2026-10-15, round-23 close — task-58 remote half on the
  round-4 PAT + fresh gate verification):** the staged remote half
  executed: origin/release/v4.1.1 (2d5ce2f, machine-proven main-ancestor
  + 0-ahead + tag v4.1.1 at tip — deletion orphans nothing) deleted from
  the remote; main pushed 5373107..29ae5e7; both ls-remote confirmed
  (remote main = 29ae5e7 = local, release/v4.1.1 gone from refs/heads).
  The full gate had run fresh in-container on the task-58 tree
  (08:58–09:24, artifacts intact in /tmp): suite 19/19 = 4313/4313
  (every chunk 227/227, failed=0), doctor 17/17 (overall=PASS), bench ×3
  = 38/0/0/37 F1=1.0000 @7161 requests / 199 findings — three runs
  structurally identical tuple-by-tuple (run-3c0652b6be, ground_truth
  sha identical). One more environment UUID auto-commit (984a934 — six
  one-line build-v430/oob-* "ok" markers = the fixture's XXE-OOB
  endpoint runtime output; main tracks zero such files; 7614ee5
  precedent) discarded by reset --hard after the proof, SHA recorded
  for audit. Branch state: local = main + release/v4.1.1 (the local
  copy kept per the order's exact scope — flagged); remote = main + 4
  archive/* (out of scope, kept, flagged). Zero history rewrites; this
  record commit is the only tree change; the PAT is inline-only, owner
  revokes on acceptance.

- **Round 22 (2026-10-15, the branches cleanup — the supervisor's
  item-by-item call on the task-54 KEPT "branches" class):** 5 local
  branches deleted, each machine-proven redundant FIRST —
  release/v4.2.0/v4.2.1/v4.2.2 (0 commits ahead of main, preserving tags
  at tips), phase/02-l1-twin (0 ahead; recovery/l1-candidate-2026-10-02
  inside its history; tip reachable via main), and
  backup/stale-f2d41e8-20261015 (the last surviving realignment backup:
  its one unique commit = the stale UUID snapshot — .env byte-identical
  to the live untracked copy, 31 iv_out files byte-identical to main,
  923-line worklog a byte-exact prefix of main's — 100% redundant).
  Local release/v4.1.1 not in the order's scope — left standing, flagged.
  Remote origin/release/v4.1.1 + push + ls-remote staged pending the
  round-4 PAT (round-3 owner-revoked on acceptance per protocol).
  Zero history rewrites; one isolated record commit; full gate re-run
  fresh per directive (engine tree untouched — records only).

- **Round 21 (2026-10-15, post-hardening closure — cleanup + Q1/Q2 + the
  4th rollback):** supervisor item-2 executed — the repo cleanup as the
  DETERMINISTIC subset of the task-54 inventory (148 files, one isolated
  commit): old gate generations + old suite runners + v4.1-era
  juice/determinism + one-off debug/probe/gj/phase/save generators, the
  v1-v3 old results EXCEPT the AR report deliverables (kept), snapshot-0419
  and pkg-v301 whole. Everything whose per-item approval died with the lost
  session was KEPT and listed pending in the worklog (owsp beyond the
  protected chain, branches, tags, evidence generators) — zero history
  rewrites, deletions are git-rm only. Full gate re-run GREEN on the
  cleaned tree, fresh: suite 19/19 = 4313/4313, doctor 17/17, bench x3
  STRUCTURALLY IDENTICAL 38/0/0/37 @7161/199 — the cleanup provably touched
  zero gate dependencies. Q1 closed (all gates ran post-edit; red-before is
  impossible by construction for a provenance-only refactor — the applicable
  differential, pre/post bench structural identity, is machine-proven);
  Q2 closed by order: 4332 was a narrative error of a lost session (zero
  record trace), 4313 is the fixed number everywhere (19 chunks x 227
  registered @case). A 4th mid-turn container rollback wiped the previous
  turn's local work — everything was redone and every step pushed at
  completion (f16dd73 worklog carry-over, 4d9c61e cleanup, then this entry);
  alignment discipline held (no merge, no force-push; stale preserved in
  backup/stale-f2d41e8-20261015). The session PAT is inline-only, owner
  revokes on acceptance.

- **Round 20 (2026-10-15, the hardening round — supervisor item-1):** the
  `passed=True -> observed variable` hardening of `build-v430/sentinel/intel.py`
  implemented FROM SCRATCH on the verified base (task 53 proved it never
  existed before): 8 oracle sites now stamp the observed boolean
  (PATH A=stable, D=okD, C=okC, C'=bool(num_redirect or num_body),
  D2=okD2, E=okE, csrf=okVR13, nosql-js=js_flip); the
  `_PRESENCE_VERIFIED_TYPES` single-response allowlist is the ONE
  deliberate exemption (VF-01 design) and was NOT touched, per the
  supervisor's own ruling. Zero behavioral drift machine-proven, not
  claimed: suite 19/19 chunks = 4313/4313 fresh, doctor 17/17, bench x3
  STRUCTURALLY IDENTICAL 38/0/0/37 @7161 requests / 199 findings tuples —
  the exact task-53 f0ae716 record. Base re-verified this session:
  origin/main = 941559a (worklog-only commits on top of f0ae716); the
  stale f2d41e8 snapshot re-preserved in backup/stale-f2d41e8-20261015;
  no merge, no force-push. The Arabic summary below lags at round 15
  (pre-existing — its numbers are the v4.3.1-era snapshot, kept for the
  record). Push + ls-remote at round close; the session PAT is
  inline-only, owner revokes on acceptance.

- **Round 19 (2026-10-14, the trustbound close):** the seven TB fix commits
  (TB-1a 5f1bbe4 / TB-1b 89a2d48 / TB-1c 25cc789 / TB-2 b33f2b7 / TB-3a
  07d0db6 / TB-3b c6d80f7 / TB-3c cc142b3, after the 986735e diagnosis) were
  each pushed individually with ls-remote confirm in their own sessions
  (origin/main = cc142b3 verified at this session's fetch). This session
  pushed the close round: the round tooling + the stack-assembly no-clobber
  fix (tomcat_guard.sh — the supervisor's item-0 order) and the trustbound
  category close itself (the merged 12-chunk scan benchmark_scan_tb_close.json
  + eval_tb_close_full.json + trustbound_category_close.md + STATE.md +
  worklog) — both commits ls-remote-confirmed at push time (see the worklog
  for the exact hashes). The session PAT is inline-only (never on
  disk/config/commits); the owner revokes it on round acceptance per
  protocol.

- **Round 18 (2026-10-13/14, the recall-push campaign):** ALL content pushed
  with ls-remote confirm after EVERY commit (the standing one-fix-one-push
  discipline): sqli closes (SQ-1/SQ-2 + the sqli category close), xss closes
  (XS-1/XS-2/XS-3 + the xss category close d3ab1bf), cmdi closes (CM-1
  efdf314 + the blocked-push honesty record 0af0fc6 + CM-2 7248c4d + CM-2b
  c3753bf + this cmdi category close). One environment event on record: the
  origin remote URL was rewritten to mememaly-oss/Sen during the rollback
  chaos (the owner name missing "ma") — every git operation failed with
  "Repository not found" and the previous session misdiagnosed it as a token
  failure; repaired at session start, the blocked CM-1 pushed, verified by
  ls-remote. The session PATs are inline-only (never on disk/config/commits).

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

## ملخص عربي صادق — الجولة 25: AXIS-18 محرك التنفيذ الرمزي (ORD-003، 2026-10-22)

أُغلق ORD-003 من البداية للنهاية على الأساس الحقيقي المسترد: حزمة إضافية بحتة
(sentinel/symbolic، ست وحدات كلٌّ أقل من 300 سطر، stdlib فقط — لا Z3 ولا angr)
خلف علم --symbolic معطّل افتراضًا (بدون العلم لا تُستورد الحزمة أصلًا — مثبت
باختبار القنبلة). السلسلة: استخراج قيود التحقق من الاستجابات (نصوص الأخطاء +
فروق رموز الحالة) -> حل رياضي دقيق (أعداد صحيحة دنيا، توليد نصي حتمي
«password123»/«admin123456»، حدود صادقة مغلقة: غير قابل للتحقيق / تناقض /
مقدَّم الصدق / معقد) -> بوابة تحظر القيم التدميرية قبل أي طلب -> تحقق يُرسل
عبر كامل ركب المحرك -> توقيع Merkle + Ed25519 قابل للتحقق الخارجي.

قصة هذه الجولة بصراحة كاملة: الحاوية المحلية كانت مرتدة ~20 جولة — تحقق
الشرط المسبق ضد القرص المحلي قرأ «غير موجود»، فبُني المحور على أساس v4.2.2
المحلي القديم أولًا، ثم كشف رفضُ الدفع أن GitHub يحمل الخط الزمني كاملًا
(RT/AXIS-14/AXIS-17/ORD-002-WIRE — الشرط كان صحيحًا على GitHub والنسخة
المحلية هي الضحية). نُقل العمل (Transplant) إلى الأساس المسترد 5349e47
وأُعيدت كل البوابات من الصفر عليه: 20/20 محور-18 + pytest ‏230 (و20 تُنفَّذ
عند الاستيراد) + bench×3 مطابقة بنيويًا مع المرجع المقبول (صفر تغيير أحكام)
+ الفاحص 19/19 + حدود النطاق 6/6×3 بهضم المرساة + المجموعة المطلوبة
4313/4313 + فحص حي بقسمٍ موثّق في الملف المودع وصفر قيود مستخرجة من vulnapp
(لا تخمين ولا إيجابيات كاذبة). المسودة القديمة محفوظة كفرع للتدقيق، وmain
لم يُلمس حتى بوابة هذه الجولة. حدود صادقة: الحلّاد خطي فقط (المعقد يُجاب
بحدٍّ صادق)، والاستخراج لأنماط منسّقة فقط، و«activated» و fact تفعيل مسار
لا تصنيف خطورة — لا أنواع Findings جديدة ولا فروع تحقق معدّلة. البرنامج:
متوقف عند البوابة المأمورة بانتظار موافقة المشرف.

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

---

## ملخص عربي صادق (Arabic honest summary) — الجولة الخارجية 1 (2026-10-16)

ما جرى بالضبط (القرار الحدودي للمشرف مُلزم): اختبار "المراجع المشروعة" يقيس
الماسح الحالي = المحرك الأساسي + المحاور 1–3؛ المحاور 4–12 غير مبنية؛ المرجع
الكمي الرسمي WAVSEP. القائمة المغلقة: 3 أهداف حرفيًا فقط.

- الاستعادة (المرحلة 0.5): انقلاب عاشر مؤكد وموثق؛ reset --hard إلى
  origin/main=867dbf5 بصفر فروق بعد برهان زائدية الالتزام الغريب. أداتان
  أعيد بناؤهما والتُزمتا ودُفعتا فورًا (bench_structural_compare نسخة ثالثة
  + مولد digest المحور الأول) — قاعدة "لا أداة عارية على القرص".
- الجزء أ: axis1_digest.log مُعاد توليده من JSONs المحور الأول الملتزمة
  حصرًا، موسومًا "regenerated from committed evidence" — cc84a91a ×3 متطابق،
  RED cf2b6a57 0/22.
- الميثاق (R): التزام + دفع قبل أي اتصال خارجي إطلاقًا.
- T1 (WAVSEP محليًا، إلزامي): بوابة طازجة كاملة — suite 4313/4313 (19/19
  مقطعًا، كل مقطع 227/227، صفر فشل) + doctor 17/17 + bench ×3 =
  run-3c0652b6be (38/0/0/37، F1=1.0، @7161 طلبًا / 199 tuple، gt
  0373baf92a92dce2) متطابق بنيويًا tuple-by-tuple مع السجل المقبول — صفر
  انحراف. الإيداعات .log ملتزمة (git add -f) + SHA256SUMS.
- T2 (testphp.vulnweb.com): محجوبة بصدق — الهدف غير قابل للوصول من هذه
  الشبكة الآن: طلب GET التحقق الوحيد المصرح به انتهى بمهلة بلا استجابة؛
  TCP 80/443 مهلة ×2 جولتين بفاصل 45 ثانية؛ DNS يحل 44.228.249.3؛ مسار
  الخروج سليم (github:443 وexample.com:80 يعملان) — الخلل من جهة
  المسار/الهدف وليس حاوية. صفر مسح، صفر نتائج (مسجلة كما هي، لا تلفيق)،
  لا بدائل (القائمة مغلقة)، لا قصف.
- T3 (OWASP Juice Shop محليًا): تعذر T3 — لا Docker (لا docker binary على
  الجهاز؛ لا بدائل تنزيل غير مأمونة) — موثق. متسق مع سجل الحالة التاريخي
  (لا docker → crAPI معلّق).
- سلسلة الجولة: 89652d6 (charter) → ef5f0c3 (T1) → 937d615 (T2 محجوبة + T3)
  → هذا الإغلاق. كل دفعة متبوعة بتحقق ls-remote.
- صدق الانحرافات: انحرافان فقط — (1) تعذر T2 لبعيد المنال (خارج إرادتنا،
  موثق بالتشخيص)؛ (2) تعذر T3 لغياب Docker. لا انحراف عن أي أمر آخر؛ صفر
  اتصال بأي مضيف خارج القائمة (طلبات إلى مضيفين آخرين: 0).
- المحور الرابع: لن يبدأ قبل مراجعة المشرف لملخص المحورين 2 و3 المرسل مع
  تقرير الإغلاق.

حالة الحفظ: ملتزم ومدفوع إلى GitHub بعد كل مرحلة من هذه الجولة مع تحقق
ls-remote. هذا الملف نفسه يُحدَّث بعد كل جولة.

---

## ملخص عربي صادق (Arabic honest summary) — جولة بوابة حافة النطاق (2026-10-16)

ما جرى بالضبط (الأمر الصارم: أثبت حالة ثغرة الحافة في مطابقة النطاق بالكود
الحي قبل أي افتراض — إصلاح فقط إن ثبت العطل): التشخيص الحي أولًا على
`_scope_ok` كما هي على القرص — الاستدعاءات الثلاثة المأمورة
(nottestfire.net / eviltestfire.net / demo.testfire.net.attacker.com) رُفضت
كلها `False` على شكلَي النطاق الفعليين (allowed=['demo.testfire.net']
الافتراضي في orchestrator.py:117، وallowed=['testfire.net'] النطاق المسجل)
مع بقاء الضوابط الشرعية مقبولة (النطاق نفسه والنطاقات الفرعية الحقيقية).
**النتيجة المعلنة بالدليل الخام: لا ثغرة** — البوابة تطبّق أصلًا الصيغة
السليمة `host == d or host.endswith("." + d)` في http_engine.py:362-365.
لذلك **صفر تعديل على كود الإنتاج** وتخطّيت خطوة الإصلاح حرفيًا.

ما أُضيف: بطارية دائمة `tests/test_scope_edge_battery.py` (6 حالات C01-C06،
خارج تسجيل @case فيبقى عقد السsuite 227×19=4313 سليمًا بايتًا ببايت):
الاستدعاءات الثلاثة على الشكلين + نقيضها المأمور (النطاقات الفرعية
الشرعية تبقى مقبولة) + عائلة typosquat + دلالات allowed_hosts كعضوية
حرفية لا لاحقة. ومعها وضع --red-proof تفاضلي يخرب البوابة داخل العملية
فقط (لاحقة عارية endswith / مطابقة جزئية in) ويثبت أن البطارية تلتقط
كلا العطلين (3 و5 مجسات تُقبل خطأً على التوالي). بصدق موثق: أول تشغيل
للبطارية التقط خطأً في توقعي أنا — ظننت evildemo.testfire.net يجب رفضه
تحت النطاق المسجل المسموح testfire.net، وهو نطاق فرعي شرعي داخل المنطقة
المسموحة — فصحّحت التوقع ووثّقت الحد الدلالي، ولم أغيّر سلوك البوابة
لتوافق توقعي.

بوابة الانحدار الكاملة (صفر انحراف عن خط الأساس في البنود الأربعة):
suite 4313/4313 (19/19 مقطعًا، كل مقطع 227/227) + doctor 17/17 + bench ×3
= run-3c0652b6be (38/0/0/37، F1=1.0، @7161 طلبًا / 199 نتيجة، gt
0373baf92a92dce2) متطابق بنيويًا مع السجل المقبول ونسخه الأربع
(COMPARE_RC=0) + البطارية 6/6 ضمن تسلسل البوابة نفسه بعد الـbench
(digest=c2916ba3b060f40b) + red-proof ملتقط للعطلين. إيداعات .log ملتزمة
(git add -f) + SHA256SUMS لستة ملفات أدلة.

عزل التزام الانقلاب 11 (`aa9c803` غير المدفوع): reset --hard إلى
origin/main=93b7150 — التزام UUID لن يدخل تاريخ origin أبدًا — مع إعادة
تطبيق حرفية لمادته (أداة phase-0 + مدخل worklog المهمة-65) في التزام
استعادة منفصل وموسوم (044d2b6) بإثبات تطابق blobs رياضيًا
(e72f9314… و42f61f49… == blobs aa9c803 بالضبط).

حالة الحفظ: التزامان معزولان (الاستعادة + هذه الجولة) دُفعا إلى GitHub
مع تحقق ls-remote حرفي (origin/main == HEAD المحلي). لا اتصال خارجيًا
هذه الجولة سوى فحوصا doctor المدمجان (تحليل DNS + اتصال TCP لـ
scanme.nmap.org — فحصا البوابة المأمورة ذاتها، مفصح عنهما في الإيداع).
هذا الملف نفسه يُحدَّث بعد كل جولة.

---

## ملخص عربي صادق (Arabic honest summary) — جولة المحور الرابع: تركيب القنوات (2026-10-16)

ما جرى بالضبط (أمر المشرف: المحور الرابع بنفس الصرامة وعقلية الفريق
الأحمر/الأزرق، لا شيء بدون اختبارات حقيقية أو تعليل الأسباب):

- **الاستصلاح قبل العمل**: انقلاب #12 (التزام UUID 8a0e153 فوق 0793b79)
  أثبتَ أنه ضوضاء oob-marker للسابقة الرابعة (6 ملفات سطر واحد، صفر تتبع
  في main، الكاتب = مخرجات XXE-OOB للتطبيق المصحوب، الزمن بعد التزام
  الجولة بـ50 ثانية) — أُقصّ بـ reset --hard وفق البروتوكول المصادق.
- **إفصاح الأصل (تعليل السبب الأول)**: جدول §4 الأصلي للمواصفة غير قابل
  للاستعادة من أي سجل ملتزم (فُتش worklog كاملًا وSTATE.md وكل كائنات
  git وأشجار البناء) — الناجي الوحيد هو اسم المحور. لذلك **اشتُقّ عقد
  H4 من الأدلة الملتزمة القابلة للمراجعة**، والتعليل معلن في صدر الـsuite
  وفي كل رسالة التزام: D1 أبجدية الحاملات الـ12 = علم القنوات المُثبت
  حيًّا في حملة trustbound (detect.py: param/param_name/resolver_name/
  self_param/self_header/self_cookie/header_name/cookie_name/segment_value/
  segment_name/header_value/cookie_value)؛ D2 متغير الذيل الضحوي ضد
  أكّالات النهايات الحية (drop_last وrewrite)؛ D3 أولوية المعامل المصرح
  (السبب الموثق من الجسم)؛ D4 قاعدة الإسناد twins-win؛ D5 فئات الحدود
  14 وdigest منطقي فقط. **الجدول الأصلي — إن وُجد لدى المشرف — يعلو على
  الاشتقاق عند أي حد محطة.**
- **السلسلة (بروتوكول المحطات: كل محطة نظيفة تُلتزم وتُدفع فورًا)**:
  M1 RED: الـsuite كُتبت أولًا — 26 حالة H4_01..H4_26 + بطارية atoms
  4a..4e؛ التنفيذ الأحمر 0/26 (digest 9b06520d30523df3) + 0/5 atoms
  (1d9f838081ce39b3) بنمط فشل واحد نقي → 4ff33c7. M2 GREEN:
  sentinel/csynth.py (~300 سطر) — أول تشغيل 25/26 والفشل الوحيد خطأ
  اختبار أنا (توكيد معكوس في H4_13: truncate يُبقي الوسم سليمًا فالقناة
  حية) صُحح بملاحظة صادقة في موضعه؛ أخضر 26/26 (7448f95ebd58be25) →
  380c5fc. M3 ATOMS: 5/5 (cf2676e2c1e14b81) — مصفوفة اكتمال 7 أصناف
  بعديات مغلقة، 2,000 تصنيف تشويه 100%، حتمية 500 شكل بمرورين
  مستقلين، 11 شكلًا عدائيًا (فريق أحمر) بلا أي انهيار، 300 تيار إسناد →
  71ad58c. M4 R3: ثلاثة تشغيلات digests متطابقة → dfe4cfe. M5 GATE:
  البوابة الكاملة طازجة — suite 4313/4313 + doctor 17/17 + bench ×3 =
  run-3c0652b6be (38/0/0/37، @7161/199) متطابق بنيويًا مع السجل المقبول
  ونسخه الأربع (COMPARE_RC=0) + بطارية المحور-4 والبطارية الدائمة
  للحدود-النطاق خضراوان على الشجرة النهائية + إيداعات .log وSHA256SUMS.
- **عزلة النواة**: الـsuite مستقلة (خارج تسجيل @case) وsentinel/__init__.py
  فارغ — المسار الساخن لا يستورد csynth أصلًا؛ صفر انحراف مثبت حيًّا لا
  بنيويًا فقط.
- كل دفعة تليها ls-remote مطابقة حرفية. لا اتصال خارجي في هذه الجولة
  سوى git (الدفع/التحقق) وفحوصا doctor المدمجة المفصح عنها.

حالة الحفظ: المحور الرابع مغلق من طرف إلى طرف وسلسلته (4ff33c7 → 380c5fc
→ 71ad58c → dfe4cfe → M5) على GitHub. هذا الملف نفسه يُحدَّث بعد كل جولة.

---

## جولة التوحيد — 9540f7d (2026-10-17)

- **الاكتشاف (القاعدة 4، صفر اشتقاق)**: جرّان موازيان نفّذا الميثاق نفسه منذ التفرع 1e2159f (3 أكتوبر). الجرّ الشقيق (origin/main 5975d38) أغلق المحاور 1-4 عبر البوابة الخمسية كاملة (4ff33c7 → 380c5fc → 71ad58c → dfe4cfe → M5) حتى v4.4.0 وسدّد ديون المرحلة صفر بعد إثبات رباعي بأن المحور 10 فُقد في بيئته هي. وجرّنا هذا يحمل ما أثبتوا فقدانه: استرداد /tmp (91267c5) وفيه perf/ كاملة. الحقيقة الموحدة: المحور 10 موجود وغير مُتحقق بوابياً.
- **أمن التوكن**: خارج أي مستودع (600)، حراسة عبر .git/info/exclude (محلي فقط، لا يُدفع أبداً)، صفر التزامات تاريخية تحمله (تحقق git log --all فارغ)، لا يُطبع كاملاً في أي مخرج أو تقرير.
- **النظافة (770036d)**: إلغاء تتبع ضجيج البيئة (.env سطر واحد بلا سر / .next / dev.log / db / tool-results) — كلها مغطاة أصلاً بـ.gitignore؛ صفر تغيير محتوى.
- **الدمج (9540f7d)**: ثلاثي الاتجاه من 1e2159f؛ التعارض الوحيد worklog.md حُل اتحاداً كاملاً (سجلهم 4935 سطراً + مهمتا الجرّ-B 14-15 معلَفتين). كل مسار مشترك حُسم بتطابق بايتي — إثبات حي أن مسترد /tmp كان محتوى السلالة نفسها.
- **البوابة الكاملة طازجة على الشجرة الموحدة**: مسح المخبأ أولاً؛ suite 4313/4313 (19/19 حزمة × 227/227، AGG_RC=0) عبر 6 نطاقات (681+454+908×3+454)؛ doctor 17/17 (فحوصاته المدمجة فقط: DNS+TCP واحد لكل منها)؛ bench ×3 = run-3c0652b6be (38/0/0/37، @7161 طلباً/199 نتيجة، gt 0373baf92a92dce2) مطابق بنيوياً للسجل المقبول ونسخه (COMPARE_RC=0) — **صفر انزياح جوهري عبر التوحيد**. عائلة v430g_1/2 (196 نتيجة) أثرية ما قبل الإصلاح — وُثقت بصدق ولا تنتمي للسلسلة المقبولة.
- **المحور 10 المسترد**: العدة 40/40 خضراء على الشجرة الموحدة — نتيجة عدة فقط، ليست إغلاقاً خماسياً؛ لا جدول H في السجل؛ صفر ادعاءات أداء (الكفاءة ≥80% والـ msg/s ≥100k غير مقيسة).
- **الإيداعات (add -f عبر تجاهل *.log)**: gate/bench_unification_9540f7d.log + unification/SHA256SUMS + مراسي العمالقة الستة في /tmp (3×10MB JSON + 3×9.7MB out) + perf/results/gate_unification.log + الأداة الدائمة scripts/assemble_unification_deposits.py (رُقعت مرة هذه الجولة: تطبيع تلخيص الـbench — مصفوفة النتائج مقابل عدّها).
- **الانضباط**: الدفعة تليها ls-remote ومطابقة حرفية. لا اتصال خارجي في هذه الجولة سوى git (الدفع/التحقق) وفحوصا doctor المدمجة المفصح عنها.

حالة الحفظ: التوحيد مكتمل — الجرّان سلالة واحدة الآن؛ المحور 10 المسترد على الخط المصادق عليه بانتظار حكم المشرف (جدول H + بوابة خمسية قبل أي ادعاء). المحوران 5 و6 ما زالا على القاعدة: لا كود قبل إذن صريح. هذا الملف نفسه يُحدَّث بعد كل جولة.
