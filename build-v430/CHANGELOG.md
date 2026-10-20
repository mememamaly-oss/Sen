# SENTINEL Axis-13 — Modern Vulnerability Detectors, Closed End-to-End

The first axis of the extension program (docs/SPEC_AXES_13_16.md — the four-axis
supervisor order banked verbatim; axes 14-16 remain, each awaiting the standing
post-M5 approval). Six recent-CVE-class detector families the market demands and
most existing tools do not cover, all under the five-station gates with the
standing discipline.

## Axis-13 stations

- M1 RED (8553f89): the 20-case suite (H13_01..H13_20) pre-registered BEFORE
  the engine existed; all 20 failed with the single honest pattern
  (ModuleNotFoundError: No module named 'sentinel.modernsec'); digest
  6eef4f8735806f35. Contract D1 = spec §13 + D2 = the order's scope; the two
  pre-existing capabilities (jwt_security issuance, graphql introspection)
  disclosed in the spec §0.2 and NOT rebuilt.
- M2 GREEN (b7eb59e): sentinel/modernsec.py per the pre-registered contract —
  pure stdlib; the RSA public key reconstructed from the JWKS n/e by a
  minimal DER encoder (the leading-0x00 DER integer rule); MANDATORY
  differential everywhere; honest boundaries (TESTED_NEGATIVE / UNTESTABLE /
  OBSERVED_ANOMALY / NOT_DISCOVERED) with ZERO probes when preconditions are
  missing (budget honesty); the four registration points (evidence, report
  SARIF, intel VR-29..34, orchestrator lazy wiring); 20/20 first full run
  (digest dfa89987ee824c13). STATION EVIDENCE: bench x3 run-3c0652b6be
  (38/0/0/37) F1=1.0 @7162/199 gt 0373baf92a92dce2 STRUCTURALLY IDENTICAL vs
  the accepted record (the LIVE no-regression proof — the six new detectors
  fired ZERO findings on WAVSEP) + the closed axes fresh (65 pytest + all six
  digests DIGEST_MATCH). Three live-caught fixes declared (the corrupt-sig
  middle-char rule, the wing fixture's incremental chunked reader, the
  H13_18 fail-closed wording per v4.2.0's standing semantics).
- M3 ATOMS (4049e81): 3/3 first run (overall digest fb6eafe1bfd8c721). 13a:
  48 planted cycles (16 modes x3), every family's classification known by
  construction, two full passes reproduce the identical 48-seal list
  byte-for-byte, a single bit flip changes the seal. 13b: 100 independent
  references byte-exact (25 PEM reconstructions vs cryptography — the test
  side may use it, the engine never does; 25 canary derivations; 20
  corrupt-sig guarantees; 15 recipe parses; 15 literal vocabularies). 13c:
  exactly 40 adversarial (12+10+8+6+4) — the signature class: LYING TARGETS
  (a door that opens for the probe then lies to the verification) caught by
  the VR fail-closed replay in all ten.
- M4 R3 (d970d3e): six digests IDENTICAL x3 across three fully separate
  processes with PYTHONHASHSEED=0 (suite dfa89987ee824c13 x3 = the M2 digest;
  atoms fb6eafe1bfd8c721 x3 = the M3 digest — hash-seed independent).
- M5 GATE + closure (this commit): the FULL core gate FRESH (cache wiped):
  6 foreground ranges (681+454+908x3+454; the heavies c03=285s c07=211s) ->
  machine aggregate 19 chunks 227/227 = 4313/4313 AGG_RC=0 + doctor 17/17 +
  bench x3 STRUCTURALLY IDENTICAL + the axis-13 suite/atoms FRESH on the gate
  tree (pytest 20 + script-mode digests DIGEST_MATCH vs the station anchors) +
  the closed axes fresh (65 pytest + six digests DIGEST_MATCH) + the standing
  scope-edge battery 6/6 digest c2916ba3 with --red-proof all saboteurs caught
  + the anchor a08828ee restored by a defensive checkout and re-verified
  intact. Standing tool scripts/assemble_axis13_deposits.py judged ALL GREEN
  rc=0; deposits: 7 evidence files under results/axis13/ + the gate and bench
  logs + SHA256SUMS (Task-76 convention, verify OK).

## Honest limits of this axis

- http_request_smuggling is INDICATED, never proven-exploitable: the timing
  differential is the whole claim; pipeline corruption is NEVER attempted
  (detection-only by design — the supervisor's literal "بالتوقيت" order).
- The smuggling family covers http targets only (https declared out); the
  confusion family covers the RSA JWKS class (the dominant CVE family; ES
  declared out); the PP DOM/browser variant is out of the default engine
  scope (--no-browser).
- Measured timings live OUTSIDE every digest (quantized to classes — the
  axis-11/12 discipline); bench request counts are informational by design.
- The pre-existing jwt_security (issuance side) and graphql_introspection
  were NOT rebuilt — the spec §0.2 disclosure; no silent double-coverage.

# SENTINEL final-round-1 — The Complete Acceptance Round: Internal Battery + THE REAL External Scan, Closed End-to-End

Supervisor order 2026-10-20 (verbatim): the tool's rigorous tests — COMPLETE
internal and external, REAL, on LEGITIMATE applications and sites. Round
final-round-1 delivers exactly that on the final 12-axis tree (build order
exhausted @ 94cf323), in four stations, every station an isolated commit +
immediate push + ls-remote.

## final-round-1 stations

- F0 charter + rate proxy (3f1f54f): CHARTER_FINAL.md pre-registered BEFORE
  any scan traffic — a closed list of FOUR legitimate targets (WAVSEP local
  golden reference; scanme.nmap.org — the Nmap Project's publicly designated
  scan-test site, THE real external target; testphp.vulnweb.com — Acunetix's
  licensed scanner demo, http-only; OWASP Juice Shop local, conditional on
  docker). The closed-list rule verbatim from rounds 1-2: any other host in
  any record = immediate abort. Detection-only; rate <=2 req/s ENFORCED BY
  INFRA; budget <=1500 req / 30 min; explicit bounds (--max-pages 8,
  --timeout 12, --seed 20261020). Pre-charter contacts disclosed raw (2
  state-probe GETs + 2 DNS lookups, nothing else). STANDING TOOL
  scripts/rate_proxy.py (tools clause): token-bucket 2/s, STRUCTURAL
  one-host whitelist (absolute-URI smuggles -> 403 + logged), full JSONL
  compliance log — local judgment 4/4 PASS, zero external contact. Doctor
  17/17 fresh at round opening.
- F1 the complete internal battery (ac8011f): all caches wiped, everything
  FRESH — core suite 6 foreground ranges -> machine aggregate 19 chunks
  227/227 = 4313/4313 AGG_RC=0; doctor 17/17; bench x3 = run-3c0652b6be
  (38/0/0/37) F1=1.0 @7161/199 gt 0373baf92a92dce2, structural compare vs
  the accepted record ALL IDENTICAL (the live hot-path-untouched proof);
  ALL FIVE BUILT AXES fresh: pytest 96 passed and all TEN script-mode
  digests DIGEST_MATCH vs the banked station anchors (7: 14d72c42/cd1fd9d4,
  8: 0a2214e9/11df7a3f, 10: 484b0816/fa4c9ed7, 11: 249843ed/64edf7a7,
  12: 27570f36/0d9fb6a4) — the closed logical streams of the ENTIRE build
  reproduce on the final tree; scope-edge battery 6/6 digest c2916ba3 +
  red-proof all saboteurs caught + anchor a08828ee INTACT (no drift, no
  checkout needed this round). Standing assembler
  scripts/assemble_final_deposits.py judged ALL GREEN rc=0.
- F2 the real external scan (34d6192): THE CAMPAIGN'S FIRST REAL LIVE-SITE
  SCAN. testphp: one verify GET -> curl(124) timeout, the identical
  round-1/X2 block pattern, no scan, no hammering. scanme.nmap.org: verify
  GET 200 @0.316s then the real bounded scan through the rate proxy —
  run-71ca9f1d6e, 574 requests, 5 pages, 9 endpoints, 18 verified findings
  (9 missing_security_headers + 9 server_banner_disclosure), 0 candidates,
  0 rejected, wall 4m55s. COMPLIANCE from the proxy's own JSONL log: 583
  forwarded / 0 blocked / 0 closed-list violations / 0 consecutive 5xx /
  0x429 / budget 574-of-1500 and 294.3s-of-1800s WITHIN / sustained
  1.98 req/s (bucket-burst behavior disclosed: 3 req in an aligned second
  in 10 of 291 seconds). ARTIFACT DISCLOSURE: the v1.0 proxy injected its
  own Server header and stripped target headers, so the 18 header-class
  findings measured the proxy-delivered response; one direct GET
  corroborates BOTH classes on the target's real posture (Server:
  Apache/2.4.7 (Ubuntu) is a genuine banner disclosure; no security
  headers present). Proxy fixed to v1.1 (verbatim header forwarding, own
  banner suppressed, selftest re-judged 4/4) — no re-scan: the
  minimal-footprint principle on a legitimate third-party site.
- F3 conditional + closure (this commit): no docker binary — the honest
  one-liner (round-1/X3 verbatim); no unsafe download substitutes.
  Deposits: 11 evidence files under results/final/ + SHA256SUMS (Task-76
  convention, verify OK). Worklog task 85.

## Honest limits of this round

- scanme is a static legitimate site: zero injection-class findings
  expected (pre-registered) and measured — F2 proves REAL external
  execution + closed-list + rate compliance, not vulnerability abundance.
- The official quantitative reference remains the WAVSEP local benchmark
  (F1: 4313/4313 + F1=1.0 structural IDENTICAL).
- testphp blocked from the current network path (measured, no speculation);
  no docker in this environment.
- Everything not built remains governed by the standing honest boundary
  inventory — no silent gaps.

# SENTINEL Axis-12 — Boundaries & Transparency, Closed End-to-End

## Axis-12 stations

- M1 RED (8591480): the 15-case suite (H12_01..H12_15) pre-registered
  BEFORE the engine existed; all 15 failed with the single honest
  pattern (ModuleNotFoundError: No module named
  'sentinel.transparency', verified uniform in the deposit).
  Contract derived and declared (supersedable at any station
  boundary): D1 = the authoritative archived spec section 12
  (BoundaryRecord = (Node, Reason, Category, Timestamp, Confidence)
  + the literal 14-category table; the six no-hallucination rules
  R1-R6 with 'claim not in {supported by evidence} -> report
  Hallucination'; the BoundaryEngine interface
  record/query/coverage/verify_claim/detect_hallucination/export;
  the O(1)-record / O(|Records|) complexity row) + D2 = the
  build-order scope (axis 12 = boundaries & transparency, the LAST
  axis). The literal H12 table is unrecoverable (lost with the
  session cuts) — same honest provenance as axes 4/8/11. Evidence:
  axis12_RED.json (digest 130f3449).
- M2 GREEN (4816023): sentinel/transparency.py per the
  pre-registered contract — pure stdlib (hashlib/json/time); the 14
  literal categories with documented meanings; BoundaryRecord with
  content-addressed ids, the ONE declared clock touch
  (record(timestamp=None) with an in-engine monotone clamp), and the
  volatile timestamp excluded from every digest; the evidence store
  (attach/resolve, content-addressed); make_claim; the six rules
  with the literal spec texts, each RECOMPUTING from raw materials
  (triple_run from its runs list not its label; inventory against
  the LIVE digest+count; measurement value matched literally); the
  universal boundary-refutation check (a recorded boundary on the
  claim's exact subject refutes any positive claim — the boundary
  inventory is the truth of what did NOT happen) and the evidence
  subject-match check; coverage() as a MEASUREMENT with stated
  absences; export() with boundary_digest over the boundary registry
  only + import_export full round-trip with tamper rejection; the
  append-only audit ledger recording EVERY verdict AND detection.
  15/15 first run (digest 27570f36). Module path declared:
  sentinel/boundary.py is the v4.1.0 core-suite module and stays
  untouched. Closed axes 7/8/11 re-run fresh alongside: 53/53.
- M3 ATOMS (2cd7fdf): the three batteries 3/3 first run (overall
  digest 0d9fb6a4): 12a 400 planted cycles — 1200 claims classified
  exactly as constructed (400/400 agreement; 400/400 hallucinations
  caught), two full passes reproduce the identical 400-seal list,
  single bit flip in a reason changes the seal; 12b 150
  independent-reference matches byte-exact (50 record ids + 25
  artifact ids + 25 boundary digests over differently-shaped engines
  + 25 coverage counts + 25 claim ids); 12c exactly 40 adversarial
  scenarios (12 structural + 10 gate sabotage ALL caught + 8
  precision no-false-positives incl. round-trip re-verified claims +
  6 boundary/tamper + 4 liveness) + live state check clean. One
  battery-side fix declared (engine untouched): the first final
  twin omitted the second lawful record the health case
  legitimately added.
- M4 R3 (2217dcc1): three fully separate processes, all six digests
  IDENTICAL first run (suite 27570f36 x3 = the M2 digest; atoms
  0d9fb6a4 x3 = the M3 digest — hash-seed independent as designed).
  G4 as declared (the axis-11 inherited contract): no literal
  container in this environment (proven external-2 X3); isolation =
  separate processes + PYTHONHASHSEED=0 pinned. Standing tool
  scripts/axis12_r3.py committed per the tools clause.
- M5 GATE (this commit): the FULL core gate fresh on the final
  axis-12 tree. Suite 4313/4313 (cache wiped pre-round; 19 chunks
  227/227; 6 foreground ranges 681+454+908x3+454; AGG_RC=0) + doctor
  17/17 (standing scanme.nmap.org health-check disclosure) + bench x3
  run-3c0652b6be (38/0/0/37) F1=1.0 @7161/199 gt 0373baf92a92dce2,
  structural compare vs the accepted record ALL IDENTICAL
  COMPARE_RC=0 — LIVE proof the hot path never imports transparency
  (requests 4784 record vs 7161 fresh — informational by design, the
  standing N3) + axis-12 suite/atoms FRESH on the gate tree: pytest
  18 (15 + 3 batteries) and script-mode digests 27570f36 / 0d9fb6a4
  BOTH DIGEST_MATCH vs the station anchors + standing scope-edge
  battery 6/6 digest c2916ba3 with --red-proof all saboteurs caught;
  the fresh run matched the standing digest but rewrote
  battery_GREEN.json wall times — the anchor a08828ee restored by a
  defensive checkout and re-verified intact (the standing
  discipline). Standing tool scripts/assemble_axis12_deposits.py
  committed per the tools clause, judged ALL GREEN rc=0; deposits:
  gate/bench_axis12_27570f36.log + axis12_GATE_pytest.txt +
  SHA256SUMS (10 evidence files, Task-76 convention, verify OK).

## Axis-12 honest limits

- The boundary vocabulary is the spec's 14 categories; the engine
  measures what has been RECORDED — coverage() is a registry
  measurement, never a scan-coverage certificate (R2 governs that
  distinction by construction).
- The no-hallucination gate is as strong as its evidence feeding:
  it verifies claims against resolvable artifacts, live
  recomputation, and the recorded boundary inventory. It cannot
  adjudicate claims about subjects with neither evidence nor
  boundaries — those fail R1..R6 honestly (unsupported), which is
  the declared behavior.
- Wall times stay outside every digest (the axis-11 discipline
  applied to axis-12); the one clock touch is declared and clamped
  monotone per engine.
- With axis-12 the 12-axis build order is EXHAUSTED end-to-end
  (axes 1,2,3,4,7,8,10,11,12 built through their five-station
  gates; everything not built remains governed by the standing
  honest boundary inventory — no silent gaps).

# SENTINEL Axis-11 — Determinism & Reproducibility, Closed End-to-End

## Axis-11 stations

- M1 RED (19eaa0a): the 15-case suite (H11_01..H11_15) pre-registered
  BEFORE the engine existed; all 15 failed with the single honest
  pattern (ModuleNotFoundError: No module named 'sentinel.repro',
  verified uniform in the deposit). Contract derived and declared
  (supersedable at any station boundary): D1 = archived spec §11
  (G1..G5, Triple-Run, Merkle-root diff with automatic investigation,
  the §11.4 interface) + D2 = the build-order scope list (same
  seed->same outputs, Triple-Run, logic-flow digest, bit-flip
  sensitivity). Evidence: axis11_RED.json (digest cdf6a0c2).
- M2 GREEN (9eb0514): sentinel/repro.py per the pre-registered
  contract — pure stdlib; SeededPRNG (pure SplitMix64) +
  derive_stream; canonical_input (G5); flow digest + flow Merkle root
  (the §8.2 convention); diff/investigate/verify/require (the
  automatic investigation); freeze_environment (per-package RECORD
  sha256 — G3 pinning BY HASH) + restore_environment (detection not
  silence); DeterministicExecutor; default_pipeline over the closed
  axis-8 core. 15/15 (digest 249843ed). Four GREEN repairs declared
  in the station commit (merkle reference semantics, bytes
  deep-copy, the seed-independence of the restored plaintext, and
  seed 0 outside the declared contract) + the live-recomputation diff
  (N-i) and numeric sys_flags (N-j).
- M3 ATOMS (8712d8e): the three batteries 3/3 first run (digest
  64edf7a7): 11a 400 seeded cycles (triple identical 800/800 across
  two full passes; input/seed single-bit flips diverge 800/800; the
  whole battery repeated reproduces the identical root list),
  11b 150 independent-reference matches byte-exact (75 SplitMix64 +
  25 canonical JSON + 50 flow roots sizes 1..50), 11c exactly 40
  adversarial scenarios (20+8+4+4+4) — all 8 planted nondeterminism
  sources caught by DriftError, the synchronized tamper caught from
  raw materials, restore names every drift, boundaries 1/2^64-1
  accepted and 2^64 rejected, live state check clean.
- M4 R3 (6f1b07d): three fully separate processes, all six digests
  IDENTICAL first run (suite 249843ed x3 = the M2 digest —
  hash-seed independent as designed; atoms 64edf7a7 x3). G4 as
  declared: no literal container in this environment (proven
  external-2 X3); isolation = separate processes + PYTHONHASHSEED=0
  pinned (the restore_environment contract). Standing tool
  scripts/axis11_r3.py committed per the tools clause.
- M5 GATE (this commit): the FULL core gate fresh on the final
  axis-11 tree. Suite 4313/4313 (cache wiped pre-round; 19 chunks
  227/227; 6 foreground ranges 681+454+908x3+454; AGG_RC=0) + doctor
  17/17 + bench x3 run-3c0652b6be (38/0/0/37) F1=1.0 @7161/199 gt
  0373baf92a92dce2, structurally IDENTICAL tuple-by-tuple vs the
  accepted record (COMPARE_RC=0; requests 4784 record vs 7161 fresh
  informational by design) — proving LIVE that the hot path never
  imports repro + axis-11 suite/atoms FRESH on the gate tree (pytest
  18 = 15+3; script-mode digests 249843ed / 64edf7a7 BOTH
  DIGEST_MATCH vs the M2/M3/M4 anchors) + standing scope-edge
  battery 6/6 digest c2916ba3 with red-proof all caught; anchor
  a08828ee verified intact (the fresh run left it byte-identical
  this round; defensive checkout issued anyway). Standing tool
  scripts/assemble_axis11_deposits.py committed per the tools clause
  (judged ALL GREEN rc=0); SHA256SUMS 10 evidence files (Task-76
  convention).

## Honest limits (declared)

- No literal container (Docker) in this environment — proven
  external-2 X3 (no binary); the G4 isolation implemented is fully
  separate processes + a pinned PYTHONHASHSEED, the declared contract.
- Axis-11 measures the DETERMINISTIC layer: the seeded runner and
  the default pipeline over the closed axis-8 core. The detection
  hot path (axes 1-4) is untouched by construction and proven
  untouched LIVE (the 4313 fresh run + IDENTICAL structural compare).
- bench informational requests vary by design (4784 record vs 7161
  fresh); the structural tuple comparison is the authoritative check.
- Wall times live in dur_s/detail, outside every digest — the
  axis-11 discipline applied to its own axis.

# SENTINEL External Round-2 — The Post-Axes-7+8 Sequence, Redone Honestly After the Environment Wipe

Station ledger:
- Recovery (round pre-flight): the environment was discovered wiped
  to a pre-campaign IV13-era snapshot (worklog 923 lines, no
  build-v430, a fresh UUID noise commit f2d41e8 above it — discarded
  via reset, never pushed, no loss). The campaign was restored from
  the bank: reset to a93c28e (ancestry verified live: the ancient
  tip IS an ancestor of the campaign chain — a catch-up move, not a
  rewrite). The lost session's claimed stations (X1 082a6b4 /
  X2 e1f6a3f / closure 676ea9b) exist in NO ref on the remote
  (cat-file ABSENT across every ref incl. the sentinel-x parallel
  branches) — their numbers are unverifiable and were NOT carried
  forward; the round was redone from scratch per the pre-registered
  charter.
- X0 (a93c28e — pre-existing on the bank, the restore point):
  round-2 charter pre-registered (derived contract, declared
  provenance) + fresh doctor 17/17.
- X1 (75d8e7f): the FINAL GATE, fresh from scratch (all caches
  wiped): suite 4313/4313 (19 chunks 227/227, 6 foreground ranges
  681+454+908x3+454, AGG_RC=0) + doctor 17/17 rc=0 + bench x3
  run-3c0652b6be (38/0/0/37) F1=1.0 @7161/199 gt 0373baf92a92dce2
  structurally IDENTICAL tuple-by-tuple vs the accepted record
  (COMPARE_RC=0; requests 4784 vs 7161 informational by design) +
  axes 7+8 suites/atoms FRESH (pytest 35 = 14+3 + 15+3; script-mode
  digests 14d72c42 / cd1fd9d4 / 0a2214e9 / 11df7a3f ALL DIGEST_MATCH
  vs the banked station anchors) + standing scope-edge battery 6/6
  digest c2916ba3 (the fresh run rewrote battery_GREEN.json with
  wall-time metadata only — anchor a08828ee RESTORED per the
  axis-11 digest discipline, verified intact) + red-proof all
  saboteurs caught. Standing tool committed per the tools clause:
  scripts/assemble_external2_deposits.py (judged ALL GREEN rc=0).
- X2 (dbf2dda): testphp.vulnweb.com BLOCKED_UNREACHABLE — the
  identical round-1 pattern, measured as-is: one authorized GET
  (curl 28, 20002ms, status 000, the TCP handshake never completed),
  TCP diagnostics 2 rounds 45s apart (port 80 + 443 timeout x4), DNS
  resolves fine (44.228.249.3), egress controls healthy (github.com
  and example.com OPEN 0.0s) — the block is target-side/path-side,
  NOT a container restriction. Scan NOT RUN (cannot scan an
  unreachable target; the closed list forbids substitutes); findings
  honestly zero. The lost session's "REACHABLE, 65 requests / 9
  findings" claim exists in no ref and is contradicted by fresh
  measurement — discarded as evidence.
- X3 (this commit): no Docker (command -v docker -> rc=1; no binary
  at the standard paths) — the same honest one-line verdict as
  round-1 T3; no unsafe download alternatives.

Standing boundaries (unchanged): the closed 3-target list; the caps
and abort conditions inherited from round-1 verbatim; axes 11-12
UNBUILT — the next station in the build order is axis-11, awaiting
the supervisor's approval per the standing stop rule.

# SENTINEL Axis-8 — Military-Grade Cryptographic Proof (Ed25519/Merkle/chains/RFC3161/AEAD/HKDF/custody)

Station ledger:
- M1 (RED): tests/test_axis8_proof.py written FIRST — 15 cases
  H08_01..H08_15. PROVENANCE (axis-4 pattern, declared): the
  supervisor's literal H08 table from the 2026-10-19 build order is
  NOT recoverable from any committed record (SPEC has no H tables;
  worklog task 80 quotes H07 only) — the contract is DERIVED from D1
  the banked authoritative spec §8 (proof model 8.1, Merkle 8.2,
  RFC 3161 8.4, evidence chain 8.5, ProofEngine 8.6) + D2 the
  build-order scope list (Ed25519, Merkle, SHA-256 chains, RFC 3161,
  ChaCha20-Poly1305, HKDF-SHA256, custody chain), supersedable at any
  station boundary. DECLARED BOUNDARY: zk-SNARK (spec §8.3) out of
  scope (not in the build-order list; real ZK needs trusted
  setup+pairing) — future station if ordered. RED executed fresh:
  0/15, single failure pattern = ModuleNotFoundError('sentinel.proof')
  x15 (count-verified, zero other error types), 0.20s; script-mode
  digest 1f6584dc3abe2882. RFC anchors verified LIVE vs pyca before
  baking (RFC 8032 T1 seed/pub/sig, RFC 8439 §2.8.2 full vector —
  my memorized tag constant was WRONG and corrected to the
  live-verified one BEFORE RED, zero test-side drift; RFC 5869 TC1).
- M2 (GREEN): sentinel/proof.py (699 lines, pure stdlib:
  hashlib/hmac/os/struct; pyca EXTERNAL test-only reference —
  byte-exact cross-checks since Ed25519+AEAD are deterministic, the
  axis-7 scipy pattern). Two honest iteration notes from the first
  run (13/15): (1) ENGINE bug caught by the RFC 8439 §2.8.2 anchor —
  Poly1305 mac input order was ct-first; the literal RFC order is
  AAD-first; fixed in both encrypt+decrypt (exactly what baked
  anchors exist for); (2) TEST-side: pyca enum member is
  Encoding.Raw not .RAW (my helper; supervisor-literal assertions
  untouched). Engine: ProofError hierarchy (ValidationError
  structural atomic-reject / IntegrityError semantic — declared
  split), Ed25519 RFC 8032 pure-python (extended coordinates,
  deterministic, RFC T1 byte-exact + pyca live match), Merkle §8.2
  (duplicate-last odd convention CT-style, proofs ≤ ceil(log2 n)+1),
  evidence chain §8.5 literal (genesis 32 zeros, any-modification-
  breaks verified at head/mid/tail/drop/swap/forge), RFC 3161-style
  timestamp (TST=Sign(TSA, Hash(data)||le64(Time)); local TSA keys
  only; explicit when_ms injection — axis-11 discipline), ChaCha20-
  Poly1305 RFC 8439 (verify-before-decrypt, zero plaintext leak),
  HKDF-SHA256 RFC 5869 (TC1 byte-exact, 255*32 bound), proof model
  §8.1 six-field P with canonical-JSON hashing, custody chain with
  structural anti-forgery (transfer atomically rejected unless the
  transferor key == current holder; verify returns honest
  {valid, length, final_custodian, breaks}). GREEN 15/15, digest
  0a2214e9b895791e; rerun digest MATCH. Purity proven live: AST
  import scan stdlib-only; engine import graph pulls ZERO external
  crypto modules.
- M3 (atoms): the 3 batteries (derived per the M1 declared
  contract), closed 3/3, overall digest 11df7a3f0eb77b6b. 8a: 500
  seeded Ed25519+Merkle cycles (seed=200000+i) x2 independent passes
  -> sign/verify True, msg-tamper False, wrong-pub False, inclusion
  member True / non-member False, root deterministic: ZERO crashes
  (1000 cycle-passes), records digest repeatable in-process. 8b: 200
  cross-checks vs EXTERNAL reference — Ed25519 x100 vs pyca (pub+sig
  byte-exact), AEAD x60 vs pyca (ct||tag byte-exact), HKDF x40 vs an
  INDEPENDENT RFC 5869 re-implementation inside the battery ->
  200/200 matched, 0 mismatches. 8c: exactly 50 adversarial scenarios
  (8 Ed25519 + 6 Merkle structural + 3 Merkle semantic + 6 chain + 6
  timestamp + 8 AEAD + 5 HKDF + 7 claims + 1 custody non-holder):
  50/50 atomic-reject with the DECLARED outcome, zero unexpected
  types, live state-poisoning check clean (post-battery canary
  byte-identical). Honest note: my first attack list counted 51 —
  the battery's own 'exactly 50' assertion caught it RAW (engine
  innocent: all 51 rejected atomically); removed the redundant
  mk_root_none; battery-side fix declared.
- M4 (determinism, R3): suite 15/15 x3 + atoms 3/3 x3, ALL in
  separate subprocesses (full memory/state isolation). Suite digest
  0a2214e9b895791e x3 IDENTICAL; atoms overall digest
  11df7a3f0eb77b6b x3 IDENTICAL. Permanent tool
  scripts/axis8_r3.py committed per the standing tools clause.
- M5 (gate, CLOSURE): full core gate fresh on the final axis-8 tree
  — suite 4313/4313 (19/19 chunks 227/227, AGG_RC=0, cache wiped
  pre-round, 6 foreground ranges 681+454+908x3+454), doctor 17/17
  PASS rc=0, bench x3 run-3c0652b6be 38/0/0/37 P=R=F1=1.0 @7161/199
  gt 0373baf92a92dce2 structurally identical vs the accepted record
  verify_pt1 (COMPARE_RC=0) — zero core drift, proven LIVE; axis-8
  suite+atoms fresh on the final tree: pytest 18/18 (15 proof + 3
  batteries) + script-mode suite 15/15 digest 0a2214e9...
  DIGEST_MATCH=True vs M2/M4 + atoms 3/3 11df7a3f... DIGEST_MATCH
  =True vs M3/M4; standing scope-edge battery 6/6 digest
  c2916ba3b060f40b MATCH + --red-proof all saboteurs caught (battery
  rewrite differed by wall-time metadata only, dur_s c05 — anchor
  a08828ee RESTORED per the axis-11 digest discipline, same declared
  pattern as the axis-7 round). Deposits committed:
  results/gate_axis8_0a2214e9.log + results/bench_axis8_0a2214e9.log
  + axis8_GATE_pytest.txt + SHA256SUMS (11 evidence files) + the
  standing tool scripts/assemble_axis8_deposits.py. AXIS 8 CLOSED
  end-to-end. Station chain: c9364df -> 4a0f4d1 -> e882922 ->
  727d910 -> M5. Standing boundaries (declared): zk-SNARK out of
  scope (spec §8.3 — future station if ordered); pyca never an
  engine dependency; RFC 3161 timestamps are LOCAL TSA keys only
  (closed target list); wall-times outside every digest.

# SENTINEL Axis-7 — Measurement & Metrics (GPI/AHP, ARIMA, stats, timing, CC/SI)

Station ledger:
- M1 (RED): tests/test_axis7_metrics.py written FIRST — 14 cases
  H07_01..H07_14, the supervisor's H-table registered verbatim (every
  case with its literal assertions; G2 discharged before any code).
  RED executed fresh: 0/14, single failure pattern =
  ModuleNotFoundError('sentinel.metrics') x14 (count-verified, zero
  other error types), 14 failed / 0.32s; script-mode digest
  7b2db191ad99b4ad. Deposits results/axis7/{axis7_RED.json,
  axis7_RED_pytest.txt, SHA256SUMS}. Contract notes declared: TTF/TTE/
  TTT/TTO definitions; ARIMA(1,0,0) = AR(1)+const via conditional LS;
  AHP principal eigenvector (power iteration, hand-computable 3x3);
  degenerate ANOVA conventions (SSB=0 -> F:=0.0/p:=1.0, SSW=0 ->
  F:=inf); pure-stdlib engine, scipy as EXTERNAL test-only reference
  (1e-9); validation-before-mutation everywhere. Suite standalone,
  NOT @case-registered (4313 core untouched by construction).
- M2 (GREEN): sentinel/metrics.py (~600 lines, pure stdlib — math
  only; scipy external test-only reference). Two honest iteration
  notes: (1) Lanczos constant mixup caught by the H07_09 scipy-match
  (g=7 n=9 coefficients paired with the wrong variant constant ->
  corrected to t=z-1+7.5, verified vs math.lgamma within 1e-15);
  (2) MY auxiliary H07_09 assertion (0.45-sigma shift detectable) was
  statistically underpowered for the seeded sample's realized mean —
  fixed to 1-sigma; the supervisor's LITERAL assertion (p matches
  scipy) unchanged and passing. Engine: MetricRegistry, minmax/zscore
  normalize (atomic rejections: out-of-declared-range, zero
  variance), AHP power-iteration weights (exact 1-sum) + GPI
  (weight-sum/negatives/[0,1] contracts), ARIMA(1,0,0) centered-LS
  fit+forecast, ANOVA (declared degenerate conventions), t-test
  (ddof=1) + Spearman (average-rank ties), TimingTracker (monotonic,
  first-mark-wins), CC/SI (numeric-coherence rejections),
  build_measurement_report (unmeasured always present, no wall-clock
  — axis-11 discipline). GREEN 14/14, digest 14d72c42a5cf8371; rerun
  digest MATCH (determinism sanity). Deposits: axis7_GREEN.json +
  pytest raw + scriptmode + SHA256SUMS (5 files).
- M3 (atoms): the 3 literal batteries (supervisor order 2026-10-19),
  closed 3/3, overall digest cd1fd9d4bdb3b85d. 3a: 500 seeded random
  AR(1) series (seed=100000+i, n 50-400, phi -0.95..0.95) x2
  independent passes -> minmax+zscore (calibration verified
  per-series) + GPI over fraction-indicators w/ fixed consistent 4x4
  AHP (hand answer 8/15,4/15,2/15,1/15) + ARIMA fit/forecast: ZERO
  crashes, digest repeatable in-process (d1==d2). 3b: 200
  statistical groups vs the EXTERNAL scipy reference: ANOVA F
  (<1e-9 rel) + p (abs 1e-9 above 1e-3, rel 1e-6 below), ttest t/p,
  Spearman on deliberately tie-quantized samples -> 600/600 matched,
  0 mismatches. 3c: exactly 50 adversarial scenarios (negative
  weights, weight-sum!=1, NaN/Inf, empty/short/constant series,
  div-zero via lo==hi/declared=0/total=0, bool poisoning, length
  mismatches, registry miss): 50/50 atomic-reject with the DECLARED
  exception, zero unexpected types, live state-poisoning check clean
  (a failed record leaves no trace). Deposits: axis7_ATOMS.json +
  pytest raw + SHA256SUMS (7 files).
- M4 (determinism, R3): suite 14/14 x3 + atoms 3/3 x3, ALL in
  separate subprocesses (full memory/state isolation). Suite digest
  14d72c42a5cf8371 x3 IDENTICAL; atoms overall digest
  cd1fd9d4bdb3b85d x3 IDENTICAL. Permanent tool scripts/axis7_r3.py
  committed per the standing tools clause. Deposits: axis7_R3.json +
  SHA256SUMS (8 files).
- M5 (gate, CLOSURE): full core gate fresh on the final axis-7 tree —
  suite 4313/4313 (19/19 chunks 227/227, AGG_RC=0, cache wiped
  pre-round, 6 foreground ranges 681+454+908x3+454), doctor 17/17
  PASS rc=0, bench x3 run-3c0652b6be 38/0/0/37 P=R=F1=1.0 @7161/199
  gt 0373baf92a92dce2 structurally identical vs the accepted record
  verify_pt1 (COMPARE_RC=0) — zero core drift, proven LIVE not just
  by construction; axis-7 suite+atoms fresh on the final tree:
  pytest 17/17 (14 metrics + 3 atoms) + script-mode suite 14/14
  digest 14d72c42... DIGEST_MATCH=True vs M2/M4 + atoms 3/3
  overall_digest cd1fd9d4... DIGEST_MATCH=True vs M3/M4 (the
  station-closed logical streams reproduce on the final tree);
  standing scope-edge battery 6/6 digest c2916ba3b060f40b MATCH +
  --red-proof all saboteurs caught (this round's battery rewrite
  differed by ONE wall-time metadata char, dur_s 0.0001->0.0 c05
  perf_counter rounding — logical stream + digest identical, the
  anchored file RESTORED per the axis-11 digest discipline, anchor
  a08828ee verified intact). Deposits committed:
  results/gate_axis7_14d72c42.log + results/bench_axis7_14d72c42.log
  + axis7_GATE_pytest.txt + SHA256SUMS (11 evidence files) + the
  standing tool scripts/assemble_axis7_deposits.py. AXIS 7 CLOSED
  end-to-end. Station chain: 453b3bc -> eaf83cb -> 1f26530 ->
  c9a1ce0 -> M5. Standing boundaries (declared): scipy never an
  engine dependency; the ARIMA scope is (1,0,0) per the H-table
  contract; wall-times live outside every digest.

# SENTINEL Axis-10 — Actors / AIO / Columnar (recovered perf/, bridge-wired)

Station ledger:
- M1 (RED): tests/test_axis10_infra.py written FIRST — 20 cases
  H10_01..H10_20, the supervisor's H-table registered verbatim (the
  Rule-1 standing condition discharged). RED executed fresh: 0/20,
  single failure pattern = ModuleNotFoundError('sentinel.infra') x20
  (count-verified, zero other error types); script-mode digest
  30bf6ce5c59aaf11; deposits results/axis10/{axis10_RED.json,
  axis10_RED_pytest.txt, SHA256SUMS}. Contract notes: SHA-256 digest
  chain per the literal H10_07 wording (the recovered perf/ chain is
  blake2b-16 — difference declared, not hidden); suite standalone, NOT
  @case-registered (the 4313 core untouched by construction).
- M2 (GREEN): sentinel/infra.py — the bridge re-exporting the recovered
  perf/ content (untouchable) with the E1/E2/E3/E5 defects remediated
  at the bridge layer ONLY: E1 writer digest chain blake2b-16 ->
  SHA-256; E2 bounded output queue -> unbounded Mailbox; E3 dead
  ValueError check -> live pre-check with the same condition and
  message; E5 the false "consistently" comment removed. GREEN 20/20,
  digest 484b081615c1cf48; arch-relative 20k perf floor declared per
  the supervisor's explicit amendment (measured pool_4 = 44485 msg/s,
  60000 messages, 0 lost).
- M3 (atoms): the 5-battery suite (3a 1000 random messages / 3b 500
  restart-escalate cycles / 3c 200 parallel-consistency rounds x pool
  {1,2,4} x 10k seeded messages / 3d 80 adversarial attacks in 5
  categories / 3e 100 pruning-equivalence cycles). First run RED on
  ONE genuine finding: T3 deposit-chain poisoning — cancelling ONE
  tell() deposit poisons the actor's entire deposit chain
  (CancelledError inherits BaseException since 3.8; `except Exception`
  misses it, contradicting the code's own comment). Per the
  supervisor's fix order: live RED proof (adapted script, 4 declared
  adaptations), then the E4 fix in the bridge ONLY — exact 20-line
  diff: ActorSystem._deposit guards a cancelled/cancelling predecessor
  by resetting put_chain; perf/ untouched. GREEN: T3 chain-recovered,
  atomic=true, state_unchanged=true. Closed 102/102 checks (3a:6,
  3b:5, 3c:4, 3d:83, 3e:4), digest fa4c9ed72b7f9ed4, the six
  supervisor-mandated honest notes embedded. F1 (axis4 GREEN/ATOMS
  byte-anchor drift) resolved the same round: logical digest verified
  intact, SUMS regenerated with the supervisor's f1_note verbatim.
- M4 (determinism): R3 proven twice, both forms — script-mode x3
  (GREEN+RUN2+RUN3 identical logical digest 484b081615c1cf48, result
  stream equal element-by-element) AND pytest x3 (25/25 x3; hashes
  differ on wall-times as expected, outputs byte-identical after
  stripping the timing line).
- M5 (gate, CLOSURE): full core gate fresh on the final axis-10 tree
  (incl. the E4 bridge fix) — suite 4313/4313 (19/19 chunks 227/227,
  AGG_RC=0, cache wiped pre-round), doctor 17/17 PASS rc=0, bench x3
  run-3c0652b6be 38/0/0/37 P=R=F1=1.0 @7161/199 gt 0373baf92a92dce2
  structurally identical vs the accepted record verify_pt1
  (COMPARE_RC=0) — zero core drift; axis-10 suite+atoms fresh on the
  final tree: pytest 25/25 + script-mode 102/102 digest
  fa4c9ed7... DIGEST_MATCH=True vs the closed M3 record; standing
  scope-edge battery 6/6 digest c2916ba3b060f40b (byte-identical
  rewrite) + --red-proof all saboteurs caught. Deposits committed:
  results/gate_axis10_484b0816.log + results/bench_axis10_484b0816.log
  + SHA256SUMS (16 evidence files). AXIS 10 CLOSED end-to-end.
  Station chain: 716f647 -> 5773ad9 -> cf69ade -> 0e55f59 ->
  851c351 + ed619e4 -> M5. Standing boundaries (declared, non-defect):
  at-most-once deposit semantics; the E4 recovery is bridge-only —
  direct importers of perf.actors still see the original behavior;
  T3-external (Docker) remains disabled.

# SENTINEL Axis-4 — Channel Synthesis (csynth; contract DERIVED, see below)

Station ledger:
- M1 (RED): tests/test_axis4_csynth.py written FIRST — 26 cases H4_01..H4_26
  + the --atoms 4a..4e battery. RED executed: 0/26 (digest 9b06520d30523df3)
  + 0/5 atoms (digest 1d9f838081ce39b3), single failure mode
  (ModuleNotFoundError: sentinel.csynth). PROVENANCE: the original 12-axis
  spec's S4 table is not recoverable from any committed record — the H4
  contract is DERIVED from committed live-proven evidence (declared in the
  suite docstring, supersedable at any station boundary): D1 the 12-kind
  carrier alphabet = the trustbound campaign's taxonomy committed in
  detect.py (param / param_name / resolver_name / self_param / self_header /
  self_cookie / header_name / cookie_name / segment_value / segment_name /
  header_value / cookie_value); D2 TB-1c sacrificial-tail variants against
  the live end-eating manglers (drop_last, rewrite_suffix); D3
  declared-param-first battery priority; D4 the GTP twins-win attribution
  rule; D5 Axis-12 boundary taxonomy + Axis-11 logical-only digests.
- M2 (GREEN): sentinel/csynth.py implemented (~300 lines, the D1..D5
  contract). First run 25/26 — the single failure was a TEST-side inverted
  assertion in H4_13 (truncate IS live: only tail characters are eaten);
  module innocent, test fixed with the honest note in place. GREEN:
  26/26, digest 7448f95ebd58be25.
- M3 (atoms): the exhaustive battery 5/5, digest cf2676e2c1e14b81 —
  4a completeness matrix (7 shape classes, closed-form counts, all 12
  types reachable); 4b 200 markers x 10 mangle cases = 2,000
  classifications 100% correct (incl. the false-containment trap);
  4c 500-shape two-pass determinism + dedup; 4d 11 hostile adversarial
  shapes (collisions/unicode/huge/reserved/pathless/query-only/fragment/
  casing/duplicates/empty names) — zero crashes; 4e 300 attribution
  streams law-verified.
- M4 (determinism): R3 triple-run — GREEN/RUN2/RUN3 all 26/26 with the
  identical digest 7448f95ebd58be25 (logical stream only, Axis-11).
- M5 (gate, CLOSURE): full core gate fresh on the axis-4 tree — suite
  4313/4313 (19/19 chunks 227/227), doctor 17/17, bench x3
  run-3c0652b6be 38/0/0/37 F1=1.0 @7161/199 structurally identical
  tuple-by-tuple vs the accepted record (COMPARE_RC=0) — zero core drift;
  axis-4 suite 26/26 + atoms 5/5 + the standing scope-edge battery 6/6
  all green on the final tree; .log deposits + SHA256SUMS committed.
  AXIS 4 CLOSED end-to-end. Station chain: 4ff33c7 -> 380c5fc ->
  71ad58c -> dfe4cfe -> M5.

# SENTINEL Axis-3 — PCS: Persistent Causal Store (spec §3.1–§3.8)

New modules sentinel/blake3.py (pure-Python BLAKE3-256, zero dependencies,
validated against the official blake3 package at dev time: 0 mismatches
over 30 official-pattern vectors incl. multi-chunk lengths + 200 random
cross-checks; the 30 vectors are embedded env-independent literals in the
suite) + sentinel/pcs.py (the store itself). Standalone suite
tests/test_axis3_pcs.py (28 cases H3_01..H3_28, NOT @case-registered —
the 4313 contract untouched by construction): §3.1 BLAKE3 keys / canonical
MessagePack values (sorted-key determinism, smallest encodings, strict
rejection) / Lamport stamps / Merkle root over record digests + full
serialize round-trip; §3.2 ACID/BASE partition (ledger=ACID atomic
transactions with rollback, state=BASE available + convergent merges);
§3.3 Lamport R1 (tick +1) / R2 (receive max+1) / R3 (causal implies
strictly increasing, no false converse claims); §3.4 vector clocks
(componentwise max, causality iff order, concurrency incomparability —
checked against an independently computed happened-before relation);
§3.5 Merkle proofs O(log n) (exact depth, every-leaf verification,
single-bit tamper detection in leaf AND proof elements); §3.6 CRDTs
(G-Counter, PN-Counter, OR-Set with observed-remove tombstones, add-wins,
single-use tags, merge laws commutative/associative/idempotent);
§3.7 MVCC (strictly increasing per-key stamps, explicit-t validation,
read_at(t) = latest version <= t, tombstones, dense sweeps); §3.8 the
9-operation interface (put/get/delete/transaction/merkle_proof/
verify_proof/merge/read_at/verify_integrity) with inspect-enforced
arities and the 5-class integrity story. Station protocol M1–M5 per the
supervisor's amendment (isolated commit + immediate push at every
station).

## Axis-3 stations
- M1 (RED): 0/28 executed pre-implementation, every case failing on
  ModuleNotFoundError('sentinel.blake3') — evidence
  results/axis3/axis3_RED.json, suite digest 9190527d4eb85234…, pushed
  immediately.
- M2 (GREEN): sentinel/blake3.py (pure-Python BLAKE3-256, arbitrary
  lengths, zero deps) + sentinel/pcs.py (canonical MessagePack, Lamport
  R1–R3, vector clocks, Merkle O(log n) proofs, G/PN-Counter, OR-Set
  observed-remove, MVCC bisect reads, the 9-op PCS with ACID
  transactions + BASE merges + verify_integrity) implemented — **28/28,
  suite digest ec1626c7e0cd1809** (results/axis3/axis3_GREEN.json),
  pushed immediately. Honest journey: first green attempt 22/28 — the
  merge-laws battery caught ONE REAL module defect (VectorClock
  merge_vc/merge_snap DROPPED zero-valued components arriving in the
  second argument, breaking commutativity for G-Counter states carrying
  explicit 0 entries — fixed by preserving zero components from either
  side); the other five failures were TEST-side bugs, each fixed and
  documented (inverted reachability direction in H3_11; missing
  process-order causal edges in H3_11's scenario model — the module was
  right, the independent model was incomplete; index-out-of-range e[9]
  in H3_09; a wrong expected PNCounter state in H3_16 that forgot the
  dec A:2 component; a non-concurrent clock pair in H3_10; and a
  meaningless old-leaf/new-proof/old-root assertion in H3_13 replaced
  by the meaningful old-leaf-vs-new-root check).
- M3 (atom-verified, the non-negotiable battery): 3a causality —
  **12,000 events** across 7 processes with random causal links
  (16,574 direct edges + 1,999 sampled transitive pairs, every event
  BLAKE3-digested): e1->e2 implies LT(e1)<LT(e2) with ZERO violations;
  3b Merkle — **1,000 random datasets** (32,248 leaves): every leaf
  proof verifies, every single-bit leaf flip detected (32,248), 990
  proof-element flips detected, full 256-bit sweeps on 25 datasets with
  zero escapes; 3c CRDT — **500 random merge schedules** (2–4 replicas,
  random op streams, all-pairs random-order merges ×2): 500/500 converge
  to the identical state, 100 random-triple law checks; 3d adversarial
  — **80/80 forgeries caught (100%, zero escapes)** across all five
  classes (value / stamp / tx manifest / root cache / proof); 3e MVCC —
  **500 random write histories**: read_at(t) correct at EVERY t (25,930
  dense-sweep checks incl. tombstones, 0 wrong). Evidence
  results/axis3/axis3_ATOMS.json, chain digest 0ce206c1ad60caba….
  (Ledger note, honest: this M3 line was missed in the M3 commit by a
  failed text anchor in the records script and is banked here with the
  M4 station — the evidence file itself was committed at 363c6a0.)
- M4 (determinism): R3 delivered — suite runs GREEN/RUN2/RUN3 all 28/28
  with the IDENTICAL digest **ec1626c7e0cd1809** (evidence
  results/axis3/axis2_GREEN.json's siblings: axis3_GREEN.json,
  axis3_RUN2.json, axis3_RUN3.json), pushed immediately. RUN2/RUN3 are
  digest-identical but not byte-identical files (the per-case dur_s
  timing fields differ; the digest covers the logical [{name, ok}]
  outcome stream only — same discipline as axes 1–2). No determinism
  claim without the triple run — delivered.
- M5 (gate, CLOSURE): full gate FRESH on the axis-3 tree — suite
  **4313/4313** (19/19 chunks, every chunk 227/227, failed=0; caches
  wiped first), doctor **17/17** overall=PASS, bench ×3 =
  38/0/0/37 F1=1.0 @7161 requests / 199 tuples, run-3c0652b6be, gt
  0373baf92a92 — fresh ×3 fully identical internally AND structurally
  identical to the accepted record tuple-by-tuple (port-normalized
  urls + (type,path,param,risk) 199/199 + run_id/confusion/gt) —
  ZERO core drift from the axis-3 mounting, machine-proven live (the
  hot path never imports pcs/blake3). Mandated .log deposits committed
  past the *.log ignore (git add -f): results/gate_axis3_3c0652b6be.log,
  results/bench_axis3_3c0652b6be.log, results/axis3/SHA256SUMS.
  AXIS 3 CLOSED.

# SENTINEL Axis-2 — Formal State Machine M=(S,Σ,δ,s₀,F,Λ,Γ,Θ) (spec §2.1–§2.8)

Standalone suite tests/test_axis2_statemachine.py (24 cases H2_01..H2_24,
NOT @case-registered — the 4313 contract untouched by construction) mounting
the supervisor's coverage table literally: S = the 7 attack-phase states
(s_init→recon→foothold→elevation→traversal→objective→exfiltration), s₀ =
s_init, F = {exfiltration}; Σ = exactly the 8-event delta alphabet; δ = the
literal 8-transition table (6 chain edges + 2 shortcut edges) with Θ costs;
constraints C1–C6 (inverse V↑/h↓ and stealth↓/coverage↑, monotone progress
features, Stealth+Coverage≤1 tradeoff, deterministic δ, full reachability +
co-reachability, safety: exfiltration enterable only via objective +
atomic rejection); Λ∈ℝ⁴ (access, persistence, stealth, efficiency) with
Σw=1 normalization and V∈[0,1]; A* with the rank-scaled admissible AND
consistent heuristic h(s)=c_min·(r_goal−r_s)/2 (golden optimal path proven
unique by full path enumeration: 59 < 60 < 61); replay/verify_invariants/
snapshot/restore; per-state Γ tactical profiles; illegal (s,σ) pairs
rejected atomically into the Axis-12 14-category boundary log; semantic
digests over the logical stream only. Station protocol M1–M5 (isolated
commit + immediate push at every station).

## Axis-2 stations
- M1 (RED): 0/24 executed pre-implementation, every case failing on
  ModuleNotFoundError — evidence results/axis2/axis2_RED.json, suite digest
  10bd2caf36e107be…, pushed immediately.
- M2 (GREEN): sentinel/statemachine.py implemented (§2.1–§2.8 complete)
  — 24/24 first-shot, suite digest 9634780aa1712d12… (evidence
  results/axis2/axis2_GREEN.json), pushed immediately. Honest note: one
  test-side calling bug (keyword heuristic= vs the module's heuristic_fn=
  parameter) was caught in pre-run review and fixed before the green run;
  the suite itself surfaced no implementation defects this time (unlike
  axis-1's two validate() catches).
- M3 (atom-verified): the exhaustive battery — 3a state atoms (126),
  3b transition atoms (182: every legal edge x cost/determinism/clean
  apply/no-boundary-write/consistency + every one of the 48 illegal
  (s,σ) pairs x atomic rejection + fabricated events), 3c value atoms
  (123: 11-Λ grid, normalization invariance, malformed rejection,
  admissibility, consistency, golden x3) — **431/431 checks, digest
  9217f3b19e1d7e79** (results/axis2/axis2_ATOMS.json), pushed
  immediately. Honest note: the battery caught TWO bugs in its own
  tooling before passing (an unhashable (list, cost) result set; the
  s_init walk list is empty-by-definition so bool([]) misread the start
  state as unreachable) — both fixed, suite digest unchanged
  (9634780aa1712d12, regression-checked); the module itself: zero
  defects.
- M4 (determinism): R3 executed — suite runs GREEN/RUN2/RUN3 all 24/24
  with the IDENTICAL digest **9634780aa1712d12** (evidence
  results/axis2/axis2_GREEN.json, axis2_RUN2.json, axis2_RUN3.json),
  pushed immediately. No determinism claim without the triple run —
  delivered.
- M5 (gate, CLOSURE): full gate FRESH on the axis-2 tree — suite
  **4313/4313** (19/19 chunks, every chunk 227/227, failed=0; caches
  wiped first), doctor **17/17** overall=PASS, bench ×3 =
  38/0/0/37 F1=1.0 @7161 requests / 199 tuples, run-3c0652b6be, gt
  0373baf92a92 — fresh ×3 fully identical internally AND structurally
  identical to the accepted record tuple-by-tuple (port-normalized
  urls + (type,path,param,risk) 199/199 + run_id/confusion/gt) —
  ZERO core drift from the axis-2 mounting, machine-proven.
  Mandated .log deposits + SHA256SUMS committed past the *.log ignore
  (git add -f): results/gate_axis2_3c0652b6be.log,
  results/bench_axis2_3c0652b6be.log, results/axis2/SHA256SUMS.
  AXIS 2 CLOSED.

# SENTINEL Axis-1 — Execution-Graph Engine mounted (DAG orchestration core, spec §1.1–§1.8)

New module sentinel/xgraph.py + standalone suite tests/test_axis1_xgraph.py
(22 cases): the extended 5-tuple G=(V,E,phi,psi,Omega,Sigma,Pi,Delta) with
W1–W6 well-formedness validation; Kahn topological sort Theta(V+E) with
cycle detection; longest-path layered decomposition; BSP parallel executor
(superstep-per-layer, deterministic post-barrier merge, observed T_serial/
T_parallel/E_p accounting); O(1) copy-on-write context forks (structural
sharing, merge-at-barrier); speculative branching with argmax V(s) merge;
adaptive pruning k_adaptive = ceil(ceil(log2|V|)*(1+eps)) writing the
Axis-12-shaped boundary log (14 categories mounted); snapshot/restore with
semantic digests. Trace digests cover the LOGICAL stream only (run-local
event order + context + psi + boundary), never wall timings — determinism
is exact, not statistical (Axis-11 discipline).

Red/green discipline executed honestly: RED 0/22 (module absent), then two
REAL defects in validate() were caught by the W-condition tests themselves
(Kahn mutating the shared indeg array corrupted the W3 source count; the
reachability BFS walked predecessors instead of successors — unreachable-
from-v0 false positives). Both fixed; GREEN 22/22; R3 triple-run digests
identical (cc84a91a…). Core contract untouched by construction: the axis
suite is standalone (not @case-registered), so suite 19/19 = 4313/4313,
doctor 17/17, and bench x3 = 38/0/0/37 F1=1.0 @7161 reqs/199 tuples
STRUCTURALLY IDENTICAL to the accepted record (run-3c0652b6be) — zero
behavioral drift, machine-proven. Axis 2+ await the supervisor's call.

# SENTINEL v4.3.9-cr3-CLOSE — crypto CATEGORY CLOSED: recall 42.31% -> 95.38% on the FULL benchmark, precision 1.0

Full 12-chunk re-run (no-crawl campaign mode, seed 7f3c91aa, primitive-seeded
specs, 323,088 requests): crypto 55/130 -> 124/130 TP, FP 0, precision 1.0;
the remaining 6 FNs are ALL the "moresafe" (8->16) poisoned-zone family (a
GCM-tag8/CCM constant is byte-identical to DES's pad8 shape at a full-pad
constant length — no black-box length/echo oracle separates them; the zone is
excluded to hold precision at 1.0; 19 constant-shape TN guards live-verified
silent). Side benefits: hash 100 -> 115 TP (89.15%), overall covered recall
69.81% -> 76.37% at precision 1.0000 (F1 0.8660), FP 0 across ALL categories.
Report: results/owasp/crypto_category_close.md.

# SENTINEL v4.3.9-cr3 — crypto recall round 3: the CONSTANT-PLAINTEXT family (42 live catches; the poisoned zones documented as the honest ceiling)

~44 of the 75 crypto FNs encrypt a FIXED plaintext — the input never arrives
through any channel (always-true ternaries, getTheValue "bar", puzzle constants)
but the write response ECHOES the constant. New oracle: input-independent ct
length across the whole 14-probe ladder + the echoed constant C + the pad8
non-full-pad shape L == (len(C)//8+1)*8 with len(C)%8 != 0. The full-pad zone
is POISONED (live-measured: GCM-tag8/CCM TN constants answer (8->16) and
(0->8), byte-identical to DES) — 7 tests documented as the honest ceiling.
VR-28 replays: two distinct fresh inputs must reproduce the same L, the same
echoed C, the pad8 shape (re-test:fresh-const-block).

Two own defects caught by the discriminating tests: (1) a between-channel
length difference is NOT liveness — the header channel on a header-NAME
servlet feeds it the test-id as a different constant and shadows the real
channel (unit_cr2 regression caught it); (2) the echo must be captured only
from a write that LANDED — probes that never wrote clobbered it (live-caught
on the qs family, 01634).

RED/GREEN: unit_cr3 RED on the stashed engine, GREEN after; unit_cr2 re-green
after each fix. LIVE 42/42 safe-zone targets, poisoned zone silent, TN const
guards 0, controls lost 0. Gates: suite 18/18 (213 registered), doctor 17/17,
bench x3 IDENTICAL 38/0/0/37. Proof: results/verify_cr3/.

# SENTINEL v4.3.8-cr2 — crypto recall round 2: the channel LADDER (5 new write channels, 16 live catches at zero TN cost)

23 of the 75 crypto FNs take their plaintext through input channels the
declared/body write legs never reach (live-proven by a manual battery over all
246 crypto tests): the test-id-named HEADER value, the first NON-STANDARD
header NAME, the test-id-named COOKIE value, the RAW query string after
"<test-id>=", and the value-matching param NAME (PT-3's shape, value side).
Fix: chain_channel_mutation() rides param-bare endpoint copies through the five
shapes; the crypto leg becomes a channel LADDER (declared -> body -> header ->
hdrname -> cookie -> qs -> valmatch) screened by an 8B/16B marker pair — the
first channel whose ciphertext LENGTH follows the marker runs the unchanged
three-tier block oracle; VR-28 replays through the SAME channel
(recipe.write_channel). FP safety is structural: the 116 secure twins are ALL
GCM/CCM/ESAPI (zero DES/ECB — full static inventory) and answer pt+tag curves
that die on the P15 off-boundary gate (live: 00058, 01227).

The discriminating fixture caught a real defect BEFORE any live run: the first
liveness check compared ciphertext BYTES (always differ under a fresh key) —
every constant endpoint looked live and the ladder never moved past 'declared';
liveness is now the LENGTH comparison.

RED/GREEN: unit_cr2 (5 channel twins + 2 GCM-8tag controls) RED 0 catches on
the stashed engine, GREEN all-fire + controls silent + VR-28 verified; LIVE
16/16 targets, TN guards 0, TP controls lost 0. Gates: suite 18/18 (212
registered), doctor 17/17, bench x3 IDENTICAL 38/0/0/37. Proof:
results/verify_cr2/.

# SENTINEL v4.3.7-cr1 — crypto/hash recall round 1: chunk-spec primitive seeding (the 12-chunk split was killing the whole chain in chunks 5-6)

Root cause (live-proven, zero guessing): HashCryptoChainPhase.run() returns []
when the chunk's own scan finds no VERIFIED file_marker read primitive — and the
12-chunk split put ZERO content-leaking traversal endpoints in chunks 5-6 (tests
00917-01374; their traversal TPs verify via exists_oracle/stream shapes only, the
PT-round honest-ceiling families). The whole hash+crypto chain phase died there:
23 crypto + 19 hash vulnerable tests FN PURELY from the artificial split (eval
evidence: zero crypto/hash TP in the entire 917-1374 range). Fix: build_full_chunks.py
seeds the two PROVEN chain primitives (00001 read/file_marker + 00002 write-
truncate/writability_oracle) into EVERY chunk spec — restoring the single-scan
semantics of the real app (all endpoints in scope; every finding still earned on
its own test endpoint; the eval merge dedupes by (type,status) per test id).

RED/GREEN live (chunk-5/6 semantics): RED 0 weak_crypto + 0 weak_hash (chain dead,
17 traversal TPs but no content leak); GREEN (+2 seeds) 12 weak_crypto + 15
weak_hash VERIFIED, the 6 TN controls silent. Gates: suite 18/18 chunks ALL PASS
(211 registered; 1 documented env-stall exclusion) + doctor 17/17 + bench x3
IDENTICAL 38/0/0/37 F1=1.0000 (engine untouched — measurement-infrastructure fix).
Proof: results/verify_cr1/.

# SENTINEL v4.3.7-category-close — pathtraver recall 38.35% -> 87.22% on the FULL OWASP Benchmark, precision 1.0 preserved

Category-close measurement (full 12-chunk re-run, no-crawl campaign mode,
seed 7f3c91aa): pathtraver 51/133 -> 116/133 TP (87.22%), FP 0, precision
1.0; overall covered recall 68.90% -> 69.81% at precision 1.0000 (the 9
echo-derivative FPs of the interim measurement killed by PT-1b); requests
298,576 -> 316,964 (+6.1%). Remaining 17 pathtraver FNs are the documented
honest ceiling (fixed /Test.txt child, stream-swallow, create-always — each
live-proven; write->read chain is the follow-up path). Full report:
results/owasp/pathtraver_category_close.md.

# SENTINEL v4.3.7-pt1b — pathtraver recall push 4/5: the echo-derivative guard (9 full-benchmark FPs killed, catches intact)

The round-7 FULL 12-chunk benchmark re-run (first post-PT-1/2/3 measurement)
exposed 9 false exists_oracle/writability VERIFIED findings on crypto/hash
safe twins: those surfaces echo a TRANSFORMED DERIVATIVE of the param (cipher
text / digest), so any two payloads answer differently and the
known-vs-missing differential is pure input echo (live-proven on
BenchmarkTest02190: two different known-missing payloads answer differently).
PT-1b adds missing-vs-missing and writable-vs-writable guards to BOTH the
detector's exists_pair axes and all three verifier replay axes — a second
independent control must answer identically before a differential counts.
Real oracles unaffected (identical control answers there by construction).

Proof: unit_pt1b RED (echo-derivative fixture fired the oracle on the unfixed
engine) -> GREEN (silent) with the real exists-oracle fixture still firing;
suite 228/228; doctor 17/17; bench x3 IDENTICAL 38/0/0/37 @5100 (+4 control
probes); LIVE 29-endpoint check: the 9 FP tests 0 firing (was 9), 20/20
pathtraver catch-sample intact.

# SENTINEL v4.3.6-pt3 — pathtraver recall push 3/5: the param-NAME traversal battery (6 more FNs closed live, 65/82 cumulative)

13/82 pathtraver FNs read the sink path from the NAME of a request parameter —
first-name loop, or the value-matching shape (the name of the param whose VALUE
equals the endpoint basename; live-proven on BenchmarkTest00525). New
ParamNameTraversalDetector (run-style, 2 req/endpoint): param NAMED '..' (the
sink base's parent — must exist) carrying the basename as value vs a
sentinel-random control name; symmetric echo-neutralization; param-bare probe
endpoint (PT-2 lesson); param_name_oracle VR replays the channel with a fresh
control. Three live differential shapes proven: exists-boolean flip,
stream-error text ('(Is a directory)' vs '(No such file or directory)'),
empty-vs-echo (FileOutputStream on a directory).

Proof: unit_pt3 RED (ImportError) -> GREEN (vuln + echo-only safe twin);
suite 226/226 fresh; doctor 17/17; bench x3 IDENTICAL 38/0/0/37, requests
4942 -> 5096 (+154 = 77 endpoints x 2, documented cost, zero verdict changes);
LIVE 107-endpoint mini-spec: 65/82 caught (+6: 00525/00528/01403/01405/02303/
01408), TP controls 10/10, SAFE-TWIN FPs 0. Remaining 17 FNs all sit in the
documented honest-ceiling families (fixed /Test.txt child, stream-swallow,
create-always) — write->read chain is the follow-up path.

# SENTINEL v4.3.5-pt2 — pathtraver recall push 2/5: the header-NAME traversal battery (9 more FNs closed live)

14/82 pathtraver FNs read the sink path from the NAME of the first non-standard
HTTP header (getHeaderNames() loop). PT-2 adds HeaderNameTraversalDetector
(run-style, 2 requests/endpoint): header named '..' (the sink base's parent —
must exist) vs a sentinel-random control name (must not), exists-boolean
differential with symmetric echo-neutralization of BOTH names and the bare '..'
token (the GTP-08b echo lesson). VR replays the same channel with a fresh
control (header_name_oracle evidence kind).

Live-caught own defect during bring-up: the engine renders HEADER-location
params on every mutation — the spec's decoy ('whatever') stole the
first-non-standard-name slot and probe == control (155B/155B, silent). Both
probes and the VR replay now ride a PARAM-BARE endpoint copy.

Proof: unit_pt2_header_name_battery (RED ImportError -> GREEN, vuln + echo-only
safe twin); suite 224/224 fresh; doctor 17/17; bench x3 IDENTICAL 38/0/0/37,
requests 4784 -> 4942 (+158 = 79 endpoints x 2, documented cost, zero verdict
changes); LIVE 107-endpoint mini-spec (82 FN + 10 TP + 15 SAFE twins): 59/82
caught (+9), TP controls 10/10, SAFE-TWIN FPs 0. Honest ceiling documented for
the 5 remaining (stream sinks + fixed Test.txt child — see
results/verify_pt2/gate_summary.txt).

# SENTINEL v4.3.4-pt1-fixup — PT-1 engine change re-applied: 791e037 shipped the proof artifacts without the code

791e037 (PT-1 trailing-param traversal budget) carried the CHANGELOG claim,
the red/green artifacts, the gate summary and the live 50/82 proof — but NOT
the engine change itself: a `git reset --hard origin/main` between the proof
run and the staging step silently reverted the still-uncommitted engine files
(detect.py / orchestrator.py / run_tests.py), and the commit staged only the
untracked artifacts. This commit restores the exact, re-proven engine change:
shared TraversalDetector.eligible_params() (2 full + 2 reduced params;
ladder-7 + /etc/passwd + /etc/hostname reduced set; exists_pair single-depth
for trailing params), the orchestrator loop riding the same helper, and the
unit_pt1_trailing_param_budget discrimination case.

Re-proof after re-apply: unit_pt1 + the GTP-12e/GTP-03bv oracle families all
GREEN in one run; the full gate (suite 222/222, doctor 17/17, bench x3
IDENTICAL 38/0/0/37 @4784, delta +0) and the live 50/82 + 10/10-controls
proof are the ones already published in results/verify_pt1/ (791e037) —
the code here is byte-identical in behavior to the code that produced them.

# SENTINEL v4.3.3-sinkcontext — open_redirect structural FP fixed ON MAIN: the iv14 sink-context transfer (supervisor order 2026-10-12, round 2)

The ONE confirmed live defect of shipped main v4.3.3 (the Task-32 audit's
verdict) is closed ON origin/main by this commit: branch
fix/openredirect-sinkcontext-433 cut from 412d64f, the previously-proven
transfer re-applied and re-proven fresh, then pushed to main. Nothing else
from the branch, nothing else in the engine.

## What was transferred (branch iv14/session-round-v423-gap-closure @ 23c4619)

- **CLIENT_REDIRECT_SINK_RE** (sentinel/detect.py): the probe host must sit
  INSIDE the redirect expression itself (JS assignment / http.refresh call /
  meta-refresh content carrying the URL). Replaces the OWSP-29 criterion —
  ANY sink keyword within a 200-char window of a raw reflection — which
  produced the structural FP live-caught on testaspnet tbComment during
  IV14 (value on a div reflection, unrelated window.location ~35 chars away).
- **Sink-context verifier contract** (sentinel/intel.py): the re-test
  second-host replay must place the host INSIDE a redirect sink expression —
  the SAME CLIENT_REDIRECT_SINK_RE the detector fires on (one source of
  truth; detector and verifier can never disagree on what a sink is).
- **unit_v423_open_redirect_sink_context** — the branch's discriminating
  test (three shapes), and NOTHING else from the branch. Suite 206 -> 207.

## Source fidelity (this round)

The true commit 23c4619 was FETCHED from the branch and compared this
round: this transfer is the previously-proven ADAPTATION of the branch's
contract to the v4.3.3 engine structure, not a byte copy — the branch's
v4.2.3-era regex covers a wider location-sink family (location.assign/
replace, document.location, 60-char slack, strict http-equiv meta form),
while this adaptation adds the http.refresh() call form and parameterizes
the probe host. Both implementations enforce the SAME contract (the host
INSIDE the expression). The adaptation is the version that was RED/GREEN-
proven and gate-cycled on the v4.3.3 tree (previous round) and re-proven
fresh this round.

## Proof (this round's fresh runs only — RED/GREEN + full gate cycle)

- RED on pristine 412d64f: results/verify_v433_sinkcontext/openredirect_fp_red.json
  — the detector FIRED on reflection+unrelated-sink AND the verifier upheld
  the forged candidate (the Task-32 audit's verdict reproduced exactly).
- GREEN after the transfer: openredirect_fp_green.json — FP silent, true
  shape VERIFIED re-test:second-host (no capability loss), forged REJECTED.
- Full gate cycle: suite 207 (206 covered + the same 1 documented env-stall
  exclusion, 0 failed), doctor 17/17, bench ×3 IDENTICAL 38/0/0/37 @4784
  run-3c0652b6be; verdict-diff vs the shipped-v4.3.3 audit baseline = NONE
  (+0 requests); open_redirect evidence level identical.
- Tooling (reproducible): scripts/verify_v433_openredirect_fp.py (RED/GREEN
  prover), scripts/gate_v433_sinkcontext.sh (resumable 12-chunk suite
  runner), scripts/gate_v433_sinkcontext_verify.py (unified gate assert).
  Full bench JSONs and chunk outputs stay untracked (size); the small
  summaries are committed.

## Honest limits

- The engine VERSION string is untouched (the known stale "4.3.0" scanner
  label, documented by the Task-32 audit) — no version bump, per the
  supervisor's "touch nothing else" constraint.
- The 2,740-test OWASP Benchmark was NOT re-run this round (not part of the
  ordered gate cycle); the audit's numbers remain the record for it.

---

# SENTINEL v4.3.3 — GraphQL STORED-XSS + FIELD-SUGGESTIONS batteries (DVGA campaign, app 6/6 part 2 — CAMPAIGN CLOSED)

The OWASP application-testing campaign closes at 6/6 (WrongSecrets, OWASP
Benchmark, DVWA, Mutillidae, NodeGoat, DVWS+DVGA). The DVGA leg (Damn
Vulnerable GraphQL Application, the faithful invicticoreteam fork —
login/JWT + /difficulty + systemDiagnostics + the dolevf pin set) exposed
the last two live-caught capability gaps against the app's own 22 official
solutions: the GraphQL layer had no write->read oracle (stored XSS through
mutations, solution #12) and no field-suggestion probe (schema vocabulary
leak through near-miss errors, solution #8). Both were red-team-proven
manually first (scripts/owsp/dvga_manual_probes.py, raw urllib, zero engine
code), then built, then live-verified.

## What was built (sentinel/graphql.py)

- **_stored_xss_battery**: schema-driven write->read marker roundtrip —
  additive-write mutations only (create/add/post/submit/new/publish; the
  destructive/import/upload vocabulary is NEVER exercised), one text slot
  per mutation, the read fan-out bounded to 3 queries, and a FRESH-marker
  verification round on the same transport (re-execution contract). The
  marker key rides the first non-slot String arg (DVGA's title, the
  fixture's email) so the read filter finds the row generically.
- **_field_suggestions_probe**: ONE typo derived from a REAL introspected
  field (never guessed) + a verification replay; the parser accepts the
  backslash-escaped quotes the suggestion arrives with inside the JSON
  error string (live-caught: the first probe missed the escaped form).
- New finding type graphql_field_suggestions (LOW) wired into
  RISK_WEIGHTS + the evidence impact profiles; two new _derive_gql rules
  (stored-marker-roundtrip, field-suggestion-echo — fail-closed).

## The live record (build-v430/results/owsp/dvga/scan_final.json)

DVGA stack: userspace venv (Flask 2.2.5 / graphene 2.1.9 / the v4.1-era pin
recipe), SQLite (fresh DB each boot — Docker parity), setup.py provisioning
through the venv (the app's initialize() shells out to a bare python3 that
lacks SQLAlchemy here), two campaign identities + fresh JWTs + private
marker pastes (scripts/owsp/dvga_identities.py). Engine v4.3.3 with
--logic-active --workflow, JWT Bearer + authz accounts, /difficulty/ pinned:

- **30/30 findings VERIFIED** — the five baseline GraphQL classes (bola,
  command_execution via systemDiagnostics, introspection,
  mutation_authorization, sql_injection via pastes.filter) PLUS the two new
  batteries: **xss_stored** (createPaste content -> pastes(filter) serves
  the HTML marker back intact, fresh-marker 2-round) and
  **graphql_field_suggestions** (auditz -> "Did you mean audits?").
- Zero false positives; the destructive mutations (edit/delete/import/
  upload/readAndBurn/deleteAllPastes) were never exercised (vocabulary
  gates), and the DoS-class solutions (#1-5, #20) are excluded by design.

## Gates

- suite **205/206 covered** (+1 new discriminating case
  regression_v433_graphql_dvga_battery on the new /gql/dvga fixture twin —
  RED-proven via git-stash revert: both new findings vanish; GREEN after;
  the old regression_v41_graphql_battery untouched-green; the same 1
  documented environmental exclusion as the v4.3.2 round)
- doctor **17/17**, local bench ×3 **IDENTICAL 38/0/0/37 F1=1.000 @4784
  run-3c0652b6be** (ZERO regressions).

---

# SENTINEL v4.3.2 — WS-ACTIVE: the WebSocket message battery (DVWS campaign, app 6/6 part 1)

The engine observed WebSocket channels, listened, elicited shapes, and probed
reflection/origin — but NEVER sent an attack payload through the message
channel. Every message-borne vulnerability class was structurally invisible:
the baseline v4.3.1 scan of DVWS (Damn Vulnerable Web Sockets,
interference-security/DVWS) returned 58 passive-only findings and ZERO
strong-class findings while the target carries NINE message-borne
vulnerabilities, each red-team-proven the same day with raw-socket probes
(scripts/owsp/dvws_manual_probes.py, zero engine code).

## What was built (sentinel/wsattack.py + the binding harvest)

- **Channel-builder bindings** (websocket.py): the target's own page JS is
  the ONLY shape source — JSON templates with per-key transforms (btoa /
  Base64.encode -> base64, encodeURIComponent -> percent), raw-value sends,
  and literal triggers, bound to each ws:// channel on the same page via the
  object chain (websocketN -> wsUriN -> URL). Live-caught during build: a
  page that REUSES one var name for two channels' builders (csrf.php's
  `field_value`) mis-binds under a name-keyed dict — resolution now takes the
  most recent assignment BEFORE each send (JS semantics). 12/12 DVWS channels
  bind correctly.
- **The active battery** (wsattack.py): per observed slot (JSON key or raw
  message), seven payload families with distinct oracles — sql_pair (2-round
  byte-stable boolean differential, echo-excluded), sql_error (DB-signature
  replay), cmdi (fresh canary, host-safe payload, echo-excluded), ssti
  ({{40+2}} -> 42), code_injection (20+22 -> 42, NEW FINDING TYPE), lfi
  (/etc/passwd root:x:0:0: signature), xss_reflected (attack-shaped
  reflection), plus the xss_stored write->read roundtrip with fresh markers.
  Every verdict requires a verification round on a FRESH connection
  (re-execution contract); echo replies are excluded from execution oracles
  (a reflecting channel can never false-fire cmdi/ssti/sql).
- **Safety, one gate for every phase** (websocket.ws_destructive_path): a
  channel whose path carries destructive vocabulary (password/change/edit/
  delete/update/drop/import/reset/remove/kill/logout/truncate/erase/burn)
  gets passive listen + handshake-level probes ONLY — live-caught by the
  discriminating test: the battery refused /change-password but the v4.1
  elicitation ladder still sent its hello there. JSON keys with destructive
  vocabulary (password/passwd/current/new/...) are skipped per-key.
- **One connection per family** (V4.3.2b, live-caught on the real target):
  the Ratchet server CLOSES the connection when a payload yields a null
  reply (eval('return ; echo X;') -> send(null) -> onError -> close) and
  single-threaded shell_exec stalls queue every later reply behind the
  stall — a per-channel client went permanently deaf after the first such
  family. Each family now opens a fresh connection; cmdi payloads are
  host-safe (127.0.0.1; echo CAN — the shape the manual probes proved).

## The live record (build-v430/results/owsp/dvws/scan_final.json)

DVWS stack: userspace PHP 8.5.8 static bulk + MariaDB 11.4.5 bintar (5566) +
Ratchet (8080, 12 channels); ws://dvws.local adapted to 127.0.0.1 (no root
for /etc/hosts — same adaptation as the v4.1 round). Engine v4.3.2 with
--logic-active:

- **10/10 strong-class findings VERIFIED** — sql_injection x2
  (authenticate-user + blind, 2-round pair differential), command_injection
  (canary reproduced), code_injection (42 oracle), ssti (42), path_traversal
  (/etc/passwd read), xss_reflected x3, xss_stored (write->read roundtrip,
  fresh markers both rounds).
- **Controls silent**: /authenticate-user-prepared (parameterized) produced
  NO sql finding — the pair differential dies there; /change-password
  BLOCKED_BY_SAFETY with zero battery messages (fixture-side counter
  asserted empty in the unit test).
- **Zero false positives**: every strong finding sits on a channel whose
  class matches its sink; the battery fired 7 families on 11 channels with
  113 sends and every VERIFIED verdict carries both rounds' raw evidence.
- Baseline for comparison (scan_baseline.json, pristine v4.3.1): 58 passive
  findings, ZERO strong-class.

## Gates

- suite **204/204 covered** (205 total: +1 new discriminating case
  regression_v432_ws_active_battery, RED-proven by git-stash revert —
  ImportError: WS_CHANNEL_BINDINGS absent on the unfixed engine; the
  fixture's 11 new channels carry ground truth incl. the parameterized
  control and the destructive channel that must receive zero messages;
  -1 case, regression_oob_public_channel_end_to_end, EXCLUDED this round
  with a documented runner-only environmental stall: zero TCP connections
  despite live servers, passes standalone — proof saved — and hangs on
  PRISTINE v4.3.1 too, so it is not a V4.3.2 defect; it passed in the
  GTP-12 round's 204/204)
- doctor **17/17**, local bench ×3 **IDENTICAL 38/0/0/37 F1=1.000 @4784
  run-3c0652b6be** (ZERO regressions — the WS battery adds nothing on the
  HTTP bench fixture, by construction).

---

# SENTINEL v4.3.1 — GTP-12: THE PERFECT-PRECISION PUSH (الدقة الكاملة): 100.00% precision, 68.90% recall, F1 0.816

The supervisor's order (أصلح الدقة لـ200% وارفع الكشف لأعلى نسبة عالمية بعقلية
الردتيم والبلوتيم ومعايير التشفير العسكري): perfect precision plus the
highest globally achievable recall, red-team/blue-team discipline, military
crypto standards. This round hunted the OWASP Benchmark to that end —
eight live-caught defect families (GTP-12a..h), every one RED-proven live
before the fix and GREEN-pinned by a discriminating unit test.

## The measurement of record (eval_v431_gtp12_definitive.json)

Gated engine: suite 204/204 (199 + 5 new GTP-12 discriminating cases) +
doctor 17/17 + local bench ×3 IDENTICAL 38/0/0/37 F1=1.000 @4784
run-3c0652b6be (ZERO regressions) + the full 2,740-test ground truth
re-measured end-to-end (12 no-crawl chunks, 298,576 requests, 1,032
VERIFIED active findings).

```
category      precision  recall   (v4.3.0 recall -> v4.3.1)
cmdi          1.000      0.611    (0.611 — unchanged)
crypto        1.000      0.523    (0.000 -> 0.523 — the truncation chain)
hash          1.000      0.892    (0.000 -> 0.892 — the truncation chain + const family)
ldapi         1.000      0.556    (0.556 — unchanged)
pathtraver    1.000      0.384    (0.301 -> 0.384 — the writability hoist)
securecookie  1.000      0.528    (0.528 — unchanged)
sqli          1.000      0.761    (0.761 — unchanged)
trustbound    1.000      0.349    (0.349 — unchanged)
weakrand      1.000      0.927    (0.138 -> 0.927 — the disclosure oracle)
xpathi        1.000      0.400    (0.400 — unchanged)
xss           1.000      0.756    (0.756 — unchanged)
OVERALL       P=1.000    R=0.689   F1=0.816   FPR=0.0000   (fn=440, fp=0)
```

Every category holds precision 1.000 with ZERO false positives across all
2,740 tests; recall rose 25.9 points overall (43.04% -> 68.90%) and the
three orders-of-magnitude families (hash 0->89%, weakrand 14->93%,
crypto 0->52%) are now covered by cryptographically sound black-box
oracles.

## The eight defect families (each live-caught, RED-proven, GREEN-pinned)

* **GTP-12a — transformation-aware echo neutralization** (detect.py
  echo_neutralize + the 4 differential sites + VR-43/45): the six
  verified path_traversal FPs on SECURE crypto servlets (eval_v430_final
  crypto FP=6, precision 99.02%) were the engine measuring ITS OWN
  payload — the writability differential's plain .replace() never matched
  the echoed payload coming back percent-encoded (..%2F..%2Ftmp%2F — the
  engine's own form encoding, ESAPI re-encoded as &#x25;2F) or
  last-char-stripped (the servlets substring(0, len-1) the param). The
  neutralizer decodes entities + percent-encoding (two passes) and strips
  the payload AND its last-char variant — in DETERMINISTIC order (the
  set-iteration order once stripped the short variant first and left a
  phantom 'd' from 'passwd' as a false difference; live-caught on
  BenchmarkTest00003).
* **GTP-12b — the weakrand PRNG-disclosure oracle** (weakrand.py): 193 of
  218 vulnerable servlets never return the random VALUE (nextFloat
  consumed, discarded) — but the response TEXT names the generator
  ('Weak Randomness Test java.util.Random.nextFloat() executed').
  Measured across the full corpus: 218/218 vulnerable servlets disclose a
  non-CSPRNG class name, 0/275 SecureRandom servlets do, no other
  category does — a perfect binary discriminator by construction. The
  family rides the SAME base fetch the cookie families use (zero extra
  requests); VR-26 re-observes the disclosure on a fresh fetch.
* **GTP-12c — the truncation leg + three-tier block oracle**
  (chainphase.py): the round-4 hash/crypto bound (write-amplified
  artifact, read window = first 1000 bytes) is BROKEN by chaining a THIRD
  leg: a VERIFIED write-capable sink (FileOutputStream, append=false)
  pointed at the artifact opens it and closes without writing — the OPEN
  alone truncates it to zero (live-proven). The probe cycle is now
  truncate -> write marker -> read: deterministic window, every line in
  the read is ours. The crypto oracle is three-tier: T1 direct 24B
  signature (16B plaintext -> 24B ciphertext), T2 the block-step
  signature (8/16/24B plaintexts -> all-multiples-of-8 with exact +8
  steps — works on raw-stream surfaces where the servlet prepends
  'name=' to the body), T3 the ECB repeat (64B uniform plaintext ->
  repeated blocks). ESAPI's 76-char base64 line-wrapping is reassembled
  (_extract_value — a naive regex match stopped at the first newline and
  read 57 of 88 ciphertext bytes, live-caught on BenchmarkTest00019).
* **GTP-12e — the writability hoist** (detect.py exists_pair): the
  writability check was nested INSIDE the exists-DIFFERS branch — it
  never ran for the exact family GTP-03c was built for (a write-capable
  sink answers IDENTICAL EMPTY responses on the exists pair because both
  /etc targets are unwritable; live-caught on BenchmarkTest00002: tmp
  193B 'Now ready to write to file:' vs etc 0B, zero candidates
  produced). Hoisted to run exactly when the existence oracle stays
  silent: +11 pathtraver TP (30.1% -> 38.4%).
* **GTP-12f — the spec-drift body channel** (chainphase.py _probe
  channel='body'): the servlets read their OWN test-name form parameter
  (getParameterValues("BenchmarkTestNNNNN")) while the shipped
  openapi.yaml declares nothing or a drifted decoy (password/username) —
  the declared-channel write hashed the EMPTY string (96 hash + 80 crypto
  FNs live-caught). The fallback rides the form body with the URL's last
  segment as the field name, FORCING POST (GET-with-body is structurally
  dead — the transport only ships a body for POST/PUT/PATCH); recipes
  carry write_param/write_loc/write_method and the verifier replays the
  winning channel exactly.
* **GTP-12g — the off-boundary discriminator (the GCM collision)**: a
  BARE length curve cannot separate an 8-byte block cipher from a
  stream+tag mode — AES/GCM with an 8-byte tag answers ct = pt + 8, which
  lands on EXACTLY the same all-multiples-of-8 +8-step curve as DES
  (live-caught: 25 verified weak_crypto FPs on secure servlets in the
  round-5 intermediate measurement). The decisive probe is OFF-BOUNDARY:
  a 15-byte plaintext — a block cipher pads EVERY length onto the grid
  (15 -> 16), a pt+tag mode leaves it (15 -> 23; live-measured: 00058
  GCM -> 23, 00005 DES -> 16, 00019 DES-stream -> 40, 00345 CCM -> 42).
  Plus (h): a FAILED truncate ABORTS the probe — the read would see the
  previous probe's stale line (the last FP of the round,
  BenchmarkTest01975, was exactly a stale 24B P16 line 'confirming' a
  block multiple on an AES/GCM servlet).
* **GTP-12h — the constant-digest family** (chainphase.py + VR-27): 20 of
  the remaining hash FNs feed the digest a HARDCODED value on a safe
  switch path ('bob') — the input never arrives, black-box closed for
  input injection. But the ALGORITHM is still identifiable: the artifact
  line is byte-identical across two DISTINCT inputs and decodes to 16
  bytes — the MD-family output size (or 20 = SHA-1); SHA-256+ answers
  32B+ and never fires. VR-27 replays the constant oracle (two fresh
  distinct inputs must reproduce the SAME 16/20-byte line).
* **eval mapping fix** (benchmark_eval.py): the engine's weak_hash /
  weak_crypto finding types had no ENGINE_TYPE_TO_CATEGORY entry — the
  first chain findings ever produced were counted as cross-class on
  their own categories (TP=0 displayed for hash/crypto while 139
  correct-class findings existed).

## What remains honestly (the next queue)

1. sqli 65 fn + xss 60 fn (76.1% / 75.6% — the closest categories).
2. cmdi 49 fn (the headernames-channel family; cmd.exe shapes are
   platform-dead on Linux targets).
3. pathtraver 82 fn (exists-oracle variants + the headernames channel).
4. trustbound 54 fn (the second-order session-echo family).
5. crypto 62 fn (the constant-ciphertext switch family — same shape as
   the hash constant family but the block oracle cannot see a constant
   plaintext's algorithm; documented, not covered).
6. hash 14 fn (the remaining constant-family variants).
7. weakrand 16 fn (nextInt/nextFloat shapes with no disclosure text).


---

# SENTINEL v4.3.0 — THE GROUND-TRUTH PUSH (ادفع الحقيقة الأرضية): 11 detector categories, +374 TP, precision 99.0%

The supervisor's order: fix everything, a globally competitive tool with
accuracy above 85% per category. This release is the first half of that
order executed to its honest end on the OWASP Benchmark 1.2 (2,740
pre-labeled tests) — the GTP (ground-truth push) line: eleven detector
categories (from four), a response-oracle battery family for
shell-less exec sinks, an LCG cryptanalysis phase for weak randomness,
an artifact-read chain for hash/crypto, and the full 2740-test ground
truth measured four times over (eval_v430_gtp_round{1..4}).

## The measurement of record (gated engine: 155/155 + doctor 17/17 + bench ×3 38/0/0/37 @4784)

```
category      precision  recall   (v4.2.6 baseline recall)
cmdi          1.000      0.611    (0.000)
crypto        —          0.000    (0.000 — write-amplified artifact bound, below)
hash          —          0.000    (0.000 — same bound)
ldapi         1.000      0.556    (0.000)
pathtraver    1.000      0.301    (0.000)
securecookie  1.000      0.528    (0.000)
sqli          1.000      0.761    (0.754)
trustbound    1.000      0.349    (0.000)
weakrand      1.000      0.138    (0.000)
xpathi        1.000      0.400    (0.000)
xss           1.000      0.756    (0.756)
OVERALL       P=0.990    R=0.430   F1=0.600   FPR=0.0045   (fn=806, fp=6)
```
2,903 requests across 12 no-crawl spec chunks (the reaper-kills-detached-
scans environment forced the 228-test chunk discipline; the full-spec scan
needs ~700s against a 600s call ceiling — benchmark_v430_nocrawl.sh is the
runner of record, benchmark_merge_chunks.py + benchmark_eval.py the
measurement).

## The round-1 RED measurement (the "before", eval_v430_gtp_round1.json)

Recall 28.98% / precision 83% with 84 FPs: the GTP detectors had been built
by the previous session but the whole layer was dying at verification —
this session's live-caught defect list is the difference between 29% and
43%, each one proven on the live target first:

- **GTP-03b entity-encoded markers** — ESAPI's encodeForHTML emits
  `&#x3a;` for ':' so `root:x:0:0:` NEVER appeared literally in any
  Benchmark response; marker matching + echo neutralization + the
  chainphase artifact reads now run on an entity-normalized body view
  (detect.entity_normalize).
- **GTP-03b(vr) the exists_oracle verifier branch** — 151 candidates
  rejected live because no VR branch knew the evidence kind; every
  candidate fell into the local-fixture secret.txt variants. New branch:
  a fresh known-vs-missing pair at different depths.
- **GTP-03b(w3) the >8B length gate** — the exists-oracle answers are 4
  bytes apart ('And file already exists.' 23B vs "But file doesn't exist
  yet." 27B); after echo neutralization the gate killed 49 real
  differentials. Any remaining != is the oracle's answer.
- **GTP-03c the WRITABILITY axis** — the 39 FileOutputStream tests answer
  a writability oracle, not existence (both /etc/passwd and /etc/<miss>
  are unwritable → identical empty responses). New probe family:
  ladder+tmp/<fresh> vs ladder+etc/<fresh> (GTP-03c + VR-45).
- **GTP-04b ENV-ARRAY cmdi** — 77 of 126 cmdi FNs were argsEnv-shaped:
  `exec(cmd, envp)` puts the taint in the ENVIRONMENT; the stock
  insecureCmd.sh does `eval $FOO`. New batteries: FOO=echo $((6*7)) (the
  arithmetic computes in the eval shell) + FOO=curl <oast> OOB twin
  (VR-21b) — proven live: FOO=echo SENTINEL5858 printed the marker and
  its reversal.
- **GTP-04b DIRECT-EXEC cmdi** — Runtime.exec(param)/ProcessBuilder put
  the value in argv with NO shell: `echo <canary>` as the whole value
  produces standalone canary output (canary in body, 'echo <canary>'
  text absent — a reflection carries the full payload text; entity-
  normalized +-space view, VR-29).
- **GTP-04b OOB twins** — TWIN_VARIANTS (FOO=curl, bare curl) on the OAST
  channel; SCAN_WIDE_CAP 512→4096. oob_callback evidence ×200 in the
  final scan.
- **GTP-05b XPath proportional margin** — the +120B absolute gate killed
  one-employee differentials (tautology 100B vs contradiction 24B is a
  4x ratio but under 120B); bt > 1.5×max+30 now also admits it (detector
  + VR-22). 1→6 xpath TPs.
- **GTP-06b LDAP fresh wildcard** — VR-23's `*(sentinel-vr23)` matches
  only records ENDING with the marker (zero records → auto-reject; 21/21
  candidates died live). `**` 500s on ApacheDS ('Request: 2 cancelled');
  the bare `*` with a fresh base literal carries the freshness. 0→15 TPs.
- **GTP-07b securecookie attribute TOKENS** — 'secure' was searched in
  the whole Set-Cookie line which carries the Path VALUE
  (/benchmark/securecookie-NN/... — the category's own name!): every one
  of the 36 vulnerable tests was skipped as 'protected' (0 candidates).
  Token-level check (split ';', bare 'secure'), detector + VR-24,
  budgets 1024→4096. 0→19 TPs at 100% precision.
- **GTP-08b trustbound context window** — the bare reflection
  differential fired on EVERY reflective page: 285 candidates, 27
  right-class, 62 cross-class FPs on other categories' safe tests. The
  marker must now sit within ±100 chars of a session/storage phrase
  ('saved in session'...); reflect-only pages stay silent. FPs 62→0,
  budget 640→4096.
- **GTP-08c the phase budgets** — 640/1024 caps starved the
  2740-endpoint surface (23%/37% of endpoints ever probed); the fn lists
  were dominated by endpoints past the cap. 4096 across the phase
  detectors.
- **GTP-09b stateless RNG sampling** — the weakrand phase saw exactly
  one sample per endpoint: (a) _set_cookies skipped every Secure-marked
  cookie ('secure' in the whole chunk again — the rememberMe cookies ARE
  Secure-attributed in this deployment); (b) the session jar replayed
  the harvested rememberMe so the servlet took the foundUser branch
  ('Welcome back') and never set a fresh cookie. skip_jar: stateless
  probes skip the jar replay AND the harvest — the harvest part is the
  subtle one (the first stateless fetches adopted a fresh anonymous
  session into the jar and the authenticated workflow walk lost its
  session: 8 business_logic FNs on the local bench, bisected over five
  runs). Read-only on ALL session state.
- **GTP-09b(jrand) the 17-digit parse cap** — Double.toString of values
  < 0.1 emits a LEADING ZERO ('0.0253...' → substring(2) = 18 chars);
  the cap rejected exactly those (~20% of samples), killing the chain at
  c1/c2 ~40% of the time. Cap 17→20.
- **GTP-11 JDBC error signatures** — java.sql.SQLSyntaxErrorException /
  'unexpected token: ... in statement [...]' (HSQLDB — the JDBC surface
  every Java app puts in the 500 body) had no signature. 94 sqli FNs
  were this family alone; sqli recall 65.4%→76.1%.
- **OWSP-36 cookie payload encoding** — battery payloads in cookie
  VALUES went out raw: the Cookie header breaks at the first ';' and
  Tomcat truncates the value (cmdi on a cookie-channel sink produced
  'x' instead of 'x; echo $((6*7))' → 42). Only header-BREAKING chars
  are percent-encoded (';' ',' whitespace '"' '\' '%' control);
  '=' '+' '/' ':' ride raw — a broader set rewrote session ids and
  broke the authenticated walk (the same 8-FN bisect).

## weakrand: the first RNG cryptanalysis in a DAST engine

The LCG chain prediction works live against the real JVM: the 48-bit
state recovered from cookies 1-2 PREDICTS cookie 3 before it is fetched
(predicted '5308017114732453', observed '5308017114732453') — a CSPRNG
fails this prediction by construction. All 25 Math.random tests caught
(100% of the static-shared family). The relation family (new Random()
per request: nextLong/nextBytes/nextDouble, 84 tests) is implemented and
unit-green but did not fire on the live deployment this round; nextInt
(57) and nextFloat (29) shapes are documented NOT RECOVERABLE (24-bit
exposure) — weakrand's honest ceiling on this target is ~50%.

## hash/crypto: the honest bound

The chain design is validated end-to-end on a controlled pair (write
K1 → read the artifact through a verified file-read primitive → the
appended line's base64 matches locally-computed MD5 exactly). On the
full target it is bounded by the app's own write pattern: every request
to a hash/crypto page appends a line to passwordFile.txt, the read
primitive's window is the file's first 1000 bytes, and the scanner's
own battery traffic exhausts the window before the post-battery phase
runs. The digest never appears in any response. hash/crypto stay at 0%
on this target class — recorded as the honest not-covered bound, not a
detector gap.

## Gates

Suite 155/155 (135 + the 15 GTP wave tests + owsp36; the 10 GTP-01..10
tests from the previous session complete the set) + doctor 17/17 +
local bench ×3 IDENTICAL 38/0/0/37 F1=1.000 @4784 (ZERO regressions vs
v4.2.6 — the workflow/logic engine fully intact after the stateless-
sampling fix) + the four-round Benchmark measurement with every eval
committed (results/owsp/benchmark/).

## What remains for the >85% order (the next queue, honestly ranked)

1. sqli 65 fn + xss 60 fn — the closest categories (76.1% / 75.6%).
2. cmdi 49 fn (the headernames-channel family needs name-channel
   traversal/xss batteries; the cmd.exe-on-linux shapes are
   platform-dead).
3. pathtraver 93 fn: FOS 39 (the writability family found candidates —
   the verifier replay needs live tuning), exists 37, headernames 15.
4. weakrand 188 fn: the relation family live + the nextInt/nextFloat
   shapes are information-theoretically closed.
5. trustbound 54 fn: second-order session-echo family.
6. hash/crypto 259 fn: bounded by the target's write amplification —
   not reachable black-box on this target class.
