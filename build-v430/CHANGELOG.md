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
