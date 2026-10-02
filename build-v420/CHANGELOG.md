# SENTINEL v4.2.0 — Verification Honesty Fixes (VF-01..04)

Born from an adversarial code review of the verification engine itself: the
reviewer's question was "what makes the engine write `passed=true` — a real
replay, or a heuristic that calls itself verification?" Four break points were
confirmed and fixed. Every fix is fail-closed: the default is now "unverified",
and VERIFIED requires an explicit derivation.

## bench-adv (2026-10-03): the benchmark now DISCRIMINATES the fix set
The stock 73-case bench scored F1=1.000 on BOTH v4.1.1 (broken oracles) and
v4.2.0 — same run-id, same confusion — because it contained zero cases in the
disagreement zone (its csrf/nosql cases only exercise scenarios where weak and
strong oracles agree). Fixture v11 + GT v11 (75 cases) add two adversarial
blanket-200 traps on /lab: `/vuln/subscribe-echo` (csrf echo) and
`/api/nosql-lockout` (soft-fail nosql + permanent lockout), both GT
present:false. Deterministic x3 each: v4.2.0 38/0/0/37 F1=1.000; frozen v4.1.1
(imported read-only by scripts/bench_adv_v411_driver.py) 38/2/0/35 F1=0.9744 —
the 2 FPs are the old r.ok oracles verifying non-exploitable endpoints.
Mechanism probes (scripts/probe_vf_mechanisms.py) prove VF-01/03/04 at
code level on both engines. Full record:
docs/VERIFICATION_FIXES_v420.md §Round 2026-10-03.

## VF-01 — the catch-all `else` branch (intel.py verify())
The old default stamped `passed=True, confidence=0.98` (the HIGHEST confidence
in the engine — above every replayed class) on ANY finding type that matched
no branch: zero verification, fail-open for every future type. Now:
- `_PRESENCE_VERIFIED_TYPES` frozenset (4 types) is the ONLY path to VERIFIED
  without a replay; confidence drastically lowered 0.98 -> 0.70.
- ssrf / command_injection without an OOB callback: explicit fail-closed
  CANDIDATE (`unverified:blind-class-no-oob`) — never VERIFIED (blind classes
  have no response oracle; the old code let them fall into the catch-all).
- Any other unlisted type: CANDIDATE (`unverified:no-branch`, conf 0.3).
- report() now carries `unverified_candidates` (visible, honestly named — no
  longer silently stamped into findings nor silently dropped); stats carry
  `unverified_candidates` counts.

## VF-02 — csrf (VR-13) and nosql (VR-14) oracles were `r.ok` (HTTP 2xx)
- VR-13 csrf: now a triple control — (1) same-origin baseline accepted,
  (2) fresh hostile Origin+Referer replay accepted with the SAME status and
  a similar body, (3) a malformed-input control REJECTED (proves the endpoint
  discriminates input, so the 2xx is a real acceptance, not blanket).
  Reproduction failure -> REJECTED; reproduction without input discrimination
  -> CANDIDATE `unverified:no-input-discrimination` (never VERIFIED).
- VR-14 nosql: now a reproduced flip — a fresh literal-credential baseline
  must be REJECTED (4xx), then a FRESH operator ($gt, independent of the
  detector's $ne) must flip the same request to ACCEPTED. The failure->
  success flip IS the injection mechanism; the second operator is the proof.

## VF-03 — PATH A (SQLi boolean) body-diff half had no status agreement
`abs(len(r1)-len(r2)) > 200` fired on ANY >200B difference — volatile-content
pages (rotating lists, timestamps) false-positived SQLi. The guard now mirrors
PATH D: both responses OK, SAME status, and the difference must exceed
`max(200, 25% of the larger body)`. (The strict status-differential half
`r1.ok and not r2.ok` is unchanged.)

## VF-04 — the three factories stamped `passed=True` by construction
workflow.py `_finding`, graphql.py `_gql_finding`, websocket.py `_ws_finding`
hardcoded `passed=True` (0.9 / 0.9 / 0.85); the discipline lived at the call
sites as convention. Now the flag is DERIVED inside each factory from RAW
observations supplied as `proof={"rule": <closed-set name>, "obs": {...}}`:
- a call site without a proof raises (mechanism, not convention);
- an unknown rule name raises (fail-closed for future types too);
- a derivation that fails yields REJECTED, never a stamped VERIFIED.
- workflow rules: lines-added / marker-executed / line-match /
  occurrences-grew / state-flip-executed (12 call sites converted).
- graphql rules: introspection-enumerated / sql-error-signature /
  row-differential / cmd-output-pattern / marker-in-object /
  sensitive-response / executed-no-errors (9 call sites).
- websocket rules: canary-in-reply / handshake-accepted / sensitive-present /
  marker-in-messages (4 call sites).

## Gates (all green, honest accounting)
- tests: 102/102 (101 prior + 1 new `unit_v420_fail_closed_verification_defaults`;
  one assertion updated to the new method format
  `oracle:workflow-state-delta:<rule>` — format change is deliberate).
- doctor 15/15; benchmark x3 F1=1.000 TP-preserved, deterministic
  (run-3c0652b6be identical x3), passive now 0.70, csrf 0.85 (triple control),
  nosql 0.9 (flip), zero unverified on the fixture.
- LIVE validation on the 4 authorized remote targets (v4.2.0 judgments vs
  independently known truth): testasp.vulnweb.com, testaspnet.vulnweb.com,
  demo.testfire.net, ginandjuice.shop — see
  docs/VERIFICATION_FIXES_v420.md §Live for the full comparison. Summary:
  every previously-known truth re-verified on the live apps (including the
  doLogin auth-bypass via PATH C on Altoro and the cart CSRF on ginandjuice
  under the NEW triple control), zero false VERIFIED, zero FP anywhere.

# SENTINEL v4.1.1 — Live Gap Closure: GraphQL (DVGA) + WebSocket (DVWS)

The two v4.1.0 WAIVED boundaries — GraphQL and WebSocket live validation
("engine proven on fixtures, no authorized live target provides them") — are
CLOSED. Two authorized, isolated, local-only training targets were deployed
and the engines were proven against real-world implementations: DVGA (Damn
Vulnerable GraphQL Application, OWASP VWAD) and DVWS (Damn Vulnerable Web
Sockets). The doctrine held: discovery -> connection -> message -> analysis ->
test -> evidence -> boundary, with no result recorded without verifiable
evidence and no destructive path executed.

The live campaigns caught and fixed REAL engine defects that no fixture could:
fixtures speak the protocol the way the fixture author wrote it; production
implementations do not.

## Phase V411-GL — GraphQL Intelligence hardened live (DVGA)

Live-caught and fixed (all proven by the re-run):

- GL-08: Int/ID argument coercion — `pastes(filter:...)` vs `paste(id: Int)`;
  an Int argument MUST render as a bare integer, never a quoted string
  (the first BOLA probe 404'd on a stringified id).
- GL-12b: custom scalars (DVGA's DateTime) and built-in scalars are PLAIN
  fields — kind from the schema registry, not presence, decides plain vs
  nested selections (a selection set on a scalar is an invalid query).
- GL-13: REQUIRED arguments were silently dropped by a flat [:3] cap —
  createPaste's `title` is argument #4; the mutation battery now renders
  every argument it can value, selection-perfect.
- Mutations are exercised with well-formed SELECTION SETS (`{ paste { id } }`)
  — a bare mutation with no selection is a protocol error on graphene.
- GL-14: identity attribution — when the wired low identity IS the primary
  identity, a self-read is NOT BOLA (honest UNTESTABLE, never a
  mis-attributed finding).
- GL-06: a static asset whose path merely contains "graphql" is never an
  endpoint candidate; GL-11: type-aware operation rendering (fragments spread
  on OBJECT types only); GL-09: the read-shaped filter gates EVERY battery
  that constructs queries from the operation inventory; GL-05/b: state-shaped
  QUERY names (readAndBurn / deleteAllPastes) are never probed; GL-01: SQLi
  battery is read-shaped QUERY string arguments only; GL-02: command-execution
  probes transmit ONLY alnum-safe flag values; GL-07: only additive/auth-shaped
  mutations (create/register/login class) are ever exercised; GL-03/03b: value-
  shaped sensitive-field analysis with masking audited across every anonymous
  answer; GL-04: variables/fragments/aliases/nested-selection coverage probe.
- Content-Type: the transport sends `application/json` (the graphene server
  rejected the earlier form-encoded posts).

Live result (DVGA, clean state, authenticated Bearer + authz pair): 26
verified findings — 2 CRITICAL (graphql_sql_injection on pastes.filter,
graphql_command_execution on systemDebug.arg), 2 HIGH (graphql_bola on id,
graphql_mutation_authorization on createPaste), introspection exposure,
credential exposure — 29 GraphQL tests, and the DVGA database SURVIVED the
scan (identities + private pastes intact; the only writes are the planner-
gated canary paste of the mutation-authz proof).

## Phase V411-WS — WebSocket Intelligence proven live (DVWS)

Live-caught and fixed:

- WS-DISC-2: real applications hold the channel URL in a JS VARIABLE —
  DVWS's pages say `var wsUri = "ws://127.0.0.1:8080/command-execution";
  websocket = new WebSocket(wsUri);`. The literal-only constructor pattern
  saw nothing, and the well-known-path probe scanned the HTTP origin's port
  (8888) while the WS server listens on 8080 — the whole 12-channel surface
  was invisible. Now: any quoted ws:// / wss:// URL in the application's own
  JavaScript (inline scripts and JS assets) is an OBSERVED channel; the
  raw-socket scope gate still authorizes every channel before any connect
  (same-host different-port is in scope — the HOST is what the operator
  authorized — and the port delta is recorded in the channel's provenance);
  an out-of-scope observed host is refused WITHOUT a single connection
  (BLOCKED_BY_SAFETY); the JS intel registries (message shapes + observed
  channels) are reset per scan.
- WS-CANARY: the reflection canary is [a-z0-9]-only — DVWS /command-execution
  appends the raw message to `shell_exec('ping -c 3 ' . $msg)` and
  /file-inclusion passes it to file_get_contents(); an alnum-only canary
  carries no shell metacharacter, no path separator, no wrapper prefix, no
  template syntax — inert by construction in every injection context.
- WS-01..06 (fixture-proven first, live-proven now): the elicitation ladder
  ({} -> the app's own JS-harvested message shapes -> graphql-ws
  connection_init), value-shaped sensitive-data matching, canary message
  reflection, verbatim replay differential, foreign-Origin CSWSH probe, and
  the extended well-known transport list (/subscriptions graphql-ws live on
  DVGA — now ALSO discovered via observed-js).

Live result (DVWS, clean state, --logic-active): ALL 12 challenge channels
discovered (source: observed-js), 12/12 handshakes, 77 WS tests across 86
connections, protocols classified per channel (text/request-json on the
request/response channels; authentication-enforced silence on the two
PHPSESSID-gated channels; environment-gated silence on command-execution
where the sandbox lacks ping — honest UNTESTABLE, never a guess). Findings:
3 MEDIUM websocket_message_reflection (post-comments — canary echoed inside
HTML markup; reflected-xss; ssti through the Twig render) + 9 LOW
websocket_origin_not_enforced. Cross-user channel access proven manually
with a planted marker (dvws_cross_user_proof.json) — the engine honestly
records UNTESTABLE there because its identity model rides HTTP authz
accounts and DVWS authenticates over WebSocket itself.

Target-state accounting (DVWS): the users table untouched (3 seed users),
seed comments intact; the scan's writes are exactly 2 empty elicitation
hello rows + 1 canary comment on /post-comments (planner-gated
STATE_CHANGING, --logic-active authorized) — and /setup.php (global reset)
was BLOCKED twice (crawl + passive vocabulary gates), never fetched.

## Safety (live-caught on both targets)

- V411-DISC-SAFE: DVGA's /start_over re-seeds the ENTIRE database on a plain
  GET — caught by the live campaign after it destroyed the test identities
  mid-scan; central destructive-GET vocabulary gates now cover the crawler,
  the passive baseline, the browser render pass AND the real-time planner
  (DESTRUCTIVE class is never sent; the vocabulary wins over every engine
  note). DVWS's /setup.php hits the same gates.
- V411-COV: an endpoint that was never exercised now carries its skip reason
  INTO the endpoint dimension account (live-caught on DVWS /setup.php:
  untested_reason was empty in the dimension while the boundary held the
  reason).

## Gates (v4.1.1)

102/102 tests (97 v4.1.0 + 5 v4.1.1 live-caught regression additions),
doctor 15/15, benchmark F1=1.000 x3, no-hallucination gate green, both live
campaigns green with their boundary registries.

# SENTINEL v4.1.0 — Full Capability & Boundary Intelligence

The platform now knows what it knows — and what it does not. Every capability
carries an honest account: what was DISCOVERED, what was TESTED, what was
VERIFIED, what was REFUTED, what could not be tested and WHY, and what is
structurally unsupported. No hallucinated coverage, no fabricated impact, no
unsupported capability presented as supported.

Core pipeline: DISCOVER → MODEL → PLAN → TEST → VERIFY → PROVE →
CLASSIFY BOUNDARY → REPORT.

Zero regression: 97/97 tests (82 v4.0.0 + 15 v4.1.0), doctor 15/15,
benchmark F1=1.000 x3 (38/0/0/35, requests identical x3 = 1756; determinism
proven on confusion + listings + all 17 coverage-dimension accounts + planner
ledger + reasoning + boundary registry + proof state-pairs).

## Phase V41-05 — Boundary Intelligence Engine (boundary.py)

The single registry of limits, in 14 unified states (TESTED/VERIFIED/REFUTED/
UNTESTABLE/NOT_DISCOVERED/NOT_SUPPORTED/BLOCKED_BY_{PERMISSION,AUTH,SAFETY,
ENVIRONMENT}/TIMEOUT/TOOL_FAILURE/DEPENDENCY_MISSING/NOT_APPLICABLE). Every
untested item carries category/target/reason/evidence/timestamp/provenance/
remediation. Structural validation is enforced (evidence mandatory for
observation states, forbidden for absence statements) and the honest-percentage
guard forbids unexplained 100% coverage claims (99.9 + the reason instead).

## Phase V41-06 — Coverage 2.0 (17 auditable dimensions)

Endpoint, parameter, authentication, identity, authorization, entity, object,
workflow, workflow-branch, state, api-protocol, graphql, websocket, browser,
oast, detector, evidence — each with discovered/tested/untested + per-reason
accounting. Absent dimensions are NOT_DISCOVERED statements, never tested
claims. Surfaced in JSON, technical HTML, executive, SARIF and the generated
capability matrix.

## Phase V41-02 — Workflow Graph 2.0 (workflow.py)

Flows are real graphs now: step nodes carry preconditions/parameters/state
pairs/impact class/dependencies/provenance/confidence, and typed edges carry
conditional branches (with honest belief: observed vs declared), approval
gates, cancel and rollback paths. Four new planner-gated attacks join the
battery (13 total): branch_bypass, unauthorized_branch, approval_bypass,
rollback_abuse — each proven by a state-oracle delta or not at all. Attacks
with structurally absent preconditions are loud zero-request skips.

Live-caught and fixed during this phase: the producer-step attribution took
the LAST landing carrying the resource id instead of the FIRST (mis-attributed
producers on approval-chain flows; vulnapp behavior unchanged — both readings
agree there).

## Phase V41-03 — GraphQL Intelligence (graphql.py)

First-class GraphQL: discovery (observed + JS + deterministic probes with a
strict data-key check), schema modeling via introspection (queries/mutations/
args/fields), and a planner-gated battery — anonymous sensitive access, BOLA
(marker-proven), field-level authorization, mutation authorization
(STATE_CHANGING, --logic-active only; destructive-shaped mutations never sent),
introspection exposure. Introspection disabled or auth-required mutations are
honest UNTESTABLE boundaries, never guesses.

## Phase V41-04 — WebSocket Intelligence (websocket.py)

A dependency-free RFC 6455 client (handshake, client/server framing, masking,
ping/pong, fragmentation, 1MB frame cap) plus the intelligence layer:
scope-gated discovery (the raw-socket transport enforces scope BEFORE any
connect), passive listening with protocol classification (json/text/binary),
sensitive-data and cross-user channel tests (marker-proven), a single
verbatim replay under the planner gate, and protocol_not_understood boundaries
for everything not readable. Live-caught and fixed during this phase: the
frame reader consumed coalesced TCP segments wholesale (lost frames when the
handshake and frames arrived in one segment).

## Phase V41-07 — Digital Twin 2.0 (twin.py)

Every node and edge now carries an explicit belief status (observed/inferred/
verified/refuted/unknown) and a provenance string — `belief_audit()` is empty
by construction and asserted by the gate. New node kinds: graphql_endpoint,
ws_channel, boundary, api. `why()` answers the auditor's question for any
node (belief + provenance + relations with their own provenance).

## Phase V41-08 — Reasoning 2.0 (reasoning.py)

Fully structured hypothesis records (id/source/preconditions/expected_behavior/
test_plan/safety_class/actual_result/verification/evidence/final_state/reason)
with explicit reasons for EVERY outcome — verified, refuted and untestable
alike. Seven new patterns (branch bypass, unauthorized branch, approval
bypass, rollback abuse, GraphQL BOLA/mutation-authz, WebSocket cross-user)
generated ONLY from observed twin nodes.

## Phase V41-09 — Proof Engine 2.0 (evidence.py)

`reproduce --replay` re-executes a finding's proof from a CLEAN engine through
the same detector + verification pipeline: REPRODUCTION_VERIFIED,
REPRODUCTION_FAILED (reason recorded, never hidden), or the honest
NOT_REPLAYABLE for scan-context-dependent classes. New impact profiles and
SARIF rules for all v4.1 finding classes.

## Phase V41-10 — Safe Attack Planner 2.0 (planner.py)

The planner is now a REAL-TIME gate: every workflow attack, GraphQL mutation
and WebSocket write passes `planner.gate()` BEFORE any request is sent, and
the decision log is the run's persisted audit ledger (the v4.0.0 post-hoc
reconstruction is gone). Live-caught and fixed during this phase: an engine
note used to whitelist destructive-vocabulary paths — DESTRUCTIVE now wins
over every classification signal.

## Phase V41-11/12 — Action Matrix + Unified API Inventory (apintel.py)

The identity x action boundary matrix (8 action classes; DISCOVERED identities
only — never an assumed admin) with honest per-cell verdicts including
untested-with-reason; and one API inventory across REST, OpenAPI-declared,
JS-extracted, GraphQL and WebSocket surfaces with per-surface findings,
coverage status and boundary status.

## Phase V41-13 — Security Memory (memory.py)

Per-application (host-scoped) cross-run memory: fingerprints, verified
findings, learned flows, rejected hypotheses, known boundaries. Application
change invalidates stale assumptions (flagged for revalidation, never
trusted); corrupt memory never crashes a scan; tenant isolation by
construction. Memory is context, NEVER evidence — enforced and tested.

## Phase V41-14 — Self-Security battery

The malicious-target fixture attacks SENTINEL itself (report HTML/JS
injection, CRLF/oversized response headers, traversal links, file:// and
metadata URLs, SSRF against SENTINEL's own REST/OAST ports, command-injection
input, JSON/u2028 report breakers, malformed GraphQL with 10k-deep nesting,
8MB WebSocket frames). Proven: the scan survives everything, every artifact
escapes attacker markup, out-of-scope destinations are never fetched, and
input stays data.

## Phase V41-15/16 — Reporting + CI contract

The unified boundary-honest report across ALL formats: Boundary Intelligence,
Coverage 2.0 dimensions, API inventory, workflow graphs, the action matrix,
memory context and twin why() examples — and the executive report may NEVER
hide the limits (enforced by test). CI exit contract: 0 = clean, 1 = findings
above threshold (policy), 2 = scan incomplete (boundary-driven coverage gap),
3 = engine failure — policy and engine failures are never conflated. SARIF
carries coverage dimensions, boundary states and the capability matrix as run
properties.

## Phase V41-17/18 — Fixtures + the No-Hallucination Gate

18-fixture coverage (4 new apps: flows, graphql x3 twins, websocket x3
channels, malicious target; each with machine ground truth including
UNTESTABLE/BOUNDARY expectations). THE GATE: six executable invariants (no
finding without evidence, no observed fact without provenance, coverage
arithmetic sound, absent capabilities never claimed tested, no unexplained
100%, boundary records valid) — with planted lies proven to FAIL it.

## Phase V41-19..22 — Verification campaign

97/97 tests, doctor 15/15, benchmark F1=1.000 x3 with the deep determinism
proof extended to all v4.1 artifacts; live validation on the four authorized
targets (WebGoat 8.2.2 authenticated + 2 fresh registered accounts, WebWolf
spec-seeded, ginandjuice.shop authenticated with the workflow engine, Juice
Shop 20.2.0); machine-generated capability matrix; this changelog; updated
README and docs; versioned release artifacts.


----

# SENTINEL v4.0.0 — Security Digital Twin

The platform's biggest architectural leap since v2.0: SENTINEL no longer only
scans an application — it BUILDS a queryable knowledge model of the
application's security plane (the Digital Twin), reasons over it to generate
attack hypotheses, proves or refutes each one with the same state-oracle
discipline that held F1=1.000 since v2.x, and ships every verified finding as
a self-contained proof file with a reproduction recipe.

Zero regression: 82/82 tests (74 v3.0.1 guards + 8 new), doctor 15/15,
benchmark F1=1.000 x3 repetitions on ground truth v10 (38 TP / 0 FP / 0 FN /
35 TN — bit-identical run ids), and a live deployment on ginandjuice.shop.

## Phase 60 — Security Digital Twin (twin.py)

One knowledge graph fusing every artifact the scan already produced (zero
extra requests, fully deterministic):

  identities + roles (the sessions the authz engine ACTUALLY exercised)
  surfaces (pages/APIs/actions, READ/WRITE/NAV classified)
  parameters -> typed entities (User/Account/Order/Invoice/Payment/
    Transaction/Document/Ticket/Message — camelCase/snake_case aware,
    longest-word-wins vocabulary)
  workflows -> steps -> states, with mints/consumes object linkage and
    rollback paths
  the authorization matrix as provable role -> surface gates edges
  findings attached to the surface that produced them
  masked secrets, coverage reasons on untested surfaces, hypotheses

Projections: authorization_matrix (role x verdict x surfaces),
entity_inventory (who carries/mints/consumes each entity), twin_summary.
CLI: `sentinel twin --db ... [--full]`.

## Phase 61 — Safe Attack Planner (planner.py)

Every planned operation is classified BEFORE it runs, with a human-readable
rationale and an auditable decision log:

  READ_ONLY       automatic (observation only)
  LOW_IMPACT      automatic (canary-valued learning walks)
  STATE_CHANGING  requires --logic-active (attack battery)
  DESTRUCTIVE     blocked by default (purge/wipe/truncate vocabulary)

stats['planner'] carries the ledger of everything the scan did — or refused
to do — to the target. This is the enterprise safety contract, machine-readable.

## Phase 62 — Autonomous Security Reasoning Engine (reasoning.py)

Deterministic hypothesis generation by MATCHING PATTERNS over the twin (no
hard-coded endpoint lists — hypotheses transfer across applications):

  R-CROSS-IDENTITY-OBJECT  minted+consumed object + second identity exists
  R-TOKENLESS-WRITE        state-changing surface with no anti-CSRF token
  R-WF-SKIP-STEP / R-WF-REPLAY-FINAL / R-WF-TAMPER-VALUE
  R-WF-DECLARED-PRIVILEGE  UI-declared privileged option
  R-WF-CROSS-STATE         rollback path exists in the flow's own forms
  R-ADMIN-SURFACE-LOW-ROLE matrix shows a low role reaching an admin surface
  R-SECRET-EXPOSURE        exposed credential class
  R-ID-PARAM-UNTESTED      object-identifier param on an untested surface

Every hypothesis carries its reasoning chain (the premise in plain language),
the twin nodes it walked, the test recipe, and its planner class — then is
resolved against what the scan actually did: tested:verified /
tested:refuted / untestable:<reason> (e.g. 'requires_second_identity'). The
hypothesis ledger is reasoning-coverage proof: which attack theories we
formed, proved, refuted, or could not test and why.

## Phase 63 — Evidence OS / Proof Engine (evidence.py)

Every verified finding becomes a SELF-CONTAINED PROOF FILE:

  attack hypothesis -> preconditions -> requests -> responses ->
  identity -> state before/after -> impact -> reproduction recipe ->
  confidence -> verification

CLI: `sentinel reproduce --finding F-xxxx --db ...` prints the full recipe
("Reproduce Finding" as a command, not archaeology).

## Phase 60b — Advanced Workflow Engine: the cross-identity battery

Three new business-logic invariants join the five v3.0.0 ones (all behind
--logic-active, all state-oracle-proven, all on fresh isolated sessions):

  6. CROSS-USER    identity B executes an object identity A minted.
                   PRECONDITION: B's oracle shows A's object as a SHARED
                   object (an id that pre-existed in B's oracle is a
                   same-name object in a SEPARATE store — identifier
                   collision detection, live-caught on the fixture itself).
  7. CROSS-OBJECT  the final step executes a FOREIGN-TYPED object visible
                   in the oracle (SORD-0001 standing order via the transfer
                   confirm step — type confusion).
  8. CROSS-STATE   the final step executes an object the flow itself moved
                   to a CANCELLED state via its own rollback path.

Absent preconditions are LOUD honest skips that never consume attack budget
and never become guesses. Fixture v10 isolates exactly these three defects
in /wf/shared/transfer (one GLOBAL object store + seeded standing order +
POST /cancel) with ALL five v3.0.0 guards intact — 18 attacks ran / 8
verified / zero false positives on the hardened twins.

## Phase 64 — Executive + Glass reporting (report.py, cli.py)

  * build_executive: risk posture in decision-maker language, business
    impact booleans (data exposure / session takeover / unauthorized
    actions / infrastructure), affected assets, coverage proof, CI gate.
  * build_glass_html: the iOS-style frosted-glass ARABIC dashboard of the
    Digital Twin (RTL, backdrop-blur cards, zero external assets).
  * SARIF 2.1.0: stable rule ids for every class incl. SEN-BL-006/007/008.
  * CI/CD: `sentinel report --ci` exits 1 on verified critical/high.
  * New CLI: twin / reproduce / report --format executive|glass.

## Gates (all green)

  * tests: 82/82 (74 prior + 8 new v4.0.0 units; phase58 e2e guardian now
    asserts all EIGHT logic classes + twin + reasoning + planner + proofs)
  * doctor: 15/15
  * benchmark: F1=1.000 x3 (GT v10: 38/0/0/35, run-3c0652b6be identical)
  * live: ginandjuice.shop (authorized) — 35 verified / 100% coverage /
    twin 86 nodes / CSRF reproduce recipe from the live target
