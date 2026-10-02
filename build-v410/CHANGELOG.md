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
