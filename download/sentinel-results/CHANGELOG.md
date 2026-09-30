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
