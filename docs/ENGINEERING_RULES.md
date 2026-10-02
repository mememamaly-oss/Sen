# SENTINEL ENGINEERING RULES

Binding engineering rules for all SENTINEL work. These rules exist because this
project has survived **seven container rollbacks** — every rule below was paid
for with a real recovery campaign. Violations have historically cost hours of
re-verification; treat them as hard gates, not suggestions.

## 1. THE PERMANENT RECOVERY RULE (binding since PHASE 02 — L1 recovery gate, 2026-10-02)

### 1.1 Before every phase

```
BASELINE + COMMIT + BRANCH + TAG + SHA256 + RECOVERY MANIFEST
```

- Record the current baseline (tag + commit + branch) in the worklog BEFORE any
  modification, and verify the baseline is immutable (engine diff vs the frozen
  archive must be 0).
- Never start work if the recorded anchors do not resolve — STOP and report
  (the documented preflight pattern).

### 1.2 After every major operation (each L-step, each gate, each release)

```
COMMIT + RECOVERY MARKER + ARCHIVE + SHA256 + TEST EVIDENCE
```

- Commit via plumbing (`scripts/l1_commit.sh` pattern: temporary index +
  `commit-tree` + `update-ref`) — HEAD is never moved mid-operation, making
  supervisor resets harmless.
- Produce/refresh a recovery archive + its SHA256 + the test-evidence JSONs,
  and record them in `docs/PROJECT_RECOVERY_LEDGER.md` (append-only).

### 1.3 Before moving to the next phase

```
ARCHIVE → CLEAN RESTORE → BUILD → TEST → SAME RESULT
```

- Extract the archives into a directory fully separate from the working tree,
  rebuild, re-run the full gate battery, and prove the results are IDENTICAL to
  the frozen evidence (check-name/status maps, not just counts).
- Only a passing clean-restore gate authorizes the next phase.

### 1.4 Never

- Delete any documented recovery artifact (archives, ledgers, manifests,
  gate reports, evidence JSONs).
- Rewrite history, backdate commits, or fabricate a "restored" SHA. A recovered
  commit is a NEW honestly-dated commit whose message documents the lost
  lineage — content is proven via SHA256-verified archives, never claimed.
- `git reset --hard` or force-move `v4.1.1` / `release/v4.1.1`.
- Rely on branch pointers or `/tmp` alone: this container resets HEAD/branches
  and reverts `/home/z/my-project` between sessions. The durable layers are
  (in order): git object store → immutable SHA256 archives → the ledger → the
  `/tmp` survivor snapshot.

## 2. Baseline & engine immutability

- `v4.1.1` (tag) = `release/v4.1.1` = the VERIFIED RECOVERED BASELINE. Content
  is frozen in `release-archives/SENTINEL-v4.1.1-source.tar.gz`
  (SHA256 `f7c6d219…fcfbb`). Engine semantics NEVER change in post-scan phases
  without a new tagged release + full re-gate.
- Protected directories (`build-v411/`, `gap-validation/`, `recovery-validation/`,
  `release-archives/`, `l1-validation/`) are read-only for feature work.
- Every gate that runs engine tests runs them on a FRESH EXTRACTION of the
  SHA256-verified frozen archive, and `git diff v4.1.1 -- build-v411/` must be
  empty.

## 3. Testing & honesty gates

- Strict accounting everywhere: `ran=N/N, failed=0, missing=[]` — a vacuous
  pass must be structurally impossible.
- Benchmark determinism: ×3 runs must be confusion-identical; volatile families
  (ports, wall-times, opaque IDs) are scrubbed or documented, never ignored.
- No-hallucination: provenance values are exactly OBSERVED / INFERRED /
  VERIFIED / REFUTED / UNKNOWN; VERIFIED requires real evidence refs; UNKNOWN
  never upgrades without evidence; conflicts are never silently resolved.
- Adversarial + malicious-input batteries are part of every new surface.
- Reports must say "observed model / normalized model / known unknowns" — never
  claim a "complete security model".

## 4. Tenant isolation

- Every query is scoped through `access.orgId` (the `/api/findings/[id]`
  pattern). Cross-org access is a 404 with no existence leak + an audit record.
- The isolation attack suite (37 checks) + the twin API matrix (33 checks) run
  on every gate.

## 5. Environment rules (this container)

- The platform shell exports `DATABASE_URL` — it OVERRIDES `.env` (prisma/
  dotenv precedence). Set it explicitly for any tree outside `/home/z/my-project`.
- `NEXTAUTH_SECRET` is an untracked secret — regenerate per environment, never
  commit.
- Long test runs go FOREGROUND and CHUNKED (the GATE-F pattern) — the
  supervisor kills background/detached processes between tool calls.
- Untracked runtime dirs (`download/`, `readiness/`, `verify-live/`,
  `tool-results/`, `live-targets/`, `gap-validation/{tools,dvga-venv,targets}`,
  `*.log`) are declared in `.gitignore` and documented as rebuildable — `git
  status` on a healthy tree must be clean.

## 6. Phase discipline

- One phase at a time; a phase ends with: gates green → docs updated →
  worklog appended → recovery ledger updated → clean-restore gate PASS.
- Explicitly out-of-scope work (e.g., Attack Paths during L1) stays out —
  record it as deferred, do not "prepare" it early.
- If any stop-rule triggers (regression, tenant leak, non-determinism, forged
  provenance, engine modification, unexpected network requests): STOP, report
  BLOCKED with evidence; never bypass a failing test.
