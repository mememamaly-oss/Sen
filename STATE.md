# STATE.md — Sen (SENTINEL) repository record

Single ordered record, maintained since the 2026-10-30 integrity pass.
Full historical detail (round-by-round ledgers, gate logs, evidence packs)
lives in the git history and tags — nothing there was deleted; this file
is a summary, not a replacement.

## What this repository is

SENTINEL: a Python DAST engine (axes 1-18, `sentinel/`) plus a Next.js
SaaS management app (`src/`, Prisma + SQLite). The engine is invoked by
the app through a subprocess CLI (`src/lib/engine.ts`).

## Current state (2026-10-31)

- Branch `main` (local = origin/main = d26513e) carries the 2026-10-30
  crypto completion chain (symbolic-ed25519 -> crypto-library-primitives
  -> Part-0 gate -> blake3 official package -> evidence) plus the
  2026-10-31 re-execution commits (repro M2-docstring correction;
  refreshed full-reverify evidence — see
  evidence/full-reverify/REEXECUTION_REPORT.md). PUSHED to origin on
  2026-10-31 after the owner's green light (fast-forward d51a5c1 ->
  d26513e, no force; wire-verified; see
  evidence/full-reverify/PUSH_RECORD.md). All cleanup/* branches
  deleted (local and remote) after merge-containment verification.
- Engine: python3, stdlib + `cryptography` + `blake3==1.0.11`
  (requirements.txt). Ed25519 is library-backed end to end (proof path:
  tests/test_proof_rfc8032.py; symbolic path: tests/test_symbolic_rfc8032.py).
- App: Next.js 16 / React 19 / next-auth 4 — build verified passing
  (2026-10-30) once NEXTAUTH_SECRET is set in the environment.
- Suites (2026-10-31, re-executed): python 189/189 (178 baseline + 7
  replay-fidelity + 4 oracle-gate tests); bun 22 pass / 0 fail / 83
  expect(); doctor 19/19 PASS.
- 2026-10-31 Phase-1 commercial campaign (commits 772cc7f, c7f0ab5, local
  — push held by the gate): replay-fidelity gap CLOSED (RP-1/2/3: proofs
  now carry request shape + producing detector + OAST wiring; fixture
  replay 5 VERIFIED / 35 NOT_REPLAYABLE / 0 FAILED, was 1/36/3; the five
  remote path_traversal replays all VERIFIED, was 5 FAILED — zero
  REPRODUCTION_FAILED anywhere). Independent verification began: Juice
  Shop 20.3.0 official bundle scored against the official 116-challenge
  list (1 DAST-DETECTED — an unauthenticated password-hash/token exposure
  on /rest/memories, manually confirmed; 48 scope-misses with per-challenge
  reasons; 36 class-gaps; 10 config-out; 21 attacker-action) — and the
  independent target exposed 7 live FPs, both root causes fixed red→green
  (PT-D1 non-determinism gate, PT-D2 input-crash gate; 116→109 findings,
  truths kept). WebGoat 2026.4: official JAR on portable JDK 25, real
  registration flow solved (register.mvc, 6..10-char policy), 40-lesson
  catalog harvested, bounded authenticated scan (14 endpoints — the
  #lesson hash-fragment SPA routing is an honest engine gap, documented).
  See docs/independent-verification/REPORT.md + evidence/
  independent-verification/. Owner actions pending: the VPS runner
  (DVWA/crAPI/full-budget Juice Shop/WebGoat deep/OWASP Benchmark) and the
  bug-bounty shortlist (docs/independent-verification/BUG_BOUNTY_SHORTLIST.md).
- Secret scanning: `.pre-commit-config.yaml` (gitleaks hook); run
  `pre-commit install` once per clone.

## Chronology (condensed)

- 2026-09/10: engine built in rounds (v2.x → v4.x) — detection families,
  OAST, vault, twin, reasoning, planner, race, symbolic axes. Full
  round ledgers in git history (worklog.md).
- 2026-10-02: recovery era — container rollbacks destroyed local state
  more than once; repo re-anchored from survivors and /tmp copies;
  tags v4.1.1..v4.2.2 mark the recovered baselines.
- 2026-10-03: v4.2.2 verification campaign; independent-verification
  packages and addendum produced (their raw session values were
  redacted from history in the 2026-10-30 pass — see below).
- 2026-10-07..21: axes 1-18 closure campaign, 19-axis security audit,
  green/red gates; evidence packs under results/* (in history).
- 2026-10-22/23: operational cleanup — non-runnable artifacts removed
  from the tree (kept in history + backup/pre-clean-2026-10-23 tag);
  QA/real-testing-gate and audit remediation branches; 19-axis audit
  final state RED→fixed.
- 2026-10-30: integrity pass (below).

## Rollback / incident record (one line each)

The development environment periodically reverted container state
(tree, .git, or checked-out branch). Documented incidents, details in
worklog.md history:

- Rollbacks #1-#3 (2026-09/10): tree reverted to earlier eras; recovered
  from /tmp survivors; worklog merged.
- Rollback #4 (2026-10-02): tree reverted AND .git destroyed (v4.1.1
  tag + branches lost); rebuilt truthfully via L1-R (recovery task).
- Rollback #5 (2026-10-02): environment switched branch mid-session;
  commits corrected to the right branch by pointer moves only (no
  history rewriting).
- Rollbacks #6-#13 (2026-10-0x): same documented pattern; each realigned
  per protocol (worklog tasks carry the details).
- Rollback #14 (axis-18 era): local container rolled back ~20 rounds;
  GitHub main was the survivor; stale-baseline draft preserved on its
  own audit branch.
- Rollbacks #15-#19+ (2026-10-2x): continued pattern, including a
  mid-benchmark stack loss rebuilt from scratch (JDK/Maven/Benchmark);
  all realignments recorded in worklog.
- 2026-10-30: environment reset the checked-out branch to main between
  operator commands during the integrity pass; Phase A commits were
  re-pointed to cleanup/integrity-pass with a branch-pointer move
  (git branch -f), no content lost.

## The 2026-10-30 integrity pass

Working tree (branch cleanup/integrity-pass, one logical change per
commit):

1. proof.py: hand-rolled Ed25519 replaced by the `cryptography`
   library; RFC 8032 §7.1 official vectors added as tests (17 tests).
2. Unsourceable competitive claims removed from docstrings/docs
   (audit.py, proof.py, oast.py, worklog.md).
3. package.json dev/start: `set -o pipefail` so exit codes propagate
   through tee.
4. Dependency compatibility verified for real: next@16.4.2 /
   next-auth@4.24.15 / react@19.3.1 — npm ls clean, full build passing.
5. .pre-commit-config.yaml (gitleaks) + README note.
6. requirements.txt records the new python dependency.

Full history (all branches + all 12 tags), applied with git-filter-repo:

- atib.ly and jbank.ly → [REDACTED-THIRD-PARTY-DOMAIN] (blobs and
  commit messages).
- Real captured session material → [REDACTED]: JSESSIONID/ASPSESSIONID/
  AWSALB/AWSALBCORS cookie values, AltoroAccounts blobs, webhook.site
  channel tokens, JWTs and API keys captured from live-scan targets
  (WebGoat/Juice/DVGA/vulnweb instances).
- Verification after rewrite (all refs): zero occurrences of the two
  domains (blobs, diffs, commit messages); zero cookie NAME=VALUE
  patterns in text files; gitleaks full-history scan — zero real
  findings (fixture/bench artifacts of local disposable apps excluded
  by design, including the vendored Juice Shop 20.2.0 public source and
  the local WebGoat/WrongSecrets H2 .db files, which are binary and
  untouched by the rewrite).
- Remote updated by forced push (branches + tags). Remote main moved
  722d9fd → fd54110 — a direct replacement (the rewritten history
  shares no commit hashes with the old one), not a fast-forward.
- Pre-rewrite full backup bundle (all refs, 425 MB):
  Sen-FULL-BACKUP-before-rewrite.bundle (kept locally, outside git).

Known-not-done (2026-10-30):

- Repository visibility change to private FAILED via API — the
  available fine-grained PAT does not carry the Administration
  (write) permission. Manual step required: GitHub → repo Settings →
  General → Danger Zone → Change visibility → Private.
- The symbolic-axes Ed25519 variant (sentinel/symbolic/models.py)
  remains a custom (non-RFC-8032-pure, domain-prefixed) implementation;
  replacing it would change every deterministic signature it has ever
  produced and was out of the pass's ordered scope.

## Where to find things

- Round-by-round history: `git log`, worklog.md (current + history).
- Pre-cleanup evidence: tags backup/pre-clean-2026-10-23,
  backup/release-v4.2.5, backup/release-v4.2.6, recovery/*.
- Verification recipe for signed reports: sentinel/audit.py
  (AUDIT_RECIPE, embedded in every enriched report).
- Engine CLI usage: README.md.
