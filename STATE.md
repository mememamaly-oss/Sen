# STATE.md — Sen (SENTINEL) repository record

Single ordered record, maintained since the 2026-10-30 integrity pass.
Full historical detail (round-by-round ledgers, gate logs, evidence packs)
lives in the git history and tags — nothing there was deleted; this file
is a summary, not a replacement.

## What this repository is

SENTINEL: a Python DAST engine (axes 1-18, `sentinel/`) plus a Next.js
SaaS management app (`src/`, Prisma + PostgreSQL — engine per-target
stores stay SQLite by design). The engine is invoked by the app through a
subprocess CLI (`src/lib/engine.ts`).

## Current state (2026-10-31)

- Branch `main`: origin/main = ee7fc87 — the first-green-CI state
  (run 41150402123, 6/6 jobs) — followed by the public-readiness
  campaign below, pushed through the same gate. Remote branches:
  main only.
- **Real-target validation now exists**: a CI job scanning OWASP Juice
  Shop v20.3.0 (pinned container) unauthenticated — the engine's first
  live real-world scan (59 verified / 1 type / 0 unmapped, budget-capped
  at 2500 requests; honest weak baseline, regression floor committed at
  evidence/real-targets/juice-shop/floor.json and enforced by CI).
  Exposed product gaps (asset burn, JSON-API auth, Angular param-intel)
  are ordered in its RECORD.md.
- Remote branches: **main only** — the 8 legacy duplicates deleted via
  the API (administration PAT) after per-branch containment proof; every
  commit on them remains reachable from main.
- Engine: python3, stdlib + `cryptography` + `blake3==1.0.11`
  (requirements.txt; requirements-dev.txt adds pytest for CI/dev).
  Ed25519 is library-backed end to end (proof path:
  tests/test_proof_rfc8032.py; symbolic path: tests/test_symbolic_rfc8032.py).
- App: Next.js 16 / React 19 / next-auth 4 — platform DB now PostgreSQL
  (P2-D, 2026-10-31: real migrations; unprivileged pgserver dev cluster
  on 127.0.0.1:55432 + docker-compose for the VPS; engine per-target
  stores stay SQLite by design). Server-side session guard on all (app)
  pages; public landing + /docs + /demo. Build verified passing
  (2026-10-31) with NEXTAUTH_SECRET set in the environment.
- Suites (2026-10-31, P2 re-executed): python 196/196 (189 + 7 compliance
  mapping tests); bun 27 pass / 0 fail / 163 expect() (22 security + 5
  compliance, incl. live parity with `sentinel compliance --json`);
  integration 26/26 over the wire on real PostgreSQL (14 legacy + 12 P2:
  public surface, server guard, demo API contract, compliance import
  path); doctor PASS; canonical fixture run reproduced EXACTLY
  (F1=1.0, TP=38/FP=0, 199 verified / 30 types / 7162 requests —
  evidence/phase2-compliance-ci/RECORD.md §2).
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
- 2026-10-31 public-readiness campaign (this chain, owner-ordered
  consolidated Parts 1–7):
  - **P1 sweep**: gitleaks 8.30.1 over EXACTLY fd54110..main (35
    post-rewrite commits) + tracked-tree scan + printed targeted
    patterns: 497/613 findings, 71 distinct values, ALL classified
    (fixture markers, fixture-issued JWT/JWE, public Juice Shop demo
    tokens, labeled CI dummies) — **zero real secrets**; remote = main
    only, all 12 tags contained in main (no pre-rewrite exposure);
    evidence/security-sweep-2026-10-31/.
  - **P2 hygiene**: LICENSE (Apache-2.0 — DEFAULT, pending owner
    confirmation), CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
    (private-vuln-reporting channel, honest 7d/30d targets), issue/PR
    templates; stray tracked files `--` and `.backup-stage-19axis.list`
    removed; README comparative-claims grep re-run — zero.
  - **P3 GitHub-native security**: .github/dependabot.yml (npm+pip,
    weekly); .github/workflows/codeql.yml (js-ts + python, guarded to
    activate only when public — CodeQL needs public/GHAS).
  - **P4A transparency log v1**: transparency-log/log.jsonl (append-only,
    hash-chained, Ed25519-signed with the pinned project key
    transparency-log/pubkey.hex), signer tools/append_transparency.py,
    INDEPENDENT verifier tools/independent_verify.py (zero sentinel
    imports; verifies log chain, bundles incl. per-finding inclusion
    proofs, and report audit blocks), tamper battery 5/5 PASS (untampered
    accepts; single-char evidence/signature/merkle-path tampers rejected;
    different-keypair rejected) — evidence/transparency-log/selftest/;
    the committed 199-finding fixture report verifies independently;
    format spec docs/transparency-log-format.md; the missing
    docs/AUDIT_VERIFICATION.md (referenced by audit.py RECIPE_DOC)
    created. Signing seed: .transparency-seed (gitignored, local) + the
    TRANSPARENCY_SEED CI secret.
  - **P4B reproducibility attestation**: scripts/repro_attest.py — two
    SEPARATE executions of the canonical fixture scan; HARD GATE asserts
    identical merkle_root + findings_count + full-set sha256; CI job
    `reproducibility` runs it on every push.
  - **P5 action packaging**: action.yml (composite: setup-python, deps,
    scan, severity gate + count outputs) + docs/github-action.md; CI job
    `action-demo` exercises it via `uses: ./` (and via the published tag
    on workflow_dispatch).
  - **P6 public polish**: docs/index.md + docs/_config.yml (GitHub Pages
    source), docs/social-preview.png (upload is UI-only — owner action),
    README badges (CI/License/Release) + Action/transparency/license
    sections.
  - CI now NINE jobs: web · engine · secrets · fixture · drift ·
    real-targets · reproducibility · transparency · action-demo.
  - Remaining P3/P7 items (branch protection, break-proof branch, tag+
    release, Pages enable, metadata/topics, visibility flip + post-flip
    secret-scanning/CodeQL verification) execute AFTER this chain's CI
    is green — recorded in the follow-up state update.
- 2026-10-31 follow-up (post-green): CI on 52fc6fc = **9/9 green + 1
  by-design skip** (run 41159065359) — including the reproducibility
  HARD GATE, which required fixing FOUR real determinism bugs the gate
  itself caught on its first runs: (1) builtin hash() probe markers
  (PYTHONHASHSEED per-process randomization), (2) a wall-clock fragment
  inside XXE oob evidence text, (3) OAST callback attribution via the
  Host header (ephemeral listener port), (4) workflow attack walks
  minting objects through the fixture's global sequential counter
  (interleaving-dependent) — now content-addressed via a deterministic
  per-walk marker. The attester also gained a loud pre-flight after a
  stale local fixture silently captured a port. Local proof: two fresh
  executions → identical merkle_root 214101804d3ee606… / identical
  findings_sha256 / 199 findings each. **The 4B.3 break/revert proof**:
  a wall-clock injection on throwaway branch qa/repro-gate-break-test
  (break commit 0734619, run 41159472706) turned the reproducibility
  job RED (roots e46771ff… vs e39fd3cd…, REPRODUCIBLE: False) while all
  detection jobs stayed green; main green; branch deleted —
  evidence/repro-gate-break-test/BREAK_PROOF.md. **The transparency log
  carries its first two real entries**: the CI canonical fixture run
  (run-d6b26b92d0, 199 findings, signed in CI with TRANSPARENCY_SEED)
  and the Juice Shop real-target run (run-c1f1909066, 59 findings,
  root 7cca176e…), both verified end-to-end by the independent verifier
  (chain + pinned-key signatures + per-finding inclusion proofs).
  Tag v4.5.0 + release created (initially at 996d757; moved to the final
  commit before the visibility flip). Branch protection, Pages,
  metadata/topics, private-vulnerability-reporting enable and the
  Part-7 gate + visibility flip follow this commit, per the order.
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
