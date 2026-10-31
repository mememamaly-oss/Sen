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

## 2026-10-31 — the comprehensive security-fix order (parts 0–4)

Owner order executed end to end; full report in download/FINAL_REPORT.md
(deliverable) and evidence/security-2026-10-31/ (in-repo proofs).

- Part 0 (exposure): PublicEvent at repo CREATION (2026-10-02T22:11:54Z,
  5 entries, no later ones visible), zero forks, Wayback/search = zero
  external archives (17 URLs probed). Conclusion: case (b) — PUBLIC from
  birth through 2026-10-23 (documented anon-200 observation), private
  10-23-evening onward, public again from ~10-31 01:38Z to now. The
  pre-rewrite history (with real captured session material) was publicly
  cloneable during [10-02 → 10-23]; unprovable whether anyone did
  (traffic API needs admin). docs/phase3 (3 files) remain LIVE-accessible
  from the public git history (verified: raw.githubusercontent HTTP 200 at
  fb334912ca8e...) — the owner's recorded deliberate non-purge; removal
  needs a separate filter-repo pass (owner decision, still pending).
- Part 1 (full-history rescan, every ref): gitleaks 8.30.1 over all 334
  commits + tracked tree; trufflehog 3.99.7 verified-only. 174,809 raw /
  1,620 distinct values, ALL classified (bench artifacts, fixture tokens,
  vendored public source, junk-commit hashes, markers); real-credential
  format battery: ZERO; product/config files: ZERO. trufflehog: zero.
  ZERO real secrets.
- Part 2 (nine items, each red->green or proven-safe with permanent
  guards — see FINAL_REPORT.md for every pair):
  2.1 BOLA: no vulnerability; 34-test permanent cross-tenant matrix.
  NOTE: a suspected broken route dir ("id]") was a console display
  artifact — the ANSI layer swallows the bytes "[m"; the dir is byte-exact
  "[mid]" (hex 5b6d69645d) and works in dev AND prod. No production code
  changed. (edd142c chain: b35a116.)
  2.2 SSRF: REAL engine vulnerability — websocket client + modernsec
  smuggling probe connected to PRIVATE targets over raw sockets without
  --allow-private (9 live hits, requests:0), incl. an explicit
  127.0.0.1/localhost allowlist carve-out. Fixed fail-closed with the
  shared pin_transport_address gate (resolve once, validate every answer,
  pin). Live red->green + 9 permanent tests + canonical fixture EXACT
  reproduction (199/30/7162). (edd142c.)
  2.3 XSS: safe at every layer (engine reports escaped — permanent tests;
  UI — real-browser proof 9/9 on the production build; no
  dangerouslySetInnerHTML in app code — guard). (d22833f.)
  2.4 iframe sandbox: safe — real-browser proof (sandbox="" exact, parent
  untouchable, opaque origin) + CSP headers captured + source tripwire.
  (d22833f.)
  2.5 vault: two real gaps fixed (tampered base64 escaped as unhandled
  binascii.Error -> now VaultError; world-readable KEY file accepted ->
  now refused like the vault file). 4 permanent key-hygiene tests.
  (684d925.)
  2.6 audit log: REAL — mutable at DB level (update/delete/deleteMany
  succeeded; org deletion REWROTE rows via SetNull). Fixed with a
  PostgreSQL BEFORE UPDATE OR DELETE trigger + FK removal (trail survives
  org/user deletion). 5/5 green. (e13caa1.)
  2.7 demo endpoint: REAL — GET polling had no limit (160-flood, zero
  refusals). Fixed: 120/hour/IP shared-store budget. POST controls proven
  over the wire (hostile body ignored — every finding URL from the
  hardcoded fixture; single lane). (0c9be25.)
  2.8 SENTINEL_ALLOW_PRIVATE_TARGETS: exact-string "1" semantics
  documented + pinned by test; unset in every deployment file. (0d8dc46.)
  2.9 rate limiter: REAL — per-process in-memory counters (two-process
  proof: A 10/10 + B 5/5 on a 10-budget key). Fixed: shared PostgreSQL
  store (RateLimitBucket) with pg_advisory_xact_lock atomicity; async
  call sites (auth + demo). Two-process green proof + 5 permanent tests.
  (8642945.)
- Part 3 (enforce_admins): reported with both owner options; NEITHER
  executed (order: await explicit owner choice).
- Part 4 final numbers (all real runs): pytest 214/214; doctor 19/19;
  bun unit 30/0 (173 expect); typecheck/lint/build PASS; canonical fixture
  gate EXACT (199/30/7162); integration battery 79/0 across 6 files
  (ratelimit 5 + api 28 + bola 34 + ssrf 3 + auditlog 5 + demo 4);
  browser proof 9/9 on the final build; manual-crypto sweep: zero
  hand-rolled primitives (full-tree, same pattern families as the
  2026-10-30 campaign).
- PUSH NOT EXECUTED: the token protocol is inline-only and the previous
  session's context (which carried it) was lost; disk-wide search = zero
  github_pat_ values. The 8 commits above are ready on local main (pure
  ff of origin/main 33008a7). Awaiting a fresh fine-grained PAT
  (Contents: Read & write on mememamaly-oss/Sen) from the owner.

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
- 2026-10-31 (later): owner-ordered governance chain — (1) license
  Apache-2.0 -> PolyForm Shield 1.0.0 (official text verbatim;
  resale-competing protection; the Apache public window was exactly
  2026-10-31T01:38:45Z (ff8af33) -> 06:58:21Z (2bcf544) = 5h19m36s;
  GitHub traffic data shows no 10-31 clone row yet (lag) — window
  clone count not enumerable; all 418 observed 14-day clones predate
  the Apache LICENSE; GitHub license detection post-change = Other /
  NOASSERTION, cause verified: licensee (GitHub detector) vendors 47
  licenses, none PolyForm — expected for a non-choosealicense license;
  the README badge is manual and correct); (2) docs/phase3/
  (pentest RFP / SOC2 readiness / hosted-tier design) removed from
  HEAD — it enumerated unresolved security gaps and control locations;
  replaced by a general external-roadmap note; full-history purge would
  need a separate filter-repo pass (not executed); (3) bootstrap
  stale-lock reclaim race root-caused via 20x instrumented stampedes
  and fixed (age-guarded atomic reclaim + holder-scoped compensation +
  2 deterministic regression tests; full detail in the race-fix
  commit); integration suite now 28/28. Trademark audit (report only):
  "SENTINEL" collides with Microsoft Sentinel / SentinelOne and is
  taken on npm+PyPI (as is "sen"); the in-tree brand is split three
  ways (SENTINEL in README/UI vs Sen/SEN in repo/Action/social
  preview); 3 verified-free alternatives proposed (burhan / mihwar /
  tadqiq — free on npm and PyPI, no same-named security tool on
  GitHub); renaming awaits explicit owner approval.

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
