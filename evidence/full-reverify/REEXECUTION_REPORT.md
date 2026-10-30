# RE-EXECUTION REPORT — strict from-scratch re-run of the crypto order (Parts 0–3)

Date: 2026-10-31. Repository: mememamaly-oss/Sen (private). Every number
below is from a fresh real execution on this date; nothing is carried over
from the 2026-10-30 FINAL_REPORT except the pre-registered predictions.json,
whose byte-integrity against its sources is itself proven below.

## Session preamble — environment incident and recovery

- The session started from a wiped working tree and a damaged .git (HEAD,
  refs, config, index all gone; the object store survived; one corrupt
  loose object d8257c93; 186 broken object links; the 74eeb09 objects lost).
- Recovery executed: corrupt object quarantined; thin-pack fetch failed
  (6 unresolvable deltas against missing objects); fresh clone (self-
  contained pack) + .git swap; ancestry verified (082c1b2, 352b2a4, 74eeb09
  ALL contained in origin/main); worktree restored; fsck clean.
- Remote state found: origin/main = d51a5c1 — the 2026-10-30 session had
  already merged and pushed the full chain (Part-0 gate b135af5, blake3
  swap fdf86fa, audit trail 5518b9d, script carry-over dc9351e, evidence
  d51a5c1). This re-execution therefore VERIFIES that state atom by atom
  and re-runs everything, rather than re-deriving it.

## PART 0 — repro.py investigation gate (re-executed)

- Callers re-traced from source: `derive_stream`/`_step_derive` defined and
  used only inside sentinel/repro.py (DeterministicExecutor.execute derives
  one stream per step; `_step_derive` draws sign_seed(32B)/aead_key(32B)/
  nonce(12B) for the 6-step canonical→derive→sign→aead→merkle→verify
  replay pipeline).
- Fresh full-tree grep: zero runtime consumers outside repro.py
  (audit.py line 16 is the historical-finding comment; cli.py:805 is
  `sentinel.evidence.reproduce_command`, a different symbol; dev scripts
  under scripts/crypto_remediation/ only).
- Real secret path contrast re-verified: sentinel/vault.py keys are
  32 os.urandom bytes, AEAD via pyca ChaCha20Poly1305; no repro dependency.
- Isolation suite REAL RUN: tests/test_repro_prng_isolation.py — 5/5
  passed (0.15 s).
- GATE DECISION (independently re-derived): the PRNG protects no real
  sensitive data — deterministic by design for replay only. Disclosure
  anchors + grep test confirmed present and accurate.
- NEW FINDING (micro-audit): the module docstring's M2-provenance line
  referenced tests/test_axis11_repro.py — a file NEVER committed
  (`git log --all` on the path is empty; same defect class as the blake3
  docstring lie fixed in fdf86fa). FIXED in commit 0759c85 on
  cleanup/repro-docstring-truth, ff-merged to local main; full suite
  178/178 on the edited tree.

## PART 1 — blake3 official library (re-executed)

- 1.1: requirements.txt pins blake3==1.0.11; installed from PyPI and
  verified (empty-input anchor af1349b9… matches).
- 1.2: official test_vectors.json FETCHED FRESH from the reference repo
  (31,922 bytes, 35 cases, lengths 0..102400). Live checks:
  sentinel.blake3() vs all 35 hash-mode vectors — 0 mismatches; package
  keyed_hash vs all 35 keyed vectors — 0 mismatches; the 35 literals
  embedded in tests/test_axis3_pcs.py == official file EXACTLY; the
  pre-swap capture == official file EXACTLY (old implementation proven
  byte-identical to the reference); 6/6 fixed extra probes re-verified
  live (probe input rule confirmed from the capture generator — the
  first probe check in this session used the official i%251 rule and was
  corrected to the generator's fixed list; recorded as a process note).
- 1.3: tests/test_axis3_pcs.py exists at the exact path the docstring
  names; REAL RUN 43/43 passed (0.18 s).
- 1.4 committed-hash enumeration (fresh): PCS empty-root anchor appears
  only in the pre-swap capture JSON; the canonical empty-input anchor
  appears in blake3.py / the runner vector table / the capture / the test
  file (all verified correct); evidence/full-reverify scan reports carry
  /audit/merkle_root values produced by proof.py's SHA-256 Merkle
  (leaf=SHA-256, node=SHA-256(L||R)) — not blake3 outputs, unaffected by
  the swap; no other committed blake3-produced digests exist (pcs.py has
  zero runtime importers).
- 1.5: version-marker block present at the swap site.
- 1.6: scripts/crypto_remediation/verify_postswap.py REAL RUN — all
  byte-identity anchors hold (5 audit keypairs, 5 HKDF, 3 AEAD, repro
  pipeline flow_digest 8a582d6a1a6addd3…, vault old-scheme envelope
  rejected as declared, new-scheme roundtrip with 16-byte Poly1305 tag).
  Full python suite 178/178.

## PART 2 — merge state (re-executed; push held by the gate)

- 2.1: repository visibility re-verified via authenticated API on
  2026-10-31: private=true.
- 2.2: chain confirmed with actual hashes: origin/main d51a5c1 contains
  082c1b2 → 2403ad3 → 352b2a4 → 1de7956 → 6b7ebc5 → 4ad4d29 → 74eeb09 →
  5518b9d → b135af5 → fdf86fa → dc9351e → d51a5c1 (all ancestry checks
  run against the fetched refs).
- 2.3: regression at the final tip (see PART 3.2 for the same-day numbers
  and the post-commit re-run): pytest 178/178; doctor 19/19 PASS; bun test
  22 pass / 0 fail / 83 expect(); bun install --frozen-lockfile OK
  (634 packages, 6.47 s, no lockfile change).
- 2.4: no new merge was needed for the 2026-10-30 chain (already linear
  on main). This session's corrective commit 0759c85 (+ the evidence
  refresh commit below) are ff-merged onto LOCAL main. PUSH IS HELD per
  the standing directive: nothing is pushed to the repository except
  after the green light together with real external tests.
- 2.5: remote has NO cleanup/* branches (API-verified branch list);
  local cleanup/symbolic-ed25519 — containment verified (352b2a4 is an
  ancestor of main), and the branch itself was absent from this clone
  after the recovery swap (nothing to delete); cleanup/repro-docstring-
  truth kept as the recovery anchor for the unpushed tip (tag
  backup/reexec-2026-10-31 also created).

## PART 3 — full engine re-verification (fresh runs, 2026-10-31)

- 3.1 pre-registration integrity: predictions.json rebuilt with the real
  builder from fixtures/vulnapp.py docstring + benchmarks/ground_truth.json
  v11 (sha256 f98cd5a0bc948553…) — REBUILD == COMMITTED byte-identical;
  the committed file's sha256 is
  11ac938821c28a4c1e6b5c05c78a8060ad38e08f44022bef599055c1369905f4
  (unchanged by this session). 75 cases: 38 positive /
  37 negative.
- 3.2 sanity: pytest 178/178; doctor 19/19 PASS (real DNS + egress +
  TLS checks); bun 22 pass / 0 fail.
- 3.3 engine runs (actual engine, fresh):
  * fixtures benchmark CLI (all detectors + race battery): wall 103 s,
    7,162 requests, 199 findings, run_id run-d6b26b92d0 (identical to the
    2026-10-30 run id — the engine's determinism contract held across
    independent sessions), 199/199 scan-time verified.
  * fixtures full-config store run (Python API; symbolic + race +
    workflow + logic; own fixture on 127.0.0.1:8777): scan wall 102.3 s,
    7,162 requests, 199 findings, persisted 200 records to store.db.
  * ginandjuice.shop (AUTHORIZED: permission page fetched 2026-10-31,
    HTTP 200, deliberately-vulnerable statement present verbatim):
    bounded full-detector run — wall 435.4 s, 350 requests (budget cap),
    28 endpoints, 15 findings, run_id run-9cddeb7b84, OAST armed
    (PublicWebhookProvider), 15/15 scan-time verified.
  * Re-execution verification, three layers: (a) scan-time differential
    verification on every finding (199/199 and 15/15); (b) cross-run
    agreement — the two fixture runs produced IDENTICAL finding sets
    (199 = 199, zero differences after port normalization); (c)
    clean-engine replay of every persisted proof — fixture: 40 proofs
    (engine cap): 1 REPRODUCTION_VERIFIED, 36 NOT_REPLAYABLE (classes
    needing scan-time context), 3 REPRODUCTION_FAILED (command_injection,
    csrf, jwt_security — detector no longer produces a candidate on a
    clean replay), 159 findings without persisted proof (the cap).
    ginandjuice: 15/15 proofs replayed — 10 NOT_REPLAYABLE (passive
    classes), 5 REPRODUCTION_FAILED (path_traversal header-name
    differential did not re-trigger); the 10 passive findings
    independently re-observed on fresh fetches: 10/10 agree.
- 3.4 scoring against the pre-registered truth:
  * (a) confirmed TPs: 38/38 positive fixture cases detected in BOTH
    runs; confusion TP=38 FP=0 FN=0 TN=37; P/R/F1 = 1.0/1.0/1.0 in both
    runs independently.
  * (b) undetermined: fixture — 7 instances outside the documented list
    (xss_reflected@/vault/transfer:acct, xss_reflected@/vuln/sqli_blind.php:id,
    path_traversal@/vuln/jwt-login:user, path_traversal@/safe/jwt-login:user,
    secure_cookie ×3) — claimed neither way; ginandjuice — all 15
    findings UNDETERMINED (no published list; pre-declared).
  * (c) misses: 0 (no false negatives in either run).
- 3.5 wall-clock and incidents: engine wall ≈ 103 + 102.3 + 435.4 + 50
  (gj replay) + 10 (re-observation) ≈ 11.7 min. Incidents: (i) the
  2d-script authorization re-check assert failed on a string-vs-int
  comparison bug in THIS session's guard (the authorization itself held —
  verified correctly in step 2a and by the HTTP 200 fetch); (ii) the
  committed replay_progress.jsonl from the prior run carried IDENTICAL
  deterministic finding ids (15/15 overlap, same run_id) — it was reset
  before replay so no stale verdict could masquerade as fresh evidence;
  (iii) no engine crashes, no timeouts, no rate-limit responses from the
  authorized target.

## Secret-gate note (commit-time audit, 2026-10-31)

The evidence commit passed through a staged secret gate, every event
recorded: (1) a first sweep aborted on a self-inflicted false positive
(a bash quote-spliced regex degenerated into a bare catch-all); (2) a
corrected sweep refused to commit because the refreshed evidence contains
strings in REAL credential formats (a 37-char ghp_-prefixed token and a
20-char AKIA-prefixed key, 53 captured instances); (3) a hash-fingerprint
gate (scripts/reexec-2026-10-31/sweep_staged_secrets_v2.py) proved both
strings byte-identical (sha256) to the synthetic literals PLANTED IN
fixtures/vulnapp.py itself — the credential_exposure test material the
engine must capture verbatim to prove the finding; the prior committed
evidence (d51a5c1) carries the same literals (43 + 43 instances), covered
by the repo's documented fixture-artifact exclusion. The session token's
literal prefix appears NOWHERE in the diff (count 0); no PEM blocks; no
github_pat_-format strings. Related environment finding: this platform's
tool-output pipeline MASKS credential-formatted strings in displayed
command output (a displayed "[REDACTED:github_token]" was proven by
character ordinals to be the 37-char fixture canary) — numeric fingerprints
(counts, ordinals, hashes) are immune, so the final gate compares sha256
fingerprints instead of displayed values. A fourth gate event: when the
sweep scripts themselves were staged for the audit trail, the gate
flagged its own runtime-derived check target — the first sweep copies
contained the session token's 17-char PREFIX as a file literal; the
literals were removed (the prefix is now derived from the GH_TOKEN
environment variable at runtime) and the gate re-run clean. A fifth event:
the gate then refused its own audit-trail copy again — the sweep script's
docstring documented the fixture canary VERBATIM (with a one-character
transcription error, producing a second unexplained 36-char ghp_-format
string); the literal was replaced by a fingerprint description
(len + sha16) and the gate passed: every remaining credential-format string
in the diff hash-matches the fixture-planted 37-char canary or the
fixture-planted 20-char AKIA key (43 instances each in benchmark.json,
scan.json and benchmark_stdout.log — identical counts in the prior
committed evidence), session-token prefix count 0, no PEM blocks, no
github_pat_-format strings.

## SKIPPED (explicit list, 2026-10-31)

1. OWASP Juice Shop / WebGoat / DVWA / crAPI / DVGA (Docker): docker
   command not found in this environment — SKIPPED; no unauthorized
   substitution made.
2. testphp.vulnweb.com: connection timeout (HTTP 000) on every attempt
   (initial check + retry) — SKIPPED; no scan performed.
3. ginandjuice browser/DOM engine: excluded on the remote target (cannot
   complete inside the single-call process limit); the browser engine ran
   on the fixture (xss_dom is among the 38 TPs).
4. ginandjuice optional state-changing batteries (workflow / logic-active
   / race / symbolic): not run on the remote target (same boundary as the
   prior campaign); they ran in full on the fixture store run.
5. store.db binaries and fixture.log stay on disk (untracked by the
   repo's *.db / *.log ignores), SHA-256-stamped in SHA256SUMS.

## Artifacts

- evidence/full-reverify/: refreshed scan.json / benchmark.json /
  replay_results.json / permission.json / permission_page.html /
  passive_reobservation.json / replay_progress.jsonl (byte-identical
  regeneration) / status files / scoring.json / SHA256SUMS (18 files) +
  this REEXECUTION_REPORT.md. predictions.json UNTOUCHED.
- scripts/reexec-2026-10-31/: this session's audit-trail scripts
  (docstring-fix runner, predictions-integrity + status refresh, scan /
  replay / re-observe / scoring wrappers, blake3 re-verification, the
  secret sweeps themselves).
- Token usage: API visibility checks (read), fetch of the repo (read).
  The push is prepared but NOT executed (gate). Token never written to
  any file.

## Gate status at report time

- Internal gates: python 178/178, bun 22/0/83, doctor 19/19, blake3
  vectors 35/35 (+35 keyed), postswap anchors all green.
- External real tests: executed against the authorized target
  (ginandjuice.shop, permission re-verified at scan time) — scan,
  replay, and re-observation all completed with recorded outcomes.
- PUSH: HELD — awaiting the green light per the standing directive.
  Local main (0759c85 + the evidence refresh commit) is ready to push
  as a fast-forward of origin/main d51a5c1.
