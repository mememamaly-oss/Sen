# FINAL REPORT — crypto completion + merge + full engine re-verification

Date: 2026-10-30. Repository: mememamaly-oss/Sen (private). All numbers
below are from real executions; nothing is carried over from prior reports
except where explicitly attributed.

## PART 0 — repro.py investigation gate (derive_stream / _step_derive)

- Callers traced: `derive_stream`/`_step_derive` are defined and used only
  inside `sentinel/repro.py` (`DeterministicExecutor.execute` at line 504
  derives one stream per step; `_step_derive` at line 549 draws
  sign_seed(32B)/aead_key(32B)/nonce(12B) for the default 6-step
  canonical→derive→sign→aead→merkle→verify pipeline).
- Repo-wide importer grep: ZERO runtime modules import `sentinel.repro`
  (`transparency.py` contains the string "triple_run" as an evidence-kind
  label, not an import; `cli.py:805` imports
  `sentinel.evidence.reproduce_command`, a different symbol). Consumers are
  tests/dev scripts only.
- Data protected by these keys: deterministic replay of self-test payloads
  (e.g. `{"probe":"env1-crypto-remediation"}`). No real secrets, user
  data, or production credentials are protected (the repo has no
  production deployment; vault keys come from `os.urandom` in
  `sentinel/vault.py`; audit keypairs from HKDF over `os.urandom(32)`).
- Historical note: a pre-2026-10-21 audit path did misuse a
  SeededPRNG-derived keypair (audit-rb-1, closed and removed 2026-10-21).
- GATE DECISION: NO real sensitive data → the deterministic-by-design
  PRNG was KEPT (replacing it would break the determinism it exists to
  prove). Added: explicit disclosure at 3 anchors (module docstring §2,
  disclosure N-k, SeededPRNG class docstring — "NOT a CSPRNG —
  deterministic by design for replay only — never use output as a real
  secret-protection key") + grep-based isolation test
  `tests/test_repro_prng_isolation.py` (5 tests: no runtime module
  consumes repro streams; vault/proof/audit/orchestrator carry no repro
  dependency; the audit-rb-1 code path stays removed; the disclosure stays
  present; subpackages clean).
- Suite after Part 0: 135 passed (130 + 5 new). Commit ed1dcfd
  (cherry-picked onto the final main as b135af5).

## PART 1 — sentinel/blake3.py: official library

- Branch provenance: at order time the LOCAL crypto branch had been
  destroyed by the environment revert; the ORIGINAL tip 74eeb09 was found
  on origin (pushed by the prior session). The branch was rebuilt from
  352b2a4 using the preserved guarded edit scripts (fresh pre/post-swap
  captures; commit 39edcf8), and the final main was then constructed OVER
  the original origin commits — tree-identity between rebuild and original
  verified by `git diff` (engine/test files identical; the rebuild adds
  only the 13 audit-trail script files).
- 1.1: hand-rolled BLAKE3 (`_rotr`/`_g`/`_round`/`_compress`, permutation
  table, CV stack, PARENT/ROOT merging) replaced by a wrapper over the
  official `blake3` PyPI package 1.0.11 (Rust reference-implementation
  bindings). requirements.txt pins `blake3==1.0.11`. Public surface
  unchanged (one function, bytes→32 bytes, TypeError on non-bytes;
  bytes/bytearray/memoryview accepted).
- 1.2: official vectors fetched from the reference repo
  (https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json,
  35 cases, input lengths 0..102400, input[i] = i % 251). BEFORE deleting
  the old code: the old implementation matched all 35 official digests
  byte-for-byte (captured in
  scripts/crypto_remediation/blake3_preswap_capture.json, plus 6 fixed
  extra probes). AFTER the swap: library output byte-identical on all 41
  captured inputs. Process note: the first hand-transcribed vector table
  contained 4 transcription errors; the capture gate caught them; the
  table was regenerated programmatically from the official JSON and
  re-verified (70/70 table entries match the JSON).
- 1.3: the stale docstring claim ("vectors live in tests/test_axis3_pcs.py"
  — a path never committed; `git log --all` on it was empty) was made
  TRUE: tests/test_axis3_pcs.py now exists with the 35 official vectors
  (parametrized) + type contract + pcs.py consumer coverage (key_digest =
  blake3(canonical msgpack); MerkleTree root/proof/verify + tamper
  rejection; single-leaf; rejection contract; PCS end-to-end incl.
  verify_integrity/serialize/deserialize; store-root determinism;
  empty-root anchor). 43 test items.
- 1.4 BREAKING CHANGE ASSESSMENT: NO committed content-hash or Merkle-root
  value produced by the old implementation exists anywhere. How checked:
  (a) `git grep` across all refs for the empty-store root hex, three
  official digests, and the string "sentinel-pcs-empty-v1" — hits only in
  blake3.py/pcs.py source and the new test/capture files; (b) pickaxe
  (`git log --all -S <anchor>`) across full history — no historical blob
  carries a pcs-produced digest; (c) sweep of every tracked non-source
  file on the branch tip and on 722d9fd for any 64-hex string: only
  SHA-256 file checksums in REMEDIATION_REPORT.md / worklog.md
  (unrelated); (d) zero runtime importers of sentinel.pcs /
  sentinel.blake3 (grep-proven), so no stored outputs ship. Additionally
  the swap is byte-identical, so even hypothetical old values remain
  valid.
- 1.5: version-marker comment block at the change site (the 2026-10-30
  swap block in blake3.py), same style as the four previous targets.
- 1.6: full suite 178 passed (43 axis-3 items added); repro determinism
  check OK (3 executions, all 6 steps, flow digest stable at
  8a582d6a1a6addd3...); doctor 19/19 PASS. pcs.py runtime consumers: none
  exist (grep-proven); consumer coverage via tests/test_axis3_pcs.py.
  Commit 3ff8171 (cherry-picked onto the final main as fdf86fa).

## PART 2 — merge gate and merge to main

- 2.1: visibility re-verified via authenticated API before any push:
  private=true, push permission=true.
- 2.2: chain confirmed with actual hashes:
  origin/main 082c1b2 → cleanup/symbolic-ed25519 352b2a4 →
  cleanup/crypto-library-primitives 74eeb09 (four commits: 1de7956 proof
  AEAD, 6b7ebc5 proof HKDF, 4ad4d29 audit HKDF, 74eeb09 vault) → 5518b9d
  (remediation audit-trail scripts) → b135af5 (Part-0 gate) → fdf86fa
  (blake3) → dc9351e (symbolic-scripts carry-over) = main.
- 2.3: full regression on the exact push candidate (dc9351e): pytest 178
  passed; doctor 19/19 PASS; bun test 22 pass / 0 fail / 83 expect()
  calls; bun install --frozen-lockfile OK (667 installs, no changes).
  (Identical results were measured on the rebuilt tip 3ff8171 and on the
  rebuilt-chain merged main 901e5e7 during the merge run; dc9351e is
  tree-identical to 901e5e7 — `git diff` empty.)
- 2.4: merge = fast-forward of main onto the crypto chain (main was at
  origin/main 082c1b2; the chain is fully descendant; no merge commit
  needed). PUSH: normal `git push origin main` (fast-forward
  082c1b2..dc9351e); NO force push used or needed. Push output:
  "082c1b2..dc9351e  main -> main". ls-remote verification:
  refs/heads/main = dc9351eec25b260b22eeeb7cecb775d8ffabf89a.
- 2.5: branch deletion: verified `74eeb09` IS an ancestor of main
  (merge-base --is-ancestor) and the branch fully contained, then deleted
  origin/cleanup/crypto-library-primitives (the only one of the three
  branches ever pushed to origin). cleanup/symbolic-ed25519 and
  cleanup/crypto-blake3 never existed on origin (ls-remote proof) —
  nothing to delete there. Local copies retained deliberately as recovery
  anchors against the documented environment reverts (tags:
  backup/local-main-pre-crypto-merge-20261030 = 131f1e5;
  backup/main-rebuilt-chain-20261030 = 901e5e7).

## PART 3 — full live engine re-verification (against merged main)

Methodology: predictions.json written and SHA-256-stamped
(11ac938821c28a4c1e6b5c05c78a8060ad38e08f44022bef599055c1369905f4) BEFORE
any scan; scoring reads the pre-registered ground truth, never engine
output.

Target whitelist actually scanned: (1) this repo's own
fixtures/vulnapp.py; (2) ginandjuice.shop — permission text fetched at
scan time and quoted verbatim in
evidence/full-reverify/ginandjuice-shop/permission.json: "This is a
deliberately vulnerable web application designed for testing web
vulnerability scanners." (© 2023 PortSwigger Ltd). Off-whitelist link
policy: engine crawl is same-host (discovery compares netloc == seed
host) and replay scope is pinned to each finding's own hostname; no
crawler-discovered off-whitelist link was followed.

- 3.1 ground truth pre-registered: fixture = 75 cases (38 positive / 37
  negative) from the fixture's own docstring + committed
  benchmarks/ground_truth.json v11 (sha256 f98cd5a0bc948553...).
  ginandjuice = NO official vulnerability list exists (PortSwigger
  publishes none; checked 2026-10-30) → every finding pre-declared
  UNDETERMINED per 3.4(b).
- 3.2 sanity pass on merged main: pytest 178/178, doctor 19/19 PASS (the
  same run reported in 2.3 — same tree, same day, no change between).
- 3.3 engine runs (actual engine, not unit tests):
  * fixtures benchmark (CLI, engine-owned fixture, all detectors + race
    battery): wall 103 s, 7162 requests, run-d6b26b92d0, 199 findings.
  * fixtures full-config store run (Python API — the CLI is a thin
    wrapper over SentinelScanner; benchmark config + symbolic + race +
    workflow + logic): wall 101.6 s, 7162 requests, 199 findings,
    persisted to store.db.
  * ginandjuice bounded run (Python API, all detector families, hard
    request budget 350, browser engine excluded — see skips): wall
    430.4 s, 350 requests (cap), 28 endpoints, 15 findings, OAST armed
    (PublicWebhookProvider).
  * Re-execution verification, three layers: (a) scan-time differential
    verification on every reported finding (all carry verification
    dicts; only verified findings are reported); (b) cross-run
    agreement — the two independent fixture runs produced IDENTICAL
    finding sets (199 = 199, zero differences after port normalization);
    (c) clean-engine replay of every persisted proof. Fixture: 40 proofs
    persisted (engine caps persisted proofs at 40 by design —
    orchestrator.py line 1895): 1 REPRODUCTION_VERIFIED, 36
    NOT_REPLAYABLE (classes that need scan-time context, per the replay
    primitive's own contract), 3 REPRODUCTION_FAILED (command_injection,
    csrf, jwt_security; recorded reason verbatim: "the detector no
    longer produces a candidate on a clean replay (target may have
    changed or the finding was context-dependent)"); the remaining 159
    findings have no persisted proof (the cap) — their re-execution
    evidence is (a)+(b). ginandjuice: 15/15 proofs replayed — 5
    REPRODUCTION_FAILED (path_traversal; the header-name differential
    did not re-trigger on clean replay), 10 NOT_REPLAYABLE (passive
    classes); the 10 passive findings were then independently
    re-observed on fresh fetches: 10/10 agree.
- 3.4 scoring against the pre-registered truth:
  * (a) confirmed true positives: 38/38 positive fixture cases detected
    in BOTH runs; confusion TP=38 FP=0 FN=0 TN=37; P/R/F1 = 1.0/1.0/1.0
    in both runs independently.
  * (b) undetermined: fixture — 7 finding instances outside the
    documented list (xss_reflected@/vault/transfer:acct,
    xss_reflected@/vuln/sqli_blind.php:id, path_traversal@/vuln/jwt-login:user,
    path_traversal@/safe/jwt-login:user, secure_cookie ×3) — flagged
    undetermined, claimed neither way. ginandjuice — all 15 findings
    undetermined (no published list); each is listed individually in
    scoring.json with severity/status.
  * (c) misses: 0 (all 38 pre-registered positives detected in both
    runs; no false negatives).
- 3.5 wall-clock and incidents: measured engine wall time ≈ 103 + 101.6 +
  64.3 (diagnostic) + 430.4 s ≈ 11.7 min (replay and re-observation calls
  were not separately instrumented; each completed within a single
  ≤500 s call). Timeouts/crashes: 4 ginandjuice attempts were killed by
  the environment's single-call process limit (540 s all-batteries
  max-pages 10; 560 s default max-pages 25; 555 s no-browser max-pages
  15; 555 s no-browser max-pages 12 — playwright's EPIPE stderr noise at
  teardown on the kills that had the browser phase active); one
  background-launch attempt died when its tool call ended (processes do
  not survive call boundaries here). Handled by switching to a
  request-budgeted engine run (350 requests), which completed. No
  rate-limit responses were observed from the authorized target.

## SKIPPED (explicit list)

1. OWASP Juice Shop / WebGoat / DVWA / crAPI / DVGA (Docker): `docker`
   command not found in this environment — SKIPPED; no unauthorized
   substitution made.
2. testphp.vulnweb.com: connection timeout (HTTP 000) on every attempt
   (initial check + final retry) — SKIPPED; no scan performed.
3. ginandjuice browser/DOM engine: excluded on the remote target
   (playwright page loads against the remote host could not complete
   inside the single-call process limit); the browser engine ran on the
   fixture (browser_pages > 0; xss_dom findings are among the 38 TPs).
4. ginandjuice optional state-changing batteries (workflow /
   logic-active / race / symbolic): not run on the remote target (they
   exceed the single-call limit there); they ran in full on the fixture
   store run.
5. ginandjuice crawl surface bounded: max_pages 12 and a 350-request
   budget (vs the historical 25-page / ~430-request default) — 28
   endpoints reached.
6. Two large raw artifacts (fixtures benchmark_stdout.log 9.6 MB and the
   two store.db binaries) stay on disk, SHA-256-stamped in
   evidence/full-reverify/SHA256SUMS, but are not committed to git; the
   raw engine reports (scan.json / benchmark.json) ARE committed.

## Artifacts

- evidence/full-reverify/: predictions.json, scoring.json,
  SHA256SUMS (18 files), fixtures-vulnapp/ (benchmark.json, scan.json,
  replay_results.json, benchmark_stdout.log, store.db), ginandjuice-shop/
  (permission.json, permission_page.html, scan.json, replay_results.json,
  passive_reobservation.json, replay_progress.jsonl, store.db),
  testphp-vulnweb/status.json, docker-targets/status.json.
- scripts/reverify/ (predictions builder, store-run+replay, scorer,
  runners), scripts/run_crypto_blake3_pass.sh, scripts/run_merge_to_main.sh,
  scripts/rebuild_crypto_library_primitives.sh.
- Token usage: API visibility check (read), fetch (read), push main
  (write), branch deletion (write). Never written to any file.
