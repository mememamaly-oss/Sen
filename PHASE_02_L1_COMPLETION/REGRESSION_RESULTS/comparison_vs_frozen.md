# CLEAN RESTORE vs FROZEN L1 EVIDENCE — SAME-RESULT PROOF

**Method**: `PHASE_02_L1_COMPLETION/SOURCE_ARCHIVE.tar.gz` (SHA256 `578709f6…e90d8`) +
`STATE_ARCHIVE.tar.gz` (SHA256 `de249dad…ff03`) were extracted into
`/home/z/l1-clean-restore` (a directory fully separate from both working trees),
then EVERY L1 gate was re-run from the restored tree. Fresh results were compared
check-by-check against the frozen L1 evidence (`saas-data/l1-twin/*.json`,
`l1-validation/engine-outputs/*`, `docs/gates/PHASE02_L1_FINAL_GATE.md`).

## Gate-by-gate comparison

| Gate | Frozen (L1 close, 2026-10-02 00:12) | Clean restore (this gate) | Identical? |
|---|---|---|---|
| Engine test suite | 102/102 (9 chunks, strict ran=N/N) | **102/102** (12+12+12+12+12+12+12+12+6, failed=0, missing=[]) | **YES** |
| Doctor | 15/15 (per-check PASS) | **15/15** — per-check status map **identical** | **YES** |
| Benchmark ×3 | F1=1.000 · TP=38 FP=0 FN=0 TN=35 · findings=190 · requests=1756 · run-3c0652b6be ×3 · GT sha a06e21173185d70f | **F1=1.000 · 38/0/0/35 · 190 · 1756 · run-3c0652b6be ×3 · GT sha a06e21173185d70f** | **YES (bit-equal metrics)** |
| Engine diff vs frozen archive | 0 files | **0 files** (restored `build-v411` diff -r vs `SENTINEL-v4.1.1-source.tar.gz` extract) | **YES** |
| L1 unit suite | 163/163 · 10 golden twinHashes | **163/163** · all 10 golden twinHashes **byte-exact** | **YES** |
| Real engine outputs (read-only twin) | 4/4 PASS (benchmark.json 899n/977e; ginjuice/webgoat/juiceshop) | **4/4 PASS** — benchmark.json **899n/977e**, same provenance/claims; invariants+equivalence+determinism PASS ×4 | **YES** |
| Twin API + tenant matrix | 33/33 · twinA/twinB 638n/643e | **33/33** — check names+statuses identical · twinA/twinB **638n/643e** | **YES** |
| SaaS E2E | 68/68 (72s) | **68/68 (72s)** — check names+statuses identical | **YES** |
| Tenant isolation (L0 suite) | 37/37 (137s) | **37/37 (137s)** — check names+statuses identical | **YES** |
| Production verification | 30/30 (67s, incl. prod.page_twin) | **30/30 (67s, incl. prod.page_twin)** — check names+statuses identical | **YES** |
| Demo data (real flows) | 2 real engine scans, 144+144 findings | **2 real engine scans, 144+144 findings** | **YES** |
| Production twin structure | 638n/643e · OBSERVED=616 INFERRED=22 · claims VERIFIED=147 REFUTED=12 · conflicts 0 · known unknowns 2 · l1-twin/1.0.0 | **BOTH fresh scans: 638n/643e · 616/22 · 147/12 · 0 · 2 · l1-twin/1.0.0** — invariants PASS, twinHash stable ×3 | **YES (structural)** |
| Browser /twin | 3 screenshots · console 0 err/0 warn · 160-of-638 honest cap · why() panel · twinHash badge | **3 screenshots · console 0 err/0 warn · same cap notice · why() panel (evidence refs N-…) · twinHash badge · from-store (TwinGraph)** | **YES** |
| TwinGraph persistence | contentHash == API twinHash, org-scoped | **2 rows, contentHash == API twinHash (05246c6f… / 6fa3c76b…), equal graphJson size (568,249 B)** | **YES** |

## Twin-hash semantics (honest scope)

- **Byte-exact reproduction (proven)**: the same raw input always yields the same
  twinHash — golden fixtures ×10 (byte-exact vs frozen goldens), per-scan API
  twinHash stable ×3, per-file determinism ×3 in the real-data check.
- **Scan-specific (expected)**: two DIFFERENT scans of the same deterministic demo
  target produce the same counts/provenance/claims but different twinHashes —
  the hash covers the full canonical twin including scan-run-specific evidence
  attributes (opaque engine request/evidence IDs). This matches the frozen L1
  evidence itself (twinA ≠ twinB ≠ production scan hash, all 638n/643e).
- **Lost inputs (rollback #7)**: the original raw `result.json` of the L1-close
  production scans (`cmuq7eq8t…`, `cmuq5u5tl…`, `cmuq5vndt…`) and their DB rows
  were destroyed with `saas-data/scans/` + `db/custom.db`. Their exact twinHashes
  (`3f774ad9…`, `3e633680…`, `c619511b…`) therefore cannot be re-derived; the
  clean restore proves **structural identity + same-input determinism** on fresh
  scans instead. Recorded in KNOWN_LIMITATIONS.

## Cross-session benchmark twin comparison (extra proof)

| Input | Nodes/Edges | Provenance | Claims | Hash |
|---|---|---|---|---|
| frozen `bench_l1_1.json` | 900/978 | 856/44 | 201/20/2, c=0 | 43bd75f3… |
| frozen `bench_l1_2.json` | 900/978 | 856/44 | 201/20/2, c=0 | 8f26340e… |
| frozen `bench_l1_3.json` | 900/978 | 856/44 | 201/20/2, c=0 | 02e788b5… |
| fresh `bench_restore_1.json` | 900/978 | 856/44 | 201/20/2, c=0 | 42ad6b9a… |
| fresh `bench_restore_2.json` | 900/978 | — | — | 5922dafe… |
| fresh `bench_restore_3.json` | 900/978 | — | — | 5e227ee3… |

Frozen-session and fresh-session benchmark runs normalize to **identical structure**
(node/edge counts, provenance distribution, claims, conflicts, known unknowns);
hashes differ per run (volatile run-scoped IDs in raw output) — the documented,
honest determinism boundary.

## VERDICT

**ARCHIVE → CLEAN RESTORE → BUILD → TEST → SAME RESULT: PASS**
(19/19 gate comparisons identical; zero regressions; zero engine differences)
