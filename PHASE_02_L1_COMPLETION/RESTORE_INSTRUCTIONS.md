# RESTORE INSTRUCTIONS — PHASE 02 — L1 (tested path)

This is the EXACT path executed and verified by the FINAL RECOVERY GATE on
2026-10-02 (results in `REGRESSION_RESULTS/comparison_vs_frozen.md`). Any
directory outside the current working tree works; below it is `<R>`.

## 0. Prerequisites

- bun ≥ 1.3, Node ≥ 24, Python ≥ 3.12 (engine), playwright + chromium for
  browser-gated engine tests (`python3 -c "import playwright"` must pass)
- Disk: ~2 GB free
- ⚠️ If your shell exports `DATABASE_URL` (this platform does), it OVERRIDES
  `.env` — always pass `DATABASE_URL` explicitly to prisma/bun commands as shown.

## 1. Extract the archives (verify integrity first)

```bash
cd <path-with>/PHASE_02_L1_COMPLETION
sha256sum -c SHA256SUMS                # must print OK for both archives

mkdir -p <R> && cd <R>
tar xzf <path-with>/PHASE_02_L1_COMPLETION/SOURCE_ARCHIVE.tar.gz .
mkdir saas-state
tar xzf <path-with>/PHASE_02_L1_COMPLETION/STATE_ARCHIVE.tar.gz -C saas-state
rsync -a saas-state/saas-data/     saas-data/
rsync -a saas-state/l1-validation/ l1-validation/
rm -rf saas-state
```

## 2. Verify engine integrity (must be 0 differences)

```bash
mkdir -p /tmp/frozen-check && tar xzf release-archives/SENTINEL-v4.1.1-source.tar.gz -C /tmp/frozen-check
diff -rq /tmp/frozen-check/SENTINEL-v4.1.1 build-v411    # → no output = OK
```

## 3. Environment + install + schema

```bash
mkdir -p db
printf 'DATABASE_URL=file:%s/db/custom.db\nNEXTAUTH_SECRET=%s\nNEXTAUTH_URL=http://localhost:3030\n' \
  "$PWD" "$(openssl rand -base64 32)" > .env
bun install                                              # 827 packages
DATABASE_URL="file:$PWD/db/custom.db" bun run db:push    # SQLite + TwinGraph
```

## 4. L1 unit suite (expect 163/163 + 10 golden hashes)

```bash
bun scripts/l1_twin_suite.ts
```

## 5. Real-output twin check (expect 4/4 PASS, benchmark.json 899n/977e)

```bash
bun scripts/l1_twin_real.ts
```

## 6. Engine gates (expect 102/102 · 15/15 · F1=1.000 ×3)

```bash
python3 scripts/run_recovery_chunks_fg.py --clone "$PWD" --ledger /tmp/ledger.jsonl 1 9
(cd build-v411 && python3 -m sentinel.cli doctor)
for i in 1 2 3; do (cd build-v411 && python3 -m sentinel.cli benchmark --out "/tmp/bench_$i.json"); done
```

## 7. SaaS build + suites (expect 68/68 · 33/33 · 37/37)

```bash
bun run build                                            # standalone output
# orchestrators assume root=<this dir>; either run from the main tree or
# sed 's|/home/z/my-project|'"$PWD"'|g' the three orchestrators + test writers:
python3 scripts/l1_e2e_orchestrator.py      --port 3021   # 68/68
python3 scripts/l1_twin_orchestrator.py     --port 3022   # 33/33
python3 scripts/l0_isolation_orchestrator.py --port 3023  # 37/37
```

## 8. Production-style instance + demo data + verification (expect 30/30)

```bash
cd .next/standalone
DATABASE_URL="file:<R>/db/custom.db" NEXTAUTH_URL=http://localhost:3030 \
SENTINEL_DATA_DIR=<R>/saas-data PORT=3030 HOSTNAME=127.0.0.1 NODE_ENV=production \
setsid nohup bun server.js > /tmp/prod.log 2>&1 &
cd <R>
python3 scripts/bootstrap_demo_data.py --base http://localhost:3030   # 2 real scans 144+144
python3 scripts/l0_prod_verify.py      --base http://localhost:3030   # 30/30
```

## 9. Twin identity (expect structural MATCH: 638n/643e, 147/12, unknowns 2)

```bash
# login as admin@sentinel.local / Sentinel-P0!Admin, then:
GET /api/v1/scans/<scanId>/twin?orgId=<orgId>   # counts + provenance + claims
# TwinGraph rows: SELECT scanId, contentHash FROM TwinGraph;  (contentHash == API twinHash)
```

## 10. Expected results summary (all verified in this gate)

| Check | Expected |
|---|---|
| Engine suite | 102/102, strict ran=N/N, failed=0, missing=[] |
| Doctor | 15/15 |
| Benchmark ×3 | F1=1.000 · TP=38 FP=0 FN=0 TN=35 · 190 findings · 1756 requests · run-3c0652b6be |
| L1 unit | 163/163 · golden twinHashes byte-exact |
| Twin API | 33/33 · twins 638n/643e |
| E2E / isolation / production | 68/68 · 37/37 · 30/30 |
| Fresh demo scans | 144+144 findings · twin 638n/643e · claims 147/12 · unknowns 2 · l1-twin/1.0.0 |
| Browser /twin | renders, console 0 errors/0 warnings |

## 11. Restoring the MAIN tree (`/home/z/my-project`) — the re-anchor path

See `docs/RECOVERY_PROCEDURE.md` + gate report §7. Short form (as executed):

```bash
cd /home/z/my-project
git tag -a v4.1.1 <A'> -m "VERIFIED RECOVERED BASELINE (re-anchor #2 …)"
git branch release/v4.1.1 <A'>
git update-ref refs/heads/main <R'>
git branch phase/02-l1-twin <G'>
git symbolic-ref HEAD refs/heads/phase/02-l1-twin && git reset   # sync index (NEVER --hard)
git status   # clean (modulo .gitignore'd runtime dirs)
```
