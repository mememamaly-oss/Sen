# Security sweep — post-rewrite delta (PART 1, 2026-10-31)

Ordered by the public-readiness order: gitleaks over exactly the commits
made after the last history rewrite, plus a targeted-pattern pass with
the regexes printed below so the "nothing else found" claim is checkable.

## Range

- **Cutoff determination**: the 2026-10-30 integrity pass
  (STATE.md §"The 2026-10-30 integrity pass") rewrote full history with
  git-filter-repo and force-updated remote main
  `722d9fd → fd54110` ("a direct replacement … the rewritten history
  shares no commit hashes with the old one"). `fd54110` is therefore the
  last commit of the rewritten history; everything after it is
  post-rewrite work. Verified this session: `fd54110` IS an ancestor of
  current main.
- **Range scanned**: `fd54110..ee7fc87` — **35 commits**, listed by
  `git log --oneline fd54110..main` (082c1b2 STATE.md after the
  integrity pass → ee7fc87 first-green-CI record).

## Remote refs (كل الفروع — all branches)

- `ls-remote` (authenticated): **branches = main only**.
- 12 tags (v4.1.1…v4.4.0, backup/*, recovery/*) — every one verified
  `merge-base --is-ancestor <tag> main` → **all contained in main**;
  none reaches pre-rewrite history (no exposure of rewritten-away
  material via refs).
- `.env` was never committed: `git log fd54110..main -- .env` → 0
  commits; `git check-ignore .env` → ignored (`.gitignore:11`).

## Tool

- gitleaks **8.30.1** (linux_x64), binary sha256
  `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`.
- Ruleset: the embedded default config, archived here:
  `gitleaks-default-config-v8.30.1.toml` (fetched from the gitleaks
  repository `master/config/gitleaks.toml`; master is the source the
  8.30.x release cut from — the exact tag no longer carries the file
  at that path).
- Exact commands (reproducible):
  ```
  gitleaks git . --log-opts "fd54110..main" --report-format json --report-path <out> --exit-code 0
  git checkout-index -a --prefix=/tmp/tree-scan/   # tracked files only
  gitleaks dir /tmp/tree-scan --report-format json --report-path <out> --exit-code 0
  ```

## Result 1 — gitleaks on the delta (`fd54110..main`)

**497 findings, all in 5 evidence files, 71 distinct values, 7 value
classes — zero real secrets.**

| file | findings |
|---|---|
| evidence/full-reverify/fixtures-vulnapp/benchmark.json | 144 |
| evidence/full-reverify/fixtures-vulnapp/benchmark_stdout.log | 142 |
| evidence/full-reverify/fixtures-vulnapp/scan.json | 141 |
| evidence/independent-verification/juice-shop-20.3.0/scan.json | 34 |
| evidence/independent-verification/juice-shop-20.3.0/scan_pre_gates.json | 34 |

Distinct values and their classification (every class):

| class | distinct | what it is |
|---|---|---|
| `sentineltb1markerzz`, `sentineltb2markerzz` | 2 | literal marker strings served by the local vulnapp fixture (taint/argv test markers) |
| `echo+sentinelargvmark1` | 1 | the fixture's echo of an injected argv marker (argument-injection test) |
| HS256 JWTs (`{"alg":"HS256","typ":"JWT"}`, claims like `sub=u1/demo/user`…) | 63 | deterministic fixture-issued JWTs captured by scanning the local fixture — synthetic by construction |
| JWE tokens (`{"alg":"dir","enc":…}`) | 2 | fixture-issued encrypted tokens (qa-results battery records) |
| RS256 JWT (`eyJ0eXAiOiJKV1Qi…`, 718 chars) | 1 | the PUBLIC OWASP Juice Shop demo app's well-known token, captured by scanning it |
| `0192023a7bbd…` (32 hex) | 1 | Juice Shop's public challenge token exposed on `/rest/memories` — this IS the documented detection (STATE.md Phase-1 campaign; manually confirmed exposure in a public training app) |
| (covered above) AWS-docs example key | — | appears via the fixture's intentional AWS-documentation example key (`fixtures/vulnapp.py`, the declared exception also documented in the CI `secrets` job) |

## Result 2 — gitleaks on the current tracked tree (what ships)

**613 findings, 71 distinct values, same 7 classes** — the same fixture
benchmark copies (`qa-results/greengate_benchmark_final.json` etc.) and
the same evidence files as above. **Zero real secrets.**

## Result 3 — targeted patterns (regexes printed — checkable)

| # | pattern (rg -n) | hits | classification |
|---|---|---|---|
| P1 | `postgresql?://[^\s"']*:[^\s"'@]+@` | 3 | CI service-container dummy (`postgres:postgres@localhost:5432` in ci.yml, labeled), docs placeholders (`<pw>`), docker-compose comment |
| P2 | `NEXTAUTH_SECRET[=:]\s*["'][^"']{16,}["']` | 2 | `ci-only-secret-not-for-production` (labeled CI dummy, ci.yml + audit-19axis note), one historical QA record quoting an already-REDACTED candidate |
| P3 | `(github_pat_…|ghp_…|gho_…|sk-…)` | 43+3 | fixture-served fake token shapes in fixture/benchmark captures + 2 lines in a QA secret-scan record |
| P4 | `AKIA[0-9A-Z]{16}` | 132 | the fixture's intentional AWS-docs EXAMPLE key repeated in captured bodies (declared exception) |
| P5 | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA )?PRIVATE KEY-----` | **0** | — |
| P6 | `eyJ….eyJ….…` (JWT shape) | 392 | fixture + Juice Shop public demo tokens (classes above) |
| P7 | `POSTGRES_PASSWORD[=:]\s*["'][^"']+["']` | 0 | — |

## Verdict

- **Zero real secrets in the post-rewrite delta and in the tree that
  ships.** All gitleaks and pattern findings are synthetic fixture data,
  CI-labeled dummies, docs placeholders, or captures from the public
  OWASP Juice Shop training app — exactly the exclusion the order
  defines ("Any real finding (not synthetic fixture data)").
- **No redaction commits required; no rotation actions required.**
- One repo-level reminder outside this sweep's scope: the GitHub PAT
  used for repository administration has been shared in chat multiple
  times and should be rotated by the owner (repo-level finding: none).

## Visibility confirmation (order 1.4)

`GET /repos/mememamaly-oss/Sen` at 2026-10-31 (this session):
`"private": true, "visibility": "private"` — confirmed private before
any other part executed. Re-confirmed again immediately before the
Part 7 visibility flip.
