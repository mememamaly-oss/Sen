# Burhan as a GitHub Action

Add a deterministic DAST scan of your web target to any workflow — one
line in your CI:

```yaml
jobs:
  sen-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # your application code
      - name: Start your app               # whatever it takes, e.g.:
        run: |
          python3 -m http.server 8080 &    # (replace with YOUR app)
          sleep 2
      - name: Burhan DAST scan
        uses: mememamaly-oss/burhan@v5.0.0
        with:
          target: http://127.0.0.1:8080
          out: burhan-result.json
          fail-on: high          # optional: fail the job on high+ findings
```

## Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `target` | yes | — | Base URL to scan |
| `out` | no | `burhan-result.json` | The enriched, **signed** JSON result |
| `db` | no | — | SQLite store path (empty = don't persist) |
| `seed` | no | — | Run seed, ≥32 bytes: same seed → same scan → same signed findings |
| `max-pages` | no | `25` | Crawl page budget |
| `timeout` | no | `12.0` | Per-request timeout (seconds) |
| `allow-private` | no | `false` | Allow loopback/private targets (CI fixtures) |
| `auth-user` / `auth-pass` / `auth-url` / `auth-user-field` / `auth-pass-field` / `auth-success-marker` | no | — | Authenticated scanning |
| `fail-on` | no | `none` | `critical` \| `high` \| `medium` \| `low` \| `none` — fails the job when VERIFIED findings at or above the threshold exist |

## Outputs

`findings-count`, `critical-count`, `high-count`, `medium-count`,
`low-count` (verified findings per severity), `result-path`.

```yaml
      - uses: mememamaly-oss/burhan@v5.0.0
        id: sen
        with: { target: "http://127.0.0.1:8080" }
      - run: echo "${{ steps.sen.outputs.findings-count }} findings, ${{ steps.sen.outputs.critical-count }} critical"
```

## What you get, and how to trust it

- The result file is **signed**: every finding hashes into a Merkle
  root; the root, the finding count and the run identity are
  Ed25519-signed. Verify any result independently (no Burhan code needed):
  ```bash
  pip install cryptography
  python3 tools/independent_verify.py verify-report burhan-result.json
  ```
- Every finding carries its compliance mapping (OWASP Top 10 2021 +
  2025, CWE, PCI DSS 6.4.2) with a source tag (`official` vs `scope`).
- The scan is deterministic under a fixed seed — the same target, build
  and seed always produce the same finding set (Burhan's own CI asserts
  byte-identical finding sets across two independent executions on
  every push).

## Requirements / honest notes

- Python 3.12 is set up by the action itself; the engine installs
  `cryptography` + `blake3` from the action repository's
  `requirements.txt`.
- Browser-rendered detection phases (DOM XSS execution, JS-discovered
  surfaces) degrade to static analysis when Playwright/Chromium is not
  present on the runner. For full coverage add:
  ```yaml
      - run: pip install playwright && python3 -m playwright install --with-deps chromium
  ```
  before the scan step.
- Scanning targets you do not own or lack permission to test is your
  responsibility, not the action's.


## المراجع القديمة (قبل إعادة التسمية) — سلوك رسمي معلن

وفقاً لتوثيق GitHub الرسمي («Renaming a repository»):
**«GitHub will not redirect calls to an action hosted by a renamed
repository. Any workflow that uses that action will fail with the error
`repository not found`.»** — أي أن مراجع Action مثل
`uses: mememamaly-oss/Sen@v4.5.0` **تتوقف عن العمل** بعد إعادة التسمية
(روابط الويب وعمليات git تُحوَّل تلقائياً، لكن مراجع Action لا).
على المستهلكين الانتقال إلى `mememamaly-oss/burhan@v5.0.0`.
تسجّل وظيفة `GitHub Action dogfood (published tag — external resolution)`
(خطوة «LEGACY pre-rename ref») نتيجة المحاولة الفعلية على كل تشغيل يدوي.
