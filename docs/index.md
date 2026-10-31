# Sen — deterministic DAST with verifiable findings

**منصة فحص اختراق تطبيقات الويب الآلي (DAST) — نتائج موقّعة يمكن التحقق
منها بشكل مستقل.**

Sen is a web application security scanner with one differentiating
property, enforced by CI on every push: **its findings are signed and
independently verifiable**. Every scan report carries a Merkle root over
its findings and an Ed25519 signature; every recorded run is chained
into a public, append-only transparency log; and the same scan against
the same target is proven byte-identical across two independent
executions before any change can merge.

- Engine: Python (`sentinel/`) — 54 detector classes across 18 axes,
  deterministic under a fixed seed.
- Platform: Next.js 16 + PostgreSQL (`src/`, `prisma/`) — scan
  management, findings, reports, compliance views.
- Compliance: every finding maps to OWASP Top 10 (2021 + 2025), CWE and
  PCI DSS 6.4.2, with `official` / `scope` source tags.

## Verify a report yourself (no Sen code needed)

```bash
pip install cryptography
python3 tools/independent_verify.py verify-report result.json
```

More: [audit verification](AUDIT_VERIFICATION.md) ·
[transparency log format](transparency-log-format.md) ·
[the committed log](https://github.com/mememamaly-oss/Sen/tree/main/transparency-log)

## Use it in your CI

```yaml
- uses: mememamaly-oss/Sen@v4.5.0
  with:
    target: http://127.0.0.1:8080
    fail-on: high
```

Full input/output reference: [GitHub Action](github-action.md)

## Documentation

- [Repository README](https://github.com/mememamaly-oss/Sen#readme) —
  setup, CLI usage, architecture
- [Audit verification](AUDIT_VERIFICATION.md) — how to verify any
  signed report with open tools
- [Transparency log format](transparency-log-format.md) — the wire
  format specification (rebuild a verifier in any language)
- [GitHub Action](github-action.md) — one-line DAST in any workflow
- [Independent verification](independent-verification/REPORT.md) —
  scoring against public targets (OWASP Juice Shop, WebGoat), honestly
  reported including scope misses
- [Known limitations](https://github.com/mememamaly-oss/Sen/blob/main/KNOWN_LIMITATIONS.md)
  — what Sen does not do, stated plainly

## Honesty policy

No unsourced comparative claims anywhere in this project — the rule is
enforced by CI. What Sen claims, it measures: the deterministic fixture
record (F1=1.0, TP=38/FP=0), the real-target baseline floor, and the
reproducibility attestation are all gated checks, not marketing.
