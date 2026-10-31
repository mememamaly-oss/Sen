# Contributing to Sen

مساهمة الكود مرحّب بها — هذا الملف يشرح القواعد الفعلية المعمول بها
في هذا المستودع حتى تبقى المساهمة سلسة للطرفين.

Contributions are welcome. This document describes the rules this
repository actually runs on — they are few, and they are enforced by CI.

## Setup

```bash
# engine (python)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt        # runtime deps + pytest
python3 -m sentinel.cli doctor            # 19 environment checks

# platform (bun / node)
bun install
cp .env.example .env                       # + set NEXTAUTH_SECRET
bash scripts/pg_dev_start.sh               # local PostgreSQL (127.0.0.1:55432)
bunx prisma migrate deploy
```

## Running the tests

Everything below must pass before a change can merge — CI runs the same
set:

```bash
python3 -m pytest tests/ -q               # engine suite (incl. compliance + crypto vectors)
python3 -m sentinel.cli doctor
bun run test                              # platform unit (security + compliance)
bun run lint && bun run typecheck
bash scripts/run_integration_tests.sh     # full integration over a real server + PostgreSQL
```

The canonical fixture run (deterministic benchmark record) is exercised
in CI (`fixture` job) together with the real-target scan of OWASP Juice
Shop (`real-targets` job, floor-gated against
`evidence/real-targets/juice-shop/floor.json`).

## House rules

1. **One logical change per commit.** This is the repository's existing
   discipline; keep commits small and self-explanatory. Evidence and
   records (`evidence/`, `STATE.md`) update in their own commits.
2. **No unsourced claims.** Documentation, README and commit messages
   must not contain comparative or superlative claims that cannot be
   backed by a measurement in this repository. This rule was applied in
   the 2026-10-30 integrity pass and is re-checked by CI grep patterns.
3. **Determinism is a product property.** Anything that enters a hash,
   a Merkle root, or a signature must be wall-clock-free (explicit
   time parameters only — see `sentinel/audit.py` design rule 2). CI
   asserts byte-identical finding sets across two independent scan
   executions (`reproducibility` job).
4. **New crypto must be library-backed and vector-tested.** Hand-rolled
   primitives are not accepted; RFC test vectors are
   (see `tests/test_proof_rfc8032.py` for the pattern).
5. **Feature flags default to OFF.** A new capability must not change
   existing scan behavior when its flag is absent.
6. **Secrets never enter the tree.** `pre-commit` runs a gitleaks hook;
   CI re-scans tracked files. Local run outputs stay local
   (`results/`, `*.log`, `*.db` are gitignored).

## Reporting bugs / proposing features

Open an issue using the templates in `.github/ISSUE_TEMPLATE/`. For
security issues in Sen itself, follow `SECURITY.md` — never a public
issue.

## Licensing

By contributing, you agree that your contributions are licensed under
the repository license (`LICENSE`, Apache-2.0).
