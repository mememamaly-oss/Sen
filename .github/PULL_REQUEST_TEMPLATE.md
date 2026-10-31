## What does this PR change?

<!-- One-paragraph summary. Reference the issue ("Closes #N") when one exists. -->

## Checklist

- [ ] One logical change (house rule — see CONTRIBUTING.md)
- [ ] Tests added or updated for the change
- [ ] `python3 -m pytest tests/ -q` green locally
- [ ] `bun run lint && bun run typecheck && bun run test` green locally
      (when `src/` or platform code is touched)
- [ ] No new unsourced comparative claims in docs/README
- [ ] No secrets in the diff (gitleaks hook is installed via
      `pre-commit install`)
- [ ] Determinism preserved: nothing wall-clock-dependent enters a hash,
      Merkle root, or signature
- [ ] New capabilities are feature-flagged, default OFF

## Evidence

<!-- For behavior-affecting changes: the measurement or test output that
     justifies the change. Real numbers only. -->
