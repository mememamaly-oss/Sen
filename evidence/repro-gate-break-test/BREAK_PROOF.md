# The 4B.3 break/revert proof — the reproducibility gate works in BOTH directions

The order: *"deliberately break determinism once (e.g. inject a timestamp
into a hashed field) to confirm the gate actually catches a mismatch,
then revert and confirm it passes — prove the gate works in both
directions."*

## The break

A one-line injection into the canonical-finding hash path
(`sentinel/audit.py` — a `_break_injected_ms` wall-clock field added to
the canonical JSON), pushed to the throwaway branch
`qa/repro-gate-break-test` (break commit `0734619`, forked from main
`52fc6fc`). The commit message self-describes as never-mergeable.

## The observation — CI run 41159472706 (branch push)

- Workflow run: https://github.com/mememamaly-oss/Sen/actions/runs/41159472706
- Reproducibility job:
  https://github.com/mememamaly-oss/Sen/actions/runs/41159472706/job/124413588962

Real log lines (2026-10-31T02:21–02:23 UTC):

```
[a] scan done in 102.0s: findings=199 root=e46771ff581e16e1…
[b] scan done in 101.8s: findings=199 root=e39fd3cdef1443b3…
run A: root=e46771ff581e16e1ee1c21c7ce6ef626185fcbbd7706f38d775641434f41963e count=199 sha=41baa9a41241d8330624a4a34134b3f7280d237a41fe7c6d5c7f3939ce8716b6
run B: root=e39fd3cdef1443b33d24dedbb3c09ba9c78ef16c4d0b5f05b0b92d7a46122704 count=199 sha=22722397f10b7d59b31170330fea47c550465dcdd2aa02b4a4aeee7dcdd556a0
  DIFFER : merkle_root
  MATCH  : findings_count
  DIFFER : findings_sha256
REPRODUCIBLE: False
```

**Job result: FAILURE** — the gate caught the injected nondeterminism.

Two further integrity gates caught the same injection independently on
that branch (all for the same root cause — the audit-block
recomputation tests):

- Engine (doctor / python suite): FAILURE — the committed-report
  audit-block verification test rejects the tampered canonical form.
- Transparency log: FAILURE — its verification step refused the run for
  the same reason.

Everything that measures DETECTION (not determinism) stayed green on the
break branch — SaaS app (lint/typecheck/tests/build/integration on real
PostgreSQL), real fixture scan (canonical run + F1==1.0/TP==38/FP==0
benchmark gate), real target (Juice Shop floor), secret scan, compliance
drift guard, action dogfood — the injection was surgical to
determinism, exactly as intended.

## The revert

There is nothing to revert on main: the break commit existed only on the
throwaway branch. Main (`52fc6fc` at the time) is the state WITHOUT the
injection and its CI run 41159065359 is **9/9 green** (the reproducibility
job passes there with byte-identical finding sets — identical
`merkle_root`, `findings_count` and full-set `findings_sha256` across two
separate executions). The branch was deleted after the observation was
recorded; the break commit `0734619` is reachable only through the run
record above.

## Both directions, proven with real runs

| direction | where | result |
|---|---|---|
| pass (identical executions → gate green) | main `52fc6fc`, run 41159065359 | Reproducibility attestation: **success** |
| catch (injected wall-clock → gate red) | break branch `0734619`, run 41159472706 | Reproducibility attestation: **failure** (DIFFER on merkle_root + findings_sha256) |
