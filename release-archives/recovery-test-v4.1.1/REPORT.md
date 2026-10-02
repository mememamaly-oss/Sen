# SENTINEL v4.1.1 — Recovery Test Evidence
date: 2026-10-01T02:27:06Z
procedure: clean local clone at tag v4.1.1 (commit 5dfa75d0c4b97a9c0cbac88b63cead89713ec899), detached, working tree clean
commands: python3 -m sentinel.cli doctor | python3 -m sentinel.cli benchmark --url http://127.0.0.1:<ephemeral> | tests via SENTINEL_TEST_FILTER chunks (foreground)

RESULTS:
- VERSION: 4.1.1 (imported from the clone's own tree)
- doctor: PASS 15/15 (per-check statuses identical to baseline)
- benchmark: F1=1.0 precision=1.0 recall=1.0 TP=38 FP=0 FN=0 TN=35 findings=190 requests=1756 (identical to bench_v411_{1,2,3})
- tests: 102/102 failed=0 strict_ok=true (case-name sets and ok-flags identical to tests_v411_FULL.json; strict ledger accounting: 9 chunks, no dups/missing/extra)
- boundary.by_category + coverage(90/90/0/100%) + api_inventory(75) + twin(78) + param_intel(54): identical

VERDICT: RECOVERY TEST PASS — tag v4.1.1 regenerates a working baseline that reproduces every frozen gate value.
