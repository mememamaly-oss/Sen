#!/usr/bin/env python3
"""Update section A records with FINAL artifact evidence (post ENG-18)."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

FINAL = "FINAL artifact = sentinel-4.0.0-source.zip (rebuilt with ENG-18 state-pair fix + harness cosmetics)"

record("A", "A01", "Full suite 82/82 from shipped source.zip", "ziprun2 (fresh extraction of FINAL zip)",
       "SENTINEL_TEST_FILTER chunks R5(69)+R6(1)+R1(1)+R4(5)+R2(3)+R3(3) → tests/run_tests.py all",
       "82 tests, 0 failed",
       f"82/82 PASS (0 failed) — {FINAL}; includes the new ENG-18 regression guard asserting every business-logic proof carries its state pair",
       "PASS", "6 independent process invocations, non-registration order",
       "/home/z/my-project/readiness/evidence/A01_FULL_FINAL.json")

record("A", "A02", "Doctor 15/15 from shipped ZIP", "ziprun2",
       "python3 sentinel/cli.py doctor", "overall PASS, 15/15",
       "overall=PASS 15/15 (runtime/dns/egress/tls/scope/detectors/strategy/sqlite/repair/browser=playwright/auth/oast/intelligence/vault/workflow)",
       "PASS", "Run from the FINAL zip extraction",
       "/home/z/my-project/readiness/evidence/A02_doctor_FINAL.json")

record("A", "A03", "Benchmark 3 consecutive runs, identical results", "local-fixture-v10 via FINAL zip",
       "sentinel benchmark x3",
       "identical confusion, listings, request counts",
       "F1=1.000 x3; TP=38/FP=0/FN=0/TN=35 x3; requests=1752 x3; per-row TP/TN listings byte-identical; all 8 business-logic state pairs identical across runs (post ENG-18)",
       "PASS", "Full determinism including the new state-pair fields",
       "/home/z/my-project/readiness/evidence/A03_FINAL_verdict.json")

record("A", "A04", "F1 not below current v4.0.0 result", "FINAL zip benchmark",
       "sentinel benchmark x3", "F1 >= 1.000",
       "F1 = 1.000 exactly in all 3 runs (precision=1.0, recall=1.0)",
       "PASS", "", "/home/z/my-project/readiness/evidence/A03_FINAL_verdict.json")

record("A", "A05", "TP/FP/FN/TN identical across iterations", "FINAL zip benchmark",
       "sentinel benchmark x3", "identical confusion matrices",
       "TP=38, FP=0, FN=0, TN=35 in all 3 runs",
       "PASS", "", "/home/z/my-project/readiness/evidence/A03_FINAL_verdict.json")

record("A", "A06", "No results depend on test execution order", "ziprun2",
       "chunks executed non-sequentially (R5,R6 first; slow e2e later)",
       "every test passes regardless of position",
       "82/82 with chunks run out of registration order; benchmark x3 identical (incl. request counts)",
       "PASS", "", "/home/z/my-project/readiness/evidence/A01_FULL_FINAL.json")

record("A", "A07", "No results depend on leftover scan data", "ziprun2 (6 suite processes + 3 benchmarks, same tree)",
       "sequential full scan cycles in one tree",
       "identical results across cycles",
       "3 benchmark cycles + 82 tests sharing one tree — byte-identical findings/TP/TN/state-pairs; zero cross-run contamination",
       "PASS", "", "/home/z/my-project/readiness/evidence/A03_FINAL_verdict.json")

record("A", "A08", "Tests run after full process restart", "ziprun2",
       "9+ separate python3 processes (6 suite chunks + doctor + 3 benchmarks)",
       "all green across process boundaries",
       "Every gate ran as an independent OS process with fresh interpreter state — all green",
       "PASS", "", "/home/z/my-project/readiness/evidence/A01_FULL_FINAL.json")

record("A", "A09", "Tests run from extracted ZIP, not dev worktree", "ziprun2",
       "unzip FINAL source.zip → run entire gate chain there",
       "all tests pass from ZIP tree",
       "82/82 + 15/15 + F1=1.000x3 all from the extracted FINAL zip; dev worktree never on sys.path",
       "PASS", "", "/home/z/my-project/readiness/evidence/A01_FULL_FINAL.json")

record("A", "A10", "No hidden stderr errors counted as success", "ziprun2",
       "stderr captured for all chunks",
       "no engine errors in stderr",
       "Zero Tracebacks in F_R1..F_R6 stderr captures; only expected chaos-fixture BrokenPipe noise (intentional connection-reset stimulus on the test's own HTTP server); SyntaxWarning eliminated in FINAL zip",
       "PASS", "The one cosmetic warning found by this campaign was fixed before final packaging (ENG-18 companion fix)",
       "/home/z/my-project/readiness/evidence/F_R5.stderr")

print("Section A FINAL: 10/10 recorded")
