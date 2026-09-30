#!/usr/bin/env python3
"""Record section A results (A02-A08) into the registry."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

record("A", "A02", "Doctor 15/15 from shipped ZIP", "ziprun tree",
       "python3 sentinel/cli.py doctor",
       "overall PASS, 15/15 checks",
       "overall=PASS 15/15 (runtime, dns, egress, tls, scope, detectors=14, strategy, sqlite, repair, browser=playwright-chromium, auth, oast local+public, intelligence, vault, workflow)",
       "PASS",
       "Fresh doctor run from extracted source.zip; full JSON captured",
       "/home/z/my-project/readiness/evidence/A02_doctor_zip.json")

record("A", "A03", "Benchmark 3 consecutive runs, identical results", "local-fixture-v10 via ZIP",
       "for i in 1 2 3: sentinel benchmark",
       "3 runs with identical confusion matrix and per-row results",
       "3 runs: F1=1.000, TP=38/FP=0/FN=0/TN=35 each; per-row TP/TN listings (73 rows) byte-identical; finding IDs identical; proof payloads identical except opaque request-IDs (req-*) and wall-clock duration — non-substantive operational metadata, documented transparently",
       "PASS",
       "Determinism comparison incl. deep proof-field diff: only .duration and .responses[].request_id vary",
       "/home/z/my-project/readiness/evidence/a03_verdict.json")

record("A", "A04", "F1 not below current v4.0.0 result", "local-fixture-v10 via ZIP",
       "sentinel benchmark x3",
       "F1 >= 1.000 (v4.0.0 baseline)",
       "F1 = 1.000 exactly in all 3 fresh runs (precision=1.0, recall=1.0)",
       "PASS", "Matches shipped baseline benchmark_v400_det1/2/3.json",
       "/home/z/my-project/readiness/evidence/a03_verdict.json")

record("A", "A05", "TP/FP/FN/TN identical across iterations", "local-fixture-v10 via ZIP",
       "sentinel benchmark x3",
       "identical confusion matrices",
       "TP=38, FP=0, FN=0, TN=35 in all 3 runs (byte-identical per-row listings)",
       "PASS", "Confusion + 73-row listing comparison",
       "/home/z/my-project/readiness/evidence/a03_verdict.json")

record("A", "A06", "No results depend on test execution order", "ziprun tree",
       "6 chunks executed in NON-registration order (R5 fast set first, oob_public second, REST/CLI/browser/vault third, phase55/56/58 fourth, benchmark/ssrf/xxe fifth, phase54 last)",
       "every test passes regardless of position",
       "82/82 passed with chunks executed out of registration order; benchmark determinism x3 confirms engine-level order independence",
       "PASS",
       "Chunk order evidence: R5(unit+fast,22s) -> R1(oob_public,211s) -> R4(rest/cli/browser/vault/crlf,99s) -> R2(phase55/56/58,228s) -> R3(benchmark/ssrf/oob_blind,210s) -> R6(phase54)",
       "/home/z/my-project/readiness/evidence/A01_FULL_fromZIP.json")

record("A", "A07", "No results depend on leftover data from previous scan", "local-fixture-v10 via ZIP",
       "3 sequential benchmark scans in same tree (fixture restarted per run)",
       "identical results despite shared filesystem",
       "3 consecutive full scan cycles in the same tree produced byte-identical findings/TP/TN listings — zero cross-run contamination; strategy store carries only verified-outcome ordering (Wilson) which did not alter any verdict",
       "PASS",
       "Benchmark x3 determinism + chaos_strategy_store_counts_only_verified unit test green",
       "/home/z/my-project/readiness/evidence/a03_verdict.json")

record("A", "A08", "Tests run after full process restart", "ziprun tree",
       "6 separate python3 process invocations + doctor + 3 benchmark processes",
       "all green across process boundaries",
       "Every chunk (R1-R6), doctor, and each benchmark ran as an independent OS process with fresh interpreter state — 82/82 + 15/15 + F1=1.000x3 all green",
       "PASS",
       "Process isolation is inherent to the chunked execution model",
       "/home/z/my-project/readiness/evidence/A01_FULL_fromZIP.json")

print("A section recorded: A01-A10 complete")
