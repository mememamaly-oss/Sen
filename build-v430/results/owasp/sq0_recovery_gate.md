# SQ-0 Recovery Gate — rollback #17, pristine origin/main re-verification (2026-10-13)

Round: sqli recall-push (supervisor order: apply patches SQ-1 then SQ-2 on
origin/main, verify gate still green, push each patch individually). The round
BLOCKED at preflight — see worklog Task 41. This file records the part of the
order that WAS executable: recover the real origin/main and prove the baseline
gate is still green, fresh this session, on the restored tree.

## Baseline

- origin/main fetched with the round PAT (inline-only protocol):
  `a456942` = "worklog: task 40 — crypto recall-push round (category closed
  95.38%, precision 1.0)".
- Local main hard-reset from the rollback-#17-era junk line (`6fcb15c`,
  Oct-3/IV13 era + iv_out temp files, backed up to
  `/home/z/iv_out_backup_pre_reset`) to `origin/main`.
- Byte-identity: `HEAD^{tree}` == `origin/main^{tree}` = `4f7e469c...`,
  `git diff origin/main` = 0 lines, `git status` clean (restored .gitignore
  re-covers runtime junk).

## Gate legs (all fresh, this session, engine build-v430 @ a456942)

| Leg | Result | Expected (shipped task-40 record) | Verdict |
|-----|--------|-----------------------------------|---------|
| Doctor | **17/17 PASS** | 17/17 | MATCH |
| Bench x3 | **38/0/0/37, F1=1.0000 x3** | 38/0/0/37 IDENTICAL | MATCH |
| Bench fingerprint | **run-3c0652b6be x3; 199 findings x3; verdict sets byte-identical** | run-3c0652b6be IDENTICAL | MATCH |
| Suite | **18/18 chunks, 212/212 ran, 0 failed** | 213 registered, 1 documented env-stall exclusion, 0 failed | MATCH |

- Suite runner: `scripts/owsp/sq0_baseline_gate.sh suite` (resumable
  18-chunk, 12 cases/chunk; SENTINEL_TEST_FILTER; orphan-fixture pkill hygiene
  between chunks per the CR-round operational note). One environment ~595s
  call-kill absorbed by the resume design (6 chunks cached, 12 completed on
  the resumed call; the killed chunk re-ran clean).
- Exclusion: `regression_oob_public_channel_end_to_end` — the documented
  runner-only env stall (hangs on pristine engines too; passes standalone) —
  NOT run, per the shipped gate contract.
- Bench evidence: /tmp/sq0_bench_{1,2,3}.json (untracked by the task-34
  evidence-size rule; numbers and fingerprint above).

## Preflight verdict on the patches

SQ-1 / SQ-2 were NOT FOUND in any recoverable source (full list in worklog
Task 41): GitHub refs + tree + releases, local git (reflog/dangling/stash),
the /tmp boot snapshot (frozen at task-40), upload/, filesystem content
search. No patch content was fabricated; no engine/test file was modified
this round. The tree at main is content-identical to a456942 apart from this
record (worklog + this file + the gate runner script).

## To unblock the round

1. Supervisor supplies SQ-1 and SQ-2 (paste diffs / upload files / push a
   branch to origin), then: apply in order, per-patch RED/GREEN + full gate
   (suite + doctor + bench x3) + individual commit + push + ls-remote verify.
2. OR re-authorize the sqli round from scratch — note the methodology's
   live-diagnosis precondition requires rebuilding the /home/z/tools
   benchmark stack (Temurin 21 + Maven 3.9.9 + BenchmarkJava + Tomcat9 +
   HSQLDB + LDAP; the cr_stack recipe is committed under scripts/owsp/),
   which rollback #17 wiped.
