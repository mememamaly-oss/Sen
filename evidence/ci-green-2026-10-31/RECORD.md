# CI Green Record — 2026-10-31 (administration session)

The repo's CI had NEVER been green (11 consecutive failed runs, observed
via the Actions API once the PAT carried Actions:Read). This session
diagnosed every failure from the downloaded job logs, fixed the causes,
and landed the first fully green run.

## Run ladder

| run | sha | result | cause of remaining failure |
|-----|-----|--------|----------------------------|
| 41147068985 | eef30e9 | 2/5 jobs | engine: `No module named pytest` (sandbox preinstall ≠ runner); drift: `scripts/gen_compliance_registry.py` never committed (scripts/ is locally git-excluded; lost to an environment recycle); fixture: TP=36/FN=2 |
| 41149783779 | 2fba859 | 5/6 jobs | web: `landing / renders publicly` timed out at exactly bun's 5000ms default — next-dev on-demand compile of `/` on a slower cold shared runner (it squeaked under 5s at eef30e9 — a race, not a regression) |
| **41150402123** | **fb725eb** | **6/6 GREEN** | — |

## Fixes (each root-caused from the job logs, each locally gated before push)

1. **Engine job** — `requirements-dev.txt` = engine deps + pytest; the job
   installs it. (Commit 2fba859.)
2. **Drift job** — `scripts/gen_compliance_registry.py` recreated and
   verified BYTE-IDENTICAL against the checked-in registry
   (`sha256` prefix `c6e31f8e9f518bb1`; the serialization contract is
   2-space indent, literal UTF-8, trailing newline). Force-added past the
   local scripts/ exclusion. The drift job now has its generator.
3. **Fixture job** — the 2 missing detections
   (`xss_dom@/vuln/dom-write:search`,
   `xss_reflected@/vuln/jsform-reflect:msg`) REQUIRE the playwright
   render engine: the first is the DOM execution phase, the second is a
   runtime-JS-built form that is statically invisible (fixture comment:
   "browser render-merge discovery; statically invisible — no <form>
   markup"). Runner log proof: `"playwright/chromium unavailable —
   static fallback": 1`. Job now installs playwright + chromium; the
   deterministic record TP=38/FP=0/FN=0/F1=1.0 reproduced on GitHub.
4. **Web job** — the integration runner now warms every public route the
   suite hits (/, /login, /docs/*, /demo) under one 240s deadline before
   handing over, and the suite runs with `--timeout 60000`. READY now
   means "routes compiled", not "process listening". (Commit fb725eb.)
5. **NEW real-targets job** — OWASP Juice Shop v20.3.0 (pinned) in a
   container, unauthenticated seeded scan, reports as artifacts. Green on
   both runs. Baseline + floor: `evidence/real-targets/juice-shop/`.

## Local gate executed before each push (the quantum rule)

pytest 196/196 · doctor 19/19 · registry `--check` in sync · canonical
fixture 199 verified / 30 types / all mapped · benchmark TP=38 FP=0 FN=0
TN=37 F1=1.0 · all five report formats exported from the store ·
real-target harness smoke vs live fixture 85 verified / 14 types rc=0 ·
secret scan clean (exact CI command) · YAML valid · lint + typecheck
clean · unit 27/27 · integration 26/26 on real PostgreSQL (clean-DB
reset; the 7 stateful bootstrap tests fail on a dirty DB by design —
verified that interpretation before re-running clean) · production build
rc=0.

## Repository state after this session

- origin/main = fb725eb (fast-forwards only, verified over the wire).
- Remote branches: **main only** — the 8 legacy duplicates
  (clean/axes-final, phase/02-l1-twin, qa/real-testing-gate,
  release/v4.1.1–v4.2.2, security/audit-remediation) deleted via the API
  AFTER per-branch containment proof (`git merge-base --is-ancestor` vs
  main — every commit on every deleted ref remains reachable from main;
  the proof output is in the session log and
  `scripts/branch_cleanup_2026-10-31.sh` re-verifies before deleting).
- Artifacts of the green run: `fixture-scan` (scan.json + 5 report
  formats + benchmark + compliance) and `real-target-juiceshop` — both
  downloadable from run 41150402123 for 90 days.
- The PAT used this session: administration confirmed via the API
  permissions object (`admin/maintain/push/triage/pull` all true).
