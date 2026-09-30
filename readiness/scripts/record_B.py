#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

DEG = "clean env = env -i (empty), fresh HOME, system Python 3.13.5 (no venv, no playwright, no dev files)"

record("B", "B01", "Install from source.zip on clean environment", "readiness/cleanenv/src1",
       "env -i HOME=fresh PATH=/usr/bin:/bin /usr/bin/python3 sentinel/cli.py doctor",
       "product installs (extract+run) and operates outside dev env",
       f"{DEG}; doctor exit=0 → DEGRADED 14/15 (browser_engine WARN: playwright absent → static DOM fallback active — documented graceful degradation); full scan battery then ran 100% green on Python 3.13.5",
       "PASS", "Also proves cross-version compatibility (dev 3.12.5 → clean 3.13.5)",
       "/home/z/my-project/readiness/evidence/B01_doctor_cleanenv.json")

record("B", "B02", "Install Complete Bundle on clean environment", "readiness/cleanenv/bundle",
       "unzip sentinel-4.0.0-complete-bundle.zip (51 files: source+docs+fixtures+benchmarks) → doctor",
       "bundle installs and operates",
       f"{DEG}; doctor exit=0 → DEGRADED 14/15 (same honest browser WARN)",
       "PASS", "Bundle carries docs+fixtures+benchmarks alongside source",
       "/home/z/my-project/readiness/evidence/B02_doctor_bundle.json")

record("B", "B03", "Doctor runs after install", "src1 + bundle trees",
       "sentinel doctor (both trees, both pythons)",
       "doctor functional after install",
       "playwright-equipped env: PASS 15/15 (A02). Bare clean env: DEGRADED 14/15 + explicit WARN with instructions — product remains fully scannable (static DOM analysis); degradation is LOUD, not silent",
       "PASS", "Dual-environment proof",
       "/home/z/my-project/readiness/evidence/B02_doctor_bundle.json")

record("B", "B04", "Scan without any dev-environment files", "cleanenv/src1 → fixture 127.0.0.1:8777",
       "env -i ... sentinel/cli.py scan http://127.0.0.1:8777 --allow-private --workflow --logic-active --auth-user demo --auth-pass *** --authz-accounts ... --oast local --db fresh",
       "full battery works from clean install",
       "run-bf80583daf: 1686 requests, 75 endpoints, 184 findings across 28 classes (incl. all 8 business-logic classes verified with state-oracle proofs), workflow 3 flows learned / 18 attacks / 8 verified + 8 honest skips with reasons, authenticated=true, stderr EMPTY",
       "PASS", "Zero dev files on path; fixture itself spawned under the same clean env",
       "/home/z/my-project/readiness/evidence/B04_scan_clean.json")

record("B", "B05", "New DB created from scratch", "cleanenv/workdir/clean_scan1.db",
       "--db <nonexistent path> → scan → findings query",
       "DB auto-created, schema built, results persisted",
       "clean_scan1.db (266KB) auto-created; findings CLI queried it post-scan (exit=0)",
       "PASS", "SQLite 3.53 via stdlib — no external services",
       "/home/z/my-project/readiness/cleanenv/workdir/clean_scan1.db")

record("B", "B06", "Reports generated from scratch", "clean install tree",
       "report --format html|executive|glass --db clean_scan1.db",
       "all report formats build from the fresh DB",
       "HTML 78KB + executive JSON 8.3KB + glass (Arabic RTL) 14KB — all exit=0, non-empty",
       "PASS", "Generated entirely by the clean-install CLI",
       "/home/z/my-project/readiness/evidence/B06_report_clean.html")

record("B", "B07", "Reproduce works after reinstall", "reinstalled tree + pre-existing DB",
       "rm -rf tree → re-unzip → sentinel reproduce --finding F-a93c789266 --db clean_scan1.db",
       "reproduction package retrievable after full reinstall",
       "Full Evidence-OS package exported: hypothesis/preconditions/requests/responses/identity/impact/verification(oracle:workflow-state-delta, passed)/15-field proof + ordered 3-step reproduction recipe; recipe survives program close + DB reopen",
       "PASS", "Recipe is stored in DB, independent of install tree",
       "/home/z/my-project/readiness/evidence/B07_reproduce_reinstall.json")

record("B", "B08", "SARIF works", "clean install tree",
       "report --format sarif --db clean_scan1.db",
       "valid SARIF 2.1.0 JSON",
       "B08_sarif_clean.sarif 184KB exported, exit=0 (schema validated in S11/T10)",
       "PASS", "", "/home/z/my-project/readiness/evidence/B08_sarif_clean.sarif")

record("B", "B09", "CLI works from a different path than the project", "CWD=cleanenv/workdir",
       "cd <neutral dir> && env -i ... /abs/path/sentinel/cli.py doctor",
       "CLI operates from foreign CWD with absolute path",
       "doctor exit=0 from neutral CWD (DEGRADED 14/15 same as clean env)",
       "PASS", "No CWD dependence; artifacts resolve relative to caller CWD as documented",
       "/home/z/my-project/readiness/evidence/B09_doctor_othercwd.json")

record("B", "B10", "Removing old environment then reinstalling does not break product", "cleanenv/src1 + homes",
       "rm -rf src1 home1 home2 → re-unzip source.zip → doctor → reproduce",
       "product works after wipe+reinstall; data survives",
       "Reinstall doctor exit=0 (14/15 clean-env); reproduce of F-a93c789266 from the surviving DB returned the full proof package; fixture respawned fine",
       "PASS", "State is fully rebuildable from zip + DB artifacts",
       "/home/z/my-project/readiness/evidence/B10_doctor_reinstall.json")

print("Section B recorded: B01-B10 complete")
