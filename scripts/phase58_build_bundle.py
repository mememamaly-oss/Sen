#!/usr/bin/env python3
"""Build the v3.0.0 complete bundle + full archive (same structure as v2.9)."""
import json, os, shutil, subprocess, zipfile

DL = "/home/z/my-project/download"
SR = os.path.join(DL, "sentinel-results")
STAGE = "/tmp/bundle300"

# ---- refresh sentinel-results with the v3.0.0 canonical artifacts
# (already copied: scan_testfire_v300_LIVE, benchmark_v300_det1/2/3,
#  tests_v300_FULL, doctor_v300)
for f in ("CHANGELOG.md", "WORKLOG.md"):
    src = os.path.join("/home/z/my-project/verify-live", f) if f == "CHANGELOG.md" else os.path.join(SR, f)
    if f == "WORKLOG.md":
        src = "/home/z/my-project/worklog.md"
    shutil.copy(src, os.path.join(SR, f))

# ---- results db snapshot
shutil.copy("/home/z/my-project/verify-live/results/sentinel.db", os.path.join(SR, "sentinel_v300.db")) \
    if os.path.exists("/home/z/my-project/verify-live/results/sentinel.db") else None

# ---- build the bundle
if os.path.exists(STAGE):
    shutil.rmtree(STAGE)
root = os.path.join(STAGE, "sentinel-3.0.0-bundle")
os.makedirs(root)
shutil.copy(os.path.join(DL, "sentinel-3.0.0-source.zip"), root)
shutil.copy("/home/z/my-project/verify-live/CHANGELOG.md", root)
shutil.copy("/home/z/my-project/worklog.md", os.path.join(root, "WORKLOG.md"))
shutil.copy("/home/z/my-project/verify-live/.gitignore-vault", root)
# results: the whole standing sentinel-results directory (v2.9 parity) — the
# bundle is the complete historical record plus the new canonical artifacts
res = os.path.join(root, "sentinel-results")
shutil.copytree(SR, res, dirs_exist_ok=True)
# ground truth ships with the benchmark's own version (v9)
shutil.copy("/home/z/my-project/verify-live/benchmarks/ground_truth.json",
            os.path.join(res, "ground_truth.json"))
readme = os.path.join(root, "README.txt")
open(readme, "w").write("""SENTINEL v3.0.0 — Workflow Intelligence — COMPLETE BUNDLE
=======================================================
Contents:
  sentinel-3.0.0-source.zip   the full platform source (pure Python 3 stdlib)
  CHANGELOG.md                every release, v1.0.0 -> v3.0.0
  WORKLOG.md                  the complete engineering work log
  .gitignore-vault            vault/key ignore template (Credential Vault)
  sentinel-results/           canonical artifacts:
      tests_v300_FULL.json      71/71 gates (unit + regression + chaos)
      doctor_v300.json          15/15 self-checks (incl. workflow_engine)
      benchmark_v300_det1..3    F1 = 1.000 deterministic x3
                                (35 TP / 0 FP / 0 FN / 29 TN, run-3c0652b6be)
      scan_testfire_v300_LIVE  light production scan, learn-only workflow:
                                honest negative /bank:chain_too_short,
                                95 verified / 0 rejected, prior classes intact
      ground_truth.json         v9 (64 rows: +5 business-logic TP, +5 TN)

What v3.0.0 adds: Business-Logic / Workflow Intelligence — the scanner
reasons about PROCESSES, not just requests. It learns multi-step flows by
guided walks (chain, resource linkage, state oracle, execution markers) and,
only with --logic-active, tests the five invariants: step bypass, out-of-
order execution, post-approval value tamper, duplicate execution, and
declared-privilege escalation. Every finding requires STATE-ORACLE PROOF
(VR-20): a server that merely fails to reject is never a finding.

Self-check (from this bundle):  unzip the source zip, then
  python3 sentinel/cli.py doctor                      -> 15/15
  python3 sentinel/cli.py benchmark                   -> F1 = 1.000
""")
subprocess.run(["zip", "-rq", os.path.join(DL, "sentinel-3.0.0-complete-bundle.zip"),
                "sentinel-3.0.0-bundle"], cwd=STAGE, check=True)
print("bundle:", len(zipfile.ZipFile(os.path.join(DL, "sentinel-3.0.0-complete-bundle.zip")).namelist()), "files")
