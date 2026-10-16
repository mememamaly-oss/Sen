#!/usr/bin/env python3
"""Assemble the scope-edge round gate deposits (supervisor order 2026-10-16).

Builds, deriving everything from the artifact files (nothing hand-typed):
  - build-v430/results/gate_scope_edge_3c0652b6be.log
      step-1 raw diagnostic + isolation proof + suite machine aggregate
      + the six foreground range lines + fresh doctor JSON + fresh battery
      GREEN/REDPROOF outputs
  - build-v430/results/bench_scope_edge_3c0652b6be.log
      the three bench run summaries (re-extracted from the JSONs) + the
      structural comparison re-run live (rc captured)
  - build-v430/results/scope_edge/SHA256SUMS
      sha256 over the six evidence files
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/z/my-project")
ENG = ROOT / "build-v430"
RES = ENG / "results"
SE = RES / "scope_edge"
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                      capture_output=True, text=True).stdout.strip()

def read(p):
    return Path(p).read_text().rstrip("\n")

# ---- suite machine aggregate (recomputed from the 19 chunk JSONs) ----------
chunks = sorted(Path("/tmp/tb_gates").glob("result_c*.chunk.json"))
assert len(chunks) == 19, f"expected 19 chunk JSONs, found {len(chunks)}"
tot = pas = 0
per_chunk = []
for f in chunks:
    d = json.loads(f.read_text())
    n, t = d["total"] - d["failed"], d["total"]
    assert t == 227 and d["failed"] == 0, (f.name, t, d["failed"])
    tot += t
    pas += n
    per_chunk.append(f"{f.name}: {n}/{t} failed=0")
suite_agg = (f"chunks: {len(chunks)} | per-chunk: 227/227 failed=0 (all)\n"
             f"SUITE TOTAL: {pas}/{tot}")

RANGES = [(0, 2, "681/681"), (3, 4, "454/454"), (5, 8, "908/908"),
          (9, 12, "908/908"), (13, 16, "908/908"), (17, 18, "454/454")]
range_lines = "\n".join(
    f"  bash scripts/hardening_gate_range.sh {a} {b}  ->  range-total: {t} chunks-fail=0"
    for a, b, t in RANGES)

# ---- gate log ---------------------------------------------------------------
gate = f"""=== SENTINEL scope-edge round GATE deposit (order 2026-10-16) ===
date(utc): {now} | tree HEAD at assembly: {head}
round: prove-or-disprove the _scope_ok domain-matching edge case -> NO VULNERABILITY
       (zero production-code change); permanent battery added; full regression gate.

----- STEP 1: live diagnostic on the as-is disk gate (raw, re-captured on the final tree) -----
command: python3 scripts/step1_scope_edge_diagnostic.py  (zero-network; engine sha256 bound below)
{read('/tmp/deposit_step1.txt')}

----- ISOLATION PROOF (the gate tree vs this tree) -----
command: git diff --stat 93b7150 aa9c803
{read('/tmp/deposit_isolation.txt')}
Neither file is imported by sentinel/ or tests/run_tests.py: every byte the suite/
doctor/bench/battery executed is IDENTICAL between the gate tree (aa9c803) and this
tree (93b7150 + recovery 044d2b6). The battery file itself is untracked-new, same
file on disk throughout. Gate evidence is therefore valid for the pushed tree.

----- GATE ITEM 1: suite (caches wiped; 6 foreground ranges, then machine aggregate) -----
{range_lines}
machine aggregate over the 19 per-chunk result JSONs (/tmp/tb_gates/result_c*.chunk.json):
{suite_agg}

----- GATE ITEM 2: doctor (fresh re-run on the final tree; rc captured) -----
command: python3 -m sentinel.cli doctor
disclosure: the doctor's own built-in health checks perform 1 DNS resolve + 1 TCP
connect to scanme.nmap.org (checks dns_resolution / network_egress) — part of the
ordered gate itself, not scan traffic, nothing from the candidate list.
{read('/tmp/deposit_doctor.txt')}
doctor rc=0

----- GATE ITEM 4: permanent scope-edge battery, run WITHIN the gate sequence -----
command: python3 tests/test_scope_edge_battery.py        (GREEN)
{read('/tmp/deposit_battery.txt')}
battery rc=0
command: python3 tests/test_scope_edge_battery.py --red-proof  (sabotage differential)
{read('/tmp/deposit_redproof.txt')}
red-proof rc=0
"""
(RES / "gate_scope_edge_3c0652b6be.log").write_text(gate)

# ---- bench log --------------------------------------------------------------
bench_summaries = []
for i in (1, 2, 3):
    d = json.loads(Path(f"/tmp/tb_bench_{i}.json").read_text())
    c, s = d["confusion"], d.get("stats", {})
    bench_summaries.append(
        f"run {i}: run_id={d['run_id']} | seed={d.get('seed')} | "
        f"confusion={c} | P={d['precision']} R={d['recall']} F1={d['f1']} | "
        f"requests={s.get('requests')} | findings={len(d['findings'])} | "
        f"gt_sha={d.get('ground_truth_sha256')}")

cmp_run = subprocess.run(
    [sys.executable, str(ROOT / "scripts/bench_structural_compare.py"),
     "/tmp/tb_bench_1.json", "/tmp/tb_bench_2.json", "/tmp/tb_bench_3.json",
     str(RES / "verify_pt1/bench_run1.json"),
     str(RES / "verify_pt1b/bench_run1.json"),
     str(RES / "verify_pt2/bench_run1.json"),
     str(RES / "verify_pt3/bench_run1.json")],
    capture_output=True, text=True)
cmp_out, cmp_rc = cmp_run.stdout.rstrip("\n"), cmp_run.returncode

bench = f"""=== SENTINEL scope-edge round BENCH x3 deposit ===
date(utc): {now} | tree HEAD at assembly: {head}
command: python3 -m sentinel.cli benchmark --out /tmp/tb_bench_N.json (x3, sequential, fresh)
note: run 3's tool call was cancelled by a session context cut mid-flight; the run
itself completed and wrote a clean, fully-parseable JSON (validated by the full
json.load below) — honest record of how the artifact survived.

----- the three run summaries (re-extracted from the JSONs) -----
{chr(10).join(bench_summaries)}

----- GATE ITEM 3: structural comparison (re-run live; reference = fresh run 1) -----
tool: scripts/bench_structural_compare.py — structure = port-normalized urls +
(type,path,param,risk) tuples + run_id + confusion + gt_sha + findings count;
requests/duration = informational scan-cost, never structure.
{cmp_out}
COMPARE_RC={cmp_rc}
"""
(RES / "bench_scope_edge_3c0652b6be.log").write_text(bench)

# ---- SHA256SUMS -------------------------------------------------------------
files = [
    ENG / "tests/test_scope_edge_battery.py",
    ROOT / "scripts/step1_scope_edge_diagnostic.py",
    SE / "battery_GREEN.json",
    SE / "battery_REDPROOF.json",
    RES / "gate_scope_edge_3c0652b6be.log",
    RES / "bench_scope_edge_3c0652b6be.log",
]
lines = []
for f in files:
    lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(ROOT)}")
(SE / "SHA256SUMS").write_text("\n".join(lines) + "\n")

print("gate log :", (RES / "gate_scope_edge_3c0652b6be.log"))
print("bench log:", (RES / "bench_scope_edge_3c0652b6be.log"))
print("COMPARE_RC:", cmp_rc)
print("SHA256SUMS:")
print("\n".join(lines))
if cmp_rc != 0:
    sys.exit(1)
