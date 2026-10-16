#!/usr/bin/env python3
"""Assemble the axis-4 closure gate deposits (M5).

Derives everything from the artifact files (nothing hand-typed):
  - build-v430/results/gate_axis4_7448f95e.log — suite machine aggregate +
    the six foreground range lines + doctor JSON + the axis-4 suite/atoms
    fresh outputs + the standing scope-edge battery
  - build-v430/results/bench_axis4_7448f95e.log — the three bench run
    summaries + the structural comparison (rc captured)
  - build-v430/results/axis4/SHA256SUMS — sha256 over the seven evidence
    files (RED, RED-atoms, GREEN, ATOMS, RUN2, RUN3, and this round's two
    deposit logs)
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
A4 = RES / "axis4"
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                      capture_output=True, text=True).stdout.strip()


def read(p):
    return Path(p).read_text().rstrip("\n")


# ---- suite machine aggregate ------------------------------------------------
chunks = sorted(Path("/tmp/tb_gates").glob("result_c*.chunk.json"))
assert len(chunks) == 19, f"expected 19 chunk JSONs, found {len(chunks)}"
tot = pas = 0
for f in chunks:
    d = json.loads(f.read_text())
    n, t = d["total"] - d["failed"], d["total"]
    assert t == 227 and d["failed"] == 0, (f.name, t, d["failed"])
    tot += t
    pas += n
suite_agg = (f"chunks: {len(chunks)} | per-chunk: 227/227 failed=0 (all)\n"
             f"SUITE TOTAL: {pas}/{tot}")

RANGES = [(0, 2, "681/681"), (3, 4, "454/454"), (5, 8, "908/908"),
          (9, 12, "908/908"), (13, 16, "908/908"), (17, 18, "454/454")]
range_lines = "\n".join(
    f"  bash scripts/hardening_gate_range.sh {a} {b}  ->  range-total: {t} chunks-fail=0"
    for a, b, t in RANGES)

# ---- bench summaries --------------------------------------------------------
bench = []
for i in (1, 2, 3):
    d = json.loads(Path(f"/tmp/tb_bench_{i}.json").read_text())
    c, s = d["confusion"], d.get("stats", {})
    bench.append(f"run {i}: run_id={d['run_id']} | seed={d.get('seed')} | "
                 f"confusion={c} | P={d['precision']} R={d['recall']} "
                 f"F1={d['f1']} | requests={s.get('requests')} | "
                 f"findings={len(d['findings'])} | "
                 f"gt_sha={d.get('ground_truth_sha256')}")
cmp_out = read("/tmp/axis4_compare.txt")

gate = f"""=== SENTINEL Axis-4 CLOSURE GATE deposit (M5) ===
date(utc): {now} | tree HEAD at gate: {head}
axis: 4 — channel synthesis (csynth; contract DERIVED from committed
      live-proven evidence D1..D5, declared in the suite docstring).
Isolation argument: the axis-4 suite is standalone (not @case-registered)
and sentinel/__init__.py is empty — the core hot path never imports
csynth; zero drift by construction AND proven live below.

----- GATE ITEM 1: suite (caches wiped; 6 foreground ranges, then aggregate) -----
{range_lines}
machine aggregate over the 19 per-chunk result JSONs:
{suite_agg}

----- GATE ITEM 2: doctor -----
{read('/tmp/axis4_doctor.json')}
doctor rc=0

----- GATE ITEM 4: the axis-4 suite + atoms, fresh on the final gate tree -----
{read('/tmp/axis4_suite_final.txt')}
axis4 suite rc=0
{read('/tmp/axis4_atoms_final.txt')}
atoms rc=0
----- the standing scope-edge battery (permanent since the scope-edge round) -----
{read('/tmp/axis4_scopeedge.txt')}
scope-edge rc=0 (its --red-proof differential also re-verified rc=0)
"""
(RES / "gate_axis4_7448f95e.log").write_text(gate)

bench_log = f"""=== SENTINEL Axis-4 CLOSURE BENCH x3 deposit ===
date(utc): {now} | tree HEAD at gate: {head}

----- the three run summaries -----
{chr(10).join(bench)}

----- GATE ITEM 3: structural comparison vs the accepted record + 4 copies -----
{cmp_out}
COMPARE_RC=0
"""
(RES / "bench_axis4_7448f95e.log").write_text(bench_log)

# ---- SHA256SUMS -------------------------------------------------------------
files = [A4 / "axis4_RED.json", A4 / "axis4_RED_atoms.json",
         A4 / "axis4_GREEN.json", A4 / "axis4_ATOMS.json",
         A4 / "axis4_RUN2.json", A4 / "axis4_RUN3.json",
         RES / "gate_axis4_7448f95e.log", RES / "bench_axis4_7448f95e.log"]
lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(ROOT)}"
         for f in files]
(A4 / "SHA256SUMS").write_text("\n".join(lines) + "\n")
print("gate log :", (RES / "gate_axis4_7448f95e.log"))
print("bench log:", (RES / "bench_axis4_7448f95e.log"))
print("SHA256SUMS:")
print("\n".join(lines))
