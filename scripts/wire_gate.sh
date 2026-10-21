#!/bin/bash
# ORD-002-WIRE — AXIS-17 WIRE FINAL GATE DRIVER (worklog task 112)
# The ordered gate, verbatim:
#   1. pytest: all old + new green
#   2. bench x3 WITHOUT --race: (38,0,0,37) IDENTICAL (structural compare vs anchor)
#   3. bench x3 WITH --race on a local target: works, no regression
#   4. doctor: 17/17
#   5. scope-edge: 6/6 x3
#   6. commit + push + ls-remote  (done outside this driver)
#   7. STATE.md + worklog.md      (done outside this driver)
#   8. STOP and await the supervisor's approval.
set -u
cd /home/z/my-project/build-v430
EVID="results/axis17/wire"
ANCHOR="results/verify_pt1/bench_run1.json"
CMP="/home/z/my-project/scripts/bench_structural_compare.py"
mkdir -p "$EVID"
LOG="$EVID/GATE_LOG.txt"
: > "$LOG"

log() { echo "$@" | tee -a "$LOG"; }

log "# ORD-002-WIRE — AXIS-17 WIRE FINAL GATE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
log "# tree: $(git rev-parse HEAD)  (M1 RED 0c70076 -> M2 GREEN c8387f4)"
log ""

# ---- 1. pytest (all old + new) --------------------------------------------
log "== 1. PYTEST (all old + new) =="
python3 -m pytest tests/ -q 2>/dev/null | tail -2 | tee -a "$LOG"
PYT_RC=${PIPESTATUS[0]}
log "PYTEST_RC=$PYT_RC"
log ""

# ---- 2. bench x3 WITHOUT --race -------------------------------------------
log "== 2. BENCH x3 WITHOUT --race =="
for i in 1 2 3; do
  python3 sentinel/cli.py benchmark --out "$EVID/bench_norace_$i.json" >/dev/null 2>&1
  python3 - "$EVID/bench_norace_$i.json" "$i" << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
c = d["confusion"]
print(f"  norace-{sys.argv[2]}: run={d['run_id']} confusion=({c['TP']},{c['FP']},{c['FN']},{c['TN']}) "
      f"P={d['precision']} R={d['recall']} F1={d['f1']} findings={len(d['findings'])} "
      f"gt={d['ground_truth_sha256'][:16]} requests={d['details'] and d.get('stats',{}).get('requests','n/a')}"
      if 'stats' in d else
      f"  norace-{sys.argv[2]}: run={d['run_id']} confusion=({c['TP']},{c['FP']},{c['FN']},{c['TN']}) "
      f"P={d['precision']} R={d['recall']} F1={d['f1']} findings={len(d['findings'])} "
      f"gt={d['ground_truth_sha256'][:16]}")
EOF
done
python3 "$CMP" "$ANCHOR" "$EVID/bench_norace_1.json" "$EVID/bench_norace_2.json" "$EVID/bench_norace_3.json" 2>&1 | tee -a "$LOG"
log "NORACE_COMPARE_RC=${PIPESTATUS[0]}"
log ""

# ---- 3. bench x3 WITH --race (local target; no regression) ----------------
log "== 3. BENCH x3 WITH --race =="
for i in 1 2 3; do
  python3 sentinel/cli.py benchmark --race --out "$EVID/bench_race_$i.json" >/dev/null 2>&1
  python3 - "$EVID/bench_race_$i.json" "$i" << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
c = d["confusion"]
race = d.get("race_analysis") or {}
probed = race.get("probed", [])
bound = {}
for p in probed:
    b = p.get("honest_boundary") or "none"
    bound[b] = bound.get(b, 0) + 1
race_findings = [f for f in d["findings"] if f["type"] == "race_condition"]
print(f"  race-{sys.argv[2]}: run={d['run_id']} confusion=({c['TP']},{c['FP']},{c['FN']},{c['TN']}) "
      f"F1={d['f1']} | race section: probed={len(probed)} boundaries={bound} "
      f"race_requests={race.get('requests', 0)} race_findings={len(race_findings)}")
EOF
done
python3 "$CMP" "$ANCHOR" "$EVID/bench_race_1.json" "$EVID/bench_race_2.json" "$EVID/bench_race_3.json" 2>&1 | tee -a "$LOG"
log "RACE_COMPARE_RC=${PIPESTATUS[0]}"
log ""

# ---- 4. doctor -------------------------------------------------------------
log "== 4. DOCTOR =="
python3 sentinel/cli.py doctor > "$EVID/doctor.json" 2>/dev/null
python3 - "$EVID/doctor.json" << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
n_ok = sum(1 for c in d["checks"] if c["status"] == "PASS")
print(f"  doctor: {n_ok}/{len(d['checks'])} PASS")
for c in d["checks"]:
    if c["status"] != "PASS":
        print(f"    [!]{c['status']}: {c['check']} — {c['detail']}")
EOF
log ""

# ---- 5. scope-edge x3 --------------------------------------------------------
log "== 5. SCOPE-EDGE x3 =="
for i in 1 2 3; do
  python3 tests/test_scope_edge_battery.py --out "$EVID/scope_edge_run$i.json" >/dev/null 2>&1
  python3 - "$EVID/scope_edge_run$i.json" "$i" << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  scope-edge-{sys.argv[2]}: {d['passed_count']}/{d['total']} "
      f"digest={d['digest'][:16]} passed={d['passed']}")
EOF
done
log ""

log "== GATE DRIVER COMPLETE =="
log "# verdicts: PYTEST_RC=$PYT_RC NORACE_COMPARE_RC above, RACE_COMPARE_RC above, doctor/scope-edge above"
cat "$LOG"
