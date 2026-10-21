#!/bin/bash
# ORD-002-WIRE gate — RESUME script (worklog task 112).
# The single-shot driver exceeds the sandbox tool deadline; the gate runs in
# sections each under ~9 minutes, appending to the SAME GATE_LOG record.
# Completed before resume (same tree 322c316, same gate record):
#   pytest 230 passed in 304.21s (PYTEST_RC=0) + norace-1/norace-2 benches.
set -u
cd /home/z/my-project/build-v430
EVID="results/axis17/wire"
ANCHOR="results/verify_pt1/bench_run1.json"
CMP="/home/z/my-project/scripts/bench_structural_compare.py"
LOG="$EVID/GATE_LOG.txt"

sec="${1:-}"
case "$sec" in
norace3)
  [ -f "$EVID/bench_norace_3.json" ] || \
    python3 sentinel/cli.py benchmark --out "$EVID/bench_norace_3.json" >/dev/null 2>&1
  python3 - "$EVID/bench_norace_3.json" 3 << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
c = d["confusion"]
print(f"  norace-{sys.argv[2]}: run={d['run_id']} confusion=({c['TP']},{c['FP']},{c['FN']},{c['TN']}) "
      f"P={d['precision']} R={d['recall']} F1={d['f1']} findings={len(d['findings'])} "
      f"gt={d['ground_truth_sha256'][:16]}")
EOF
  ;;
race1|race2|race3)
  i="${sec#race}"
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
rf = [f for f in d["findings"] if f["type"] == "race_condition"]
print(f"  race-{sys.argv[2]}: run={d['run_id']} confusion=({c['TP']},{c['FP']},{c['FN']},{c['TN']}) "
      f"F1={d['f1']} | race section in doc: {'yes' if race else 'NO'} probed={len(probed)} "
      f"boundaries={bound} race_requests={race.get('requests', 0)} race_findings={len(rf)}")
EOF
  ;;
compare)
  echo "-- structural compare: NORACE x3 vs anchor --" | tee -a "$LOG"
  python3 "$CMP" "$ANCHOR" "$EVID/bench_norace_1.json" "$EVID/bench_norace_2.json" "$EVID/bench_norace_3.json" 2>&1 | tee -a "$LOG"
  echo "NORACE_COMPARE_RC=${PIPESTATUS[0]}" | tee -a "$LOG"
  echo "-- structural compare: RACE x3 vs anchor --" | tee -a "$LOG"
  python3 "$CMP" "$ANCHOR" "$EVID/bench_race_1.json" "$EVID/bench_race_2.json" "$EVID/bench_race_3.json" 2>&1 | tee -a "$LOG"
  echo "RACE_COMPARE_RC=${PIPESTATUS[0]}" | tee -a "$LOG"
  ;;
doctor)
  echo "== 4. DOCTOR ==" | tee -a "$LOG"
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
  ;;
scope)
  echo "== 5. SCOPE-EDGE x3 ==" | tee -a "$LOG"
  for i in 1 2 3; do
    python3 tests/test_scope_edge_battery.py --out "$EVID/scope_edge_run$i.json" >/dev/null 2>&1
    python3 - "$EVID/scope_edge_run$i.json" "$i" << 'EOF' | tee -a "$LOG"
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  scope-edge-{sys.argv[2]}: {d['passed_count']}/{d['total']} "
      f"digest={d['digest'][:16]} passed={d['passed']}")
EOF
  done
  ;;
*)
  echo "usage: wire_gate_resume.sh {norace3|race1|race2|race3|compare|doctor|scope}"
  exit 2
  ;;
esac
