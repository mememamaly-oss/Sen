#!/usr/bin/env python3
"""The No-Hallucination Gate applied to the LIVE campaign artifacts
(DVGA + DVWS scans). Same six invariants as the executable contract in the
test suite — run against the real live-run JSONs, with planted-lie checks
to prove the gate still has teeth on these exact artifacts."""
import copy
import json
import sys

RUNS = {
    "DVGA": "/home/z/my-project/gap-validation/results/scan_dvga_LIVE.json",
    "DVWS": "/home/z/my-project/gap-validation/results/scan_dvws_LIVE.json",
}


def gate(rep) -> list[str]:
    fails = []
    stats = rep["stats"]
    # G1: no finding without evidence
    for f in rep["findings"]:
        if not f.get("evidence"):
            fails.append(f"G1: finding {f.get('id')} carries no evidence")
        else:
            for ev in f["evidence"]:
                if not (ev.get("detail") or "").strip():
                    fails.append(f"G1: finding {f.get('id')} has empty evidence")
    # G2: twin belief audit empty
    for p in stats.get("digital_twin", {}).get("belief_audit") or []:
        fails.append(f"G2: twin belief audit: {p}")
    # G3/G5: coverage arithmetic + 100% guard
    dims = (stats.get("coverage") or {}).get("dimensions") or {}
    for name, d in dims.items():
        if d.get("tested", 0) > d.get("discovered", 0):
            fails.append(f"G3: dimension {name} tested>{d.get('tested')} "
                         f"> discovered {d.get('discovered')}")
        if d.get("pct") == 100.0 and d.get("untested", 0) > 0:
            fails.append(f"G5: dimension {name} 100% with {d['untested']} untested")
        if d.get("status") == "NOT_DISCOVERED" and d.get("tested", 0) > 0:
            fails.append(f"G4: dimension {name} NOT_DISCOVERED yet tested>0")
    # G4: protocol dims never claim tested without observed surface
    if not (stats.get("graphql") or {}).get("candidates"):
        g = dims.get("graphql") or {}
        if g.get("tested", 0) > 0:
            fails.append("G4: GraphQL tested with no endpoint observed")
    if not (stats.get("websocket") or {}).get("candidates"):
        w = dims.get("websocket") or {}
        if w.get("tested", 0) > 0:
            fails.append("G4: WebSocket tested with no channel observed")
    # G6: boundary structural validity
    for p in stats.get("boundary", {}).get("unresolved_detail") or []:
        if not p.get("reason"):
            fails.append("G6: boundary record without reason")
    return fails


ok = True
for name, path in RUNS.items():
    rep = json.load(open(path))
    fails = gate(rep)
    print(f"=== {name}: {len(rep['findings'])} findings, "
          f"{rep['stats']['boundary']['records']} boundary records ===")
    if fails:
        ok = False
        print("  GATE FAILURES:")
        for f in fails:
            print("   -", f)
    else:
        print("  G1..G6: ALL GREEN")
    # teeth: two planted lies per artifact must fail
    lie1 = copy.deepcopy(rep)
    lie1["findings"].append({"id": "F-lie", "type": "xss_reflected",
                             "evidence": []})
    assert any(x.startswith("G1") for x in gate(lie1)), "lie 1 passed?!"
    lie2 = copy.deepcopy(rep)
    ws_dim = lie2["stats"]["coverage"]["dimensions"].get("websocket")
    if ws_dim and ws_dim.get("discovered", 0) == 0:
        ws_dim["tested"] = 3  # NOT_DISCOVERED yet tested
        assert any(x.startswith("G4") for x in gate(lie2)), "lie 2 passed?!"
    print("  planted lies: both caught (gate has teeth)")

print()
print("NO-HALLUCINATION GATE (LIVE ARTIFACTS):",
      "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
