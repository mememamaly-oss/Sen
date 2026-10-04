#!/usr/bin/env python3
"""Unified L2 path regeneration (round 6, citation-integrity hotfix).

Regenerates attack_paths for ALL FOUR live targets with the FIXED apath
builder (rotating-cookie citation pairing), each from its real live journal:

  - gruyere2, testasp : fresh v4.3.0 live scans (live_v430/*.json) — the
    journal/findings are the real fresh scan output; only the embedded paths
    are rebuilt with the hotfixed builder (identical to what the shipped
    pipeline now embeds via orchestrator.report()).
  - testaspnet, ginjuice : v4.3.0 L2 projection over their REAL v4.2.3 live
    journals (this environment kills background processes and caps foreground
    calls at 600s; those scans take 936s/620s; the engine is verdict-identical
    per the gates and L2 is a zero-request pure projection; a fresh ginjuice
    re-scan attempt overran the window and was discarded).

Every file gets an explicit l2_source provenance string — consumers can
always see where the paths came from. Zero requests are sent.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "build-v423"))

from sentinel.apath import build_attack_paths  # noqa: E402

R = os.path.join(ROOT, "build-v423", "results")


def main():
    manifest = {
        # fresh v4.3.0 live scans — rebuild paths in place from their own journals
        "gruyere2": {
            "src": f"{R}/live_v430/gruyere2.json", "dst": f"{R}/live_v430/gruyere2.json",
            "note": ("fresh v4.3.0 live scan ({run_id}, seed {seed}); attack paths "
                     "REBUILT with the citation-integrity hotfix (rotating-cookie "
                     "citation pairing) — identical to what the shipped pipeline now "
                     "embeds via orchestrator.report()")},
        "testasp": {
            "src": f"{R}/live_v430/testasp.json", "dst": f"{R}/live_v430/testasp.json",
            "note": ("fresh v4.3.0 live scan ({run_id}, seed {seed}); attack paths "
                     "REBUILT with the citation-integrity hotfix (rotating-cookie "
                     "citation pairing) — identical to what the shipped pipeline now "
                     "embeds via orchestrator.report()")},
        # projections over the real v4.2.3 live journals
        "testaspnet": {
            "src": f"{R}/live_v423/testaspnet.json", "dst": f"{R}/live_v430/testaspnet.json",
            "note": ("v4.3.0 L2 projection over the v4.2.3 live journal ({run_id}, seed "
                     "{seed}) — the engine is verdict-identical (gate verdict-diff vs "
                     "frozen v4.2.2 = NONE) and L2 is a zero-request pure projection; "
                     "this environment cannot host a >600s fresh re-scan of this target "
                     "(measured 936s in the v4.2.3 re-gate)")},
        "ginjuice": {
            "src": f"{R}/live_v423/ginjuice.json", "dst": f"{R}/live_v430/ginjuice.json",
            "note": ("v4.3.0 L2 projection over the v4.2.3 live journal ({run_id}, seed "
                     "{seed}) — the engine is verdict-identical (gate verdict-diff vs "
                     "frozen v4.2.2 = NONE) and L2 is a zero-request pure projection; "
                     "this environment cannot host a >600s fresh re-scan of this target "
                     "(measured 620s; a fresh attempt overran the 600s window and was "
                     "discarded)")},
    }
    out = {}
    for t, m in manifest.items():
        rep = json.load(open(m["src"], encoding="utf-8"))
        paths = build_attack_paths(rep)
        rep["attack_paths"] = paths
        rep["l2_source"] = m["note"].format(run_id=rep.get("run_id"), seed=rep.get("seed"))
        with open(m["dst"], "w", encoding="utf-8") as fh:
            json.dump(rep, fh)
        s = paths.get("summary", {})
        out[t] = {"run_id": rep.get("run_id"), "paths": s.get("paths_total"),
                  "verified": s.get("paths_verified"), "inferred": s.get("paths_inferred"),
                  "weak": s.get("weak_link_histogram")}
        print(f"{t}: {out[t]}")
    print(json.dumps({"regenerated": out}))


if __name__ == "__main__":
    main()
