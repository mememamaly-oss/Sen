#!/usr/bin/env python3
"""L3 LIVE impact-probe driver (supervisor order, trace 1a107bbe20c548bd).

For every authorized target: load its ROUND-7 FRESH scan report (L2 evidence
base), plan the SAFE minimal-benign impact probes, execute them LIVE (engine +
headless browser + our OAST channel for the redirect landing), assess honestly
(VERIFIED only via a confirming fresh probe), and write the raw evidence:
probe journal + assessment + per-target report + combined register.

Safety (fail-closed, enforced before anything is sent):
  - the target host must be in the AUTHORIZED set;
  - every planned request's host must equal the target host (the OAST sink is
    only ever reached by the LOCAL browser following the redirect, never by
    the engine);
  - all request material comes from the plan's fail-closed registries.
"""
import json
import os
import sys
import urllib.parse

ROOT = "/home/z/my-project/build-v423"
sys.path.insert(0, ROOT)
sys.path.insert(0, "/home/z/my-project/scripts")

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.oast import OastServer
from sentinel import impact

OUT = os.path.join(ROOT, "results", "l3_impact")
os.makedirs(OUT, exist_ok=True)

AUTHORIZED = {
    "ginandjuice.shop", "google-gruyere.appspot.com",
    "testasp.vulnweb.com", "testaspnet.vulnweb.com",
}

TARGETS = [
    # name, report path, plan overrides
    ("ginjuice", os.path.join(ROOT, "results", "live_v430", "ginjuice.json"),
     {"cart_view": "/catalog/cart", "redirect_param": "back"}),
    ("gruyere2", os.path.join(ROOT, "results", "live_v430", "gruyere2.json"), {}),
    ("testasp", os.path.join(ROOT, "results", "live_v430", "testasp.json"), {}),
    ("testaspnet", os.path.join(ROOT, "results", "live_v430", "testaspnet.json"), {}),
]


def main():
    args = [a for a in sys.argv[1:] if a != "planonly"]
    plan_only = "planonly" in sys.argv[1:]
    only = args or None
    oast = OastServer()          # our OOB channel: the redirect landing sink
    sink = oast.url("l3redir-ab12")
    print(json.dumps({"oast": oast.public_base, "redirect_sink": sink}))
    register = []
    for name, path, overrides in TARGETS:
        if only and name not in only:
            continue
        rep = json.load(open(path, encoding="utf-8"))
        target = rep.get("target") or ""
        host = (urllib.parse.urlsplit(target).hostname or "").lower()
        assert host in AUTHORIZED, f"{name}: host {host!r} NOT in the authorized set — refusing"
        plan = impact.plan_impact_probes(rep, redirect_sink=sink, **overrides)
        # defense in depth: every planned request must stay on the target host
        for p in plan["path_plans"]:
            for r in p.get("requests") or []:
                rh = (urllib.parse.urlsplit(r["url"]).hostname or "").lower()
                assert rh == host, "planned request leaves the target host: " + str(r["url"])
        if plan_only:
            print(json.dumps({"target": name, "plan": plan["summary"]}, ensure_ascii=False))
            for p in plan["path_plans"]:
                print(f"   {p['status']:18s} {p['probe_kind']:32s} {p['findings']} reqs={len(p.get('requests') or [])} legs={[l['probe_kind'] for l in p.get('legs') or []]}")
                if p.get("refusal_reason"): print(f"      reason: {p['refusal_reason'][:140]}")
            continue
        engine = RequestEngine(ScopeRule(allowed_domains=[host], allow_private=False),
                               EventBus("run-l3-live"))
        journal = impact.execute_impact_probes(plan, engine)
        assessment = impact.assess_impacts(rep, plan, journal)
        d = os.path.join(OUT, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "probe_journal.json"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(journal, indent=1, ensure_ascii=False) + "\n")
        with open(os.path.join(d, "plan.json"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(plan, indent=1, ensure_ascii=False) + "\n")
        with open(os.path.join(d, "assessment.json"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(assessment, indent=1, ensure_ascii=False) + "\n")
        impact.write_report(assessment, plan, journal, os.path.join(d, "report.md"))
        hits = oast.poll("l3redir-ab12", timeout=0.5) or []
        register.append({
            "target": name, "host": host, "run_id": rep.get("run_id"),
            "plan": plan["summary"], "assessment": assessment["summary"],
            "oast_redirect_hits": len(hits),
            "impacts": [{"probe_kind": i["probe_kind"], "status": i["status"],
                         "findings": i["findings"],
                         "detail": i.get("detail")}
                        for i in assessment["impacts"]],
        })
        print(json.dumps({"target": name, "plan": plan["summary"],
                          "assessment": assessment["summary"],
                          "oast_redirect_hits": len(hits)}, ensure_ascii=False))
        for i in assessment["impacts"]:
            mark = {"VERIFIED": "V", "INFERRED": "i", "PROBE_FAILED": "X",
                    "NOT_SAFE_TO_PROVE": "-", "REFUSED": "R"}.get(i["status"], "?")
            print(f"  [{mark}] {i['probe_kind']:32s} {i['findings']}")
    oast.stop()
    with open(os.path.join(OUT, "l3_live_register.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"redirect_sink": sink, "targets": register},
                            indent=1, ensure_ascii=False) + "\n")
    tv = sum(t["assessment"]["verified"] for t in register)
    tt = sum(t["assessment"]["total"] for t in register)
    print(json.dumps({"combined": {"total": tt, "verified": tv}}))


if __name__ == "__main__":
    main()
