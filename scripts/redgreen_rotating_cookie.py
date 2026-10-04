#!/usr/bin/env python3
"""Quick RED/GREEN check for the rotating-cookie citation regression.
Runs the exact fixture+assertions of unit_l2_identity_citation_rotating_cookie
without importing the whole test module (which executes all 121 cases)."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v423")
import sentinel.apath as apath


def J(rid, method, url, req_headers=None, body="", status=200, resp_headers=None, resp_body=""):
    return {rid: {"request": {"method": method, "url": url, "path": url.split("fixture.test", 1)[-1],
                              "headers": req_headers or {}, "body": body},
                  "response": {"status": status, "headers": resp_headers or {}, "body": resp_body}}}


journal = {}
journal.update(J("req-200", "GET", "http://fixture.test/", {}, "", 200,
                 {"set-cookie": "AWSALB=aaa; Path=/"}, "<html>home</html>"))
journal.update(J("req-201", "GET", "http://fixture.test/item?id=7%20AND%201%3D1",
                 {"Cookie": "AWSALB=bbb"}, "", 200, {}, "rowA"))
journal.update(J("req-202", "GET", "http://fixture.test/item?id=7%20AND%201%3D2",
                 {"Cookie": "AWSALB=ccc"}, "", 200, {}, "rowB"))
finding = {"id": "F-rot01", "type": "sql_injection", "severity": "critical", "status": "verified",
           "confidence": 0.95, "method": "GET", "url": "http://fixture.test/item", "parameter": "id",
           "evidence": [{"kind": "response_diff", "detail": "body differential rowA vs rowB on condition flip"}],
           "verification": {"method": "oracle:replay-2round", "passed": True, "confidence": 0.95,
                            "rounds": 2, "notes": "replay"},
           "run_id": "run-rotfixture", "risk": 85,
           "impact": {"grade": "proven", "statement": "Boolean differential oracle proven.",
                      "safe_proof": "non-destructive verification",
                      "evidence_chain": {"request": "GET http://fixture.test/item", "parameter": "id",
                                         "evidence_kinds": ["response_diff"], "out_of_band": False,
                                         "verification": "oracle:replay-2round", "verification_passed": True}}}
rep = {"run_id": "run-rotfixture", "seed": "seed-rot", "scanner": "sentinel-core/4.3.0",
       "target": "http://fixture.test",
       "stats": {"requests": 3, "request_journal": journal, "request_journal_dropped": 0,
                 "digital_twin": {"identities": 0, "node_kinds": {"surface": 1},
                                  "entity_inventory": [], "authorization_matrix": {}},
                 "action_matrix": {"identities": [{"name": "anonymous", "role": "anonymous"}],
                                   "actions": ["read"], "matrix": {}}},
       "findings": [finding]}

out = apath.build_attack_paths(rep)
assert out["summary"]["paths_total"] == 1, out["summary"]
p = out["paths"][0]
ident = next(l for l in p["links"] if l["slot"] == "identity")
assert ident["status"] == "verified"
bad = []
cited_any = False
for e in ident["evidence"]:
    if e["kind"] != "journal":
        continue
    cited_any = True
    entry = journal.get(e["ref"])
    if entry is None:
        bad.append(f"cited {e['ref']} not in journal")
        continue
    req, resp = entry.get("request") or {}, entry.get("response") or {}
    raw_fields = ([str(v) for v in (req.get("headers") or {}).values()]
                  + [str(req.get("url") or ""), str(req.get("body") or "")]
                  + [str(v) for v in (resp.get("headers") or {}).values()]
                  + [str(resp.get("body") or "")])
    if not any(e["excerpt"] and e["excerpt"] in fld for fld in raw_fields):
        bad.append(f"excerpt not a slice of CITED {e['ref']}: {e['excerpt']!r}")
print("identity statement:", ident["statement"][:160])
print("journal evidence:", [(e["ref"], e["excerpt"][:60]) for e in ident["evidence"] if e["kind"] == "journal"])
print("cited_any:", cited_any)
if bad or not cited_any:
    print("RESULT: RED (regression present)")
    for b in bad:
        print("  -", b)
    sys.exit(1)
print("RESULT: GREEN (citation integrity holds)")
