#!/usr/bin/env python3
import json, sys
out = open("/home/z/my-project/tool-results/bench_probe.txt", "w")
try:
    d = json.load(open("/home/z/my-project/build-v420/results/bench_v420_1.json"))
    out.write("LOADED keys=%d\n" % len(d))
    row = {k: d.get(k) for k in ("run_id", "precision", "recall", "f1", "tp",
                                 "fp", "fn", "tn", "findings", "requests")}
    out.write(json.dumps(row, sort_keys=True) + "\n")
    if row.get("tp") is None:
        m = d.get("metrics") or {}
        out.write("metrics=" + json.dumps({k: m.get(k) for k in ("precision", "recall", "f1", "tp", "fp", "fn", "tn")}) + "\n")
    st = d.get("stats") or {}
    out.write("unverified_candidates=%s\n" % st.get("unverified_candidates"))
    out.write("arrays: verified=%d rejected=%d unverified=%d\n" % (
        len(d.get("findings", [])), len(d.get("rejected_candidates", [])),
        len(d.get("unverified_candidates", []) or [])))
    for f in d.get("findings", []):
        if f.get("type") == "missing_security_headers":
            out.write("passive conf=%s method=%s\n" % (f.get("confidence"), (f.get("verification") or {}).get("method")))
            break
    for f in d.get("findings", []):
        if f.get("type") in ("csrf", "nosql_injection"):
            out.write("%s conf=%s method=%s passed=%s\n" % (
                f.get("type"), f.get("confidence"),
                (f.get("verification") or {}).get("method"),
                (f.get("verification") or {}).get("passed")))
    for f in (d.get("unverified_candidates") or []):
        out.write("UNVERIFIED %s conf=%s method=%s\n" % (
            f.get("type"), f.get("confidence"), (f.get("verification") or {}).get("method")))
    out.write("PROBE-OK\n")
except Exception as e:
    out.write("ERROR %r\n" % (e,))
out.flush()
out.close()
