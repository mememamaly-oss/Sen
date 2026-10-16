#!/usr/bin/env python3
"""Classify every FN test by CHANNEL + SPEC-DRIFT against the servlet source + openapi spec.

Channel families (from servlet source):
  names      — the dopostNames shape: iterates param names, matches VALUE==testID, injects the NAME
  value      — request.getParameter("<testID>") (or map.get) — value is the injection point
  header     — request.getHeader("<testID>")
  cookie     — cookie named <testID>
  headername — request.getHeaderNames()
  querystring— request.getQueryString() parsing
Spec drift: the openapi.yaml declared param names vs the servlet's true param name.
"""
import json, re, sys
from pathlib import Path

SRC = Path("/home/z/my-project/tools/benchmark-src")
TCD = SRC / "src/main/java/org/owasp/benchmark/testcode"
EVAL = Path("/home/z/my-project/build-v430/results/owsp/benchmark/eval_v430_final_v430.json")

_spec = None
def spec():
    global _spec
    if _spec is None:
        import yaml
        s = yaml.safe_load((SRC / "data/openapi.yaml").read_text())
        _spec = {p.rsplit("/", 1)[-1]: (p, s["paths"][p]) for p in s["paths"] if "/BenchmarkTest" in p}
    return _spec

def spec_param_names(entry):
    names = []
    op = entry.get("post") or entry.get("get") or {}
    for prm in op.get("parameters", []) or []:
        if "name" in prm: names.append(prm["name"])
    rb = (op.get("requestBody") or {}).get("content", {})
    for ct, blob in rb.items():
        for pn in ((blob.get("schema") or {}).get("properties") or {}):
            names.append(pn)
    return names

def classify(t):
    src = (TCD / f"{t}.java").read_text(errors="replace")
    chan, true_name = None, t
    if "names.hasMoreElements()" in src and 'value.equals("' in src:
        chan = "names"
    elif re.search(r'getHeaderNames\(\)', src):
        chan = "headername"
    elif re.search(r'getCookies\(\)', src) and f'"{t}"' in src and "getHeader(" not in src and "getParameter(" not in src:
        chan = "cookie"
    elif re.search(r'getHeader\("' + t + r'"\)', src):
        chan = "header"
    elif re.search(r'getQueryString\(\)', src):
        chan = "querystring"
    elif re.search(r'getParameter\("' + t + r'"\)|map\.get\("' + t + r'"\)', src):
        chan = "value"
    else:
        # fallback: any getParameter with a literal name
        m = re.search(r'getParameter\("([^"]+)"\)', src) or re.search(r'map\.get\("([^"]+)"\)', src)
        if m:
            chan, true_name = "value", m.group(1)
        else:
            chan = "other"
    sp = spec().get(t)
    if sp is None:
        return chan, "NO-SPEC", true_name
    declared = spec_param_names(sp[1])
    if chan == "names":
        return chan, "names-ok" if t in declared or any(d for d in declared) else "?", true_name
    if true_name in declared:
        return chan, "spec-correct", true_name
    return chan, "DRIFTED", true_name

def main():
    d = json.load(open(EVAL))
    only = set(sys.argv[1:]) or None
    from collections import Counter
    print(f"{'cat':<14}{'total':>6} | channel+drift histogram")
    grand = Counter()
    detail = {}
    for cat, v in d["per_category"].items():
        fns = v.get("fn_tests") or []
        if not fns: continue
        hist = Counter()
        for t in fns:
            chan, drift, tn = classify(t)
            hist[f"{chan}/{drift}"] += 1
            grand[f"{chan}/{drift}"] += 1
        detail[cat] = dict(hist)
        top = "  ".join(f"{k}={n}" for k, n in hist.most_common(8))
        print(f"{cat:<14}{len(fns):>6} | {top}")
    print("\nGRAND:", "  ".join(f"{k}={n}" for k, n in grand.most_common()))
    json.dump(detail, open("/home/z/my-project/scripts/owsp/fn_channels.json", "w"), indent=1)

if __name__ == "__main__":
    main()
