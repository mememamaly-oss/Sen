#!/usr/bin/env python3
"""Task 42 (sqli recall round) — classify ALL 272 sqli tests (TP vs FN) by
input shape / sink / transform, to isolate what separates the 65 FNs from the
207 TPs. Zero engine code — pure source + spec analysis (live diagnosis)."""
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

SRC = Path("/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode")
EVAL = json.load(open("/home/z/my-project/build-v430/results/owsp/benchmark/eval_v439_cr3_full_final.json"))
spec = yaml.safe_load(open("/home/z/tools/benchmark/data/openapi.yaml"))

rows = []
for line in open("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv"):
    if line.startswith("#") or not line.strip():
        continue
    name, cat, real, cwe = line.strip().split(",")
    if cat == "sqli":
        rows.append((name, real))

spec_by_test = {}
for p, ops in spec["paths"].items():
    spec_by_test[p.rsplit("/", 1)[-1]] = ops


def spec_shape(t):
    ops = spec_by_test.get(t) or {}
    method = list(ops.keys())[0] if ops else "?"
    op = list(ops.values())[0] if ops else {}
    locs = []
    for prm in op.get("parameters", []) or []:
        locs.append(prm.get("in"))
    body = (op.get("requestBody") or {}).get("content", {})
    if "application/x-www-form-urlencoded" in body:
        fields = list((body["application/x-www-form-urlencoded"].get("schema") or {})
                      .get("properties", {}).keys())
        locs.append("form:" + ",".join(fields))
    return method, ";".join(str(x) for x in locs)


def input_shape(s):
    if "getHeaderNames" in s:
        return "header_names_loop"
    if "getHeader(" in s:
        return "header_value"
    if "getCookies" in s or "getTheCookie" in s:
        return "cookie"
    if "getQueryString" in s:
        return "raw_qs"
    if "getParameterNames" in s or "getParameterMap" in s:
        if ".equals(" in s or "value.equals" in s:
            return "resolver_value_match"
        return "param_names_other"
    m = re.findall(r'get(?:The)?Parameter\("([^"]+)"\)', s)
    if m:
        return "param_literal"
    if "getParameter(" in s:
        return "param_dynamic"
    return "other"


def sink(s):
    if "prepareStatement" in s and "SELECT" in s:
        return "prep_select"
    if "prepareCall" in s or "{call" in s:
        return "callable"
    if "prepareStatement" in s:
        return "prep_other"
    if "createStatement" in s:
        return "createStatement"
    if "hibernate" in s.lower() or "Hibernate" in s:
        return "hibernate"
    return "other"


out = defaultdict(lambda: {"tp": 0, "fn": 0, "fn_tests": []})
for name, real in rows:
    f = SRC / f"{name}.java"
    s = f.read_text()
    shp = input_shape(s)
    snk = sink(s)
    m, locs = spec_shape(name)
    key = (shp, snk, m, locs)
    status = "fn" if name in EVAL["per_category"]["sqli"]["fn_tests"] else "tp"
    out[key][status] += 1
    if status == "fn":
        out[key]["fn_tests"].append(name.replace("BenchmarkTest", ""))

print(f"{'shape':22s} {'sink':14s} {'m':5s} {'spec-locs':38s} {'TP':>4s} {'FN':>4s}")
for key in sorted(out, key=lambda k: -(out[k]["fn"])):
    shp, snk, m, locs = key
    v = out[key]
    print(f"{shp:22s} {snk:14s} {m:5s} {locs[:38]:38s} {v['tp']:4d} {v['fn']:4d}  {','.join(v['fn_tests'][:8])}")
