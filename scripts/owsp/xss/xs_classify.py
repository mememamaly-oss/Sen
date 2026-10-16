#!/usr/bin/env python3
"""xss recall round — classify ALL xss tests (TP vs FN) by input shape /
sink / transform, to isolate what separates the 60 FNs from the 186 TPs.
Zero engine code — pure source + spec analysis (live diagnosis, phase 1).
Same pattern as Task 42's sq_classify.py."""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

SRC = Path("/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode")
EVAL = json.load(open("/home/z/my-project/build-v430/results/owsp/benchmark/eval_sq_close_full.json"))
spec = yaml.safe_load(open("/home/z/tools/benchmark/data/openapi.yaml"))

TP = set(EVAL["per_category"]["xss"]["tp_tests"])
FN = set(EVAL["per_category"]["xss"]["fn_tests"])

spec_by_test = {}
for p, ops in spec["paths"].items():
    spec_by_test[p.rsplit("/", 1)[-1]] = ops


def spec_shape(t):
    ops = spec_by_test.get(t) or {}
    method = list(ops.keys())[0] if ops else "?"
    op = list(ops.values())[0] if ops else {}
    locs = [prm.get("in") for prm in op.get("parameters", []) or []]
    body = (op.get("requestBody") or {}).get("content", {})
    if "application/x-www-form-urlencoded" in body:
        fields = list((body["application/x-www-form-urlencoded"]
                       .get("schema") or {}).get("properties", {}).keys())
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
    if "getTheMultipartParameter" in s or "isMultipart" in s or "getPart" in s:
        return "multipart"
    if "getFilename" in s or "getTheFilename" in s or "getSubmittedFileName" in s:
        return "filename"
    if "getServletPath" in s or "getRequestURI" in s or "getPathTranslated" in s:
        return "path_info"
    if "getThePassword" in s or "getPassword" in s:
        return "password"
    if "getTheSession" in s or "getSession(" in s:
        return "session"
    return "other"


def sink_shape(s):
    out = []
    if "sendRedirect" in s:
        out.append("redirect")
    if re.search(r'getWriter\(\)\s*\.\s*(println|print|write|append|format)\s*\(', s) \
       or "getWriter()." in s:
        kinds = set(re.findall(r'getWriter\(\)\s*\.\s*(\w+)\s*\(', s))
        out.append("writer:" + ",".join(sorted(kinds)))
    if "getOutputStream" in s:
        out.append("ostream")
    if "ServletOutputStream" in s:
        out.append("sostream")
    return ";".join(out) if out else "no-direct-sink"


def transform_shape(s):
    t = []
    if "ESAPI" in s or "esapi" in s:
        t.append("esapi")
    if "URLEncoder" in s or "URIBuilder" in s:
        t.append("urlenc")
    if "Base64" in s or "b64" in s or "encodeBase64" in s:
        t.append("b64")
    if re.search(r'\.encode\s*\(', s):
        t.append("encode")
    if "escape" in s.lower():
        t.append("escape")
    if "replace(" in s:
        t.append("replace")
    if "MessageFormat" in s or "String.format" in s or ".format(" in s:
        t.append("fmt")
    if "MessageDigest" in s or "digest" in s:
        t.append("hash")
    if "random" in s.lower():
        t.append("rand")
    if "Integer.parseInt" in s or "parse" in s:
        t.append("parse")
    return ",".join(t) if t else "none"


rows = []
tests = TP | FN
for t in sorted(tests):
    src = (SRC / f"{t}.java").read_text()
    # strip comments to avoid comment-only matches
    nc = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    nc = re.sub(r'//.*', '', nc)
    rows.append({
        "test": t,
        "verdict": "TP" if t in TP else "FN",
        "input": input_shape(nc),
        "sink": sink_shape(nc),
        "transform": transform_shape(nc),
        "spec": spec_shape(t),
    })

Path("/home/z/my-project/tool-results/xss_round/xs_classify.json").write_text(
    json.dumps(rows, indent=1))

# family tables: input x verdict, then per-input sink/transform for FNs
print(f"total xss tests classified: {len(rows)}  (TP {len(TP)} / FN {len(FN)})\n")
print("=== INPUT source x verdict ===")
c = Counter((r["input"], r["verdict"]) for r in rows)
inputs = sorted({r["input"] for r in rows})
for i in inputs:
    tp = c[(i, "TP")]; fn = c[(i, "FN")]
    tot = tp + fn
    print(f"  {i:24s} TP {tp:3d}  FN {fn:3d}   (FN share {fn/tot:.0%})")

print("\n=== FN families: input -> sink -> transform ===")
fam = defaultdict(list)
for r in rows:
    if r["verdict"] == "FN":
        fam[(r["input"], r["sink"], r["transform"])].append(r["test"])
for k in sorted(fam, key=lambda k: -len(fam[k])):
    print(f"  {k[0]} | {k[1]} | {k[2]}  ->  {len(fam[k]):2d}  {fam[k]}")

print("\n=== TP families (for contrast): input -> sink ===")
fam2 = defaultdict(list)
for r in rows:
    if r["verdict"] == "TP":
        fam2[(r["input"], r["sink"])].append(r["test"])
for k in sorted(fam2, key=lambda k: -len(fam2[k]))[:12]:
    print(f"  {k[0]} | {k[1]}  ->  {len(fam2[k]):3d}")
