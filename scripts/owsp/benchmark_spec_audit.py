#!/usr/bin/env python3
"""Cross-check: the shipped openapi.yaml's declared param names vs the ACTUAL
param names each test servlet reads (getParameter/getHeader/getQueryString/
cookie name), straight from the committed servlet source. The spec was auto-
generated and (hypothesis) its names drift on a large fraction of tests.
"""
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

SRC = Path("/home/z/my-project/tools/benchmark-src")
TC = SRC / "src/main/java/org/owasp/benchmark/testcode"


def actual_vector(java: str):
    """Extract (source, name) the servlet reads."""
    m = re.search(r'request\.getParameter\("([^"]+)"\)', java)
    if m:
        return "param", m.group(1)
    m = re.search(r'request\.getHeader\("([^"]+)"\)', java)
    if m:
        return "header", m.group(1)
    if "request.getQueryString()" in java:
        m = re.search(r'getParameterNames\(\)', java)
        return "querystring", None
    m = re.search(r'theCookie\.getName\(\)\.equals\("([^"]+)"\)', java)
    if m:
        return "cookie", m.group(1)
    m = re.search(r'request\.getCookies\(\)', java)
    if m:
        return "cookie", None
    m = re.search(r'names = request\.getHeaderNames\(\)', java)
    if m:
        return "headernames", None
    return "unknown", None


def main():
    spec = yaml.safe_load((SRC / "data/openapi.yaml").read_text())
    stats = Counter()
    mismatches = []
    for path, ops in spec["paths"].items():
        tcid_m = re.search(r"(BenchmarkTest\d{5})$", path)
        if not tcid_m:
            continue
        tcid = tcid_m.group(1)
        jf = TC / f"{tcid}.java"
        if not jf.exists():
            stats["no_source"] += 1
            continue
        java = jf.read_text()
        src_kind, src_name = actual_vector(java)
        # declared params in spec for this path
        declared = []
        for op in ops.values():
            if isinstance(op, dict):
                for prm in op.get("parameters", []) or []:
                    declared.append((prm.get("in", "query"), prm.get("name")))
                body = (op.get("requestBody") or {}).get("content", {})
                for ct in body:
                    for fld in (body[ct].get("schema") or {}).get("properties", {}):
                        declared.append(("body", fld))
        if not declared:
            stats["no_declared"] += 1
            continue
        ok = False
        for loc, name in declared:
            if src_name and name == src_name:
                ok = True
            elif src_kind == "querystring" and loc == "query":
                ok = True   # reads the whole query string; any query param reaches
            elif src_kind == "headernames" and loc == "header":
                ok = True
        if ok:
            stats["match"] += 1
        else:
            stats["MISMATCH"] += 1
            mismatches.append((tcid, src_kind, src_name, declared[:3]))
    print("spec-vs-source param-name audit:", dict(stats))
    print("sample mismatches (first 12):")
    for t, k, n, d in mismatches[:12]:
        print(f"  {t} servlet reads {k}:{n!r}  spec declares {d}")


if __name__ == "__main__":
    main()
