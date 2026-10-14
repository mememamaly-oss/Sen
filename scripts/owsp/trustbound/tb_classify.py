#!/usr/bin/env python3
"""TB fix round — step 1: per-family ID mapping for the 51 trustbound FNs.

The diagnosis (commit 986735e) proved the root causes and recorded family
COUNTS; this script re-derives the exact per-family ID LISTS from the same
8b67a88 sources + the openapi specs, so each fix's coverage can be verified
test-by-test at the close. Also live-probes the resolver-name family and the
OTHER-9 (the diagnosis's recorded 'first session act of the fix round').
Channels classified from the source's READ expression:
  - tcid-value        : getParameter/getParameterValues/getTheParameter("<TCID>")
  - raw-query-string  : getQueryString() substring/URLDecoder
  - resolver-name     : getParameterNames scan + value == basename (NAME tainted)
  - header-name       : headerNames scan, first non-standard header NAME
  - map-read          : request.getParameterMap() scan (value or name read)
  MANGLE: last-char eat/replace before the trusted-store sink.
"""
import json
import re
import sys
from pathlib import Path

SRC = Path("/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode")
SPEC_DIR = Path("/home/z/my-project/tool-results/bm_full_chunks")

FNS = ['00031', '00251', '00424', '00427', '00508', '00587', '00588', '00670',
       '00671', '00754', '00756', '00759', '00833', '00834', '00836', '01082',
       '01143', '01206', '01299', '01374', '01375', '01455', '01456', '01457',
       '01458', '01546', '01547', '01548', '01551', '01615', '01616', '01617',
       '01618', '01708', '01709', '01710', '01711', '01876', '01958', '01960',
       '02015', '02016', '02165', '02263', '02352', '02448', '02524', '02527',
       '02622', '02623', '02624']


def classify(src: str, tcid: str) -> dict:
    bn = "BenchmarkTest" + tcid          # the TCID basename (the resolver sentinel)
    out = {"channels": set(), "mangle": None, "sink": None}
    # read channels
    if re.search(r'get(?:The)?Parameter(?:Values)?\(\s*"' + bn + '"', src):
        out["channels"].add("tcid-value")
    if "getQueryString(" in src:
        out["channels"].add("raw-query-string")
    if "getParameterNames(" in src:
        out["channels"].add("resolver-name")
    if re.search(r'getHeaderNames\(|getHeaders\(', src):
        out["channels"].add("header-name")
    if re.search(r'getHeader\(\s*"' + bn + '"', src):
        out["channels"].add("header-tcid-value")
    if "getParameterMap(" in src:
        out["channels"].add("map-read")
    if re.search(r'getCookie|getValue\(\).*URLDecoder|Cookie\[', src) or \
            ("getCookies()" in src and "URLDecoder.decode" in src):
        out["channels"].add("cookie-value")
    # mangle detection (the XS-2 family: exactly ONE trailing char destroyed)
    if re.search(r'substring\s*\(\s*0\s*,[^)]*length\(\)\s*-\s*1\s*\)', src):
        out["mangle"] = "drop-last"
    if re.search(r'replace\s*\([^)]*length\(\)\s*-[^)]*\)\s*,\s*"Z"', src) or \
            re.search(r'\.replace\s*\([^)]*length\(\)\s*-\s*"?[A-Za-z]"?\.length\(\)', src):
        out["mangle"] = out["mangle"] or "rewrite-last"
    if re.search(r'deleteCharAt\s*\(\s*\w+\s*-\s*1', src):
        out["mangle"] = out["mangle"] or "delete-last"
    # trusted-store sink phrases (for context confirmation)
    for pat, name in ((r"setAttribute", "session-attr"),
                      (r"put\(", "map-put"),
                      (r"setProperty", "sys-prop")):
        if re.search(pat, src):
            out["sink"] = (out["sink"] or "") + name + ","
    return out


def declared_params(tcid: str) -> dict:
    """The openapi-spec declared body fields for the test (from any spec chunk)."""
    for spec in sorted(SPEC_DIR.glob("spec_*.json")):
        try:
            d = json.loads(spec.read_text())
        except Exception:
            continue
        for p, methods in (d.get("paths") or {}).items():
            if tcid in p:
                info = methods.get("post") or methods.get("get") or {}
                rb = info.get("requestBody", {}).get("content", {})
                props = {}
                for v in rb.values():
                    props = v.get("schema", {}).get("properties", {})
                    if props:
                        break
                qs = [q.get("name") for q in info.get("parameters", [])
                      if q.get("in") == "query"]
                return {"spec": spec.name, "body": list(props), "query": qs}
    return {}


def main():
    rows = {}
    for tcid in FNS:
        f = SRC / f"BenchmarkTest{tcid}.java"
        if not f.exists():
            rows[tcid] = {"error": "source missing"}
            continue
        c = classify(f.read_text(errors="replace"), tcid)
        c["declared"] = declared_params(tcid)
        rows[tcid] = c
    # report: cluster by primary channel
    families = {}
    for tcid, c in rows.items():
        ch = c.get("channels") or {"UNCLEAR"}
        key = "+".join(sorted(ch))
        families.setdefault(key, []).append(tcid)
    print("=" * 78)
    print("FAMILY CLUSTERS (51 trustbound FNs, source-derived):")
    for key in sorted(families, key=lambda k: -len(families[k])):
        ids = families[key]
        mangle_ct = sum(1 for t in ids if rows[t].get("mangle"))
        print(f"  {key:<44} {len(ids):>3} tests  (mangle: {mangle_ct})")
        print(f"      {', '.join('BenchmarkTest' + t for t in ids)}")
    print("=" * 78)
    print("PER-TEST DETAIL (mangle / declared params / sink):")
    for tcid in FNS:
        c = rows[tcid]
        print(f"  {tcid}: mangle={c.get('mangle')} sink={c.get('sink')} "
              f"declared={c.get('declared')}")
    Path("/home/z/my-project/scripts/owsp/trustbound/tb_family_map.json").write_text(
        json.dumps(rows, indent=1, default=list))


if __name__ == "__main__":
    main()
