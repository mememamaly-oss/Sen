#!/usr/bin/env python3
"""Task 40 — FINAL classifier: what plaintext actually reaches doFinal in each
of the 75 crypto FN servlets (and the 55 TP + 116 TN contrasts).

Decides, per servlet:
  extraction  : getTheValue | header-named | header-loop-NAME | cookie | qs |
                map.get(testid) | getParameter(testid) | value-match |
                getInputStream | named-param
  override    : always-true ternary -> constant / getTheValue -> "bar" /
                string-puzzle / none (param flows)
  final_pt    : CONSTANT(<literal>) or CONTROLLED(<channel>)

Pattern basis (live source read):
  bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;   # 232>200 always
  scr.getTheValue("BenchmarkTestNNNNN")                               # returns "bar"
"""
import json, re, os
from collections import Counter

SRC = "/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"
ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fn_ids = [t.replace("BenchmarkTest", "") for t in cc["fn_tests"]]
tp_ids = [t.replace("BenchmarkTest", "") for t in cc["tp_tests"]]
# TN = secure crypto tests in the ground truth = CSV crypto rows minus tp minus fn
csv_rows = [l.split(",") for l in open(
    "/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv").read().splitlines() if l]
all_crypto = {r[0].replace("BenchmarkTest", "") for r in csv_rows if len(r) > 2 and r[1] == "crypto"}
tn_ids = sorted(all_crypto - set(fn_ids) - set(tp_ids))
print(f"counts: FN {len(fn_ids)}  TP {len(tp_ids)}  TN(derived) {len(tn_ids)} (eval says 116)")

def classify(num):
    s = open(f"{SRC}/BenchmarkTest{num}.java", encoding="utf-8", errors="replace").read()
    tid = f"BenchmarkTest{num}"
    # --- extraction
    if "getTheValue(" in s: ext = "getTheValue->bar"
    elif re.search(rf'getHeader\("{tid}"\)', s): ext = "header-named(testid)"
    elif "getHeaderNames()" in s: ext = "header-loop-NAME"
    elif re.search(r'getHeader\("([A-Za-z0-9_-]+)"\)', s):
        ext = "header-named(" + re.search(r'getHeader\("([A-Za-z0-9_-]+)"\)', s).group(1)[:20] + ")"
    elif "getCookies()" in s: ext = "cookie-named(testid)"
    elif "getQueryString()" in s: ext = "querystring"
    elif re.search(rf'map\.get\("{tid}"\)|getParameter\("{tid}"\)', s): ext = "param-named(testid)"
    elif f'value.equals("{tid}")' in s: ext = "value-match(NAME is pt)"
    elif "getInputStream()" in s: ext = "raw-body"
    else:
        ps = re.findall(r'getParameter\("([^"]+)"\)', s)
        ext = f"named-param({','.join(ps)[:24]})" if ps else "OTHER"
    # --- override between extraction and use
    ovr = "none"
    m = re.search(r'\? \s*"([^"]{3,60})"\s*:\s*(param|bar|str)\s*;', s)
    m2 = re.search(r'\?\s*(param|bar|str)\s*:\s*"([^"]{3,60})"\s*;', s)
    if "This_should_always_happen" in s: ovr = 'CONST("This_should_always_happen",26B)'
    elif m: ovr = f'CONST("{m.group(1)}",{len(m.group(1))}B)'
    elif m2: ovr = "ternary-param-true(?)"
    elif "getTheValue(" in s: ovr = 'CONST("bar",3B)'
    # string puzzle markers
    puzzle = bool(re.search(r'replaceAll\(|\.concat\(|StringBuilder|String\.format|\.trim\(\)|toUpperCase\(|toLowerCase\(|substring\(', s))
    # final plaintext
    if ovr.startswith("CONST"): final = ovr
    elif "getTheValue" in ext: final = 'CONST("bar",3B)'
    elif ext in ("raw-body",): final = "CONTROLLED(raw-body)"
    elif ext == "value-match(NAME is pt)": final = "CONTROLLED(param-name)"
    elif ext.startswith("header-named"): final = "CONTROLLED(header-value)"
    elif ext == "header-loop-NAME": final = "CONTROLLED(header-name)"
    elif ext == "cookie-named(testid)": final = "CONTROLLED(cookie-value)"
    elif ext == "querystring": final = "CONTROLLED(qs)"
    elif ext.startswith("param-named"): final = "CONTROLLED(form-field-testid)"
    else: final = "CONTROLLED(named-param)"
    return {"num": num, "ext": ext, "ovr": ovr, "final": final, "puzzle": puzzle}

rows = {"fn": [classify(n) for n in fn_ids],
        "tp": [classify(n) for n in tp_ids],
        "tn": [classify(n) for n in tn_ids]}

print("=== FN: final plaintext reaching doFinal ===")
for k, v in Counter(r["final"] for r in rows["fn"]).most_common():
    mem = [r["num"] for r in rows["fn"] if r["final"] == k]
    print(f"{v:3d}  {k:42s} {','.join(mem[:10])}")
print("\n=== TP contrast ===")
for k, v in Counter(r["final"] for r in rows["tp"]).most_common():
    print(f"{v:3d}  {k:42s}")
print("\n=== TN (SECURE) contrast — the FP danger set ===")
for k, v in Counter(r["final"] for r in rows["tn"]).most_common():
    mem = [r["num"] for r in rows["tn"] if r["final"] == k]
    print(f"{v:3d}  {k:42s} {','.join(mem[:8])}")
print("\n=== TN constant literals (what do SECURE constants encrypt to?) ===")
tn_const = [(r["num"], r["ovr"]) for r in rows["tn"] if r["final"].startswith("CONST")]
for n, o in tn_const[:20]: print(n, o)
print("\n=== FN puzzle flags among non-CONST ===")
for r in rows["fn"]:
    if not r["final"].startswith("CONST") and r["puzzle"]:
        print(r["num"], r["ext"], r["final"])
json.dump(rows, open("/home/z/my-project/tool-results/cr_final_plaintext.json", "w"), indent=1)
print("\nwritten: tool-results/cr_final_plaintext.json")
