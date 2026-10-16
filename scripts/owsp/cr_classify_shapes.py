#!/usr/bin/env python3
"""Task 40 — refined input-shape classifier for the 75 crypto FN servlets.

Shapes (from live source reading):
  A. getTheValue         : SeparateClassRequest.getTheValue(testname) -> constant "bar"
  B. value-matching loop : getParameterNames loop; param NAME whose VALUE == testname is the plaintext
  C. headers             : getHeader/getHeaderNames loop
  D. cookies             : getCookies
  E. querystring         : getQueryString
Plus: cipher source (literal vs benchmark.properties), key generation (fresh random
KeyGenerator each request?), IV (fresh SecureRandom?), transform per family.
"""
import json, re, os
from collections import Counter, defaultdict

SRC = "/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"

ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fns = [t.replace("BenchmarkTest", "") for t in cc["fn_tests"]]
tps = [t.replace("BenchmarkTest", "") for t in cc["tp_tests"]]

def classify(num):
    s = open(f"{SRC}/BenchmarkTest{num}.java", encoding="utf-8", errors="replace").read()
    tid = f"BenchmarkTest{num}"
    shapes = []
    if "getTheValue(" in s: shapes.append("A-constant-bar")
    if re.search(r'getParameterNames\(\)', s) and f'value.equals("{tid}")' in s:
        shapes.append("B-value-match-name")
    elif re.search(r'getParameterNames\(\)', s) and re.search(r'getParmeterValues|getParameterValues|value\.equals', s):
        shapes.append("B?-paramnames-other")
    if re.search(r'getHeader[s]?\(', s) or "getHeaderNames" in s: shapes.append("C-headers")
    if "getCookies" in s: shapes.append("D-cookies")
    if "getQueryString" in s: shapes.append("E-querystring")
    if re.search(r'getParameter\("', s): shapes.append("F-named-param")
    # cipher source
    lit = re.findall(r'Cipher\.getInstance\("([^"]+)"', s)
    prop = re.findall(r'getProperty\("([^"]+)"', s)
    keygen = re.findall(r'KeyGenerator\.getInstance\("([^"]+)"\)\.generateKey\(\)', s)
    rand_key = "generateKey()" in s
    rand_iv = "generateSeed" in s
    hard_key = "SecretKeySpec(" in s
    return {"num": num, "shapes": shapes, "literal_cipher": lit, "prop_cipher": prop,
            "keygen": keygen, "rand_iv": rand_iv, "hard_key": hard_key}

fn_rows = [classify(n) for n in fns]
tp_rows = [classify(n) for n in tps]

print("=== FN input shapes ===")
shape_combo = Counter("+".join(r["shapes"]) or "NONE" for r in fn_rows)
for k, v in shape_combo.most_common():
    members = [r["num"] for r in fn_rows if ("+".join(r["shapes"]) or "NONE") == k]
    print(f"{v:3d}  {k:35s} {','.join(members[:8])}")

print("\n=== TP input shapes (contrast, all 55) ===")
shape_combo_tp = Counter("+".join(r["shapes"]) or "NONE" for r in tp_rows)
for k, v in shape_combo_tp.most_common():
    print(f"{v:3d}  {k}")

print("\n=== FN cipher source ===")
lit_only = sum(1 for r in fn_rows if r["literal_cipher"] and not r["prop_cipher"])
prop_only = sum(1 for r in fn_rows if r["prop_cipher"] and not r["literal_cipher"])
both = sum(1 for r in fn_rows if r["prop_cipher"] and r["literal_cipher"])
neither = sum(1 for r in fn_rows if not r["prop_cipher"] and not r["literal_cipher"])
print(f"literal-only {lit_only} | property-only {prop_only} | both {both} | neither {neither}")
print("property keys:", Counter(k for r in fn_rows for k in r["prop_cipher"]))
print("literal transforms:", Counter(t for r in fn_rows for t in r["literal_cipher"]))
print("TP literal transforms:", Counter(t for r in tp_rows for t in r["literal_cipher"]))
print("\n=== key/IV regime (FN) ===")
print("fresh KeyGenerator:", sum(1 for r in fn_rows if r["keygen"]), Counter("|".join(r["keygen"]) for r in fn_rows if r["keygen"]))
print("random IV:", sum(1 for r in fn_rows if r["rand_iv"]))
print("hardcoded SecretKeySpec:", sum(1 for r in fn_rows if r["hard_key"]))

json.dump({"fn": fn_rows, "tp": tp_rows}, open("/home/z/my-project/tool-results/cr_shapes.json", "w"), indent=1)
print("\nwritten: tool-results/cr_shapes.json")
