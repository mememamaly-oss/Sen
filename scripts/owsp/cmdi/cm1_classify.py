#!/usr/bin/env python3
"""cmdi round — classify all 51 FN (and 75 TP for contrast) test sources by
injection surface and sink shape, directly from the 8b67a88 clone."""
import json
import re
from collections import Counter, defaultdict

CSV = "/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv"
SRC = "/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode"
evalj = json.load(open("/home/z/my-project/build-v430/results/owsp/benchmark/eval_xs_close_full.json"))
FN = evalj["per_category"]["cmdi"]["fn_tests"]
TP = evalj["per_category"]["cmdi"]["tp_tests"]

def classify(t):
    s = open(f"{SRC}/{t}.java").read()
    # entry surface
    if re.search(r'request\.getHeader\(', s): entry = "header"
    elif re.search(r'getCookies\(\)', s): entry = "cookie"
    elif re.search(r'\.getParameter\s*\(\s*"?', s) or 'map.get("' in s:
        entry = "param"
    else: entry = "?"
    # resolver pass (ThingInterface doSomething indirection)
    resolver = "doSomething(" in s
    # sink: where does the tainted value end up?
    envp = bool(re.search(r'argsEnv\s*=\s*\{', s)) or "getOSCommandArray" not in s and re.search(r'exec\s*\(\s*args', s) and "argsEnv" in s
    argv_arr = bool(re.search(r'new (String|java\.lang\.String)\[\]\s*\{[^}]*"', s)) or "getOSCommandArray(" in s
    single = bool(re.search(r'exec\s*\(\s*(?!args|new)(cmd|bar|command|param)\b', s)) or re.search(r'exec\s*\(\s*"[^"]*"\s*\+', s)
    pb = "ProcessBuilder" in s
    # the tainted value placement
    if envp: sink = "envp-array"
    elif pb: sink = "ProcessBuilder"
    elif argv_arr: sink = "argv-array"
    elif single: sink = "exec-single-string"
    else: sink = "other"
    return entry, sink, resolver

for label, lst in (("FN", FN), ("TP", TP)):
    c = Counter()
    per = defaultdict(list)
    for t in lst:
        e, sk, rs = classify(t)
        c[(e, sk, rs)] += 1
        per[(e, sk, rs)].append(t)
    print(f"=== {label} ({len(lst)}) ===")
    for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
        print(f"  {v:3d}  entry={k[0]:<7} sink={k[1]:<18} resolver={k[2]}")
        print(f"        tests: {', '.join(per[k][:14])}{' ...' if len(per[k])>14 else ''}")
