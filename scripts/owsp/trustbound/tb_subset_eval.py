#!/usr/bin/env python3
"""TB close-out 3.1: evaluate the full-trustbound-subset scan against the
expected CSV — recall on the 83 vulnerable tests, FP on the 43 safe twins,
per-test channel/variant attribution for the closure report."""
import json
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, "/home/z/my-project/scripts/owsp")

EXPECTED = "/home/z/my-project/tools/benchmark-src/expectedresults-1.2.csv"
SCAN = sys.argv[1] if len(sys.argv) > 1 else "/tmp/tb_subset_scan.json"
ENGINE_TYPE_TO_CATEGORY = {"trust_bound": "trustbound"}


def tcid(url):
    m = re.search(r"(BenchmarkTest\d{5})(?:[?/].*)?$", url)
    return m.group(1) if m else None


exp = {}
for row in __import__("csv").reader(open(EXPECTED)):
    if row and row[1].strip() == "trustbound":
        exp[row[0]] = row[2].strip() == "true"

d = json.load(open(SCAN))
hits = defaultdict(list)
for f in d.get("findings", []):
    t = tcid(f.get("url", ""))
    if t:
        hits[t].append(f)

tp = fn = fp = tn = 0
fn_list, fp_list = [], []
attribution = {}
for tcid_, vuln in exp.items():
    fs = hits.get(tcid_, [])
    right = [f for f in fs if f.get("type") == "trust_bound"
             and f.get("status") == "verified"]
    other_active = [f for f in fs if f.get("type") not in
                    ("trust_bound", "missing_security_headers",
                     "server_banner_disclosure", "tech_banner")
                     and f.get("status") == "verified"]
    if vuln:
        if right:
            tp += 1
            det = " ".join(str(e.get("detail", "")) for e in right[0].get("evidence", []))
            m = re.search(r"channel=(\w+)", det)
            v = "tail" if "variant=tail" in det else "plain"
            attribution[tcid_] = (m.group(1) if m else "?", v)
        else:
            fn += 1
            fn_list.append((tcid_, [f["type"] for f in fs]))
    else:
        if right or other_active:
            fp += 1
            fp_list.append((tcid_, [f["type"] for f in fs if f.get("status") == "verified"]))
        else:
            tn += 1

print(f"trustbound subset: TP={tp} FN={fn} FP={fp} TN={tn}  "
      f"(total {len(exp)})")
if tp + fn:
    print(f"recall = {tp}/{tp+fn} = {tp/(tp+fn)*100:.2f}%")
if tp + fp:
    print(f"precision = {tp}/{tp+fp} = {tp/(tp+fp)*100:.4f}")
print("channel attribution (TP):", dict(Counter(attribution.values())))
if fn_list:
    print("FN:", fn_list)
if fp_list:
    print("FP:", fp_list)
reqs = d.get("stats", {}).get("requests")
print("requests:", reqs)
json.dump({"tp": tp, "fn": fn, "fp": fp, "tn": tn, "attribution": attribution,
           "fn_list": [x[0] for x in fn_list], "fp_list": [x[0] for x in fp_list],
           "requests": reqs},
          open("/tmp/tb_subset_eval.json", "w"), indent=1)
