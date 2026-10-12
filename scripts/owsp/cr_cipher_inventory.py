#!/usr/bin/env python3
"""Task 40 — static cipher inventory of ALL 246 crypto tests (TP/FN/TN):
the FP-danger map for the coming channel + oracle fixes."""
import json, re
from collections import Counter

SRC = "/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"
ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fn_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["fn_tests"])
tp_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["tp_tests"])
csv_rows = [l.split(",") for l in open(
    "/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv").read().splitlines() if l]
all_crypto = {r[0].replace("BenchmarkTest", "") for r in csv_rows if len(r) > 2 and r[1] == "crypto"}
tn_ids = sorted(all_crypto - set(fn_ids) - set(tp_ids))

# benchmark.properties actual values (live read earlier):
PROPS = {"cryptoAlg1": "DES/ECB/PKCS5Padding", "cryptoAlg2": "AES/CCM/NoPadding"}

def cipher_of(num):
    s = open(f"{SRC}/BenchmarkTest{num}.java", encoding="utf-8", errors="replace").read()
    lit = re.findall(r'Cipher\.getInstance\("([^"]+)"', s)
    if lit:
        return lit[0], "literal"
    m = re.search(r'getProperty\("(cryptoAlg\d)"', s)
    if m:
        return PROPS.get(m.group(1), m.group(1)), f"property:{m.group(1)}"
    if "ESAPI" in s and "encrypt" in s:
        return "ESAPI-encryptor", "esapi"
    return "UNKNOWN", "unknown"

inv = {"TP": {}, "FN": {}, "TN": {}}
for grp, ids in (("TP", tp_ids), ("FN", fn_ids), ("TN", tn_ids)):
    for n in ids:
        inv[grp][n] = cipher_of(n)

print("=== cipher inventory ===")
for grp in ("TP", "FN", "TN"):
    print(f"\n-- {grp} ({len(inv[grp])}) --")
    for c, k in Counter(f"{v[0]} [{v[1]}]" for v in inv[grp].values()).most_common():
        n = sum(1 for v in inv[grp].values() if f"{v[0]} [{v[1]}]" == c)
        print(f"{n:3d}  {c}")

# the specific FP danger: TN with 8-byte-block ciphers reachable by new channels
print("\n=== TN with DES-family ciphers (FP danger if channels reach them) ===")
danger = {n: v for n, v in inv["TN"].items() if "DES" in v[0] or "RC4" in v[0] or "Blowfish" in v[0]}
print(f"count: {len(danger)}  (these would be MISSED-secure or actually weak-mislabeled?)")
for n, v in list(danger.items())[:10]:
    print(" ", n, v)
print("\n=== TN ECB modes (T3 repeat-oracle danger) ===")
ecb = {n: v for n, v in inv["TN"].items() if "ECB" in v[0]}
print(f"count: {len(ecb)}")
for n, v in list(ecb.items())[:10]:
    print(" ", n, v)
json.dump(inv, open("/home/z/my-project/tool-results/cr_cipher_inventory.json", "w"), indent=1)
print("\nwritten: tool-results/cr_cipher_inventory.json")
