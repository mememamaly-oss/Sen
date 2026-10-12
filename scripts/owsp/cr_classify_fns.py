#!/usr/bin/env python3
"""Task 40 (crypto recall) — source-side classifier for the 75 crypto FN servlets.

Reads each FN test's Java source from the live clone and extracts:
  - crypto primitive: Cipher.getInstance(...) transform, key derivation, digest
  - param channel + name: getParameter/getHeader/getCookies/getQueryString
  - sink: writes passwordFile artifact? echoes value? other file?
  - response shape: the response.getWriter() message

Output: /home/z/my-project/tool-results/cr_fn_classification.json + readable table.
Contrast group: a sample of TP tests for differential framing.
"""
import json, re, os, sys
from collections import Counter, defaultdict

SRC = "/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"
OUT = "/home/z/my-project/tool-results/cr_fn_classification.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fns = [t.replace("BenchmarkTest", "") for t in cc["fn_tests"]]
tps = [t.replace("BenchmarkTest", "") for t in cc["tp_tests"]]

def analyze(num):
    path = f"{SRC}/BenchmarkTest{num}.java"
    if not os.path.exists(path):
        return {"missing": True}
    s = open(path, encoding="utf-8", errors="replace").read()
    d = {"num": num}
    # crypto primitive
    m = re.findall(r'Cipher\.getInstance\("([^"]+)"', s)
    d["cipher"] = m
    m = re.findall(r'Cipher\.getInstance\([^)]*,\s*([^)]+)\)', s)  # provider form
    if m: d["cipher_provider"] = m
    d["secretkeyspec"] = re.findall(r'SecretKeySpec\([^;]{0,80}', s)
    d["pbekeyspec"] = bool(re.search(r'PBEKeySpec|PBEParameterSpec', s))
    d["ivspec"] = re.findall(r'IvParameterSpec\(([^;]{0,60})\)', s)
    d["digest"] = re.findall(r'MessageDigest\.getInstance\("([^"]+)"\)', s)
    d["keygen"] = re.findall(r'KeyGenerator\.getInstance\("([^"]+)"\)', s)
    d["keypairgen"] = re.findall(r'KeyPairGenerator\.getInstance\("([^"]+)"\)', s)
    d["keyfactory"] = re.findall(r'KeyFactory\.getInstance\("([^"]+)"\)', s)
    d["truststore"] = bool(re.search(r'TrustStore|KeyStore', s))
    d["esapi"] = bool(re.search(r'ESAPI\.encryptor|ESAPI\.encoder\(\)\.encrypt', s))
    # param channel
    d["params"] = sorted(set(re.findall(r'getParameter\("([^"]+)"\)', s)))
    d["headers"] = sorted(set(re.findall(r'getHeader\("([^"]+)"\)', s)))
    d["header_names_loop"] = bool(re.search(r'getHeaderNames\(\)', s))
    d["first_header"] = bool(re.search(r'while.*hasMoreElements|getHeaders\(', s))
    d["cookies"] = bool(re.search(r'getCookies\(\)', s))
    d["querystring"] = bool(re.search(r'getQueryString\(\)', s))
    d["body_read"] = bool(re.search(r'getReader\(\)|getInputStream\(\)', s))
    # sink
    d["writes_passwordfile"] = bool(re.search(r'passwordFile', s))
    d["other_file"] = sorted(set(re.findall(r'new File\(([^;]{0,70})\)', s)))
    d["filewriter"] = bool(re.search(r'FileWriter|FileOutputStream', s))
    # response shape
    msgs = re.findall(r'println\(\s*"([^"]{0,90})', s)
    d["resp_msgs"] = [m for m in msgs if m][:4]
    # structural notes
    d["bar_hardcoded"] = bool(re.search(r'"bar"', s))
    d["str_input_len"] = bool(re.search(r'strInput|bytes.*hexStringToByteArray|toByteArray', s))
    return d

rows_fn = [analyze(n) for n in fns]
rows_tp = [analyze(n) for n in tps[:60]]

json.dump({"fn": rows_fn, "tp": rows_tp, "fn_ids": fns, "tp_ids": tps},
          open(OUT, "w"), indent=1)

# ---- family rollup over FNs ----
def fam(r):
    c = (r.get("cipher") or [""])[0] if r.get("cipher") else ""
    cset = "+".join(sorted(set(r.get("cipher") or [])))
    return cset or (r.get("digest") and "digest:" + "+".join(r["digest"])) or "other"

fam_count = Counter()
fam_members = defaultdict(list)
for r in rows_fn:
    if r.get("missing"):
        f = "SOURCE-MISSING"
    else:
        f = fam(r)
        # sub-split by sink
        if not r.get("writes_passwordfile"):
            f += " | NO-PWFILE"
    fam_count[f] += 1
    fam_members[f].append(r.get("num"))

print(f"FN total: {len(rows_fn)}  (source-missing: {sum(1 for r in rows_fn if r.get('missing'))})")
print(f"TP contrast sample: {len(rows_tp)}\n")
print("=== FN families (cipher | sink-split) ===")
for f, c in fam_count.most_common():
    print(f"{c:3d}  {f:55s}  {','.join(fam_members[f][:6])}")

# channel split
print("\n=== FN param channels ===")
print("params-only :", sum(1 for r in rows_fn if r.get("params") and not r.get("headers") and not r.get("cookies")))
print("headers     :", sum(1 for r in rows_fn if r.get("headers") or r.get("header_names_loop")))
print("cookies     :", sum(1 for r in rows_fn if r.get("cookies")))
print("querystring :", sum(1 for r in rows_fn if r.get("querystring")))
print("body-read   :", sum(1 for r in rows_fn if r.get("body_read")))
print("no-param-at-all:", sum(1 for r in rows_fn if not r.get("params") and not r.get("headers") and not r.get("cookies") and not r.get("querystring")))
print("\n=== cipher transform histogram (FN) ===")
for t, c in Counter(t for r in rows_fn for t in (r.get("cipher") or [])).most_common():
    print(f"{c:3d}  {t}")
print("\n=== cipher transform histogram (TP sample) ===")
for t, c in Counter(t for r in rows_tp for t in (r.get("cipher") or [])).most_common():
    print(f"{c:3d}  {t}")
print("\nwritten to", OUT)
