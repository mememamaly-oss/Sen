#!/usr/bin/env python3
"""FN analysis for OWASP Benchmark v1.2 — map missed tests to their servlet source features.

Reads eval_v430_final_v430.json, classifies each FN test by sink family + input channel
from the actual servlet source, and prints a per-category feature histogram.
"""
import json, os, re, sys, collections

SRC = "/home/z/my-project/tools/benchmark-src/src/main/java/org/owasp/benchmark/testcode"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v430_final_v430.json"

def features_of(src):
    f = set()
    # sink families
    if "FileOutputStream" in src: f.add("FOS")
    if "FileInputStream" in src: f.add("FIS")
    if ".exists()" in src or "File(" in src and ".exists" in src: f.add("exists")
    if "Runtime" in src and "exec" in src: f.add("runtime_exec")
    if "ProcessBuilder" in src: f.add("processbuilder")
    if re.search(r"MessageDigest|\.getInstance\(\"MD5|SHA", src): f.add("digest")
    if re.search(r"Cipher\.getInstance", src): f.add("cipher")
    if "new Random" in src or "Math.random" in src or "nextInt" in src or "nextLong" in src or "nextFloat" in src or "SecureRandom" in src: f.add("random")
    if "LDAP" in src: f.add("ldap")
    if "XPath" in src or "xpath" in src: f.add("xpath")
    if re.search(r"createStatement|prepareStatement|createQuery|executeQuery|executeUpdate", src): f.add("sql")
    if re.search(r"response\.getWriter|println", src): f.add("html_echo")
    if "getParameter" in src: f.add("param")
    if "getHeader(" in src: f.add("header")
    if "getCookies" in src: f.add("cookie")
    if "getHeaderNames" in src: f.add("headername")
    if "getQueryString" in src: f.add("querystring")
    # hash/crypto specifics
    if "passwordFile" in src: f.add("passwordFile")
    if "doPost" in src: f.add("POST")
    if "doGet" in src and "doPost" not in src: f.add("GETonly")
    if "bar" in src and "echo" in src.lower(): pass
    # what is echoed
    if re.search(r"response\.setHeader", src): f.add("set_header")
    if re.search(r"sendRedirect", src): f.add("redirect")
    return f

def main():
    d = json.load(open(EVAL))
    cats = sys.argv[1:] if len(sys.argv) > 1 else list(d["per_category"].keys())
    out = {}
    for cat in cats:
        v = d["per_category"][cat]
        fns = v.get("fn_tests") or []
        hist = collections.Counter()
        samples = collections.defaultdict(list)
        missing = 0
        for t in fns:
            p = os.path.join(SRC, f"{t}.java")
            if not os.path.exists(p):
                missing += 1
                continue
            src = open(p, encoding="utf-8", errors="replace").read()
            fs = features_of(src)
            key = ",".join(sorted(fs)) or "(none)"
            hist[key] += 1
            if len(samples[key]) < 2:
                samples[key].append(t)
        print(f"\n=== {cat}: {len(fns)} FN (missing src: {missing}) ===")
        for k, n in hist.most_common(12):
            print(f"  {n:>4}  {k}   e.g. {samples[k]}")
        out[cat] = dict(hist)
    json.dump(out, open("/home/z/my-project/scripts/owsp/fn_features.json", "w"), indent=1)

if __name__ == "__main__":
    main()
