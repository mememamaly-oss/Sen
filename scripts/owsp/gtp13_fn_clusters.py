#!/usr/bin/env python3
"""GTP-13 diagnostic: cluster Benchmark FN tests by (category, param-location, source-shape).

Reads the definitive GTP-12 eval, the target's own openapi.yaml, and the Java
testcase sources. Output: per-category FN breakdown by param channel + the
distinct sink families, so the fix work targets real families, not guesses.
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path("/home/z/my-project")
SRC = ROOT / "tools/benchmark-src"
EVAL = ROOT / "build-v430/results/owsp/benchmark/eval_v431_gtp12_definitive.json"
JAVA = SRC / "src/main/java/org/owasp/benchmark/testcode"

SINK_PATTERNS = [
    (r"getRuntime\(\)\.exec", "Runtime.exec"),
    (r"ProcessBuilder", "ProcessBuilder"),
    (r"ScriptEngine", "ScriptEngine"),
    (r"FileInputStream", "FileInputStream-read"),
    (r"FileOutputStream", "FileOutputStream-write"),
    (r"Files\.newInputStream|Files\.read", "Files-read"),
    (r"Files\.newOutputStream|Files\.write|Files\.copy", "Files-write"),
    (r"Scanner\(new java\.io\.File", "Scanner-file"),
    (r"createTempFile|deleteOnExit|File\.delete\(\)|\.delete\(", "file-delete"),
    (r"MessageDigest", "MessageDigest"),
    (r"Cipher", "Cipher"),
    (r"Mac\.getInstance", "Mac"),
    (r"SecretKey", "SecretKey"),
    (r"IvParameterSpec", "IV"),
    (r"SecureRandom", "SecureRandom"),
    (r"java\.util\.Random|Math\.random", "weakRandom"),
    (r"HttpSession.*setAttribute|putValue", "session-bind"),
    (r"new javax\.servlet\.http\.Cookie|addCookie", "cookie-set"),
    (r"Cipher\.getInstance\(\"DES", "DES"),
    (r"Cipher\.getInstance\(\"AES", "AES"),
    (r"xpath|XPath", "XPath"),
    (r"SearchControls|ldap.*filter|DirContext|SearchResult", "LDAP"),
    (r"prepareStatement|createStatement|executeQuery", "SQL"),
]

SOURCE_PATTERNS = [
    (r"getCookies", "cookie"),
    (r"getHeader", "header"),
    (r"getParameterMap|getParameter\(", "param"),
    (r"getQueryString", "querystring"),
    (r"getRequestedSessionId", "sessionid"),
]


def param_of_test(name, spec_paths):
    for p, ops in spec_paths.items():
        if not p.endswith("/" + name):
            continue
        for op in ops.values():
            if not isinstance(op, dict):
                continue
            for prm in op.get("parameters", []) or []:
                return prm.get("in"), prm.get("name")
    return None, None


def classify_source(java_text):
    hits = [lbl for rx, lbl in SOURCE_PATTERNS if re.search(rx, java_text)]
    return "+".join(sorted(set(hits))) or "?"


def classify_sinks(java_text):
    hits = [lbl for rx, lbl in SINK_PATTERNS if re.search(rx, java_text)]
    return "+".join(sorted(set(hits))) or "?"


def main():
    ev = json.load(open(EVAL))
    spec = yaml.safe_load((SRC / "data" / "openapi.yaml").read_text())

    print(f"{'cat':<13}{'loc':<7}{'src':<16}{'sink':<42}count  tests")
    rows = []
    for cat, c in sorted(ev["per_category"].items(), key=lambda x: x[1]["recall"]):
        if not c["fn_tests"]:
            continue
        groups = defaultdict(list)
        for t in c["fn_tests"]:
            jp = JAVA / f"{t}.java"
            if not jp.exists():
                groups[("?", "?", "?")].append(t)
                continue
            txt = jp.read_text(errors="replace")
            loc, pname = param_of_test(t, spec["paths"])
            src = classify_source(txt)
            sink = classify_sinks(txt)
            groups[(loc or "?", src, sink)].append(t)
        for (loc, src, sink), tests in sorted(groups.items(), key=lambda x: -len(x[1])):
            rows.append((cat, loc, src, sink, len(tests), tests))
            print(f"{cat:<13}{loc:<7}{src:<16}{sink:<42}{len(tests):<3}    {','.join(tests[:4])}")
    json.dump([{"cat": r[0], "loc": r[1], "src": r[2], "sink": r[3],
                "n": r[4], "tests": r[5]} for r in rows],
              open(ROOT / "build-v430/results/owsp/benchmark/fn_clusters.json", "w"), indent=1)
    print("\nsaved -> build-v430/results/owsp/benchmark/fn_clusters.json")


if __name__ == "__main__":
    main()
