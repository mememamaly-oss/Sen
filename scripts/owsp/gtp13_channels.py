#!/usr/bin/env python3
"""GTP-13: full FN channel×category matrix from Java sources.

Classifies every FN test's INPUT channel (resolver / querystring / self-named /
header / cookie / regular param / multipart) and cross-tabs with category, so
the fix list is complete and prioritized by real family size.
"""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path("/home/z/my-project")
JAVA = ROOT / "tools/benchmark-src/src/main/java/org/owasp/benchmark/testcode"
EVAL = ROOT / "build-v430/results/owsp/benchmark/eval_v431_gtp12_definitive.json"


def channel(txt: str, name: str) -> str:
    resolver = "getParameterNames" in txt and f'value.equals("{name}")' in txt.replace('"BenchmarkTest', '"BenchmarkTest')
    qs = "getQueryString" in txt
    selfnamed = f'getParameter("{name}")' in txt
    header = "getHeader" in txt
    cookie = "getCookies" in txt
    parts = []
    if resolver:
        parts.append("resolver")
    if qs:
        parts.append("querystring")
    if selfnamed:
        parts.append("selfname")
    if header:
        parts.append("header")
    if cookie:
        parts.append("cookie")
    if not parts:
        parts.append("param")
    return "+".join(parts)


def main():
    ev = json.load(open(EVAL))
    matrix = {}
    for cat, c in ev["per_category"].items():
        cnt = Counter()
        for t in c["fn_tests"]:
            jp = JAVA / f"{t}.java"
            if not jp.exists():
                cnt["<no-source>"] += 1
                continue
            cnt[channel(jp.read_text(errors="replace"), t)] += 1
        matrix[cat] = dict(cnt.most_common())
        print(f"{cat:<14} (fn={c['fn']})  {dict(cnt.most_common())}")
    json.dump(matrix, open(ROOT / "build-v430/results/owsp/benchmark/fn_channel_matrix.json", "w"), indent=1)
    print("\nsaved -> fn_channel_matrix.json")


if __name__ == "__main__":
    main()
