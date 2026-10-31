#!/usr/bin/env python3
"""RP-3 patch: stamp detector= on the remaining ambiguous Finding sites in
sentinel/detect.py (path_traversal x2, cmdi x2, cmdi_echo x3, trav_hname,
trav_pname). Anchors are unique Evidence-kind strings; each patch finds its
anchor then the NEXT status=FindingStatus.CANDIDATE) close (asserted within
1200 chars = same call). Idempotency guard: skips if the close already
carries detector=.
"""
from pathlib import Path

P = Path("/home/z/my-project/sentinel/detect.py")
src = P.read_text(encoding="utf-8")
CLOSE = "status=FindingStatus.CANDIDATE)"
SITES = [
    ("vs missing ({len(rm.body or '')}B) differ", "traversal"),
    ('Evidence("writability_oracle"', "traversal"),
    ('Evidence("header_name_oracle"', "trav_hname"),
    ('Evidence("param_name_oracle"', "trav_pname"),
    ('Evidence("input_channel"', "cmdi"),
    ('if form == "twin-direct" else', "cmdi"),
    ('Evidence("shell_arithmetic"', "cmdi_echo"),
    ('Evidence("env_arithmetic"', "cmdi_echo"),
    ('Evidence("argv_echo"', "cmdi_echo"),
]
done = 0
for anchor, det in SITES:
    i = src.index(anchor)                     # raises if anchor missing
    j = src.index(CLOSE, i)
    assert j - i < 1200, f"anchor {anchor!r} -> close too far ({j-i})"
    already = src[j:j + 200].startswith(CLOSE[:-1] + ", detector=")
    if already:
        print(f"skip (already patched): {anchor!r}")
        continue
    repl = f'status=FindingStatus.CANDIDATE, detector="{det}")'
    src = src[:j] + repl + src[j + len(CLOSE):]
    done += 1
    print(f"patched {det:10s} <- {anchor!r}")

P.write_text(src, encoding="utf-8")
print(f"total patched: {done}")
import ast
ast.parse(src)
print("SYNTAX OK")
