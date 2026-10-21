#!/usr/bin/env python3
"""RT-06 ReDoS differential proof (standing tool).

RED  (banked, Step 1, same tree pre-fix): _HOSTNAME_RE.findall('A'*50000+'!')
      -> REDOS_CONFIRMED (>5s SIGALRM) — quadratic backtracking.
GREEN (fixed tree): the supervisor's exact script — same payload, must be
      OK < 0.1s. Plus: semantic-equivalence differential (the OLD raw pattern
      vs the NEW bounded wrapper on realistic bodies must extract IDENTICAL
      hostname sets) and a hostile mixed-case battery.
"""
import re
import signal
import sys
import time

REPO = "/home/z/my-project/build-v430"
sys.path.insert(0, REPO)

from sentinel.impact import _HOSTNAME_RE  # noqa: E402

# --- GREEN part 1: supervisor's exact script -------------------------------
def h(s, f):
    raise TimeoutError()


signal.signal(signal.SIGALRM, h)
signal.alarm(2)
try:
    payload = 'A' * 50000 + '!'
    t = time.time()
    _HOSTNAME_RE.findall(payload[:65536])
    print(f"GREEN supervisor-script: OK {time.time()-t:.3f}s")
except TimeoutError:
    print("GREEN supervisor-script: STILL_REDOS")
finally:
    signal.alarm(0)

# --- GREEN part 2: larger hostile battery (all must be fast) ----------------
hostile = {
    "dots_only_60k": "." * 60000,
    "A_run_60k_dots_tail": "A" * 59000 + ".a.a",
    "A_run_60k_dots_head": "a.a." + "A" * 59000,
    "alternating_60k": ".A" * 30000,
    "trailing_bang_50k": "A" * 50000 + "!",
    "over_cap_200k": ("A" * 50000 + ".b.b ") * 4,
}
for name, s in hostile.items():
    t = time.time()
    _HOSTNAME_RE.findall(s)
    el = time.time() - t
    print(f"hostile[{name}]: {el:.3f}s {'OK' if el < 0.5 else 'TOO_SLOW'}")

# --- Semantic equivalence: OLD raw pattern vs NEW wrapper -------------------
OLD = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2,}", re.IGNORECASE)
realistic = (
    "control body: fetched from cdn.example-cdn.com at 2026-10-21, "
    "see also api.vulnweb.local and sub.domain.testfire.net/path?x=1 "
    "noise: 12345 67890 hello-world single.dot.tailed "
    "UPPER.CASE.HOST also matches; version 1.2.3 not-a-host "
    "evil.attacker-domain.io exfil target oast1.collab.example.org "
    "trailing token ends without newline"
)
old_set = set(OLD.findall(realistic))
new_set = set(_HOSTNAME_RE.findall(realistic))
print(f"equivalence: old={sorted(old_set)}")
print(f"equivalence: new={sorted(new_set)}")
print(f"EQUIVALENT: {'YES' if old_set == new_set else 'NO — DIFF: ' + str(old_set ^ new_set)}")

# long-token boundary honesty check: hostname at the tail of a long dot-run
longtail = "A" * 400 + ".example.com"
print(f"long-tail token extraction: {_HOSTNAME_RE.findall(longtail)}")
