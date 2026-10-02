#!/usr/bin/env python3
"""Recovery test suite runner for SENTINEL v4.1.1 (step 11 of the baseline
freeze). Parameterized clone of the original chunked runner
(scripts/run_tests_chunked_v411.py) — identical chunking (12), identical
strict accounting, identical SENTINEL_TEST_FILTER mechanism — but pointed at
a RECOVERED CLONE instead of the original tree.

Usage:
  python3 run_recovery_suite_v411.py --clone /path/to/clone --out /path/out.json
"""
import argparse
import json
import os
import re
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", required=True, help="path to the recovered clone (contains build-v411/)")
    ap.add_argument("--out", required=True, help="output JSON path")
    a = ap.parse_args()

    TESTS = os.path.join(a.clone, "build-v411", "tests", "run_tests.py")
    assert os.path.isfile(TESTS), f"missing {TESTS}"

    src = open(TESTS).read()
    names = re.findall(r"@case\s*\ndef\s+([a-zA-Z_0-9]+)", src)
    print("total cases:", len(names))
    assert len(names) == 102, f"expected 102 cases in v4.1.1 suite, found {len(names)}"

    CHUNK = 12
    chunks = [names[i:i + CHUNK] for i in range(0, len(names), CHUNK)]
    all_cases, failed = [], 0
    for i, ch in enumerate(chunks):
        env = dict(os.environ, SENTINEL_TEST_FILTER=",".join(ch))
        r = subprocess.run([sys.executable, TESTS], capture_output=True,
                           text=True, timeout=600, env=env, cwd=os.path.dirname(TESTS))
        data = r.stdout + "\n" + r.stderr
        m = re.search(r'\{\s*"suite"', data)
        if not m:
            print(f"CHUNK {i+1}: NO RESULT OUTPUT — runner crashed")
            print(data[-600:])
            sys.exit(2)
        start = m.start()
        depth, end = 0, -1
        for pos in range(start, len(data)):
            if data[pos] == '{':
                depth += 1
            elif data[pos] == '}':
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        j = json.loads(data[start:end])
        ran = [c for c in j["cases"] if not c.get("skipped")]
        skipped_real = [c for c in ch if c not in [c2["name"] for c2 in ran]]
        for c in ran:
            all_cases.append(c)
            if not c.get("ok"):
                failed += 1
                print("FAIL:", c["name"], str(c.get("error", ""))[:200])
        print(f"chunk {i+1}/{len(chunks)}: ran={len(ran)}/{len(ch)} "
              f"failed={j['failed']} skipped_unexpected={skipped_real}")
        if len(ran) != len(ch) or j["failed"] != 0 or skipped_real:
            print("STRICT ACCOUNTING VIOLATION — aborting")
            sys.exit(3)

    summary = {"suite": "v4.1.1-recovery", "total": len(all_cases), "failed": failed,
               "ran": len(all_cases), "expected": len(names),
               "strict_ok": len(all_cases) == len(names) and failed == 0,
               "cases": all_cases}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(summary, open(a.out, "w"), indent=1)
    print(f"\nFINAL: {len(all_cases)}/{len(names)} ran, {failed} failed, "
          f"strict_ok={summary['strict_ok']}")
    print("saved:", a.out)
    sys.exit(0 if summary["strict_ok"] else 1)


if __name__ == "__main__":
    main()
