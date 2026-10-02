#!/usr/bin/env python3
"""SENTINEL full-suite chunked driver (sandbox 590s wall workaround).

The single-process `run_tests.py all` run needs >590s wall (sandbox kills it).
This driver executes the suite as sequential foreground chunks — every case
runs EXACTLY ONCE, in registration order, across chunks; per-chunk verdicts are
saved individually and later merged by merge_suite_chunks.py.

Usage:  run_suite_chunk.py <start_idx> <end_idx> <tag>
        (1-based indices into the registration order of @case defs)

For each chunk it:
  1. reads the ordered @case names from tests/run_tests.py (no import),
  2. runs `python3 tests/run_tests.py all` with SENTINEL_TEST_FILTER set to
     the EXACT chunk member names (others register as skipped — untouched),
  3. extracts the verdict JSON from the log tail,
  4. verifies: executed == expected members, failed == 0, no timeout,
  5. writes results/chunks/<tag>.json and prints a one-line summary.
Exit 0 = chunk green.
"""
import json
import os
import re
import subprocess
import sys
import time

ROOT = "/home/z/my-project/verify-live"
TESTS = os.path.join(ROOT, "tests", "run_tests.py")
CHUNK_DIR = os.path.join(ROOT, "results", "chunks")


def ordered_case_names():
    src = open(TESTS, encoding="utf-8").read()
    names = re.findall(r"^@case\ndef (\w+)", src, re.M)
    if not names:
        raise SystemExit("no @case defs found — parser broken")
    return names


def extract_verdict(log_text):
    decoder = json.JSONDecoder()
    idx = log_text.rfind("{")
    while idx != -1:
        try:
            obj, end = decoder.raw_decode(log_text, idx)
        except ValueError:
            idx = log_text.rfind("{", 0, idx)
            continue
        if isinstance(obj, dict) and "suite" in obj and "cases" in obj \
                and log_text[end:].strip() == "":
            return obj
        idx = log_text.rfind("{", 0, idx)
    return None


def main():
    if len(sys.argv) != 4:
        print("usage: run_suite_chunk.py <start> <end> <tag>", file=sys.stderr)
        return 2
    start, end, tag = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    names = ordered_case_names()
    if not (1 <= start <= end <= len(names)):
        print(f"bad range {start}..{end} (suite has {len(names)})", file=sys.stderr)
        return 2
    members = names[start - 1:end]
    os.makedirs(CHUNK_DIR, exist_ok=True)
    env = dict(os.environ)
    env["SENTINEL_TEST_FILTER"] = ",".join(members)
    log_path = os.path.join(CHUNK_DIR, f"{tag}.log")
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, TESTS, "all"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=570)
    wall = round(time.time() - t0, 1)
    full_log = proc.stdout + "\n--- STDERR ---\n" + proc.stderr
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(full_log)
    # the verdict is print()ed to STDOUT as the runner's final act; fixture
    # [api]/server logs go to STDERR — extraction must use stdout ONLY.
    verdict = extract_verdict(proc.stdout)
    if verdict is None:
        print(f"[{tag}] NO VERDICT (rc={proc.returncode}, wall={wall}s) — see {log_path}",
              file=sys.stderr)
        return 1
    executed = [c for c in verdict["cases"] if not c.get("skipped")]
    exec_names = [c["name"] for c in executed]
    problems = []
    if exec_names != members:
        problems.append(f"executed set mismatch: got {len(exec_names)}")
    if verdict["failed"] != 0:
        for c in executed:
            if not c["ok"]:
                problems.append(f"FAILED {c['name']}: {c.get('error', '')[:160]}")
    out = {
        "tag": tag, "range": [start, end], "members": members,
        "wall_s": wall, "returncode": proc.returncode,
        "failed": verdict["failed"], "executed": len(exec_names),
        "cases": executed, "log": log_path,
    }
    out_path = os.path.join(CHUNK_DIR, f"{tag}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    if problems:
        for p in problems:
            print(f"[{tag}] PROBLEM: {p}", file=sys.stderr)
        print(f"[{tag}] RED: {len(exec_names)} executed, {verdict['failed']} failed, "
              f"{wall}s -> {out_path}")
        return 1
    print(f"[{tag}] GREEN: {len(exec_names)}/{len(members)} executed, 0 failed, "
          f"{wall}s -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
