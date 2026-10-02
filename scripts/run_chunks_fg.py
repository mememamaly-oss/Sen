#!/usr/bin/env python3
"""Run selected chunks of the v4.1.1 suite in FOREGROUND (the sandbox reaps
background processes between tool calls). Appends per-chunk results to a
JSONL ledger; the merge step (merge_v411_jsonl.py) enforces STRICT accounting
over the whole ledger: every case ran exactly once, failed=0.

Usage: run_chunks_fg.py <chunk_start> <chunk_end>   (1-based, inclusive)
"""
import json, os, re, subprocess, sys

TESTS = "/home/z/my-project/build-v411/tests/run_tests.py"
LEDGER = "/home/z/my-project/gap-validation/results/tests_v411_chunks.jsonl"

start, end = int(sys.argv[1]), int(sys.argv[2])
src = open(TESTS).read()
names = re.findall(r"@case\s*\ndef\s+([a-zA-Z_0-9]+)", src)
CHUNK = 12
chunks = [names[i:i + CHUNK] for i in range(0, len(names), CHUNK)]
print(f"total cases: {len(names)}  chunks: {len(chunks)}  "
      f"running {start}..{end}")

for i in range(start - 1, min(end, len(chunks))):
    ch = chunks[i]
    env = dict(os.environ, SENTINEL_TEST_FILTER=",".join(ch))
    r = subprocess.run([sys.executable, TESTS], capture_output=True,
                       text=True, timeout=560, env=env,
                       cwd=os.path.dirname(TESTS))
    data = r.stdout + "\n" + r.stderr
    m = re.search(r'\{\s*"suite"', data)
    if not m:
        print(f"CHUNK {i+1}: NO RESULT OUTPUT — runner crashed")
        print(data[-800:])
        sys.exit(2)
    s = m.start()
    depth, epos = 0, -1
    for pos in range(s, len(data)):
        if data[pos] == '{':
            depth += 1
        elif data[pos] == '}':
            depth -= 1
            if depth == 0:
                epos = pos + 1
                break
    j = json.loads(data[s:epos])
    ran = [c for c in j["cases"] if not c.get("skipped")]
    missing = [c for c in ch if c not in [x["name"] for x in ran]]
    rec = {"chunk": i + 1, "ran": len(ran), "expected": len(ch),
           "failed": j["failed"], "missing": missing,
           "ok": j["failed"] == 0 and len(ran) == len(ch) and not missing,
           "cases": ran}
    with open(LEDGER, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"chunk {i+1}/{len(chunks)}: ran={len(ran)}/{len(ch)} "
          f"failed={j['failed']} missing={missing} "
          f"{'OK' if rec['ok'] else 'VIOLATION'}")
    if not rec["ok"]:
        for c in ran:
            if not c.get("ok"):
                print("  FAIL:", c["name"], str(c.get("error", ""))[:200])
print("done.")
