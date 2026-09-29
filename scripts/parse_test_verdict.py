#!/usr/bin/env python3
"""Extract the final JSON verdict block from a SENTINEL test-runner log.

The runner prints interleaved output during execution and the verdict as the
LAST JSON object (dict with a "suite" key). This script scans candidate '{'
positions from the end, decodes, and accepts the first dict that (a) has a
"suite" key, (b) contains "cases", and (c) decodes cleanly to (near) EOF.

Usage: parse_test_verdict.py <logfile> <out.json>
Exit 0 on success (writes extracted verdict), exit 2 if no verdict found.
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: parse_test_verdict.py <logfile> <out.json>", file=sys.stderr)
        return 2
    log_path, out_path = sys.argv[1], sys.argv[2]
    with open(log_path, "r", errors="replace") as fh:
        text = fh.read()
    # candidate start positions of '{' from the end of file
    positions = []
    idx = text.rfind("{")
    while idx != -1:
        positions.append(idx)
        idx = text.rfind("{", 0, idx)
    decoder = json.JSONDecoder()
    for pos in positions:
        try:
            obj, end = decoder.raw_decode(text, pos)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        if "suite" not in obj or "cases" not in obj:
            continue
        # verdict must extend to (near) EOF — allow trailing whitespace/newline
        if text[end:].strip() != "":
            continue
        with open(out_path, "w") as fh:
            json.dump(obj, fh, indent=1)
        total = obj.get("total")
        failed = obj.get("failed")
        print(f"verdict extracted: suite={obj.get('suite')} total={total} "
              f"failed={failed} -> {out_path}")
        for c in obj["cases"]:
            if not c.get("ok"):
                print(f"  FAILED: {c['name']}: {c.get('error', '')[:200]}")
        skipped = [c["name"] for c in obj["cases"] if c.get("skipped")]
        if skipped:
            print(f"  skipped({len(skipped)}): {', '.join(skipped)}")
        return 0
    print(f"no verdict JSON found in {log_path}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
