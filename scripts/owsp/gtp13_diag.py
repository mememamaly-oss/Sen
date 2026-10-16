#!/usr/bin/env python3
"""GTP-13 diagnostic: per-FN-test detector-activity analysis from a FULL journal.

For every FN test in the scanned chunk: which battery families sent probes to
it, how many, and what the responses looked like (status / marker presence).
Output: a compact per-category root-cause table.
"""
import json
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import unquote

SCAN = sys.argv[1] if len(sys.argv) > 1 else \
    "/home/z/my-project/tools/benchmark-src/target/campaign/gtp13_fn_00_full.json"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v431_gtp12_definitive.json"
EXPECTED = "/home/z/my-project/tools/benchmark-src/expectedresults-1.2.csv"

# Battery fingerprints (substring -> family label)
FPRINTS = [
    ("sentineltb1marker", "trustbound"), ("sentineltb2marker", "trustbound"),
    ("sentinelxssmarker", "xss"),
    ("etc/passwd", "traversal"), ("windows/win.ini", "traversal"),
    ("sentinel-redirect-check", "redirect"),
    ("sentinelcrlf", "crlf"),
    ("XXE", None), ("sentinelxxe", "xxe"), ("SYSTEM", None), ("<!DOCTYPE", None),
    ("sentinel-attr-", "ssrf"), ("oast", "ssrf"),
    ("sentinelcmd", "cmdi"), ("/bin/", "cmdi"), ("ping -c", "cmdi"), ("echo sentinel", "cmdi"),
    ("sentinelcookie", "securecookie"),
    ("(", "xpath"), ("'", "sqli"), (" AND 1", "sqli"), (" OR ", "sqli"),
    ("sentinelbase", "sqli"),
]

CATEGORY_BY_PREFIX = {
    "pathtraver": "pathtraver", "trustbound": "trustbound", "crypto": "crypto",
    "securecookie": "securecookie", "cmdi": "cmdi", "sqli": "sqli",
    "weakrand": "weakrand", "ldapi": "ldapi", "xss": "xss", "hash": "hash",
    "xpathi": "xpathi",
}


def main():
    d = json.load(open(SCAN))
    jr = d["stats"]["request_journal"]
    ev = json.load(open(EVAL))
    fn_all = set()
    for c in ev["per_category"].values():
        fn_all.update(c["fn_tests"])

    # group journal entries per test
    per_test = defaultdict(list)
    for rid, e in jr.items():
        url = e["request"].get("url") or ""
        m = re.search(r"(BenchmarkTest\d{5})", url)
        if not m:
            continue
        per_test[m.group(1)].append(e)

    verified_tests = set()
    PASSIVE_TYPES = {"missing_security_headers", "server_banner_disclosure",
                     "tech_banner_disclosure", "tech_banner", "server_banner",
                     "vulnerable_js_dependency"}
    for f in d["findings"]:
        if f.get("type") in PASSIVE_TYPES:
            continue
        m = re.search(r"(BenchmarkTest\d{5})", f.get("url") or "")
        if m and f.get("status") == "verified":
            verified_tests.add(m.group(1))

    # what got verified in this chunk
    scanned_fns = [t for t in per_test if t in fn_all]
    print(f"journal: {len(jr)} | FN tests touched: {len(scanned_fns)} | "
          f"FN tests with VERIFIED finding: {len(verified_tests & fn_all)}")

    # per-category: FN tests with zero battery activity
    no_probes = defaultdict(list)
    low_probe = defaultdict(list)
    ok = defaultdict(list)
    for t in scanned_fns:
        cat = next((c for c, v in ev["per_category"].items() if t in v["fn_tests"]), "?")
        entries = per_test[t]
        # battery probes = non-baseline requests (baseline = passive-baseline note or plain GET/POST with no payload)
        probes = [e for e in entries
                  if "passive-baseline" not in (e["request"].get("note") or "")]
        if t in verified_tests:
            ok[cat].append(t)
        elif len(probes) <= 1:
            no_probes[cat].append((t, len(entries), len(probes)))
        else:
            low_probe[cat].append((t, len(entries), len(probes)))

    print("\n=== FN tests RECOVERED in this scan (now verified) ===")
    for cat, ts in sorted(ok.items()):
        print(f"  {cat}: {len(ts)}  {','.join(sorted(ts)[:6])}")
    print("\n=== FN tests with ~ZERO battery probes (missed BEFORE detection) ===")
    for cat, ts in sorted(no_probes.items()):
        print(f"  {cat}: {len(ts)}")
        for t, tot, pr in ts[:8]:
            print(f"     {t}: total_reqs={tot} probes={pr}")
    print("\n=== FN tests probed but NOT verified (detection/verification miss) ===")
    for cat, ts in sorted(low_probe.items()):
        print(f"  {cat}: {len(ts)}")
        for t, tot, pr in ts[:6]:
            print(f"     {t}: total_reqs={tot} probes={pr}")

    json.dump({"recovered": {k: v for k, v in ok.items()},
               "no_probes": {k: [t for t, _, _ in v] for k, v in no_probes.items()},
               "probed_not_verified": {k: [t for t, _, _ in v] for k, v in low_probe.items()}},
              open("/home/z/my-project/build-v430/results/owsp/benchmark/gtp13_diag_chunk0.json", "w"),
              indent=1)


if __name__ == "__main__":
    main()
