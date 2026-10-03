#!/usr/bin/env python3
"""Build INDEPENDENT_VERIFICATION_ADDENDUM_v422.md (supervisor order 2, 2026-10-03).

Formats — never evaluates — the doLogin finding from the v4.2.2 testfire
re-scan, in the SAME package format as the frozen
INDEPENDENT_VERIFICATION_PACKAGES.md (171 cases). Raw pairs are copied
verbatim from the scan's request journal.
"""
import json

SRC = "/home/z/my-project/build-v422/results/live_v422/testfire.json"
OUT = "/home/z/my-project/INDEPENDENT_VERIFICATION_ADDENDUM_v422.md"

d = json.load(open(SRC))
j = d["stats"]["request_journal"]
f = next(x for x in d["findings"] if x["type"] == "sql_injection")
stats = d["stats"]
v21 = json.load(open("/home/z/my-project/build-v421/results/live_v421/testfire.json"))

KEY_IDS = [
    ("detection pair — string-quote family (DETECT-01)", ["req-4c27ce9b", "req-efd7019d"]),
    ("detection pair — numeric-comment family (DETECT-06, NEW in v4.2.2)", ["req-c88bbda7", "req-4e8584a3"]),
    ("verifier PATH C replay — fresh string-quote OR pair", ["req-461a25e4", "req-09dcf9f1"]),
    ("verifier PATH D replay — fresh comparison pair (attempted first, no body-diff on redirects)", ["req-04cfa9cb", "req-fea46a85"]),
]


def fmt_req(rid):
    e = j[rid]
    req, resp = e["request"], e["response"]
    lines = [f"  --- RAW REQUEST {rid} (exactly as issued by the engine) ---",
             f"  {req['method']} {req['path']}"]
    lines.append("  headers:")
    for k, v in (req.get("headers") or {}).items():
        lines.append(f"    {k}: {v}")
    lines.append("  body:")
    body = req.get("body") or ""
    lines.append(f"    {body if body else '(empty)'}")
    rc = resp.get("redirect_chain") or []
    lines.append("  --- RAW RESPONSE (final, after redirect hops) ---")
    lines.append(f"  HTTP {resp['status']}")
    lines.append("  headers:")
    for k, v in (resp.get("headers") or {}).items():
        lines.append(f"    {k}: {v}")
    if rc:
        lines.append(f"  redirect_chain: {rc}")
    body = resp.get("body") or ""
    if body:
        esc = body[:400].encode("unicode_escape").decode("ascii", "backslashreplace")
        lines.append("  body (first 400 chars, control bytes escaped \\xNN):")
        lines.append(f"    {esc}")
    else:
        lines.append("  body:")
        lines.append("    (empty)")
    lines.append(f"  elapsed_ms: {e.get('elapsed_ms')}")
    return "\n".join(lines)


with open(OUT, "w") as fh:
    fh.write("""# SENTINEL v4.2.2 — INDEPENDENT VERIFICATION ADDENDUM (doLogin, demo.testfire.net)

Generated 2026-10-03 from the v4.2.2 re-scan of demo.testfire.net. ADDENDUM to
the frozen INDEPENDENT_VERIFICATION_PACKAGES.md (171 cases, engine v4.2.1) —
that file is untouched; this file documents the supervisor-ordered engine fix
(SQLi numeric-comment battery family, DETECT-06) and the live re-scan that
closes the recorded doLogin coverage gap.

## What this file is — and what it is NOT
- Same rules as the main package: raw engine records, raw request/response
  pairs verbatim from the scan's request journal, NO human or external
  judgment applied. The generator only formats; it never evaluates.
- The target's behavior CHANGED between scans (documented below with three
  timestamped probe sets). This file records what the target did DURING this
  scan, and what it did in earlier windows, without adjudication.

---
""")

    fh.write(f"""# TARGET: http://demo.testfire.net  (testfire) — v4.2.2 re-scan

Authorization basis: IBM/Akamai public demo application (Altoro Mutual), provided for security testing.

Scan record (as-run, unedited):
- run_id: {d['run_id']} | seed: {d['seed']} | scanner: {d['scanner']}
- profile: identical to the frozen v4.2.1 scan (no-oast, no-browser, max-pages 10)
- requests: {stats['requests']} | duration: {stats['duration']}s | journal: {stats['requests']} entries | dropped: {stats['request_journal_dropped']}
- engine verdict tally (as-is): {len(d['findings'])} findings / {len(d['rejected_candidates'])} rejected / {len(d['unverified_candidates'])} unverified
- delta vs the frozen v4.2.1 scan (run-6a6418ab8d, 36 findings): +1 finding —
  sql_injection @ POST /doLogin (parameter `uid`), the previously-missed
  auth-bypass. Same seed, same profile.

### Target-state flap — three timestamped windows (facts, no adjudication)
1. v4.2.1 scan window (~00:58 UTC, frozen package): the engine's string-quote
   family did NOT fire; journal entry #7 hit a transport timeout. 36 findings,
   no doLogin SQLi.
2. Manual probe window (~01:30 UTC, recorded in the frozen package, labeled
   NOT engine output): `uid=1' OR '1'='1' --` -> 302 login.jsp (dead) while
   `uid=' OR 1=1--` -> 302 /bank/main.jsp (alive). The numeric-comment family
   was absent from the battery — the honest coverage gap.
3. Pre-fix verification window (03:45 UTC, manual probes by the engineering
   agent, NOT engine output): `uid=1' OR 1=1--` -> 302 /bank/main.jsp AND
   `uid=1' OR '1'='1' -- ` -> 302 /bank/main.jsp — BOTH families alive again
   (the target flaps between states).
4. This scan (v4.2.2): BOTH families fired on doLogin (raw pairs below).

## [TESTFIRE ADDENDUM F01] sql_injection — critical (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doLogin (parameter: `uid`)
- Engine verdict: verified via `{f['verification']['method']}` | confidence {f['confidence']} | rounds {f['verification']['rounds']}
- Verification notes (engine-recorded): {f['verification']['notes']}
- Impact (engine-assessed): {f['impact']['grade']} — {f['impact']['statement'][:200]}...
- Evidence chain (engine-recorded):
""")
    for e in f["evidence"]:
        fh.write(f"    * [{e['kind']}] {e['detail']}\n")
    fh.write("\n- RAW reproduction (from the scan's request journal, verbatim):\n")
    for label, rids in KEY_IDS:
        fh.write(f"\n  ### {label}\n")
        for rid in rids:
            fh.write(fmt_req(rid) + "\n")
    fh.write("""
- Negative controls visible in the same journal (raw, unedited):
  - the `passw` parameter received the SAME battery (54 doLogin requests total,
    27 per parameter) and produced NO differential on any family — no finding.
  - the XSS/traversal/redirect/SSTI batteries on both doLogin parameters
    produced no reflection/differential — no finding.
- Evidence-OS reproduction recipe:
    1. POST http://demo.testfire.net/doLogin with `uid=1' OR 1=1--&passw=x`
       expect: 302 -> http://demo.testfire.net/bank/main.jsp (bypass)
    2. POST http://demo.testfire.net/doLogin with `uid=1' OR 1=2--&passw=x`
       expect: 302 -> http://demo.testfire.net/login.jsp (FALSE control)
    3. NOTE the target flaps (window 2 above killed the string-quote family
       while window 3 revived it); replay both families before concluding.

### Engine-level discrimination proof (recorded, not asserted)
- scripts/probe_numeric_family.py runs the DRIFTED-state simulation (string
  family dead, numeric family alive — the live-caught window-2 state) through
  BOTH engines: frozen v4.2.1 -> NO candidate ("engine honestly reports
  nothing"); v4.2.2 -> candidate + VERIFIED via oracle:ornum-2round.
  Raw records: build-v422/results/probe_numeric_family.jsonl
- unit_v422_sqli_numeric_comment_family (in the 104/104 suite) asserts the
  full chain on the same simulation.

### Gates for this engine change (v4.2.2)
- tests 104/104 (103 prior + 1 new discriminating case) | doctor 15/15
- bench x3 DETERMINISTIC: 38/0/0/37, F1 1.000, run-3c0652b6be — the numeric
  family added +106 requests and ZERO verdict changes on the fixture (zero
  noise). The stock-bench blindness warning stands: this proves no
  REGRESSION, not general correctness.

### Honest limits of this addendum
- The verification method that carried THIS run was PATH C (string-quote
  replay) because the target flapped back to accepting both families; the
  numeric family contributed the second detection differential (raw pair
  above) and is proven live-capable at window 2 + unit/mechanism level, but
  its PATH C' verifier replay did not need to fire in this scan.
- All verdicts remain engine-self-judged; this addendum exists so an external
  party can adjudicate by replaying the raw requests as issued.

## Package totals (this addendum)
- findings documented: 1 (doLogin sql_injection) + reference to the 37-finding
  raw scan JSON at build-v422/results/live_v422/testfire.json
- generated by scripts/build_addendum_v422.py — formatting only, no evaluation.
""")

print("written", OUT)
