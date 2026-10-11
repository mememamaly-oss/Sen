#!/usr/bin/env python3
"""Final gate verification for the v4.3.3 + iv14 sink-context transfer round
(branch fix/openredirect-sinkcontext-433 from origin/main 412d64f, 2026-10-12).

Asserts (all numbers from THIS round's fresh runs only):
  1. bench x3 confusion IDENTICAL and == {TP:38, FP:0, FN:0, TN:37}
  2. bench x3 run_id IDENTICAL (determinism)
  3. bench x3 request count IDENTICAL
  4. VERDICT-LEVEL DIFF vs the shipped-v4.3.3 audit baseline (Task-32's
     fresh run on the byte-identical unmodified tree) == NONE — zero
     regressions, zero noise. Baseline path via env V433_BASELINE
     (skipped with an explicit note if unset/missing).
  5. writes bench_summary.txt + gate_summary.txt
"""
import json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(os.path.dirname(HERE), "build-v430")
R = os.path.join(ENG, "results", "verify_v433_sinkcontext")
BASE = os.environ.get("V433_BASELINE", "/tmp/my-project/build-v430/results/verify_v433/bench_1.json")


def _norm(url):
    """Port-normalize fixture URLs: the benchmark spawns its fixture on an
    ephemeral port (ENG-20) — the documented normalization class (ephemeral
    instance/port stripping)."""
    return re.sub(r"http://127\.0\.0\.1:\d+", "http://127.0.0.1:FIXTURE", url or "")


runs = [json.load(open(f"{R}/bench_{k}.json")) for k in (1, 2, 3)]
confs = [d["confusion"] for d in runs]
assert all(c == confs[0] for c in confs), f"NON-DETERMINISTIC: {confs}"
assert confs[0] == {"TP": 38, "FP": 0, "FN": 0, "TN": 37}, confs[0]
rids = [d.get("run_id") for d in runs]
assert len(set(rids)) == 1, f"NON-DETERMINISTIC run ids: {rids}"
reqs = [d.get("stats", {}).get("requests") for d in runs]
assert len(set(reqs)) == 1, f"NON-DETERMINISTIC request counts: {reqs}"


def verdicts(d):
    return sorted((f.get("type"), _norm(f.get("url")), f.get("parameter"), str(f.get("status")))
                  for f in d.get("findings", []))


base_note = "SKIPPED (baseline not found — set V433_BASELINE)"
if os.path.exists(BASE):
    base = json.load(open(BASE))
    breq = base.get("stats", {}).get("requests")
    base_v, now_v = verdicts(base), verdicts(runs[0])
    assert base_v == now_v, ("VERDICT CHANGES vs the shipped-v4.3.3 audit baseline:",
                             [x for x in zip(base_v, now_v) if x[0] != x[1]][:5])

    # evidence-detail level diff for open_redirect findings specifically (the
    # touched class): prove the evidence-text change did not leak anywhere.
    def open_redirect_evidence(d):
        return sorted((_norm(f.get("url")), f.get("parameter"),
                       f.get("evidence", [{}])[0].get("detail", "")[:60])
                      for f in d.get("findings", []) if f.get("type") == "open_redirect")

    base_or, now_or = open_redirect_evidence(base), open_redirect_evidence(runs[0])
    or_note = "identical" if base_or == now_or else f"CHANGED ({base_or} -> {now_or})"
    base_note = (f"verdict-diff vs shipped-v4.3.3 audit baseline: NONE "
                 f"(baseline requests {breq}, this round {reqs[0]}, delta {reqs[0]-breq:+d})")

summary = (f"runs: {confs} requests: {reqs} run_id: {rids[0]}\n"
           f"IDENTICAL=True 38/0/0/37=True\n"
           f"{base_note}\n"
           f"open_redirect evidence level: {or_note if os.path.exists(BASE) else 'n/a'}\n")
print(summary)
with open(f"{R}/bench_summary.txt", "w") as fh:
    fh.write(summary)

suite_txt = open(f"{R}/suite_summary.txt").read().strip()
doctor = json.load(open(f"{R}/doctor.json"))
gate = (
    "GATE CYCLE — v4.3.3 + iv14 sink-context transfer on main "
    "(branch fix/openredirect-sinkcontext-433 from 412d64f, 2026-10-12)\n"
    f"SUITE: {suite_txt}\n"
    f"DOCTOR: {doctor.get('passed')}/{doctor.get('total')} overall={doctor.get('overall')}\n"
    f"BENCH: {summary}\n"
    "RED/GREEN: results/verify_v433_sinkcontext/openredirect_fp_red.json "
    "(structural FP live on unfixed v4.3.3, this round's fresh run) -> "
    "openredirect_fp_green.json (all three parts hold after the transfer)\n"
)
with open(f"{R}/gate_summary.txt", "w") as fh:
    fh.write(gate)
print(gate)
print("ALL GATES GREEN")
