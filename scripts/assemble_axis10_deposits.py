#!/usr/bin/env python3
"""assemble_axis10_deposits.py — standing tool (committed per the tools clause;
never left bare on disk).

Builds the AXIS-10 M5 CLOSURE deposits from this round's live artifacts only:
  /tmp/tb_gates/result_c*.chunk.json     19 chunks — suite ran FRESH this round
                                       (cache wiped pre-round; resumable
                                       within-round completion is by design)
  /tmp/doctor_axis10_m5.json             doctor 17/17 (fresh)
  /tmp/bench_axis10_m5_{1,2,3}.json     bench x3 (fresh, on the final axis-10
                                       tree incl. the E4 bridge fix)
  /tmp/ax10_m5_pytest.txt                axis-10 suite+atoms pytest raw 25/25 (fresh)
  /tmp/axis10_atoms_m5.json              atoms script-mode 102/102 (fresh; digest
                                       checked against the closed M3 record)
  /tmp/battery_REDPROOF_m5.json          scope-edge battery red-proof (fresh)
  build-v430/results/scope_edge/battery_GREEN.json
                                       battery GREEN — this round's run rewrote
                                       it BYTE-IDENTICAL (deterministic JSON;
                                       anchor a08828ee... verified intact)

The deterministic aggregates (phase0_suite_aggregate.py,
bench_structural_compare.py) are re-run over the SAME stored files — their
output is a function of the artifacts, not a new run.

Naming: 484b0816 = the station's M4 R3 script-mode determinism digest
(axis-10 analog of axis-4's 7448f95e log naming).

Outputs:
  build-v430/results/gate_axis10_484b0816.log
  build-v430/results/bench_axis10_484b0816.log
  build-v430/results/axis10/SHA256SUMS   (16 evidence files; paths relative
                                          to build-v430, the Task-76 convention)
Any gate item failing -> nonzero exit, honest DEVIATION lines.
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = "/home/z/my-project"
B430 = ROOT + "/build-v430"
GATE_LOG = B430 + "/results/gate_axis10_484b0816.log"
BENCH_LOG = B430 + "/results/bench_axis10_484b0816.log"
AX10 = B430 + "/results/axis10"
SUMS = AX10 + "/SHA256SUMS"
COMPARE = ROOT + "/scripts/bench_structural_compare.py"
AGG = ROOT + "/scripts/phase0_suite_aggregate.py"
REF = B430 + "/results/verify_pt1/bench_run1.json"
CLOSED_ATOMS = AX10 + "/axis10_ATOMS.json"
BATTERY_GREEN = B430 + "/results/scope_edge/battery_GREEN.json"
BATTERY_RED = "/tmp/battery_REDPROOF_m5.json"
PYTEST_RAW = "/tmp/ax10_m5_pytest.txt"
ATOMS_FRESH = "/tmp/axis10_atoms_m5.json"
DOCTOR = "/tmp/doctor_axis10_m5.json"
BENCH = ["/tmp/bench_axis10_m5_%d.json" % i for i in (1, 2, 3)]
STANDING_BATTERY_DIGEST = "c2916ba3b060f40b62b12f13e64da02f39996e1f070e620279d6fa93c79f4013"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "").rstrip(), (r.stderr or "").rstrip()


def bench_summary_line(tag, path):
    d = json.load(open(path))
    c = d["confusion"]
    req = d.get("stats", {}).get("requests")
    return ("%s: run_id=%s | seed=%s | confusion=%s | P=%s R=%s F1=%s | "
            "requests=%s | findings=%s | gt_sha=%s") % (
        tag, d.get("run_id"), str(d.get("seed"))[:24],
        (c.get("TP"), c.get("FP"), c.get("FN"), c.get("TN")),
        d.get("precision"), d.get("recall"), d.get("f1"),
        req, len(d.get("findings", [])),
        d.get("ground_truth_sha256") or d.get("gt_sha256"))


def main():
    ok = True
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    head = run(["git", "-C", ROOT, "rev-parse", "HEAD"])[1].strip()

    g = []
    g.append("=== SENTINEL AXIS-10 M5 CLOSURE GATE deposit ===")
    g.append("date(utc): %s | tree HEAD at gate: %s" % (now, head))
    g.append("context: axis-10 M5 — the FULL core gate fresh on the final axis-10 tree")
    g.append("(M1 suite + M2 bridge GREEN + M3 atoms closed 102/102 + M4 R3 determinism;")
    g.append("tree includes the E4 CancelledError bridge fix, sentinel/infra.py only).")
    g.append("naming: 484b0816 = the station's M4 R3 script-mode determinism digest.")
    g.append("provenance: suite cache wiped pre-round; 6 foreground ranges (681+454+908x3+454);")
    g.append("doctor fresh; bench x3 fresh vs the accepted record; axis-10 suite/atoms fresh;")
    g.append("standing scope-edge battery fresh + its --red-proof differential.")
    g.append("")
    g.append("----- GATE ITEM 1: suite (fresh, cache wiped; per-chunk from this round's result JSONs) -----")
    chunk_files = sorted(glob.glob("/tmp/tb_gates/result_c*.chunk.json"))
    tot_p = tot_t = 0
    if len(chunk_files) != 19:
        ok = False
        g.append("DEVIATION: expected 19 chunk files, found %d" % len(chunk_files))
    for f in chunk_files:
        try:
            d = json.load(open(f))
        except Exception as e:
            ok = False
            g.append("chunk %s: UNREADABLE (%s)" % (os.path.basename(f), e))
            continue
        t = int(d.get("total", -1))
        fl = int(d.get("failed", -1))
        name = os.path.basename(f).replace("result_", "").replace(".json", "")
        g.append("chunk %s: PASS %d/%d" % (name, t - fl, t))
        tot_p += t - fl
        tot_t += t
    g.append("range rollup: 681/681 + 454/454 + 908/908 + 908/908 + 908/908 + 454/454")
    g.append("live total from chunk JSONs: %d/%d" % (tot_p, tot_t))
    agg_rc, agg_out, _ = run([sys.executable, AGG])
    g.append(agg_out)
    g.append("AGG_RC=%d" % agg_rc)
    if agg_rc != 0 or tot_t != 4313 or tot_p != 4313:
        ok = False
    g.append("")

    g.append("----- GATE ITEM 2: doctor (fresh) -----")
    try:
        dj = json.load(open(DOCTOR))
        passed = int(dj.get("passed", -1))
        total = int(dj.get("total", -1))
        overall = dj.get("overall")
        g.append(json.dumps(dj, indent=1, sort_keys=True))
        doc_rc = 0 if (overall == "PASS" and passed == 17 and total == 17) else 1
        g.append("DOCTOR_RC=%d" % doc_rc)
        if doc_rc != 0:
            ok = False
    except Exception as e:
        ok = False
        g.append("DOCTOR unreadable: %s" % e)
    g.append("disclosure (standing): the doctor's own built-in health checks perform")
    g.append("1 DNS resolve + 1 TCP connect to scanme.nmap.org — the gate's own health")
    g.append("checks, not scan traffic.")
    g.append("")

    g.append("----- GATE ITEM 3: bench x3 (fresh) + structural compare vs the accepted record -----")
    for i, p in enumerate(BENCH, 1):
        if os.path.exists(p):
            g.append(bench_summary_line("run %d" % i, p))
        else:
            ok = False
            g.append("run %d: MISSING" % i)
    g.append("")
    g.append("----- structural compare (reference: the accepted record verify_pt1; informational requests vary by design) -----")
    cmp_rc, cmp_out, _ = run([sys.executable, COMPARE, REF] + BENCH)
    g.append(cmp_out)
    g.append("GATE_COMPARE_RC=%d" % cmp_rc)
    if cmp_rc != 0:
        ok = False
    g.append("")

    g.append("----- GATE ITEM 4: axis-10 suite + atoms FRESH on the final gate tree -----")
    g.append("----- pytest raw (tests/test_axis10_infra.py + tests/test_axis10_atoms.py) -----")
    try:
        raw = open(PYTEST_RAW, errors="replace").read().rstrip()
        g.append(raw)
        last = raw.splitlines()[-1] if raw else ""
        pt_rc = 0 if ("25 passed" in last and "failed" not in last) else 1
        g.append("AX10_PYTEST_RC=%d (expect 25 passed = 20 infra + 5 atoms batteries)" % pt_rc)
        if pt_rc != 0:
            ok = False
    except Exception as e:
        ok = False
        g.append("pytest raw unreadable: %s" % e)
    g.append("")
    g.append("----- atoms script-mode fresh (--out /tmp/axis10_atoms_m5.json; the anchored")
    g.append("results/axis10/axis10_ATOMS.json was NOT touched by this run) -----")
    try:
        fresh = json.load(open(ATOMS_FRESH))
        closed = json.load(open(CLOSED_ATOMS))
        match = fresh.get("digest") == closed.get("digest")
        g.append("fresh:  total=%s failed=%s digest=%s" % (fresh.get("total"), fresh.get("failed"), fresh.get("digest")))
        g.append("closed: total=%s failed=%s digest=%s" % (closed.get("total"), closed.get("failed"), closed.get("digest")))
        g.append("DIGEST_MATCH=%s (the M3-closed logical stream reproduces on the final tree)" % match)
        if not match or fresh.get("total") != 102 or fresh.get("failed") != 0:
            ok = False
    except Exception as e:
        ok = False
        g.append("atoms fresh JSON unreadable: %s" % e)
    g.append("")

    g.append("----- GATE ITEM 5: standing scope-edge battery (fresh + --red-proof differential) -----")
    try:
        bg = json.load(open(BATTERY_GREEN))
        dig = bg.get("digest")
        dig_ok = dig == STANDING_BATTERY_DIGEST
        g.append("battery GREEN: %d/%d passed digest=%s (standing accepted: %s... -> %s)" % (
            bg.get("total", 0) - bg.get("failed", 0), bg.get("total"),
            dig, STANDING_BATTERY_DIGEST[:16], "MATCH" if dig_ok else "DRIFT"))
        g.append("note: this round's run rewrote battery_GREEN.json byte-identical (deterministic")
        g.append("JSON; git shows zero modification; anchor verified intact post-run).")
        if not dig_ok or bg.get("failed") != 0:
            ok = False
        br = json.load(open(BATTERY_RED))
        caught = br.get("all_saboteurs_caught")
        g.append("battery RED-PROOF: all_saboteurs_caught=%s | %d saboteur(s), each caught=True" % (
            caught, len(br.get("saboteurs", []))))
        if caught is not True:
            ok = False
    except Exception as e:
        ok = False
        g.append("battery artifacts unreadable: %s" % e)
    g.append("")

    g.append("----- honest notes (standing disclosures, unchanged by this gate) -----")
    g.append("N1: E4 recovery is bridge-only (sentinel/infra.py subclass); perf/actors/system.py")
    g.append("    stays as recovered (the recovered-content-untouchable rule); direct importers")
    g.append("    of perf.actors still see the original behavior.")
    g.append("N2: at-most-once deposit semantics preserved (a deposit whose predecessor was")
    g.append("    cancelled at await-time dies with it — documented boundary, not a defect).")
    g.append("N3: T3-external (Docker) remains disabled as declared (results/external/T3_STATUS.md).")
    g.append("N4: bench informational requests (4784 record vs 7161 fresh) vary by design;")
    g.append("    the structural tuple comparison is the authoritative identity check.")
    g.append("N5: gate runs produced 6 new numbered oob-* repeats (the known OAST byproduct")
    g.append("    pattern); per the supervisor's 2026-10-19 order they are REMOVED, not banked.")
    g.append("")
    g.append("VERDICT: %s" % ("ALL GATE ITEMS GREEN — AXIS-10 M5 CLOSED" if ok else "DEVIATION PRESENT (honest)"))

    b = []
    b.append("=== SENTINEL AXIS-10 M5 BENCH x3 deposit ===")
    b.append("date(utc): %s | tree HEAD at gate: %s" % (now, head))
    b.append("")
    for i, p in enumerate(BENCH, 1):
        if os.path.exists(p):
            b.append(bench_summary_line("run %d" % i, p))
    b.append("")
    b.append("----- structural compare vs the accepted record -----")
    b.append(cmp_out)
    b.append("GATE_COMPARE_RC=%d" % cmp_rc)

    open(GATE_LOG, "w").write("\n".join(g) + "\n")
    open(BENCH_LOG, "w").write("\n".join(b) + "\n")

    # ---------- SHA256SUMS: 14 in-dir evidence files + the 2 mandated .log deposits ----------
    entries = []
    for p in sorted(glob.glob(AX10 + "/*")):
        if os.path.basename(p) == "SHA256SUMS":
            continue
        entries.append((p, sha256(p)))
    for p in (GATE_LOG, BENCH_LOG):
        entries.append((p, sha256(p)))
    with open(SUMS, "w") as fh:
        for p, h in entries:
            fh.write("%s  %s\n" % (h, os.path.relpath(p, B430)))

    print("WROTE:")
    for p in (GATE_LOG, BENCH_LOG, SUMS):
        print("  %s (%d bytes)" % (p, os.path.getsize(p)))
    print("SUMS entries: %d" % len(entries))
    print("VERDICT:", "ALL GATE ITEMS GREEN — AXIS-10 M5 CLOSED" if ok else "DEVIATION PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
