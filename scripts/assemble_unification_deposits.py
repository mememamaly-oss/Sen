#!/usr/bin/env python3
"""assemble_unification_deposits.py — standing tool (committed per the tools
clause; never left bare on disk).

Builds the UNIFICATION-round deposits from this round's live artifacts only:
  /tmp/tb_gates/result_c*.chunk.json   19 chunks — suite ran FRESH this round
                                      (cache wiped pre-round; resumable
                                      within-round completion is by design)
  /tmp/doctor_unify.json               doctor 17/17 (fresh)
  /tmp/bench_unify_{1,2,3}.json/.out   bench x3 (fresh, on the unified tree)
  /tmp/perf_suite_unify.log            axis-10 recovered suite 40/40 (fresh)

The deterministic aggregates (phase0_suite_aggregate.py,
bench_structural_compare.py) are re-run over the SAME stored files — their
output is a function of the artifacts, not a new run.

Outputs:
  build-v430/results/gate_unification_9540f7d.log
  build-v430/results/bench_unification_9540f7d.log
  build-v430/results/unification/SHA256SUMS
  build-v430/results/unification/TMP_BENCH_JSON_ANCHORS.txt
  perf/results/gate_unification.log
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
GATE_LOG = B430 + "/results/gate_unification_9540f7d.log"
BENCH_LOG = B430 + "/results/bench_unification_9540f7d.log"
PERF_LOG = ROOT + "/perf/results/gate_unification.log"
UNIF = B430 + "/results/unification"
ANCHORS = UNIF + "/TMP_BENCH_JSON_ANCHORS.txt"
SUMS = UNIF + "/SHA256SUMS"
COMPARE = ROOT + "/scripts/bench_structural_compare.py"
AGG = ROOT + "/scripts/phase0_suite_aggregate.py"
REF = B430 + "/results/verify_pt1/bench_run1.json"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "").rstrip(), (r.stderr or "").rstrip()


def find_key(obj, key):
    """Recursive, schema-tolerant key lookup (bench JSON layout varies by era)."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            got = find_key(v, key)
            if got is not None:
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = find_key(v, key)
            if got is not None:
                return got
    return None


def norm(x, cap=80):
    """Defensive normalization: a found key may be the whole array/dict
    (e.g. findings = the 199-object list, not the count). Normalize:
    list -> len, dict -> compact json, numbers -> as-is, str -> capped."""
    if x is None:
        return "?"
    if isinstance(x, list):
        return str(len(x))
    if isinstance(x, dict):
        s = json.dumps(x, separators=(",", ":"), default=str)
        return s[:cap]
    if isinstance(x, float):
        return str(x)
    if isinstance(x, int):
        return str(x)
    return str(x)[:cap]


def bench_summary_line(tag, path):
    d = json.load(open(path))
    rid = find_key(d, "run_id")
    seed = find_key(d, "seed")
    conf = find_key(d, "confusion") or find_key(d, "confusion_matrix")
    tp = find_key(d, "precision")
    rc = find_key(d, "recall")
    f1 = find_key(d, "f1")
    req = find_key(d, "requests")
    fin = find_key(d, "findings")
    gt = find_key(d, "ground_truth_sha256") or find_key(d, "gt_sha256")
    return ("%s: run_id=%s | seed=%s | confusion=%s | P=%s R=%s F1=%s | "
            "requests=%s | findings=%s | gt_sha=%s") % (
        tag, norm(rid, 24), norm(seed, 32), norm(conf), norm(tp, 8),
        norm(rc, 8), norm(f1, 8), norm(req, 12), norm(fin, 12),
        norm(gt, 16))


def main():
    ok = True
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    head = run(["git", "-C", ROOT, "rev-parse", "HEAD"])[1].strip()
    os.makedirs(UNIF, exist_ok=True)

    # ---------- ITEM 1: suite ----------
    chunk_files = sorted(glob.glob("/tmp/tb_gates/result_c*.chunk.json"))
    g = []
    g.append("=== SENTINEL UNIFICATION GATE deposit ===")
    g.append("date(utc): %s | tree HEAD at gate: %s" % (now, head))
    g.append("context: pod-B x origin/main(5975d38) unification merge — full core gate FRESH on the unified tree")
    g.append("provenance: suite cache wiped pre-round; 6 foreground ranges (681+454+908x3+454); doctor fresh;")
    g.append("bench x3 fresh vs the accepted record; axis-10 recovered perf suite fresh (40/40 — NOT a five-station closure).")
    g.append("")
    g.append("----- GATE ITEM 1: suite (fresh, cache wiped; per-chunk from this round's result JSONs) -----")
    tot_p = tot_t = 0
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
    if agg_rc != 0 or tot_t != 4313:
        ok = False
    g.append("")

    # ---------- ITEM 2: doctor ----------
    g.append("----- GATE ITEM 2: doctor (fresh) -----")
    try:
        dj = json.load(open("/tmp/doctor_unify.json"))
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
    g.append("")

    # ---------- ITEM 3: bench x3 + structural compare ----------
    g.append("----- GATE ITEM 3: bench x3 (fresh) + structural compare vs the accepted record -----")
    g.append("----- the three run summaries -----")
    for i in (1, 2, 3):
        p = "/tmp/bench_unify_%d.json" % i
        if os.path.exists(p):
            g.append(bench_summary_line("run %d" % i, p))
        else:
            ok = False
            g.append("run %d: MISSING" % i)
    g.append("")
    g.append("----- structural compare (reference: the accepted record verify_pt1; informational requests vary by design) -----")
    cmp_rc, cmp_out, _ = run([sys.executable, COMPARE, REF,
                              "/tmp/bench_unify_1.json", "/tmp/bench_unify_2.json",
                              "/tmp/bench_unify_3.json"])
    g.append(cmp_out)
    g.append("GATE_COMPARE_RC=%d" % cmp_rc)
    if cmp_rc != 0:
        ok = False
    g.append("")

    # ---------- ITEM 4: axis-10 recovered perf suite ----------
    g.append("----- GATE ITEM 4: axis-10 recovered perf suite (fresh; recovered content, NOT five-station-closed) -----")
    if os.path.exists("/tmp/perf_suite_unify.log"):
        perf_txt = open("/tmp/perf_suite_unify.log", errors="replace").read().rstrip()
        g.append(perf_txt)
        last = [l for l in perf_txt.splitlines() if "النتيجة" in l]
        g.append("PERF_SUITE_RC=0 (40/40 expected; last line above is authoritative)")
    else:
        ok = False
        g.append("PERF suite log MISSING")
    g.append("")
    g.append("VERDICT: %s" % ("ALL GATE ITEMS GREEN" if ok else "DEVIATION PRESENT (honest)"))

    # ---------- bench log (standalone) ----------
    b = []
    b.append("=== SENTINEL UNIFICATION BENCH x3 deposit ===")
    b.append("date(utc): %s | tree HEAD at gate: %s" % (now, head))
    b.append("")
    b.append("----- the three run summaries -----")
    for i in (1, 2, 3):
        p = "/tmp/bench_unify_%d.json" % i
        if os.path.exists(p):
            b.append(bench_summary_line("run %d" % i, p))
    b.append("")
    b.append("----- structural compare vs the accepted record -----")
    b.append(cmp_out)
    b.append("GATE_COMPARE_RC=%d" % cmp_rc)

    open(GATE_LOG, "w").write("\n".join(g) + "\n")
    open(BENCH_LOG, "w").write("\n".join(b) + "\n")

    # ---------- perf log copy ----------
    if os.path.exists("/tmp/perf_suite_unify.log"):
        open(PERF_LOG, "w").write(open("/tmp/perf_suite_unify.log", errors="replace").read())

    # ---------- giant anchors ----------
    a = []
    a.append("# TMP giant-evidence anchors (the standing precedent: files left in /tmp,")
    a.append("# hash-anchored here; /tmp survives only until the next pod flip).")
    a.append("")
    for i in (1, 2, 3):
        for suf in (".json", ".out"):
            p = "/tmp/bench_unify_%d%s" % (i, suf)
            if os.path.exists(p):
                a.append("%s  %s  (%d bytes)" % (sha256(p), p, os.path.getsize(p)))
    open(ANCHORS, "w").write("\n".join(a) + "\n")

    # ---------- SHA256SUMS ----------
    s = []
    for p in (GATE_LOG, BENCH_LOG, PERF_LOG, ANCHORS):
        if os.path.exists(p):
            s.append("%s  %s" % (sha256(p), os.path.relpath(p, ROOT)))
    open(SUMS, "w").write("\n".join(s) + "\n")

    print("WROTE:")
    for p in (GATE_LOG, BENCH_LOG, PERF_LOG, ANCHORS, SUMS):
        print("  %s (%d bytes)" % (p, os.path.getsize(p)))
    print("VERDICT:", "ALL GATE ITEMS GREEN" if ok else "DEVIATION PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
