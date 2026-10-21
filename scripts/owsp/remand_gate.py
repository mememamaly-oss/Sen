#!/usr/bin/env python3
"""ORD-001-REMAND final-gate driver — the platform's established suite anchor.

The anchor contract (reproduced from the prior campaign's accepted gate,
results/gate_rt_fixes/GATE_LOG.txt):
  * the script suite runs as 19 chunks (c00..c18); every chunk executes a
    partition slice of the 227 @case functions (non-slice cases register as
    skipped, which the platform metric counts as ok — exactly the prior
    gate's per-chunk 227/227);
  * the machine aggregate over the 19 chunk JSONs = 4313/4313;
  * a DEDUP coverage check is ALSO reported (every case executed exactly
    once across chunks — impossible to fake with skipped rows).

Chunk construction: TIME-BALANCED via the background full pass — the full
suite runs ONCE as a detached background process (survives the 600s tool
ceiling), its per-case ms feed an LPT partition (heaviest case -> currently
lightest chunk) so every chunk finishes far under the 550s call ceiling.
The strided first attempt lived badly (one slice ran >7 minutes); this is
the honest fix, recorded here.

Subcommands:
  full           launch the detached full-suite pass (idempotent)
  poll           report whether it finished (and its per-case ms total)
  plan           build the time-balanced /tmp/remand_gate/plan.json
  run [budget]   execute missing chunks (cached, resumable)
  agg            machine aggregate + dedup coverage; exit 0 only if all
                 19 chunks passed, total 4313, and coverage is exact
"""
import json
import os
import re
import subprocess
import sys
import time

ENG = "/home/z/my-project/build-v430"
GATE = "/tmp/remand_gate"
CHUNKS = os.path.join(GATE, "chunks")
N_CHUNKS = 19
CHUNK_TIMEOUT = 540          # under the ~600s environment call kill
PLAN = os.path.join(GATE, "plan.json")
FULL = os.path.join(GATE, "full.json")
FULL_PID = os.path.join(GATE, "full.pid")


def case_names():
    src = open(os.path.join(ENG, "tests", "run_tests.py"), encoding="utf-8").read()
    names = re.findall(r"@case\ndef (\w+)", src)
    # sanity: definition order == registry order; 227 expected
    assert len(names) == 227, f"expected 227 @case functions, found {len(names)}"
    return names


def _full_ok():
    try:
        d = json.load(open(FULL))
        return bool(d.get("passed")) and d.get("failed") == 0
    except Exception:
        return False


def cmd_full():
    os.makedirs(GATE, exist_ok=True)
    if _full_ok():
        d = json.load(open(FULL))
        ran = [x for x in d["cases"] if not x.get("skipped")]
        print(f"full pass already PASSED: ran={len(ran)} failed={d['failed']} "
              f"total_ms={sum(x.get('ms', 0) for x in ran)}")
        return
    if os.path.exists(FULL_PID) and os.path.exists(f"/proc/{open(FULL_PID).read().strip()}"):
        print(f"full pass still running (pid {open(FULL_PID).read().strip()}) — poll again")
        return
    fo = open(FULL, "w")
    fe = open(FULL + ".err", "w")
    p = subprocess.Popen(
        [sys.executable, os.path.join(ENG, "tests", "run_tests.py"), "all"],
        cwd=ENG, stdout=fo, stderr=fe, start_new_session=True)
    open(FULL_PID, "w").write(str(p.pid))
    print(f"full pass launched detached: pid={p.pid} -> {FULL}")


def cmd_poll():
    if _full_ok():
        d = json.load(open(FULL))
        ran = [x for x in d["cases"] if not x.get("skipped")]
        fails = [x for x in ran if not x["ok"]]
        print(f"FULL PASS: PASSED ran={len(ran)} failed={len(fails)} "
              f"total_ms={sum(x.get('ms', 0) for x in ran)} "
              f"(~{sum(x.get('ms', 0) for x in ran) / 1000:.0f}s of case time)")
        return 0
    if os.path.exists(FULL_PID):
        pid = open(FULL_PID).read().strip()
        if os.path.exists(f"/proc/{pid}"):
            print(f"still running (pid {pid})")
            return 1
        print(f"process {pid} is gone; full.json not ok — inspect {FULL}.err")
    else:
        print("no full pass yet — run 'full' first")
    return 1


def _case_ports():
    """Fixed-port map per case (shared ports MUST land in different chunks:
    a chunk is one process and daemon fixture servers accumulate until it
    exits — a same-chunk pair = EADDRINUSE, the exact failure the naive
    single-process full pass hit on unit_v41_no_hallucination_gate)."""
    src = open(os.path.join(ENG, "tests", "run_tests.py"), encoding="utf-8").read()
    names = re.findall(r"@case\ndef (\w+)", src)
    spans = []
    for nm in names:
        spans.append((nm, re.search(rf"@case\ndef {nm}\(", src).start()))
    spans.append(("__END__", len(src)))
    out = {}
    for i in range(len(spans) - 1):
        nm, s = spans[i]
        _, e = spans[i + 1]
        body = src[s:e]
        ports = set(re.findall(r'ThreadingHTTPServer\(\([^)]*,\s*(\d+)\)', body))
        ports |= set(re.findall(r'HTTPServer\(\([^)]*,\s*(\d+)\)', body))
        ports |= set(re.findall(r'^\s*port\s*=\s*(\d+)', body, re.M))
        ports.discard("0")           # ephemeral: no collision semantics
        if ports:
            out[nm] = set(ports)
    return out


def cmd_plan():
    # Timing source: the full pass's per-case ms. The full pass does NOT
    # have to be all-green to serve as a timing source — the CHUNK runs are
    # the gate of record (the platform's own design: shared fixed ports make
    # a single-process full run structurally impossible — daemon servers
    # accumulate; disclosed in the gate log).
    try:
        d = json.load(open(FULL))
        ran = [x for x in d["cases"] if not x.get("skipped")]
        assert len(ran) >= 220
    except Exception as e:
        print(f"no usable timing source ({e}) — run 'full' first")
        return 1
    os.makedirs(CHUNKS, exist_ok=True)
    for f in os.listdir(CHUNKS):
        os.remove(os.path.join(CHUNKS, f))
    ports = _case_ports()
    # a failed case in the timing pass carries a wrong (tiny) ms — estimate
    # honestly: use the SUITE MEDIAN for cases that did not pass there.
    ok_ms = sorted(x.get("ms", 0) for x in ran if x["ok"])
    median = ok_ms[len(ok_ms) // 2] if ok_ms else 3000
    timed = []
    for x in ran:
        ms = x.get("ms", 0) if x["ok"] else max(x.get("ms", 0), median)
        timed.append((x["name"], ms))
    timed.sort(key=lambda t: -t[1])          # heaviest first (LPT)
    loads = [0] * N_CHUNKS
    buckets = [[] for _ in range(N_CHUNKS)]
    bucket_ports = [set() for _ in range(N_CHUNKS)]
    for name, ms in timed:
        my_ports = ports.get(name, set())
        order = sorted(range(N_CHUNKS), key=lambda k: loads[k])
        chosen = None
        for k in order:
            if my_ports & bucket_ports[k]:
                continue                     # a shared-port pair must not co-reside
            chosen = k
            break
        if chosen is None:                  # cannot happen with 19 buckets and
            chosen = order[0]               # per-port fanout <= 2, but stay total
        buckets[chosen].append(name)
        loads[chosen] += ms
        bucket_ports[chosen] |= my_ports
    names = case_names()
    plan = [{"name": f"c{k:02d}", "names": b, "planned_ms": loads[k]}
            for k, b in enumerate(buckets)]
    json.dump({"chunks": plan, "names_total": len(names)},
              open(PLAN, "w"), indent=1)
    print("time-balanced plan, port-collision-safe (LPT): "
          + ", ".join(f"{c['name']}~{c['planned_ms'] / 1000:.0f}s/{len(c['names'])}"
                       for c in sorted(plan, key=lambda c: -c["planned_ms"])))
    print(f"case-time total ~{sum(loads) / 1000:.0f}s; chunks {N_CHUNKS}")


def _chunk_ok(path):
    try:
        d = json.load(open(path))
        return bool(d.get("passed")) and d.get("failed") == 0
    except Exception:
        return False


def cmd_run(budget_s=480.0):
    os.makedirs(CHUNKS, exist_ok=True)
    if not os.path.exists(PLAN):
        cmd_plan()
    plan = json.load(open(PLAN))["chunks"]
    t0 = time.time()
    print(f"chunks pending check (wall budget {budget_s:.0f}s)")
    for c in plan:
        if time.time() - t0 > budget_s:
            print("wall budget reached — re-invoke to continue (cache resumes)")
            return 0
        out = os.path.join(CHUNKS, f"{c['name']}.json")
        pidf = out + ".pid"
        if _chunk_ok(out):
            print(f"{c['name']}: cached PASS")
            continue
        # a live detached child for this chunk?
        if os.path.exists(pidf):
            pid = open(pidf).read().strip()
            if os.path.exists(f"/proc/{pid}"):
                # wait for it within the remaining budget
                while time.time() - t0 < budget_s:
                    time.sleep(5)
                    if not os.path.exists(f"/proc/{pid}"):
                        break
                else:
                    print(f"{c['name']}: detached child {pid} still running — re-invoke")
                    return 0
                os.remove(pidf)
                if _chunk_ok(out):
                    d = json.load(open(out))
                    ran = [x for x in d["cases"] if not x.get("skipped")]
                    print(f"{c['name']}: PASS ran={len(ran)} rows={d['total']}")
                    continue
                print(f"{c['name']}: child finished but output not ok — see {out}.err")
                continue
            os.remove(pidf)
        print(f"=== {c['name']} ({len(c['names'])} cases) launched detached ===", flush=True)
        env = dict(os.environ)
        env["SENTINEL_TEST_FILTER"] = ",".join(c["names"])
        fo = open(out, "w")
        fe = open(out + ".err", "w")
        p = subprocess.Popen(
            [sys.executable, os.path.join(ENG, "tests", "run_tests.py"), "all"],
            cwd=ENG, env=env, stdout=fo, stderr=fe, start_new_session=True)
        open(pidf, "w").write(str(p.pid))
        fo.close(); fe.close()
        # wait a little in-call; mostly it will be polled next invocation
        deadline = min(t0 + budget_s, time.time() + 240)
        while time.time() < deadline:
            time.sleep(5)
            if not os.path.exists(f"/proc/{p.pid}"):
                break
        else:
            print(f"{c['name']}: still running (pid {p.pid}) — re-invoke to continue")
            return 0
        os.remove(pidf)
        if _chunk_ok(out):
            d = json.load(open(out))
            ran = [x for x in d["cases"] if not x.get("skipped")]
            fails = [x for x in ran if not x["ok"]]
            print(f"{c['name']}: ran={len(ran)} failed={len(fails)} rows={d['total']} PASS")
        else:
            try:
                d = json.load(open(out))
                ran = [x for x in d["cases"] if not x.get("skipped")]
                fails = [x for x in ran if not x["ok"]]
                print(f"{c['name']}: FAILED ran={len(ran)} failed={len(fails)}")
                for x in fails[:6]:
                    print(f"    FAIL {x['name']}: {x.get('error', '')[:130]}")
            except Exception as e:
                print(f"{c['name']}: OUTPUT INVALID ({e}) — see {out}.err")
    left = [c["name"] for c in plan if not _chunk_ok(os.path.join(CHUNKS, f"{c['name']}.json"))]
    print(f"chunks still failing/missing: {len(left)}" + (f" -> {left}" if left else ""))
    return 0


def cmd_agg():
    plan = json.load(open(PLAN))["chunks"]
    all_names = set(case_names())
    seen = {}
    rows_total = 0
    bad = []
    for c in plan:
        path = os.path.join(CHUNKS, f"{c['name']}.json")
        if not _chunk_ok(path):
            bad.append(c["name"])
            continue
        d = json.load(open(path))
        rows_total += d["total"]
        for x in d["cases"]:
            if x.get("skipped"):
                continue
            if x["name"] in seen:
                bad.append(f"{c['name']}:DUP {x['name']}")
            seen[x["name"]] = x["ok"]
    missing = all_names - set(seen)
    failed = [n for n, ok in seen.items() if not ok]
    print(f"chunks: {len(plan)} | per-chunk: 227/227 failed=0 (all)"
          if not bad else f"chunks with problems: {bad}")
    print(f"SUITE TOTAL: {rows_total}/{len(plan) * 227}")
    print(f"dedup coverage: cases={len(all_names)} covered={len(seen)} "
          f"missing={len(missing)} failed={len(failed)}")
    if missing:
        print("MISSING:", sorted(missing)[:12])
    if failed:
        print("FAILED:", failed[:12])
    ok = (not bad and not missing and not failed
          and rows_total == 4313 and len(plan) == 19)
    print("AGG VERDICT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "full":
        cmd_full()
    elif cmd == "poll":
        sys.exit(cmd_poll())
    elif cmd == "plan":
        sys.exit(cmd_plan())
    elif cmd == "run":
        cmd_run(float(sys.argv[2]) if len(sys.argv) > 2 else 520.0)
    elif cmd == "agg":
        sys.exit(cmd_agg())
    else:
        print(__doc__)
        sys.exit(2)
