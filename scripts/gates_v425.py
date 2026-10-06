#!/usr/bin/env python3
"""v4.2.5 gate cycle driver (post OWSP-21..23, Mutillidae round) — same proven
per-step pattern as gates_v423.py: each step fits one foreground call.

Usage:
  gates_v425.py count              # print total cases + chunk plan
  gates_v425.py chunk N            # run chunk N only (foreground, <590s)
  gates_v425.py doctor             # run doctor
  gates_v425.py bench K            # run benchmark run K (1..3)
  gates_v425.py verify             # assert chunks + doctor + bench x3 identical 38/0/0/37 + verdict-diff vs frozen v422
"""
import json, os, re, subprocess, sys, time

ROOT = "/home/z/my-project/build-v425"
CHUNK_SIZE = 14
TAG = "v425m"  # Mutillidae-round artifacts (fresh names, no collision with DVWA cycle)


def chunks():
    src = open(os.path.join(ROOT, "tests", "run_tests.py"), encoding="utf-8").read()
    names = re.findall(r"^@case\ndef (\w+)", src, re.M)
    if not names:
        raise SystemExit("no @case defs found")
    out = []
    i = 0
    while i < len(names):
        out.append(names[i:i + CHUNK_SIZE])
        i += CHUNK_SIZE
    return out


def extract_verdict(log_text):
    dec = json.JSONDecoder()
    idx = log_text.rfind("{")
    while idx != -1:
        try:
            obj, end = dec.raw_decode(log_text, idx)
        except ValueError:
            idx = log_text.rfind("{", 0, idx)
            continue
        if isinstance(obj, dict) and "suite" in obj and "cases" in obj and log_text[end:].strip() == "":
            return obj
        idx = log_text.rfind("{", 0, idx)
    return None


def run_chunk(idx):
    names = chunks()[idx - 1]
    env = dict(os.environ, SENTINEL_TEST_FILTER=",".join(names))
    t0 = time.time()
    r = subprocess.run([sys.executable, "tests/run_tests.py", "all"], cwd=ROOT,
                       env=env, capture_output=True, text=True, timeout=585)
    v = extract_verdict(r.stdout)
    if v is None:
        raise RuntimeError(f"chunk {idx}: no verdict JSON (rc={r.returncode}) tail={r.stdout[-300:]} {r.stderr[-300:]}")
    executed = [c["name"] for c in v["cases"] if not c.get("skipped")]
    assert sorted(executed) == sorted(names), f"chunk {idx}: executed mismatch"
    assert v["failed"] == 0, f"chunk {idx}: {v['failed']} FAILED: " + str(
        [c for c in v["cases"] if not c.get("skipped") and not c["ok"]])
    os.makedirs(os.path.join(ROOT, "results", "chunks"), exist_ok=True)
    with open(os.path.join(ROOT, "results", "chunks", f"{TAG}_c{idx}.json"), "w") as fh:
        json.dump(v, fh, indent=1)
    print(f"[{TAG}_c{idx}] {len(names)} cases OK ({time.time()-t0:.0f}s)")


def run_doctor():
    r = subprocess.run([sys.executable, "-m", "sentinel.cli", "doctor"], cwd=ROOT,
                       capture_output=True, text=True, timeout=300)
    dv = json.loads(r.stdout[r.stdout.index("{"):])
    checks = dv.get("checks", [])
    bad = [c for c in checks if c.get("status") != "PASS"]
    with open(os.path.join(ROOT, "results", f"doctor_{TAG}.json"), "w") as fh:
        json.dump(dv, fh, indent=1)
    print(f"DOCTOR: {dv.get('passed')}/{dv.get('total')} overall={dv.get('overall')}")
    assert not bad, bad
    assert dv.get("overall") == "PASS", dv.get("overall")


def run_bench(k):
    out = os.path.join(ROOT, "results", f"bench_{TAG}_{k}.json")
    log = os.path.join(ROOT, "results", f"bench_{TAG}_{k}.log")
    # stdout -> FILE (not a pipe): the CLI leaves the fixture grandchild holding
    # the inherited stdout; a pipe makes subprocess.run wait for EOF forever.
    with open(log, "w") as lf:
        r = subprocess.run([sys.executable, "-m", "sentinel.cli", "benchmark",
                            "--url", "http://127.0.0.1:8791", "--out", out],
                           cwd=ROOT, stdout=lf, stderr=subprocess.STDOUT, timeout=560)
    if r.returncode != 0 or not os.path.exists(out):
        raise RuntimeError(f"bench {k} rc={r.returncode}: {open(log).read()[-400:]}")
    d = json.load(open(out))
    print(f"BENCH {k}: {d['confusion']} run_id={d.get('run_id')} "
          f"req={d.get('stats',{}).get('requests')} dur={d.get('stats',{}).get('duration')}s")


def verify():
    plan = chunks()
    total = 0
    for i in range(1, len(plan) + 1):
        p = os.path.join(ROOT, "results", "chunks", f"{TAG}_c{i}.json")
        assert os.path.exists(p), f"missing chunk {i}"
        v = json.load(open(p))
        ex = [c for c in v["cases"] if not c.get("skipped")]
        assert v["failed"] == 0 and len(ex) == len(plan[i - 1]), (i, v["failed"], len(ex))
        total += len(ex)
    print(f"SUITE: {total}/{sum(len(c) for c in plan)} executed, 0 failed, {len(plan)} chunks")
    dv = json.load(open(os.path.join(ROOT, "results", f"doctor_{TAG}.json")))
    print(f"DOCTOR: {dv.get('passed')}/{dv.get('total')} overall={dv.get('overall')}")
    confs = [json.load(open(os.path.join(ROOT, "results", f"bench_{TAG}_{k}.json")))["confusion"] for k in (1, 2, 3)]
    assert all(c == confs[0] for c in confs), f"NON-DETERMINISTIC: {confs}"
    assert confs[0] == {"TP": 38, "FP": 0, "FN": 0, "TN": 37}, confs[0]
    print(f"BENCH x3: identical {confs[0]} = F1 1.000")
    runs = [json.load(open(os.path.join(ROOT, "results", f"bench_{TAG}_{k}.json"))) for k in (1, 2, 3)]
    rids = [d.get("run_id") for d in runs]
    assert len(set(rids)) == 1, f"NON-DETERMINISTIC run ids: {rids}"
    reqs = [d.get("stats", {}).get("requests") for d in runs]
    assert len(set(reqs)) == 1, f"NON-DETERMINISTIC request counts: {reqs}"
    base = json.load(open("/home/z/my-project/build-v422/results/bench_v422_1.json"))
    breq = base.get("stats", {}).get("requests")
    dvwa = json.load(open("/home/z/my-project/build-v425/results/bench_v425_final2_1.json"))
    dreq = dvwa.get("stats", {}).get("requests")
    print(f"BENCH run_id={rids[0]} requests={reqs[0]} (v422 {breq}, DVWA-cycle {dreq}, delta vs DVWA {reqs[0]-dreq:+d})")
    # zero verdict changes vs the frozen v422 baseline, case by case
    def verdicts(d):
        return sorted((f.get("type"), f.get("url"), f.get("parameter"), str(f.get("status")))
                      for f in d.get("findings", []))
    v422_v, now_v = verdicts(base), verdicts(runs[0])
    assert v422_v == now_v, ("VERDICT CHANGES vs v422 baseline:",
                             [x for x in zip(v422_v, now_v) if x[0] != x[1]][:5])
    print("VERDICT-LEVEL DIFF vs frozen v422: NONE (bit-stable on every fixture finding)")
    print("ALL GATES GREEN")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "count"
    if mode == "count":
        plan = chunks()
        print(f"total cases: {sum(len(c) for c in plan)} in {len(plan)} chunks:",
              [len(c) for c in plan])
    elif mode == "chunk":
        run_chunk(int(sys.argv[2]))
    elif mode == "doctor":
        run_doctor()
    elif mode == "bench":
        run_bench(int(sys.argv[2]))
    elif mode == "verify":
        verify()
