#!/usr/bin/env python3
"""v4.2.2 gate cycle — per-step driver (each step fits one foreground call).

Usage:
  gates_v422.py count              # print total cases + chunk plan
  gates_v422.py chunk N            # run chunk N only (foreground, <590s)
  gates_v422.py doctor             # run doctor
  gates_v422.py bench K            # run benchmark run K (1..3)
  gates_v422.py verify             # assert all chunks complete + doctor + bench x3 identical 38/0/0/37
"""
import json, os, re, subprocess, sys, time

ROOT = "/home/z/my-project/build-v422"
CHUNK_SIZE = 14


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
    with open(os.path.join(ROOT, "results", "chunks", f"v422_c{idx}.json"), "w") as fh:
        json.dump(v, fh, indent=1)
    print(f"[v422_c{idx}] {len(names)} cases OK ({time.time()-t0:.0f}s)")


def run_doctor():
    r = subprocess.run([sys.executable, "-m", "sentinel.cli", "doctor"], cwd=ROOT,
                       capture_output=True, text=True, timeout=300)
    dv = json.loads(r.stdout[r.stdout.index("{"):])
    checks = dv.get("checks", [])
    bad = [c for c in checks if c.get("status") != "PASS"]
    with open(os.path.join(ROOT, "results", "doctor_v422.json"), "w") as fh:
        json.dump(dv, fh, indent=1)
    print(f"DOCTOR: {dv.get('passed')}/{dv.get('total')} overall={dv.get('overall')}")
    assert not bad, bad
    assert dv.get("overall") == "PASS", dv.get("overall")


def run_bench(k):
    out = os.path.join(ROOT, "results", f"bench_v422_{k}.json")
    log = os.path.join(ROOT, "results", f"bench_v422_{k}.log")
    # stdout -> FILE (not a pipe): the CLI leaves the fixture grandchild holding
    # the inherited stdout; a pipe makes subprocess.run wait for EOF forever
    # AFTER the bench itself already finished (bench 1 completed in 82s but the
    # pipe wait hung the call). File redirection returns at child exit.
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
        p = os.path.join(ROOT, "results", "chunks", f"v422_c{i}.json")
        assert os.path.exists(p), f"missing chunk {i}"
        v = json.load(open(p))
        ex = [c for c in v["cases"] if not c.get("skipped")]
        assert v["failed"] == 0 and len(ex) == len(plan[i - 1]), (i, v["failed"], len(ex))
        total += len(ex)
    print(f"SUITE: {total}/{sum(len(c) for c in plan)} executed, 0 failed, {len(plan)} chunks")
    dv = json.load(open(os.path.join(ROOT, "results", "doctor_v422.json")))
    print(f"DOCTOR: {dv.get('passed')}/{dv.get('total')} overall={dv.get('overall')}")
    confs = [json.load(open(os.path.join(ROOT, "results", f"bench_v422_{k}.json")))["confusion"] for k in (1, 2, 3)]
    assert all(c == confs[0] for c in confs), f"NON-DETERMINISTIC: {confs}"
    assert confs[0] == {"TP": 38, "FP": 0, "FN": 0, "TN": 37}, confs[0]
    print(f"BENCH x3: identical {confs[0]} = F1 1.000 (baseline preserved, zero noise added)")
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
