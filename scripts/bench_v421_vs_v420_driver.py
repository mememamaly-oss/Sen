#!/usr/bin/env python3
"""v4.2.1 gate: journal passivity proof.

Runs the v4.2.0 engine (build-v420, frozen, imported read-only via sys.path)
and the v4.2.1 engine (build-v421, with the request journal) each against a
FRESH fixture instance (business-logic findings are stateful BY DESIGN — the
fixture's workflow ledger mutates during a scan, so sequential runs on one
instance contaminate each other; caught live by this gate's first version).
Same seed; ports differ per instance and the verdict comparison normalizes
the port out. The journal must change ZERO verdicts.

Also proves the journal's substance: every finding-proof request_id must
resolve to a journal entry carrying BOTH request and response.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
V420 = ROOT / "build-v420"
V421 = ROOT / "build-v421"


def run_engine(build_dir: Path, port: int, out_path: Path, label: str):
    """Import the target engine READ-ONLY (sys.path), run the official
    benchmark scan config against a fresh fixture on `port`, return the
    result dict. The CLI auto-spawns fixtures/vulnapp.py with PORT env."""
    code = f"""
import sys
sys.path.insert(0, r"{build_dir}")
from sentinel.cli import main
sys.argv = ["sentinel", "benchmark", "--url", "http://127.0.0.1:{port}",
            "--out", r"{out_path}"]
main()
"""
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=560)
    if r.returncode != 0:
        print(f"[{label}] STDERR tail:", r.stderr[-600:])
        raise RuntimeError(f"{label} run failed rc={r.returncode}")
    return json.load(open(out_path))


def verdict_tuples(d: dict):
    out = []
    for f in d.get("findings", []):
        v = f.get("verification", {}) or {}
        out.append((f.get("type"), f.get("url"), f.get("parameter"), f.get("status"),
                    v.get("method"), v.get("passed"), round(v.get("confidence", 0), 3), v.get("rounds")))
    for f in d.get("rejected_candidates", []):
        v = f.get("verification", {}) or {}
        out.append((f.get("type"), f.get("url"), f.get("parameter"), f.get("status"),
                    v.get("method"), v.get("passed"), round(v.get("confidence", 0), 3), v.get("rounds")))
    for f in d.get("unverified_candidates", []):
        out.append((f.get("type"), f.get("url"), f.get("parameter"), f.get("status"), "", "", "", ""))
    return sorted(map(repr, out))


def journal_substance(b: dict):
    """Every proof request_id resolves to a journal entry with request+response."""
    jr = (b.get("stats", {}) or {}).get("request_journal", {})
    proofs = (b.get("stats", {}) or {}).get("proofs", [])
    missing = []
    checked = 0
    for p in proofs:
        for r in p.get("responses", []):
            rid = r.get("request_id", "")
            if not rid:
                continue
            checked += 1
            if rid not in jr:
                missing.append(rid)
            else:
                e = jr[rid]
                if not e.get("request") or not e.get("response"):
                    missing.append(rid + ":incomplete")
    dropped = (b.get("stats", {}) or {}).get("request_journal_dropped", 0)
    print(f"journal entries: {len(jr)} | dropped: {dropped}")
    print(f"proof request_ids checked: {checked} | unresolved/incomplete: {len(missing)}")
    return not missing and len(jr) > 0


def main():
    a = run_engine(V420, 8911, ROOT / "build-v421/results/bench_v420_replay_1.json", "v420")
    b = run_engine(V421, 8913, ROOT / "build-v421/results/bench_v421_replay_1.json", "v421")
    va, vb = verdict_tuples(a), verdict_tuples(b)
    va = [t.replace(":8911", ":FIXTURE") for t in va]
    vb = [t.replace(":8913", ":FIXTURE") for t in vb]
    print(f"v420 verdicts: {len(va)} | v421 verdicts: {len(vb)}")
    print("VERDICTS-IDENTICAL:", va == vb)
    if va != vb:
        import difflib
        for line in list(difflib.unified_diff(va, vb, "v420", "v421"))[:30]:
            print(line[:200])
        print("JOURNAL PASSIVITY: FAILED — verdicts diverged")
        sys.exit(1)
    if not journal_substance(b):
        print("JOURNAL SUBSTANCE: FAILED — proof request_ids unresolved")
        sys.exit(1)
    print("GATE PASS: journal is passive (verdicts identical) and substantive (every proof id resolves to a raw pair)")


if __name__ == "__main__":
    main()
