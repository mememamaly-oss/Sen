#!/usr/bin/env python3
"""محطة M4 R3 للمحور 7 — ثلاث تشغيلات مستقلة، هضم منطقي متطابق.

يستدعي جناح المحور-7 (الـ14 حالة) والبطاريات (3a/3b/3c) ثلاث مرات
في عمليات منفصلة (subprocess — عزل كامل للذاكرة والحالة)، ويقارن
الهضم المنطقي عبر التشغيلات. أي انحراف = فشل المحطة يُلصق خاماً.

Usage:
  python3 scripts/axis7_r3.py
"""
import json
import subprocess
import sys
from pathlib import Path

ENG = Path(__file__).resolve().parents[1] / "build-v430"
OUT = ENG / "results" / "axis7"

SUITE = "tests/test_axis7_metrics.py"
ATOMS = "tests/test_axis7_atoms.py"


def _run(script: str, tmp: str) -> dict:
    r = subprocess.run(
        [sys.executable, str(ENG / script), "--out", tmp],
        capture_output=True, text=True, timeout=600, cwd=str(ENG))
    if r.returncode != 0:
        print(f"FAIL: {script} rc={r.returncode}\n{r.stdout}\n{r.stderr}")
        sys.exit(1)
    with open(tmp) as f:
        return json.load(f)


def main() -> int:
    runs = {"suite": [], "atoms": []}
    for i in (1, 2, 3):
        d = _run(SUITE, f"/tmp/ax7_r3_suite_{i}.json")
        runs["suite"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["digest"]})
        d = _run(ATOMS, f"/tmp/ax7_r3_atoms_{i}.json")
        runs["atoms"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["overall_digest"]})

    suite_digests = [r["digest"] for r in runs["suite"]]
    atoms_digests = [r["digest"] for r in runs["atoms"]]
    suite_ok = len(set(suite_digests)) == 1 and runs["suite"][0]["passed"] == 14
    atoms_ok = len(set(atoms_digests)) == 1 and runs["atoms"][0]["passed"] == 3

    doc = {
        "suite": "axis7-r3",
        "station": "M4-R3",
        "runs": runs,
        "suite_digest_identical": suite_ok,
        "atoms_digest_identical": atoms_ok,
        "passed": bool(suite_ok and atoms_ok),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "axis7_R3.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)

    print(f"suite digests:  {suite_digests[0][:16]} x3 -> "
          f"{'IDENTICAL' if suite_ok else 'DRIFT (raw above)'}")
    print(f"atoms digests:  {atoms_digests[0][:16]} x3 -> "
          f"{'IDENTICAL' if atoms_ok else 'DRIFT (raw above)'}")
    for r in runs["suite"] + runs["atoms"]:
        print(f"  run{r['run']}: {r['passed']}/{r['total']} "
              f"digest={r['digest'][:32]}")
    return 0 if doc["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
