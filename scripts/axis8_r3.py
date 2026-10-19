#!/usr/bin/env python3
"""محطة M4 R3 للمحور 8 — ثلاث تشغيلات مستقلة، هضم منطقي متطابق.

يستدعي جناح المحور-8 (الـ15 حالة) والبطاريات (8a/8b/8c) ثلاث مرات
في عمليات منفصلة (subprocess — عزل كامل للذاكرة والحالة)، ويقارن
الهضم المنطقي عبر التشغيلات. أي انحراف = فشل المحطة يُلصق خاماً.

Usage:
  python3 scripts/axis8_r3.py
"""
import json
import subprocess
import sys
from pathlib import Path

ENG = Path(__file__).resolve().parents[1] / "build-v430"
OUT = ENG / "results" / "axis8"

SUITE = "tests/test_axis8_proof.py"
ATOMS = "tests/test_axis8_atoms.py"


def _run(script: str, tmp: str) -> dict:
    r = subprocess.run(
        [sys.executable, str(ENG / script), "--out", tmp],
        capture_output=True, text=True, timeout=1200, cwd=str(ENG))
    if r.returncode != 0:
        print(f"FAIL: {script} rc={r.returncode}\n{r.stdout}\n{r.stderr}")
        sys.exit(1)
    with open(tmp) as f:
        return json.load(f)


def main() -> int:
    runs = {"suite": [], "atoms": []}
    for i in (1, 2, 3):
        d = _run(SUITE, f"/tmp/ax8_r3_suite_{i}.json")
        runs["suite"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["digest"]})
        d = _run(ATOMS, f"/tmp/ax8_r3_atoms_{i}.json")
        runs["atoms"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["overall_digest"]})

    suite_digests = [r["digest"] for r in runs["suite"]]
    atoms_digests = [r["digest"] for r in runs["atoms"]]
    suite_ok = len(set(suite_digests)) == 1 and runs["suite"][0]["passed"] == 15
    atoms_ok = len(set(atoms_digests)) == 1 and runs["atoms"][0]["passed"] == 3

    doc = {
        "suite": "axis8-r3",
        "station": "M4-R3",
        "runs": runs,
        "suite_digest_identical": suite_ok,
        "atoms_digest_identical": atoms_ok,
        "passed": bool(suite_ok and atoms_ok),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "axis8_R3.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    print(f"axis8-R3: suite {'IDENTICAL x3' if suite_ok else 'DRIFT'} "
          f"({suite_digests[0][:16]}); atoms "
          f"{'IDENTICAL x3' if atoms_ok else 'DRIFT'} "
          f"({atoms_digests[0][:16]}) -> "
          f"{'PASS' if doc['passed'] else 'FAIL'}")
    for r in runs["suite"] + runs["atoms"]:
        print(f"  run {r['run']}: {r['passed']}/{r['total']} "
              f"digest={r['digest'][:16]}")
    return 0 if doc["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
