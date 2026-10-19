#!/usr/bin/env python3
"""محطة M4 R3 للمحور 13 — ثلاث تشغيلات مستقلة، هضم منطقي متطابق.

يستدعي جناح المحور-13 (الـ20 حالة) والبطاريات (13a/13b/13c) ثلاث مرات
في عمليات منفصلة (subprocess — عزل كامل للذاكرة والحالة)، ويقارن
الهضم المنطقي عبر التشغيلات. أي انحراف = فشل المحطة يُلصق خاماً.

عزل G4 الموروث (عقد المحور-11 — لا حاوية حرفية في هذه البيئة؛ أُثبتت
في external-2 X3: لا ثنائي docker): كل تشغيل عملية مستقلة كاملة
+ PYTHONHASHSEED="0" مثبت في بيئتها. القيود الزمنية المقاسة (توقيت
التهريب) خارج الهضم أصلاً (مكمَّاة صنفاً — N3 في عقد الجناح).

Usage:
  python3 scripts/axis13_r3.py
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ENG = Path(__file__).resolve().parents[1] / "build-v430"
OUT = ENG / "results" / "axis13"

SUITE = "tests/test_axis13_detectors.py"
ATOMS = "tests/test_axis13_atoms.py"


def _run(script: str, tmp: str) -> dict:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "0"          # G4: hash seed مثبت عبر العقد
    r = subprocess.run(
        [sys.executable, str(ENG / script), "--out", tmp],
        capture_output=True, text=True, timeout=1500, cwd=str(ENG),
        env=env)
    if r.returncode != 0:
        print(f"FAIL: {script} rc={r.returncode}\n{r.stdout}\n{r.stderr}")
        sys.exit(1)
    with open(tmp) as f:
        return json.load(f)


def main() -> int:
    runs = {"suite": [], "atoms": []}
    for i in (1, 2, 3):
        d = _run(SUITE, f"/tmp/ax13_r3_suite_{i}.json")
        runs["suite"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["digest"]})
        d = _run(ATOMS, f"/tmp/ax13_r3_atoms_{i}.json")
        runs["atoms"].append({
            "run": i, "total": d["total"], "passed": d["passed_count"],
            "digest": d["overall_digest"]})

    suite_digests = [r["digest"] for r in runs["suite"]]
    atoms_digests = [r["digest"] for r in runs["atoms"]]
    suite_ok = len(set(suite_digests)) == 1 and runs["suite"][0]["passed"] == 20
    atoms_ok = len(set(atoms_digests)) == 1 and runs["atoms"][0]["passed"] == 3

    doc = {
        "suite": "axis13-r3",
        "station": "M4-R3",
        "isolation": "3 separate subprocesses, full memory/state isolation; "
                      "PYTHONHASHSEED=0 pinned in each env (the inherited "
                      "G4 contract: no literal container in this "
                      "environment — proven external-2 X3)",
        "runs": runs,
        "suite_digest_identical": suite_ok,
        "atoms_digest_identical": atoms_ok,
        "passed": bool(suite_ok and atoms_ok),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "axis13_R3.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    print(f"axis13-R3: suite {'IDENTICAL x3' if suite_ok else 'DRIFT'} "
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
