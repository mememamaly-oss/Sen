#!/usr/bin/env python3
"""SENTINEL v4.0.0 Production Readiness — central results registry.
Every A-Z check appends here; final compiler builds PRODUCTION_READINESS_v4.0.0.md.
"""
import json, os, sys, datetime

BASE = "/home/z/my-project/readiness"
RESULTS = os.path.join(BASE, "results")
EVID = os.path.join(BASE, "evidence")
ZIPRUN = os.path.join(BASE, "ziprun")          # extracted sentinel-4.0.0-source.zip (the SHIPPED artifact)
CLEAN = os.path.join(BASE, "cleanenv")          # clean-environment install tree
DOWNLOAD = "/home/z/my-project/download"

SECTIONS = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]

def _path(section):
    return os.path.join(RESULTS, f"{section}.json")

def load(section):
    p = _path(section)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return []

def record(section, tid, name, target, command, expected, actual, status, evidence="", artifact=""):
    """status: PASS | FAIL | BLOCKED | WAIVED"""
    assert status in ("PASS","FAIL","BLOCKED","WAIVED"), status
    rows = load(section)
    rows = [r for r in rows if r["id"] != tid]  # idempotent re-record
    rows.append({
        "id": tid, "name": name, "target": target, "command": command,
        "expected": expected, "actual": actual, "status": status,
        "evidence": evidence, "artifact": artifact,
        "recorded_at": datetime.datetime.now().isoformat(timespec="seconds"),
    })
    rows.sort(key=lambda r: r["id"])
    os.makedirs(RESULTS, exist_ok=True)
    with open(_path(section), "w") as f:
        json.dump(rows, f, indent=1, ensure_ascii=False)
    return rows[-1]

def summary():
    out = {}
    for s in SECTIONS:
        rows = load(s)
        out[s] = {
            "total": len(rows),
            "PASS": sum(1 for r in rows if r["status"]=="PASS"),
            "FAIL": sum(1 for r in rows if r["status"]=="FAIL"),
            "BLOCKED": sum(1 for r in rows if r["status"]=="BLOCKED"),
            "WAIVED": sum(1 for r in rows if r["status"]=="WAIVED"),
        }
    return out

if __name__ == "__main__":
    if sys.argv[1:] == ["summary"]:
        print(json.dumps(summary(), indent=1))
    elif sys.argv[1:] == ["list", sys.argv[1] if len(sys.argv)>1 else ""]:
        pass
