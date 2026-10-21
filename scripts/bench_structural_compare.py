#!/usr/bin/env python3
"""Structural comparison of two SENTINEL benchmark result JSONs.

Established by the prior campaign's accepted gate (the inline tool was not
persisted then — this is now the standing version, definition documented):

  path_tuples      sorted multiset over findings of
                   (type, url-path, parameter, method, status)
  norm_url_tuples  sorted multiset over findings of
                   (type, normalized-url, parameter) where normalized-url =
                   scheme://host[:non-default-port] + path (host lowercased)
  struct_meta      {benchmark, label, confusion, precision, recall, f1,
                   ground_truth_sha256, findings_count}

EXCLUDED by design (seed-derived presentation, not scan behavior):
run_id, seed, scanner, signature/public key, request counts (reported as
informational), findings' evidence text (canary values are seed-derived),
finding ids/confidence/risk (per-run detail fields carrying no verdict
semantics).

Usage: bench_structural_compare.py REFERENCE.json RUN1.json [RUN2.json ...]
Exit 0 iff every RUN is IDENTICAL to REFERENCE on all three families.
"""
import json
import sys
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _norm_url(u):
    """Normalized target identity: scheme://host + path. The PORT is
    stripped by design — the bench spawns its fixture on an EPHEMERAL port
    every run (ENG-20 determinism doctrine), so the port is run plumbing,
    never target identity (keeping it would make ANY two runs mismatch)."""
    p = urlsplit(u)
    host = (p.hostname or "").lower()
    return f"{p.scheme}://{host}{p.path}"


def path_tuples(d):
    return sorted(
        (f["type"], urlsplit(f["url"]).path, f.get("parameter") or "",
         f.get("method") or "", f.get("status") or "")
        for f in d["findings"])


def norm_url_tuples(d):
    return sorted(
        (f["type"], _norm_url(f["url"]), f.get("parameter") or "")
        for f in d["findings"])


def struct_meta(d):
    return {
        "benchmark": d.get("benchmark"),
        "label": d.get("label"),
        "confusion": d.get("confusion"),
        "precision": d.get("precision"),
        "recall": d.get("recall"),
        "f1": d.get("f1"),
        "ground_truth_sha256": d.get("ground_truth_sha256"),
        "findings_count": len(d.get("findings") or []),
    }


def info(d):
    return (f"run_id={d.get('run_id')} seed={str(d.get('seed'))[:12]}… "
            f"confusion={tuple(d['confusion'][k] for k in ('TP', 'FP', 'FN', 'TN'))} "
            f"P={d.get('precision')} R={d.get('recall')} F1={d.get('f1')} "
            f"requests={(d.get('stats') or {}).get('requests')} "
            f"findings={len(d.get('findings') or [])} "
            f"gt={d.get('ground_truth_sha256')}")


def compare(ref_path, run_path):
    ref = json.load(open(ref_path))
    run = json.load(open(run_path))
    pt = "EQ" if path_tuples(ref) == path_tuples(run) else "MISMATCH"
    nu = "EQ" if norm_url_tuples(ref) == norm_url_tuples(run) else "MISMATCH"
    sm = "EQ" if struct_meta(ref) == struct_meta(run) else "MISMATCH"
    verdict = "IDENTICAL" if (pt, nu, sm) == ("EQ", "EQ", "EQ") else "MISMATCH"
    print(f"{run_path}:")
    print(f"  {info(run)}")
    print(f"  vs {ref_path}: path_tuples={pt} norm_url_tuples={nu} "
          f"struct_meta={sm} (info: requests "
          f"{(ref.get('stats') or {}).get('requests')} vs "
          f"{(run.get('stats') or {}).get('requests')}) -> {verdict}")
    if verdict == "MISMATCH":
        if pt != "EQ":
            only_ref = [t for t in path_tuples(ref) if t not in path_tuples(run)][:6]
            only_run = [t for t in path_tuples(run) if t not in path_tuples(ref)][:6]
            print(f"    path_tuples only-in-ref: {only_ref}")
            print(f"    path_tuples only-in-run: {only_run}")
        if sm != "EQ":
            print(f"    struct_meta ref : {struct_meta(ref)}")
            print(f"    struct_meta run : {struct_meta(run)}")
    return verdict == "IDENTICAL"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    ref = sys.argv[1]
    runs = sys.argv[2:]
    ref_d = json.load(open(ref))
    print(f"REFERENCE {ref}:")
    print(f"  {info(ref_d)}")
    results = [compare(ref, r) for r in runs]
    # mutual identity across the fresh runs (same seed -> same run_id too)
    mutual = True
    for i in range(1, len(runs)):
        a, b = json.load(open(runs[i - 1])), json.load(open(runs[i]))
        if (a.get("run_id") != b.get("run_id")
                or path_tuples(a) != path_tuples(b)
                or norm_url_tuples(a) != norm_url_tuples(b)
                or struct_meta(a) != struct_meta(b)):
            mutual = False
            print(f"MUTUAL MISMATCH: {runs[i - 1]} vs {runs[i]}")
    print(f"MUTUAL x{len(runs)}: {'IDENTICAL' if mutual else 'MISMATCH'}")
    ok = all(results) and mutual
    print("VERDICT:", "ALL IDENTICAL" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
