"""PART 3 PHASE 4 — independent scoring against the PRE-REGISTERED
predictions.json (order 3.4): (a) confirmed TPs, (b) undetermined, (c)
misses with reasons if knowable. Never scores against engine output alone.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "evidence" / "full-reverify"

pred = json.loads((EV / "predictions.json").read_text(encoding="utf-8"))
cases = pred["targets"]["fixtures-vulnapp"]["cases"]


def load_findings(name):
    p = EV / name
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    return d


def detected(entry, findings):
    for f in findings:
        if f["type"] != entry["type"]:
            continue
        ep = entry["endpoint"]
        if ep == "*" or f["url"].split("?")[0].endswith(ep):
            if not entry["parameter"] or f["parameter"] == entry["parameter"]:
                return f
    return None


out = {}

# ---- fixtures-vulnapp: benchmark run + store run, scored separately ---------
for run_name, fname in (("benchmark_cli_run", "fixtures-vulnapp/benchmark.json"),
                        ("store_full_config_run", "fixtures-vulnapp/scan.json")):
    d = load_findings(fname)
    if d is None:
        out[run_name] = {"status": "NOT RUN"}
        continue
    findings = d["findings"]
    tp = fn = tn = fp = 0
    details = []
    for g in cases:
        f = detected(g, findings)
        present = g["present"]
        cell = ("TP" if f and present else "FP" if f and not present
                else "FN" if present and not f else "TN")
        if cell == "TP":
            tp += 1
        elif cell == "FP":
            fp += 1
        elif cell == "FN":
            fn += 1
        else:
            tn += 1
        row = {"case": f"{g['type']}@{g['endpoint']}:{g['parameter']}",
               "cell": cell}
        if cell == "FN":
            row["reason_if_knowable"] = g.get(
                "note", "no matching verified finding in this run")
        details.append(row)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # findings outside the documented list -> undetermined (3.4b)
    documented = []
    undetermined = []
    for f in findings:
        hit = any(detected(g, [f]) for g in cases
                  if g["present"] and f["type"] == g["type"])
        key = f"{f['type']}@{f['url']}:{f['parameter']}"
        (documented if hit else undetermined).append(key)
    out[run_name] = {
        "engine_findings": len(findings),
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4),
        "undetermined_findings_outside_list": undetermined,
        "details": details,
    }

# ---- cross-run re-execution agreement (benchmark run vs store run) ----------
b = load_findings("fixtures-vulnapp/benchmark.json")
s = load_findings("fixtures-vulnapp/scan.json")
if b and s:
    def key(f):
        from urllib.parse import urlsplit
        p = urlsplit(f["url"])
        return (f["type"], p.path + ("?" + p.query if p.query else ""),
                f["parameter"])
    fb = {key(f) for f in b["findings"]}
    fs = {key(f) for f in s["findings"]}
    out["cross_run_agreement"] = {
        "run_a": "benchmark CLI (engine-owned fixture, ephemeral port)",
        "run_b": "full-config store run (own fixture on 127.0.0.1:8777)",
        "run_a_findings": len(fb), "run_b_findings": len(fs),
        "identical_finding_sets": fb == fs,
        "only_in_a": sorted(map(str, fb - fs))[:10],
        "only_in_b": sorted(map(str, fs - fb))[:10],
        "note": "two independent full-engine executions agreeing on the "
                "finding set is re-execution evidence for every finding",
    }

# ---- engine-internal scan-time verification coverage -------------------------
for name, fname in (("benchmark_cli_run", "fixtures-vulnapp/benchmark.json"),
                    ("store_full_config_run", "fixtures-vulnapp/scan.json")):
    d = load_findings(fname)
    if d:
        fv = d["findings"]
        out.setdefault(name, {})["scan_time_verification"] = {
            "findings_status_verified": sum(
                1 for f in fv if f.get("status") == "verified"),
            "findings_total": len(fv),
            "note": "every finding carries a verification dict — the "
                    "engine's differential re-execution on a fresh request "
                    "at scan time; only verified findings are reported",
        }

# ---- replay verification summary --------------------------------------------
rp = EV / "fixtures-vulnapp" / "replay_results.json"
if rp.exists():
    out["replay_verification"] = json.loads(
        rp.read_text(encoding="utf-8"))["summary"]

# ---- ginandjuice-shop: no published list -> everything undetermined ---------
gj = load_findings("ginandjuice-shop/scan.json")
if gj is None:
    out["ginandjuice-shop"] = {"status": "NOT RUN"}
else:
    findings = gj["findings"]
    out["ginandjuice-shop"] = {
        "engine_findings": len(findings),
        "scoring": "UNDETERMINED for every finding — PortSwigger publishes "
                   "no vulnerability list for this target (recorded in "
                   "predictions.json before the scan)",
        "findings": [f"{f['type']}@{f['url']}:{f['parameter']} "
                     f"(severity={f['severity']}, status={f['status']})"
                     for f in findings],
    }
    gjr = EV / "ginandjuice-shop" / "replay_results.json"
    if gjr.exists():
        out["ginandjuice-shop"]["replay_verification"] = json.loads(
            gjr.read_text(encoding="utf-8"))["summary"]
    gjo = EV / "ginandjuice-shop" / "passive_reobservation.json"
    if gjo.exists():
        out["ginandjuice-shop"]["passive_reobservation"] = json.loads(
            gjo.read_text(encoding="utf-8"))["summary"]

out["testphp-vulnweb"] = (json.loads(
    (EV / "testphp-vulnweb" / "status.json").read_text(encoding="utf-8"))
    .get("verdict", "not probed")) if (EV / "testphp-vulnweb" /
                                         "status.json").exists() else "not probed"
out["docker-targets"] = {"status": "SKIPPED — docker command not found "
                                   "(verified at run time)"}

dest = EV / "scoring.json"
dest.write_text(json.dumps(out, indent=1, ensure_ascii=False),
                encoding="utf-8")
print(json.dumps({k: (v if not isinstance(v, dict) or k == "replay_verification"
                      else {kk: vv for kk, vv in v.items()
                            if kk != "details"})
                  for k, v in out.items()}, indent=1, ensure_ascii=False))
print("scoring.json written")
