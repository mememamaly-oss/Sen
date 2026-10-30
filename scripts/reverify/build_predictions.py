"""PART 3 PHASE 1 — pre-registered predictions (BEFORE any scan).

Builds evidence/full-reverify/predictions.json from sources that are NOT
the engine's own output:
  * fixtures/vulnapp.py  — the fixture's own docstring (what is seeded)
  * benchmarks/ground_truth.json — the repo's committed case list (v11)
  * ginandjuice.shop homepage — fetched permission text (2026-10-30)
No scan has run yet at the time this file is written (enforced by the
calling script's ordering; this script itself performs zero requests).
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "evidence" / "full-reverify"

gt_raw = (ROOT / "benchmarks" / "ground_truth.json").read_text(
    encoding="utf-8")
gt = json.loads(gt_raw)
cases = gt["ground_truth"]
pos = [g for g in cases if g["present"]]
neg = [g for g in cases if not g["present"]]

fixture_doc = (ROOT / "fixtures" / "vulnapp.py").read_text(
    encoding="utf-8").split('"""')[1]

GINANDJUICE_PERMISSION = (
    "https://ginandjuice.shop/ (fetched 2026-10-30, HTTP 200): "
    "\"This is a deliberately vulnerable web application designed for "
    "testing web vulnerability scanners. Put your scanner to the test! "
    "... open 24/7 to satisfy all of your web vulnerability scanner "
    "evaluation needs. (c) 2023 PortSwigger Ltd.\"")

predictions = {
    "registered_at": "2026-10-30 (before any Part-3 scan)",
    "method": "ground truth pre-registered from fixture source + repo "
              "ground_truth.json + targets' own published statements — "
              "never from engine output",
    "targets": {
        "fixtures-vulnapp": {
            "basis": "fixtures/vulnapp.py docstring (read from source) + "
                     "benchmarks/ground_truth.json v11 (committed file)",
            "ground_truth_sha256": hashlib.sha256(
                gt_raw.encode()).hexdigest(),
            "case_count": len(cases),
            "expected_positives": len(pos),
            "expected_negatives": len(neg),
            "cases": cases,
            "environment_notes": gt.get("environment", ""),
            "fixture_docstring_excerpt": fixture_doc[:2000],
        },
        "ginandjuice-shop": {
            "basis": "the site's own homepage statement (quoted verbatim)",
            "permission_text": GINANDJUICE_PERMISSION,
            "official_vuln_list": (
                "NONE EXISTS: PortSwigger publishes no vulnerability or "
                "challenge list for ginandjuice.shop (checked 2026-10-30 "
                "via web search — only the deliberately-vulnerable "
                "declaration above). Per order 3.4(b), every finding on "
                "this target is scored UNDETERMINED — claimed neither as "
                "confirmed-TP nor as FP."),
            "pre_registered_expectation": (
                "deliberately vulnerable by design; anonymous scan only "
                "(no credentials published); findings scored undetermined"),
        },
        "testphp-vulnweb": {
            "basis": "Acunetix's public test site; permission statement "
                     "lives on acunetix.com pages",
            "status_at_registration": "UNREACHABLE from this environment "
                                      "on 2026-10-30 (connection timeout, "
                                      "HTTP and HTTPS) — will be retried "
                                      "once at scan time",
        },
        "docker-targets": {
            "basis": "OWASP Juice Shop / WebGoat / DVWA / crAPI / DVGA as "
                     "official Docker images on localhost",
            "status_at_registration": "SKIPPED — docker command not found "
                                      "in this environment (verified "
                                      "2026-10-30); no unauthorized "
                                      "substitution made",
        },
    },
    "scoring_rules": {
        "a_confirmed_tp": "finding matches a pre-registered positive case "
                          "(type + endpoint + parameter)",
        "b_undetermined": "finding outside the documented list (or on a "
                          "target with no published list) — flagged "
                          "undetermined, never claimed either way",
        "c_miss": "pre-registered positive with no matching finding — "
                  "recorded as FN with the reason if knowable",
    },
}

EV.mkdir(parents=True, exist_ok=True)
out = EV / "predictions.json"
out.write_text(json.dumps(predictions, indent=1, ensure_ascii=False),
               encoding="utf-8")
print(f"predictions.json written: {len(cases)} fixture cases "
      f"({len(pos)} positive / {len(neg)} negative), ginandjuice "
      f"permission recorded, testphp + docker status recorded")
print("ground_truth sha256:", predictions["targets"]
      ["fixtures-vulnapp"]["ground_truth_sha256"])
