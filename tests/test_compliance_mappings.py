"""P2-C (2026-10-31): compliance registry invariants.

The registry is a compliance claim surfaced to buyers — so it is tested like
one. These tests fail CI when:
  * a detector class appears in report.SARIF_RULES without a mapping row
    (or the reverse — a stale row for a class the engine no longer emits)
  * an "official" source tag is not backed by the embedded official
    mapped-CWE list for that category/year (the self-audit)
  * any code/CWE/format drifts from its canonical shape
  * the fixture's ground-truth types are not fully covered
  * the checked-in platform registry (src/lib/compliance-registry.json)
    drifts from the Python source (parity with the generated artifact)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sentinel.compliance import (OFFICIAL_LISTS, PCI_DSS_REQUIREMENT,
                                 COMPLIANCE, compliance_for)
from sentinel.report import SARIF_RULES

ROOT = Path(__file__).resolve().parents[1]

CWE_RE = re.compile(r"^CWE-\d+$")
OWASP_RE = re.compile(r"^A\d\d:(2021|2025)$")
SRC_VALUES = {"official", "scope"}


def test_registry_covers_every_sarif_rule_exactly():
    """Parity with the engine's stable rule registry — both directions."""
    rules = set(SARIF_RULES)
    rows = set(COMPLIANCE)
    missing = rules - rows
    stale = rows - rules
    assert not missing, f"SARIF_RULES without compliance mapping: {sorted(missing)}"
    assert not stale, f"compliance rows for unknown detector classes: {sorted(stale)}"


def test_row_shapes_are_canonical():
    for ftype, row in COMPLIANCE.items():
        assert CWE_RE.match(row["cwe"]), f"{ftype}: bad CWE {row['cwe']}"
        assert OWASP_RE.match(row["owasp_2021"]), f"{ftype}: bad 2021 code"
        assert OWASP_RE.match(row["owasp_2025"]), f"{ftype}: bad 2025 code"
        assert row["owasp_2021_src"] in SRC_VALUES, f"{ftype}: bad 2021 src"
        assert row["owasp_2025_src"] in SRC_VALUES, f"{ftype}: bad 2025 src"


def test_official_tags_are_backed_by_the_official_lists():
    """The self-audit: every 'official' claim must be reproducible from the
    fetched mapped-CWE lists — otherwise it must be tagged 'scope'."""
    for ftype, row in COMPLIANCE.items():
        for year, code_key, src_key in (
            ("2021", "owasp_2021", "owasp_2021_src"),
            ("2025", "owasp_2025", "owasp_2025_src"),
        ):
            if row[src_key] == "official":
                key = (year, row[code_key])
                assert key in OFFICIAL_LISTS, (
                    f"{ftype}: 'official' tag for {key} but no embedded list")
                assert row["cwe"] in OFFICIAL_LISTS[key], (
                    f"{ftype}: claims official {code_key}={row[code_key]} "
                    f"({year}) but {row['cwe']} is NOT in that category's "
                    f"official mapped-CWE list — retag as scope or fix the mapping")


def test_pci_dss_is_the_v4_web_app_requirement():
    assert PCI_DSS_REQUIREMENT == "6.4.2"
    for ftype in COMPLIANCE:
        c = compliance_for(ftype)
        assert c["pci_dss"] == "6.4.2", f"{ftype}: PCI mapping must be uniform"


def test_unknown_type_is_honestly_unmapped():
    c = compliance_for("not_a_real_detector_class")
    assert c["mapped"] is False
    assert c["cwe"] is None and c["owasp_2021"] is None and c["owasp_2025"] is None


def test_ground_truth_types_are_fully_covered():
    """The fixture benchmark's ground truth must never fall outside the map."""
    gt = json.loads((ROOT / "benchmarks" / "ground_truth.json").read_text())
    types = {row["type"] for row in gt["ground_truth"]}
    unmapped = [t for t in sorted(types) if not compliance_for(t)["mapped"]]
    assert not unmapped, f"ground-truth types without a compliance row: {unmapped}"


def test_platform_registry_json_is_in_sync():
    """src/lib/compliance-registry.json is GENERATED — parity with the source
    of truth. Drift fails here AND in the CI drift-guard job."""
    gen = ROOT / "scripts" / "gen_compliance_registry.py"
    if not gen.exists():
        pytest.skip("generator not present (source layout changed)")
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, str(gen)], capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    checked_in = json.loads((ROOT / "src" / "lib" / "compliance-registry.json").read_text())
    fresh = json.loads(
        subprocess.run(
            [sys.executable, "-c",
             "import json;from sentinel.compliance import compliance_json;"
             "print(json.dumps(compliance_json()))"],
            capture_output=True, text=True, cwd=str(ROOT)).stdout)
    assert checked_in["types"] == fresh["types"], (
        "src/lib/compliance-registry.json is stale — regenerate: "
        "python3 scripts/gen_compliance_registry.py")
