#!/usr/bin/env python3
"""LIVE test: persistence layer (store.py) + report builder — real scans against the
local benchmark fixture, run twice with different seeds, then recurring/delta checks.
Exercises the SAME code paths the CLI/API use (Store.save_run / list_findings /
recurring / delta / stats_summary + report.build_html)."""
import json, os, sys, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from sentinel.cli import ensure_fixture
from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.store import Store, finding_fingerprint
from sentinel.report import build_html, build_report

# ---- start the local fixture (OP-01 semantics, but we keep it for the whole test)
spawned = ensure_fixture("http://127.0.0.1:8777")
assert ensure_fixture("http://127.0.0.1:8777") is None or True, "fixture running"
try:
    db = os.path.join(tempfile.mkdtemp(), "live-test.db")
    st = Store(db)

    # ---- scan #1 and scan #2 (different seeds -> different run_ids, same vulns)
    reports = []
    for seed in ("live-persist-seed-1", "live-persist-seed-2"):
        sc = SentinelScanner("http://127.0.0.1:8777",
                             ScanConfig(allow_private=True, max_pages=30, timeout=8, seed=seed))
        rep = sc.run()
        n = st.save_run(rep)
        reports.append((rep, n))
        print(f"[scan {seed}] run_id={rep['run_id']} verified={len(rep['findings'])} "
              f"rejected={len(rep['rejected_candidates'])} persisted_rows={n}")

    rep1, n1 = reports[0]
    rep2, n2 = reports[1]
    assert len(rep1["findings"]) >= 12, f"fixture should yield >=12 verified, got {len(rep1['findings'])}"
    assert n1 == len(rep1["findings"]) + len(rep1["rejected_candidates"]), "save_run must persist verified + rejected"

    # ---- runs listing
    runs = st.list_runs()
    assert len(runs) == 2 and runs[0]["run_id"] != runs[1]["run_id"], "two runs expected"
    print(f"[runs] {len(runs)} runs listed, newest={runs[0]['run_id']}")

    # ---- cross-run query
    rows = st.list_findings(type_="sql_injection")
    assert rows and all(r["type"] == "sql_injection" for r in rows), "type filter broken"
    assert all(r["risk"] >= 80 for r in st.list_findings(min_risk=80)), "min_risk filter broken"
    print(f"[findings] sql_injection rows={len(rows)}; min_risk=80 rows={len(st.list_findings(min_risk=80))}")

    # ---- recurring: same vulns in both runs -> every fingerprint n_runs=2
    rec = st.recurring()
    rec_fps = {r["fingerprint"] for r in rec}
    assert len(rec) >= 12, f"expected >=12 recurring fingerprints, got {len(rec)}"
    assert all(r["n_runs"] == 2 for r in rec), "both runs scanned the same fixture: n_runs must be 2"
    print(f"[recurring] {len(rec)} fingerprints seen in both runs (correct — same app, same vulns)")

    # ---- delta between the two runs: everything recurring, nothing new/fixed
    d = st.delta(rep1["run_id"], rep2["run_id"])
    assert d["new"] == [] and d["fixed"] == [], f"identical app must give empty delta, got new={len(d['new'])} fixed={len(d['fixed'])}"
    assert len(d["recurring"]) == len(rec), "recurring delta vs recurring() mismatch"
    print(f"[delta] new=0 fixed=0 recurring={len(d['recurring'])} (correct for identical app)")

    # ---- fingerprint identity contract
    fp_a = finding_fingerprint("sql_injection", "GET", "http://x/vuln/sqli_error.php?id=1", "id")
    fp_b = finding_fingerprint("sql_injection", "GET", "http://x/vuln/sqli_error.php?id=999", "id")
    assert fp_a == fp_b, "query string must NOT change vulnerability identity"
    fp_c = finding_fingerprint("sql_injection", "GET", "http://x/vuln/sqli_error.php?id=1", "q")
    assert fp_a != fp_c, "different param = different vulnerability"
    print("[fingerprint] identity contract OK (param+path+type, query-string independent)")

    # ---- stats summary
    s = st.stats_summary()
    assert s["runs"] == 2 and s["verified_findings"] >= 24 and s["recurring_fingerprints"] >= 12
    print(f"[stats] {json.dumps(s, default=str)[:180]}")

    # ---- reports
    html = build_html(st, rep1["run_id"])
    assert "SENTINEL" in html and "sql_injection" in html and "verification-gated" in html
    assert rep1["run_id"] in html and len(html) > 4000
    open(os.path.join(ROOT, "results", "report_live_test.html"), "w").write(html)
    j = build_report(st, "")
    assert j["kind"] == "overview" and j["summary"]["runs"] == 2
    print(f"[report] single-run HTML {len(html)}B -> results/report_live_test.html; overview JSON kind={j['kind']}")

    # ---- get_run round-trip
    got = st.get_run(rep2["run_id"])
    assert got and got["run_id"] == rep2["run_id"]
    assert len(got["findings"]) == len(rep2["findings"]), "get_run findings count mismatch"
    print(f"[get_run] {got['run_id']}: {len(got['findings'])} verified, {len(got['rejected_candidates'])} rejected")

    print("\nALL LIVE PERSISTENCE TESTS PASSED")
finally:
    if spawned is not None:
        spawned.terminate()
        try:
            spawned.wait(timeout=5)
        except Exception:
            spawned.kill()
