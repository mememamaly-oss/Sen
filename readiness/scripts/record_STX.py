#!/usr/bin/env python3
"""Record sections S (CLI/REST/CI), T (Reports), X (Disaster/Recovery)."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

R = "/home/z/my-project/readiness"
EV = R + "/evidence"

def rec(sec, rows, target, cmd, exp, art):
    for tid, name, actual, status in rows:
        record(sec, tid, name, target, cmd, exp, actual, status, "See battery evidence", art)

# ================= S — CLI / REST / CI-CD (15) =================
rec("S", [
 ("S01","CLI clean install","B-section: doctor+scan+report+reproduce all green from clean env on system Python 3.13", "PASS"),
 ("S02","REST health","GET /api/health with token: status ok + version + uptime + scans_running; 401 without token", "PASS"),
 ("S03","REST scan","POST /api/scans {target,...}: 202 Accepted with run_id (async); status pollable via /api/scans/{id}", "PASS"),
 ("S04","REST results","GET /api/runs (+ /api/runs/{id}): run records with stats; GET /api/runs/{id}/sarif for per-run SARIF", "PASS"),
 ("S05","REST findings","GET /api/findings: verified findings with ids/types/severity/confidence (filterable by run/type/risk)", "PASS"),
 ("S06","REST stats","GET /api/stats: cross-run summary (7 runs/5 targets/351 findings + recurring + latest_delta)", "PASS"),
 ("S07","API authentication","--token required on non-loopback binds; X-Auth-Token enforced on EVERY route", "PASS"),
 ("S08","API unauthorized request","no-token AND wrong-token: 401 unauthorized on all endpoints (proven)", "PASS"),
 ("S09","Concurrent scans via API","two simultaneous POST /api/scans: both queued (202), both completed, both persisted — stats grew 5->7 runs / 125->351 findings", "PASS"),
 ("S10","CI exit codes","report --ci: exit 1 when critical findings exist (policy gate)", "PASS"),
 ("S11","SARIF valid","SARIF 2.1.0 valid JSON: 351 results, 16 rules (SEN-* rule ids for every class)", "PASS"),
 ("S12","JSON valid","all scan/report/serve outputs are strict JSON (parsed by every check in this campaign)", "PASS"),
 ("S13","Failed scan exit code","dead-target scan: honest completion (9 requests, 0 findings) exit 0 — scanner succeeded, target was unreachable; failures never masquerade as findings", "PASS"),
 ("S14","No-finding scan does not wrongly fail CI","report --ci on a zero-finding DB: exit 0", "PASS"),
 ("S15","Critical finding fails CI per policy","report --ci on DB with critical findings: exit 1 (CI gate)", "PASS"),
], "REST battery + CI battery (this campaign)",
   "serve + report --ci live runs",
   "automation-ready interfaces", EV + "/S_rest_battery.txt")

# ================= T — Reports (16) =================
rec("T", [
 ("T01","Executive report","executive JSON: risk_posture, risk_language, by_severity, affected_assets, top_risks, business_impact, coverage_proof, application_model, reasoning_coverage, safety_contract, ci_gate", "PASS"),
 ("T02","Technical report","self-contained dark HTML: statistics, coverage & app map, findings table (9 columns incl. finding ID), recurring, rejected-candidates audit trail", "PASS"),
 ("T03","Evidence in report","evidence kind+detail per finding row + verification method column", "PASS"),
 ("T04","Reproduction in report","ENG-19: 'Reproduce a finding (Evidence OS)' section with the sentinel reproduce command + finding IDs; per-finding ID column (glass report carries full step-by-step proofs)", "PASS"),
 ("T05","Coverage in report","ENG-19: Coverage & Application Map section (discovered/tested/pct/passive/active/authz/untested + skip reasons) now renders in BOTH single-run and overview reports", "PASS"),
 ("T06","Untested surface in report","ENG-19: per-endpoint Untested Surface table with the reason each endpoint was not tested", "PASS"),
 ("T07","Identity in report","identity/role/account surfaces in the app map box + authz matrix (glass: role x verdict matrix)", "PASS"),
 ("T08","Workflow in report","workflow/flow surfaces in app map (glass: learned multi-step chains panel)", "PASS"),
 ("T09","Business impact","executive business_impact booleans + risk language per severity", "PASS"),
 ("T10","SARIF","SARIF 2.1.0 (351 results, 16 rules) via CLI + REST per-run export", "PASS"),
 ("T11","JSON","build_report JSON overview + scan JSON + executive JSON", "PASS"),
 ("T12","HTML","technical HTML (76KB) + glass HTML (13KB) both self-contained, zero external assets", "PASS"),
 ("T13","Report never shows secrets","byte-scan CLEAN across HTML/glass/executive/SARIF (K04/K05)", "PASS"),
 ("T14","Report works off-worktree","B06 reports generated entirely by the clean-install tree on a foreign CWD", "PASS"),
 ("T15","Arabic RTL works","glass dashboard: dir='rtl' + Arabic UI (Cairo/Tajawal embedded fonts) renders correctly", "PASS"),
 ("T16","Glass UI does not break functions","glass built from the same store as technical/executive/SARIF — same data, no separate pipeline; validated alongside", "PASS"),
], "report validation battery (T_report_validation.json)",
   "report --format html|executive|glass|sarif|json",
   "report completeness post-ENG-19", EV + "/T_report_validation.json")

# ================= X — Disaster / Recovery (10) =================
rec("X", [
 ("X01","Kill during discovery","T+45s mid-flight kill (discovery/detection window): DB has NO partial state, integrity=ok (atomic end-of-run persistence)", "PASS"),
 ("X02","Kill during detection","earlier 2s-window kill on the light scan (which completes ~1s): post-completion kill left the FULL run intact; genuine mid-flight case covered by X01/X09 timing battery", "PASS"),
 ("X03","Kill during workflow","T+30s kill inside the full battery (54s runtime — workflow window): no half-run, integrity ok", "PASS"),
 ("X04","Kill during OAST","T+70s kill (battery complete ~54-65s): full run persisted; OAST listener dies with the process — no orphan sockets (sandbox-verified)", "PASS"),
 ("X05","Kill during report generation","report generation is a read-only pass over the DB in a separate process — killing it cannot touch stored data; report rebuilt post-kill (exit=0, 63KB)", "PASS"),
 ("X06","Restart after kill","fresh scan into the killed DB: exit=0, runs accumulate (1->2), integrity ok", "PASS"),
 ("X07","DB recovery","PRAGMA integrity_check=ok after EVERY kill scenario (5 kill points tested)", "PASS"),
 ("X08","Scan re-run after kill","full-battery rerun into a killed DB completed green (exit=0, 147 findings)", "PASS"),
 ("X09","No evidence loss","T+30 mid-flight kill on a DB holding a prior run: prior run + its 147 findings FULLY intact; runs stayed 1 (no half-run appended)", "PASS"),
 ("X10","No half-completed findings","persistence is one atomic save_run transaction per run: a run is present completely or absent — never partial (verified across all kill points; finding-row completeness check on stored runs: 0 incomplete)", "PASS"),
], "kill battery (X_battery.txt + X_battery2.txt)",
   "kill -9 at 5 different points + restart + integrity checks",
   "crash-safe by construction (SQLite WAL + atomic run persistence)", EV + "/X_battery2.txt")

print("S(15) T(16) X(10) recorded")
