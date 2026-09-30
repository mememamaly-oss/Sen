#!/usr/bin/env python3
"""Record section Z (commercial value proofs) — all docs now exist in the shipped zip."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

Z = [
 ("Z01","5-minute demo","docs/DEMO_5MIN.md — scripted 5-minute demo: the one-line message, minute-by-minute flow, Q&A table (audience: technical leaders / security buyers / engineers)"),
 ("Z02","Re-runnable benchmark","docs/BENCHMARK_AUDIT.md defines benchmarking as a PROCEDURE any third party re-executes: exact commands, fixture ownership (ENG-20 fresh instance), seed, expected identical outputs; proven by the campaign's x3 runs"),
 ("Z03","Benchmark with real TP and TN","GT v10 = 73 rows: 38 TRUE positives (real planted vulnerabilities) and 35 TRUE negatives (hardened twins that must stay silent) — both directions real, FP=0/FN=0"),
 ("Z04","Ground-truth construction documented","BENCHMARK_AUDIT: every positive has a shape-matched hardened twin (/vuln/* vs /safe/*, vulnerable vs safe wizard); GT file carries SHA-256 recorded in every benchmark report"),
 ("Z05","Benchmark limits documented","BENCHMARK_AUDIT scope + KNOWN_LIMITATIONS #10: the fixture proves discipline, not universal field performance; live-target results vary by surface"),
 ("Z06","Architecture document","docs/ARCHITECTURE_IP.md: 6-layer architecture, the deterministic-by-construction doctrine, data flow"),
 ("Z07","IP/package document","ARCHITECTURE_IP: the 5 technical moats + the IP file map (which files embody which moat)"),
 ("Z08","Threat model for SENTINEL","docs/THREAT_MODEL.md (NEW): assets, 8 attack surfaces with controls mapped to tests, out-of-scope, assumptions"),
 ("Z09","Security model","docs/SECURITY_MODEL.md (NEW): 5 principles, control layers table, tenancy model, ENG defect lifecycle, liability boundaries"),
 ("Z10","Installation guide","docs/INSTALLATION_GUIDE.md (NEW): requirements, source+bundle installs, doctor interpretation, playwright, troubleshooting — validated by the Y01 clean-room install"),
 ("Z11","User guide","docs/USER_GUIDE.md (NEW): the full 11-step operator journey (anonymous/auth/token/authz/workflow/reports/REST/vault) — validated end-to-end by the Y walkthrough"),
 ("Z12","API/CLI documentation","docs/API_CLI_REFERENCE.md (NEW): every flag, every REST route, exit codes — validated against live REST battery"),
 ("Z13","Known limitations","docs/KNOWN_LIMITATIONS.md (NEW): 12 explicit limitations incl. GraphQL/WS/branching/JSON-login/proof-cap — honest by design"),
 ("Z14","Supported environments","docs/SUPPORTED_ENVIRONMENTS.md (NEW): tested (Python 3.12/3.13, Linux, 4 live target stacks) / expected / constraints"),
 ("Z15","Release/versioning policy","docs/RELEASE_POLICY.md (NEW): semver, the 7 non-negotiable release gates, ENG defect policy, package contents"),
]
for tid, name, actual in Z:
    record("Z", tid, name, "shipped zip docs/",
           "documentation review against the checklist",
           "document exists and covers its checklist item", actual, "PASS",
           "All 8 new docs written during this campaign; validated by the Y walkthrough",
           "/home/z/my-project/download/sentinel-4.0.0-source.zip")
print("Z (15) recorded")
