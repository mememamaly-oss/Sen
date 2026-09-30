#!/usr/bin/env python3
"""Record sections G (Digital Twin), H (Reasoning), I (Evidence/Proof)."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

R = "/home/z/my-project/readiness"
EV = R + "/evidence"

# ================= G — Digital Twin (17) =================
G = [
 ("G01","Users discovered","fixture twin identity nodes: 3 (demo-admin, bob, carol from authz sessions); ginjuice live: 1 (carlos)"),
 ("G02","Roles discovered","fixture role nodes: 2 (admin, user) with has_role edges; ginjuice: 1 role"),
 ("G03","APIs discovered","surface nodes: fixture 76, ginjuice live 28 (write 3 / read 12 classified)"),
 ("G04","Parameters discovered","parameter nodes: fixture 52, ginjuice live 14, each with carries edges to its surface"),
 ("G05","Entities discovered","entity nodes: fixture 7, ginjuice live 3 (Order/Message/Session — typed via camelCase/snake_case vocabulary)"),
 ("G06","Objects discovered","workflow resource objects: fixture TRF-xxxx transfer objects + foreign SORD-0001 (mints/consumes edges: 6 mints, 3 consumes)"),
 ("G07","States discovered","state nodes: fixture 3 (PENDING/EXECUTED/CANCELLED from execution-marker vocabulary + rollback paths)"),
 ("G08","Workflows discovered","workflow nodes: fixture 3 learned flows (+9 workflow_step nodes); live targets honest (0 flows where apps have no wizard chains)"),
 ("G09","Actions discovered","action vocabulary: state-changing surfaces classified (surfaces_write) + declared_privilege options (wire=admin-only) — planner evaluates 26 operations"),
 ("G10","Relations between elements linked","352 edges in fixture twin across 11 edge kinds (has_role/authenticated/carries/typed_as/gates/step_of/transitions_to/mints/consumes/produced_finding/exposed_secret/declared_privilege/generated_hypothesis)"),
 ("G11","Identity linked to Object","cross_user proof links identity B to A's object (authz_context attacker=role:user object_owner=primary); has_role + gates edges connect identities to surfaces"),
 ("G12","Object linked to Workflow","mints/consumes edges: producer step mints TRF id, final step consumes it (resource linkage in the graph)"),
 ("G13","Workflow linked to Finding","produced_finding edges: 184 in fixture twin (every finding hangs off its surface/flow); ginjuice 35"),
 ("G14","No fake nodes","twin fuses ONLY observed artifacts (endpoints+paramintel+authz matrix+learned flows+findings+masked secrets+coverage reasons) — zero speculative nodes; unit_twin_graph_fusion asserts the fusion is derived, not invented"),
 ("G15","Every important node traceable to evidence","surfaces carry discovery source (seed/crawl:html/js:static/robots.txt/dom:browser); findings carry request ids + proofs; params carry their endpoints; hypotheses carry premises from the access matrix"),
 ("G16","Twin changes when the app changes","G16 experiment: added a reachable page+form -> twin 198->201 nodes, 152->154 edges, 46->47 surfaces (delta exactly reflects the app change)"),
 ("G17","No stale data across scans","G17 experiment: same app scanned twice on FRESH DBs -> byte-identical twin summaries (198/152/46 both runs); no cross-run carryover"),
]
for tid, name, actual in G:
    record("G", tid, name, "fixture twin (374 nodes/352 edges) + ginjuice live twin (84/59) + G16/G17 experiments",
           "twin CLI/scan stats + graph experiments",
           "twin is a faithful, evidence-backed model", actual, "PASS",
           "Evidence: B04 twin stats, C03 twin stats, G16_G17_verdict.json",
           EV + "/G16_G17_verdict.json")

# ================= H — Reasoning Engine (11) =================
H = [
 ("H01","Hypotheses from real data","fixture: 32 hypotheses generated from the access matrix + param intel + workflow model (e.g. R-ADMIN-SURFACE-LOW-ROLE premise quotes the actual matrix row); ginjuice live: 2 from real surface behavior"),
 ("H02","Correct hypothesis -> Verified","fixture: 11 verified; ginjuice: R-TOKENLESS-WRITE on POST /catalog/cart verified (the engine-fired CSRF)"),
 ("H03","Wrong hypothesis -> Rejected","fixture: 19 refuted (status tested:refuted); ginjuice: 1 refuted"),
 ("H04","Untestable hypothesis -> clear reason","fixture: 2 untestable with reason 'precondition_absent' (untestable_reasons dict)"),
 ("H05","Final decision never depends on LLM","reasoning.py is 100% deterministic pattern evaluation over the twin (no LLM/network imports anywhere in the codebase — verified: zero non-stdlib imports; H05 also backed by benchmark determinism x3 identical)"),
 ("H06","Every hypothesis has Preconditions","proof preconditions list (class-aware, e.g. 'a learned multi-step flow with resource linkage and a state oracle', 'explicit operator permission (--logic-active)')"),
 ("H07","Every hypothesis has Attack Path","hypothesis structure carries chain (identity->surface), pattern, plan (planner classification), test method"),
 ("H08","Every hypothesis has Verification","resolution maps to tested:verified / tested:refuted / untestable:<reason>; findings only from verified"),
 ("H09","Verified hypothesis has Evidence","verified hypotheses link to findings (generated_hypothesis edges) which carry full proofs (request/response/oracle)"),
 ("H10","No unnecessary duplicate hypotheses","32 hypotheses for 184 findings — dedup by pattern+surface; determinism x3 identical sets"),
 ("H11","No guess converted to Finding","findings only via verified detectors/hypotheses (VR system + state-oracle proofs); benchmark FP=0 across 73 GT rows"),
]
for tid, name, actual in H:
    record("H", tid, name, "fixture reasoning (32 gen/11 ver/19 ref/2 untest) + ginjuice live (1v/1r)",
           "reasoning engine lifecycle",
           "deterministic hypothesis lifecycle", actual, "PASS",
           "Evidence: B04/C03 reasoning stats + D_E_H_extract.json H_sample",
           EV + "/D_E_H_extract.json")

# ================= I — Evidence / Proof (15) =================
I = [
 ("I01","Hypothesis in proof","attack_hypothesis field on every proof (e.g. 'a workflow step executes an object in a cancelled/rejected state')"),
 ("I02","Preconditions in proof","preconditions list (class-aware) on every proof"),
 ("I03","Identity in proof","identity field ('primary scan session' / authz_context 'attacker=role:user object_owner=primary')"),
 ("I04","Request in proof","requests[] with method/url/parameter"),
 ("I05","Response in proof","responses[] with kind/detail/request_id"),
 ("I06","State before","state_before populated for all 8 business-logic proofs post-ENG-18 (e.g. 'TRF-0006 800001 1111 ach CANCELLED'); request-level classes carry the differential in responses (documented design)"),
 ("I07","State after","state_after populated ('... EXECUTED' etc.) — regression-guarded forever by the ENG-18 assertion in regression_phase58"),
 ("I08","Impact in proof","impact.grade (proven/indicated) + statement + safe_proof note"),
 ("I09","Verification in proof","verification.method (oracle:workflow-state-delta / re-test / differential) + passed + rounds + notes"),
 ("I10","Reproduction recipe","ordered step list (authenticate -> walk flow on fresh session -> send the attack request with the canary -> expect the same evidence kind)"),
 ("I11","Confidence","confidence values 0.5-0.98 calibrated per class"),
 ("I12","Independent reviewable evidence","evidence_chain (request/response custody) inside impact; proofs stored in DB independent of scan process"),
 ("I13","sentinel reproduce returns the result","B07: full proof package exported for F-a93c789266 (15 fields incl. verification passed=true)"),
 ("I14","Reproduction after program close","B07 executed in a separate OS process from a reinstalled tree — recipe intact"),
 ("I15","Reproduction after DB reopen","B07 read the finding from a DB opened fresh by the new process"),
]
for tid, name, actual in I:
    record("I", tid, name, "B04 proofs (40) + B07 reproduce output",
           "Evidence OS proof completeness",
           "every finding carries a complete proof file", actual, "PASS",
           "ENG-18 fix (found by THIS campaign) completed the state-pair fields; permanent regression guard added",
           EV + "/B07_reproduce_reinstall.json")

print("G (17), H (11), I (15) recorded")
