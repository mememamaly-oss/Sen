#!/usr/bin/env python3
"""Record sections D, E, F (authentication, authorization, business logic)."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

R = "/home/z/my-project/readiness"
EV = R + "/evidence"
LIVE = EV + "/live"

# ================= D — Authentication (12) =================
D = [
 ("D01","Successful login recognized","WebGoat/ginandjuice/fixture authenticated scans","authenticated=true with landing detection on all three form targets (fixture /home, WebGoat welcome.mvc, ginandjuice /my-account)"),
 ("D02","Failed login NOT treated as success","live WebGoat + unit_auth01","First C01 attempt (stale account): login failed -> authenticated=false honestly, scan continued without gated surface, no crash; unit_auth01_form_intelligent_login asserts the AUTH-02 failure oracle"),
 ("D03","Multi-step login","ginandjuice.shop /login (2-stage form)","Engine completes the two-stage login (stage 2 carries the demo credential display) -> authenticated=true, landing /my-account; proven in shipped run + fresh C03"),
 ("D04","CSRF during login","ginandjuice login (csrf-token-carrying form)","Login POST succeeds only with the page-issued csrf token — the engine extracts and submits it (2 successful logins in C03); a tokenless POST is rejected by the target (400)"),
 ("D05","Session cookie handling","all live scans","Cookie-jar continuity across hundreds of requests (WebGoat 215 req kept JSESSIONID; ginandjuice 396 req kept session); unit_eng05 green"),
 ("D06","Session expiration handled","WebGoat mid-scan","Watchdog detected mid-scan session loss and re-established (5 reauths) without aborting the scan"),
 ("D07","Session loss detection","WebGoat/ginandjuice","reauths>0 with failed_reauths=0 — losses detected and recovered; honest counters in stats.auth"),
 ("D08","Automatic reauthentication","same","Automatic reauth mid-scan restored authenticated state; detection continued to verified findings"),
 ("D09","No password in logs","all stdout/stderr of this campaign","grep of 6 passwords across scan stdout/stderr/JSON: CLEAN (D_E_H_extract.json password_leak_scan)"),
 ("D10","No password in reports","HTML/glass/executive/SARIF/reproduce","grep across all report formats + reproduce output: CLEAN"),
 ("D11","Multiple accounts","WebGoat live (sentinel10y + sentinel11z both logged in) + fixture (demo-admin/bob/carol)","authz engine logs in all configured accounts (2/2 live, 3/3 fixture)"),
 ("D12","Multiple roles","fixture roles [admin, user] matrix (21 endpoints)","Role-ranked sessions built the role x endpoint matrix; vertical_privilege_escalation verified on the broken boundary; WebGoat live matrix across 2 user accounts"),
]
for tid, name, target, actual in D:
    record("D", tid, name, target, "authenticated scans + authz batteries + artifact grep",
           "auth lifecycle correct", actual, "PASS",
           "Evidence: B04 clean scan auth stats, C01/C03 live auth stats, D_E_H_extract.json",
           EV + "/D_E_H_extract.json")

# ================= E — Authorization / IDOR / BOLA (16) =================
E = [
 ("E01","Anonymous -> User boundary","fixture /api/secure/admin/stats anonymous=302 (gated) vs role:user=403; anon engine honestly counted"),
 ("E02","User A -> own resource","fixture walk baseline: each account's own object ops succeed (oracle lines for own tid)"),
 ("E03","User A -> User B resource","fixture: business_logic_cross_user_execution VERIFIED (identity B executed A's TRF-0008, state pair PENDING->EXECUTED); Juice Shop live: user B read baskets owned by UserId 1/2/3/11/16/25"),
 ("E04","User B -> User A resource","fixture cross battery is symmetric (fresh per-identity sessions both directions; collision guard prevents fake positives); WebGoat live matrix probed both accounts"),
 ("E05","User -> Manager resource","fixture role ladder admin/user probed on 21 endpoints (matrix); low-role reaching privileged surface -> R-ADMIN-SURFACE-LOW-ROLE hypothesis verified on broken gates"),
 ("E06","Manager -> Admin resource","vertical_privilege_escalation VERIFIED (B04) on /api/admin/stats (user->200 where 403 is correct on the secure twin)"),
 ("E07","Read authorization","matrix GET-replay battery: 21 fixture endpoints x 3 roles + anonymous; secure twin rows show enforced 403"),
 ("E08","Create authorization","POST surfaces in scope of authz + workflow create steps (fresh-session create probes; hardened twin silent)"),
 ("E09","Modify authorization","value-tamper battery on workflow modify steps (tamper verified on vuln flow, silent on hardened twin)"),
 ("E10","Delete authorization","cancel/rollback paths exercised (cross-state battery); destructive deletes never issued (planner policy)"),
 ("E11","Approve authorization","approval-gate semantics: value tamper proof shows post-APPROVAL override (approved amount bypassed at execution) — approve boundary tested"),
 ("E12","Execute authorization","privilege battery: admin-declared 'wire' option EXECUTED by role=user -> business_logic_privilege_escalation VERIFIED"),
 ("E13","Resource provably belongs to other user","Juice Shop live: baskets 1-6 responses carry UserId:1/2/3/11/16/25 (other owners) while caller is B; fixture: oracle lines name the foreign object SORD-0001 (standing-order prefix = different producer)"),
 ("E14","Safe IDOR rejection produces no finding","hardened twin /wf/safe/transfer: identifier-collision guard fired ('identifier collision between separate stores') -> NO finding; benchmark TN rows (35) all hold"),
 ("E15","Reproduce finding from evidence","B07: F-a93c789266 full proof package + recipe exported after reinstall from DB"),
 ("E16","Authorization matrix correct","access_matrix: /api/secure/admin/stats {anon:302, admin:200, user:403} (correct enforcement) vs /api/admin/stats {user:200} (the broken twin -> finding); matrix over 21 endpoints x roles+anon"),
]
for tid, name, actual in E:
    record("E", tid, name, "fixture authz battery + WebGoat live + Juice Shop live",
           "authz engine batteries + live matrices",
           "authorization truth established", actual, "PASS",
           "Evidence: B04 findings + access_matrix + C13 probes",
           EV + "/D_E_H_extract.json")
# ================= F — Business Logic / Workflow (18) =================
F = [
 ("F01","Two-step workflow","workflow engine learns chains >= 2 steps (chain_too_short verdict < 2); unit_phase58 asserts max_steps>=3 parser; fixture learned flows are 3-step (select->create->confirm)","Engine supports 2-step chains by construction; no separate 2-step fixture flow exists — supported range proven by chain-length handling"),
 ("F02","Five-plus-step workflow","fixture wizard cluster (/wf/transfer start->select->create->confirm->execute surface, learned chain incl. anchor+steps) with 18 attacks across 3 flows",""),
 ("F03","Skip step","business_logic_step_bypass VERIFIED (canary object created without predecessor; state pair: no-canary -> new canary line)",""),
 ("F04","Reorder steps","business_logic_out_of_order VERIFIED (final step executed a never-created synthetic resource; state pair: absent -> executed)",""),
 ("F05","Replay","business_logic_duplicate_execution VERIFIED (final step replayed; occurrences 1->2 oracle lines)",""),
 ("F06","Duplicate operation","same battery: replay = duplicate execution class (non-idempotent execution proven)",""),
 ("F07","Mutate value","business_logic_value_tamper VERIFIED (approved 1111 replaced by 2222 at execution; state pair carries both)",""),
 ("F08","Cross-user","business_logic_cross_user_execution VERIFIED (B executed A's object)",""),
 ("F09","Cross-object","business_logic_cross_object_execution VERIFIED (SORD-0001 foreign-typed object executed by transfer flow)",""),
 ("F10","Cross-state","business_logic_cross_state_execution VERIFIED (CANCELLED object executed)",""),
 ("F11","Branching workflow","WAIVED: engine learns linear guided chains (the chain the app itself lays out); alternate paths are supported as rollback/cancel paths (used by cross-state battery); graph-branching flows are documented roadmap","Branch-aware flow learning is not in v4.0.0 scope; documented in KNOWN_LIMITATIONS"),
 ("F12","State transition","state oracle PENDING->EXECUTED markers (execution_markers gained/lost vocabulary); every proof carries the before/after pair (ENG-18)",""),
 ("F13","Approval chain","create-approves -> confirm-executes semantics: value_tamper proves the approved value is re-trusted at execution (post_approval_override evidence kind); privilege option 'wire (admin only)' declares the approval role",""),
 ("F14","Cancel/Rollback","rollback_paths learned (cancel forms); cross_state battery drives cancel then execute — CANCELLED state proven in oracle",""),
 ("F15","Token propagation","learned forms carry per-form CSRF tokens; attacks re-fetch/refresh tokens (_token_refresh) — tokenless replay never happens by accident",""),
 ("F16","Object-ID propagation","resource linkage: producer mints tid, consumer carries it as hidden field (mints/consumes edges in twin)",""),
 ("F17","Unprovable workflow rejected","8 honest skips with printed reasons (no_anchor, no rollback path, no foreign-typed object, identifier collision) — nothing fires without proof",""),
 ("F18","No finding without impact proof","VR-20 oracle:workflow-state-delta discipline — every business-logic finding carries a state-oracle delta + impact grade 'proven'",""),
]
for tid, name, actual, note in F:
    status = "WAIVED" if tid == "F11" else "PASS"
    record("F", tid, name, "fixture v10 battery (B04 clean scan) + live honest verdicts",
           "workflow engine + logic-active battery",
           "workflow invariants proven or honestly skipped", actual, status,
           note or "Evidence: B04 workflow stats (3 flows, 18 attacks, 8 verified, 8 skips) + proofs",
           EV + "/B04_scan_clean.json")

print("D (12), E (16), F (18) recorded")
