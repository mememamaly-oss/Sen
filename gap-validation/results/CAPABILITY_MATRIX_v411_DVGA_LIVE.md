# SENTINEL v4.1.0 — Capability Matrix

**Generated from run `run-68f024cd5a` on `http://127.0.0.1:5013/`** — every number below is derived from the run's stored artifacts (coverage dimensions, engine stats, the boundary registry); this file is MACHINE-GENERATED (`sentinel capability-matrix`), never hand-written.

| Capability | Discovered | Tested | Verified | Unsupported / reason |
|---|---|---|---|---|
| REST | 24 | 22 | 22 |  |
| Parameters | 0 | 0 | 0 | no parameter surface was observed on this target |
| Workflow | 0 | 0 | 0 | no workflow surface was observed on this target |
| Branching | 0 | 0 | 0 | no workflow branch surface was observed on this target |
| State | 0 | 0 | 0 | no state surface was observed on this target |
| GraphQL | 1 | 1 | 1 |  |
| WebSocket | 9 | 9 | 9 |  |
| Authorization | 0 | 0 | 0 | no authorization surface was observed on this target |
| Identities | 3 | 3 | 3 |  |
| Browser | 1 | 1 | 1 |  |
| OAST | 1 | 0 | 0 |  |
| Evidence | 1 | 0 | 0 |  |
| GraphQL operations | 12 | 29 | 29 |  |
| WebSocket channels | 9 | 9 | 9 |  |
| Business-logic flows | 0 | 0 | 0 | workflow engine disabled |

## Boundary account (what this run could NOT test, and why)

- boundary records: **28** · unresolved: **15**
- by state: `{"BLOCKED_BY_PERMISSION": 2, "BLOCKED_BY_SAFETY": 5, "TESTED": 13, "UNTESTABLE": 8}`

| Category | State | Reason | Remediation |
|---|---|---|---|
| crawl/destructive-get | BLOCKED_BY_SAFETY | path names a destructive/global-reset operation — a plain GET is state-changing on this surface (sta | verify the route's behavior manually on a staging copy if its coverage matters |
| crawl/operator-exclusion | BLOCKED_BY_PERMISSION | surface excluded by the operator (--exclude-url): stateful GET routes that change target configurati |  |
| crawl/operator-exclusion | BLOCKED_BY_PERMISSION | surface excluded by the operator (--exclude-url): stateful GET routes that change target configurati |  |
| graphql/mutation-vocabulary | BLOCKED_BY_SAFETY | mutation(s) deletePaste, editPaste, importPaste carry non-additive vocabulary (edit/update/import/de | verify these mutations' authorization manually on a staging copy |
| graphql/state-query | BLOCKED_BY_SAFETY | query operation 'deleteAllPastes' carries state-changing vocabulary (server-side write semantics ins | verify the operation's authorization manually on a staging copy |
| graphql/state-query | BLOCKED_BY_SAFETY | query operation 'readAndBurn' carries state-changing vocabulary (server-side write semantics inside  | verify the operation's authorization manually on a staging copy |
| passive/destructive-get | BLOCKED_BY_SAFETY | path names a destructive/global-reset operation — even a passive baseline GET is state-changing on t | verify the route's behavior manually on a staging copy if its coverage matters |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |

## The honesty contract

- A capability with 0 discovered surfaces is reported as **NOT_DISCOVERED** — never as tested.
- No dimension claims 100% while unexplained untested items exist.
- Every finding carries reproducible evidence; every twin node carries provenance; memory is context, never evidence.
