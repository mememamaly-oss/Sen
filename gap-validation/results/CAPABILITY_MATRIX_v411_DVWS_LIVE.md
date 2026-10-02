# SENTINEL v4.1.0 — Capability Matrix

**Generated from run `run-50068c1562` on `http://127.0.0.1:8888/`** — every number below is derived from the run's stored artifacts (coverage dimensions, engine stats, the boundary registry); this file is MACHINE-GENERATED (`sentinel capability-matrix`), never hand-written.

| Capability | Discovered | Tested | Verified | Unsupported / reason |
|---|---|---|---|---|
| REST | 32 | 31 | 31 |  |
| Parameters | 15 | 15 | 15 |  |
| Workflow | 0 | 0 | 0 | no workflow surface was observed on this target |
| Branching | 0 | 0 | 0 | no workflow branch surface was observed on this target |
| State | 0 | 0 | 0 | no state surface was observed on this target |
| GraphQL | 0 | 0 | 0 | no graphql surface was observed on this target |
| WebSocket | 12 | 12 | 12 |  |
| Authorization | 0 | 0 | 0 | no authorization surface was observed on this target |
| Identities | 0 | 0 | 0 | no identity surface was observed on this target |
| Browser | 1 | 1 | 1 |  |
| OAST | 1 | 0 | 0 |  |
| Evidence | 1 | 0 | 0 |  |
| GraphQL operations | 0 | 0 | 0 | no GraphQL endpoint observed |
| WebSocket channels | 12 | 12 | 12 |  |
| Business-logic flows | 0 | 0 | 0 | workflow engine disabled |

## Boundary account (what this run could NOT test, and why)

- boundary records: **48** · unresolved: **15**
- by state: `{"BLOCKED_BY_SAFETY": 2, "NOT_DISCOVERED": 1, "TESTED": 33, "UNTESTABLE": 12}`

| Category | State | Reason | Remediation |
|---|---|---|---|
| crawl/destructive-get | BLOCKED_BY_SAFETY | path names a destructive/global-reset operation — a plain GET is state-changing on this surface (sta | verify the route's behavior manually on a staging copy if its coverage matters |
| graphql | NOT_DISCOVERED | no GraphQL endpoint observed (path-shape, JS extraction and well-known probes all empty) |  |
| passive/destructive-get | BLOCKED_BY_SAFETY | path names a destructive/global-reset operation — even a passive baseline GET is state-changing on t | verify the route's behavior manually on a staging copy if its coverage matters |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/cross-user | UNTESTABLE | no configured identity markers to listen for | configure accounts (--authz) with markers to enable cross-user channel testing |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |
| websocket/protocol | UNTESTABLE | channel is silent to passive listening and elicitation did not produce a readable reply (not authori | supply the message schema or capture samples to enable content analysis |

## The honesty contract

- A capability with 0 discovered surfaces is reported as **NOT_DISCOVERED** — never as tested.
- No dimension claims 100% while unexplained untested items exist.
- Every finding carries reproducible evidence; every twin node carries provenance; memory is context, never evidence.
