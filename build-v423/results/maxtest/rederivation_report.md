# Maxtest — Phase 4: Independent Re-derivation Report

Zero-trust re-derivation of every VERIFIED claim from the RAW journals
with fresh logic sharing no code with the engine's verdict paths.
**6/6 claims independently re-derived (MATCH)**

- [MATCH] **JS sql_injection VERIFIED** — journal re-derivation: base->200, quote->500 w/ SQLITE_ERROR, doubled->200 (found base=200, quote=500, pair=200)
- [MATCH] **JS credential_exposure VERIFIED** — 3 journal fetches of http://localhost:3100/rest/memories; secret-shaped assignment present in fresh body: True; class=generic_secret_assignment
- [MATCH] **JS L3 sql_version_oracle VERIFIED** — raw probe journal: control 4000B vs 30B (sep=True), version 4000B vs 30B (sep=True)
- [MATCH] **WG sql_injection x9 VERIFIED** — 9/9 re-derived with raw-journal differentials; problems: []
- [MATCH] **JuiceShop L2 VERIFIED paths evidence refs** — 1 VERIFIED paths; 4/4 refs resolve in the raw journal; missing=[]
- [MATCH] **WebGoat L2 VERIFIED paths evidence refs** — 11 VERIFIED paths; 44/44 refs resolve in the raw journal; missing=[]
