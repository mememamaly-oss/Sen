# Maxtest — Phase 2: Attack-the-Tool Battery

Adversarial inputs against the tool itself (per the supervisor order).
**4/4 attacks withstood**

- [PASS] **A1 apaths on hostile result** — rc=0 crash=False paths=4 verified-without-evidence=0
- [PASS] **B1 L3 refuses destructive smuggles** — all 6 destructive-shape findings REFUSED at planning, no crash
- [PASS] **C1 hostile-server scan (no crash/hang)** — completed in 0.1s, findings=6, no exception
- [PASS] **D1 report injection (escaped)** — raw <script> payload NOT present verbatim in the exported HTML
