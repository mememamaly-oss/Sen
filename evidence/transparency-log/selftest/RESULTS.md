# Transparency-log tamper battery — results

Independent verifier: `tools/independent_verify.py` (subprocess; zero code shared with the signer).

| case | expectation | result |
|---|---|---|
| case_1_untampered | verify-log rc==0 AND verify-bundle rc==0 | PASS (rc=0) |
| case_2_tamper_evidence | verify-bundle rc==1 (tamper rejected) | PASS (rc=1) |
| case_3_tamper_signature | verify-bundle rc==1 (tamper rejected) | PASS (rc=1) |
| case_4_tamper_merkle_path | verify-bundle rc==1 (tamper rejected) | PASS (rc=1) |
| case_5_different_keypair | verify-bundle rc==1 (entry signed with a different keypair is rejected under the pinned key) | PASS (rc=1) |

**All checks passed: True**

Reproduce: `python3 tools/transparency_selftest.py --out <dir>`
