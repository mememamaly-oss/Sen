"""Repro determinism check — exercises the proof.py AEAD path end-to-end
(canonical -> derive -> sign -> aead -> merkle -> verify) via the default
pipeline. Any drift in the AEAD or signature layers raises DriftError /
fails require_determinism. Run from repo root."""
import sys

from sentinel.repro import (DeterministicExecutor, default_pipeline,
                            require_determinism)

ex = DeterministicExecutor(default_pipeline(), name="crypto-swap-check")
runs = [ex.execute({"probe": "env1-crypto-remediation"}, seed=20261030)
        for _ in range(3)]
require_determinism(runs)
names = [st["name"] for st in runs[0]["steps"]]
assert names == ["canonical", "derive", "sign", "aead", "merkle", "verify"], names
# _step_verify decrypts the AEAD box and compares against the canonical
# input — its success IS the proof that encrypt+decrypt worked end-to-end.
final = runs[0]["final_payload"]
assert final == b'{"probe":"env1-crypto-remediation"}', final[:80]
print("REPRO OK: 3 executions, require_determinism passed; all 6 steps "
      "ran (sign/aead/merkle/verify) and the verify step decrypted the "
      f"AEAD box back to the canonical input ({len(final)} bytes)")
