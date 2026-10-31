# Sen transparency log

An append-only, hash-chained, Ed25519-signed record of published scan
runs. Anyone can verify — with this repository's published public key
and nothing else — that a given findings set is exactly what was signed,
and that the log has not been edited.

```
log.jsonl     the log itself (one signed JSON entry per line, chain-linked)
pubkey.hex    the pinned Ed25519 public key (32 bytes, hex)
```

Evidence bundles live in `evidence/transparency-log/<run_id>/`
(findings + per-finding Merkle inclusion proofs + the entry).

## Verify (30 seconds)

```bash
pip install cryptography
python3 tools/independent_verify.py verify-log transparency-log/log.jsonl \
    --pubkey transparency-log/pubkey.hex

# a specific run, end to end:
python3 tools/independent_verify.py verify-bundle evidence/transparency-log/<run_id> \
    --pubkey transparency-log/pubkey.hex --log transparency-log/log.jsonl
```

The verifier (`tools/independent_verify.py`) implements the published
format from scratch and shares **no code** with the signer — a bug in
the signer cannot hide in a verifier built from the same source.

## Why this matters

A scanner's report is a claim. This log makes the claim checkable:
every finding hashes into a Merkle root; the root, the run identity and
the finding count are signed; the signatures chain into an append-only
ledger committed to the repository. Editing one byte of any finding,
one digit of any signature, one node of any Merkle path — or re-signing
anything with a different key — breaks verification with a specific
error message. The tamper battery that proves all of this runs in CI on
every push (`tests/test_transparency_log.py`, artifacts under
`evidence/transparency-log/selftest/`).

## Honest limitations

- An append-only log inside a git repository is tamper-**evident**, not
  tamper-proof: a party who controls the repository can rewrite history,
  but the rewrite is visible (and breakes any existing clone's chain).
- The signing seed is held by the project (locally, and in the
  `TRANSPARENCY_SEED` CI secret). Compromise voids guarantees from the
  moment of compromise; recovery is a key-rotation entry (procedure in
  `docs/transparency-log-format.md` §7).
- Entries are appended for **recorded** runs — runs whose evidence
  bundles are committed. CI runs on every push; not every CI run is
  recorded in the log. Every *recorded* run is fully verifiable.

Format specification (enough to rebuild a verifier in any language):
`docs/transparency-log-format.md`.
