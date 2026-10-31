# Verifying a Sen scan report independently

Every enriched Sen report (`result.json` / `scan.json`) carries an
`audit` section that makes its findings verifiable with open tools and
**zero access to Sen's code**. The literal recipe is embedded in the
report itself (`audit.recipe`); this page adds a ready-made verifier and
the transparency-log layer.

## The guarantees, stated honestly

- The **Merkle root** in `audit.merkle_root` covers every finding in
  `report.findings` (with the declared volatile keys — timings, notes,
  stats — stripped recursively, so one seed always yields the same
  root). Changing any finding changes the root.
- The **Ed25519 signature** covers
  `SHA256(run_id || 0x00 || merkle_root || 0x00 || findings_count || 0x00 || header)`
  and is made with a keypair deterministically derived from the run
  **seed** — which is embedded in the report and public by design.
  This binds the findings, the count, and the run identity together:
  it proves the report was not modified after signing. It is an
  integrity mechanism, not an identity system.
- The **transparency log** (`transparency-log/log.jsonl`) adds the
  project-level layer: entries signed with the project's pinned key and
  hash-chained, so published runs cannot be silently edited or removed.
  Format: `docs/transparency-log-format.md`.

## The one-command way

`tools/independent_verify.py` implements the whole recipe from the
public specification using only the standard library and the audited
`cryptography` package — it imports nothing from Sen:

```bash
pip install cryptography

# any enriched report
python3 tools/independent_verify.py verify-report result.json

# the public transparency log (chain + pinned-key signatures)
python3 tools/independent_verify.py verify-log transparency-log/log.jsonl \
    --pubkey transparency-log/pubkey.hex

# one evidence bundle end-to-end (findings → leaves → proofs → entry)
python3 tools/independent_verify.py verify-bundle evidence/transparency-log/<run_id> \
    --pubkey transparency-log/pubkey.hex --log transparency-log/log.jsonl
```

Exit code `0` = verified. Any tampering — a byte of a finding, a digit
of the signature, a node of a Merkle path, or an entry signed with a
different key — is rejected with a specific reason.

## The manual way (no Sen files needed at all)

For a report `R` with findings list `F`:

1. For each finding `f` in `F`, delete the volatile keys
   (`notes, duration, duration_s, wall_time, wall, elapsed, timestamp,
   dur_s, latency, latency_ms, time_ms, time, generated_at, date, stats,
   requests, started_at, finished_at, verified_at`) recursively, then
   serialize with sorted keys and compact separators (UTF-8, no escaped
   non-ASCII): `leaf_i = SHA256(utf8(canonical(f_i)))`.
2. Build the tree: pair bottom-up, `node = SHA256(left || right)`;
   when a level has an odd count, duplicate its last hash once. The root
   must equal `R.audit.merkle_root` (empty set root is `SHA256(b"")`).
3. Digest: `SHA256(run_id || 0x00 || merkle_root || 0x00 ||
   findings_count || 0x00 || canonical({"run_id","seed","scanner","target"}))`.
4. Derive the keypair: HKDF-SHA256, salt
   `SENTINEL-axis14-ed25519-HKDF-SHA256-v1`, info
   `axis14-ed25519-keypair`, length 32, IKM = the report's `seed`
   (≥64-char even-length ASCII hex decodes as hex; otherwise its UTF-8
   bytes). Verify the Ed25519 (RFC 8032) signature `audit.signature_b64`
   of the digest under `audit.public_key_b64` (32 raw bytes, base64).

`openssl` path for step 4: build the SPKI PEM
`302a300506032b6570032100` || pubkey, save the digest as `msg.bin` and
the signature as `sig.bin`, then
`openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin -sig sig.bin`.
