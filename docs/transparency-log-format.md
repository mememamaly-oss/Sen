# Transparency log — wire format v1

This document specifies the Sen transparency log format precisely enough
that a compatible verifier can be built in any language, from this
document alone, without reading Sen's source code. A reference
implementation exists at `tools/independent_verify.py` (Python; standard
library + the `cryptography` package) — it deliberately imports nothing
from the Sen codebase, because a verifier that shares code with the
signer would also share its bugs.

## 1. Files

| Path | Content |
|---|---|
| `transparency-log/log.jsonl` | the append-only log: one JSON object per line, UTF-8, no BOM |
| `transparency-log/pubkey.hex` | the project Ed25519 public key (32 bytes, 64 lowercase hex chars + newline) |
| `evidence/transparency-log/<run_id>/` | one evidence bundle per logged run |

## 2. Log entry

One JSON object per line with exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `version` | int | `1` |
| `kind` | string | `"scan-run"` (only kind defined by v1) |
| `run_id` | string | the scan run identifier, as in the report |
| `scanner` | string | scanner identity string, e.g. `"sentinel-core/4.4.0"` |
| `target` | string | the scanned base URL |
| `label` | string | human tag, e.g. `"fixture:vulnapp"` or `"juice-shop:20.3.0"` |
| `seed` | string | the run seed — **public by design** (it is embedded in every report; it derives the per-run report key, §6) |
| `findings_count` | int | number of findings in the run |
| `merkle_root` | string | 64 lowercase hex — Merkle root over the canonical findings (§4) |
| `timestamp_ms` | int | UTC milliseconds, set by the signer at signing time (declared; verifiers do not check it against a clock) |
| `evidence` | string | repository-relative path of the evidence bundle |
| `prev_entry_hash` | string | 64 lowercase hex — the `entry_hash` of the previous entry; the FIRST entry uses 64 `"0"` characters (genesis) |
| `entry_hash` | string | 64 lowercase hex — see §3 |
| `signature` | string | 128 lowercase hex — see §3 |
| `public_key` | string | 64 lowercase hex — the signer's Ed25519 public key; **must equal the pinned `pubkey.hex`** |

## 3. Hashing and signing

**Canonical JSON** (`canon(x)`): `JSON` serialization with object keys
sorted lexicographically, separators `","` and `":"` (no whitespace),
UTF-8 encoded, non-ASCII characters NOT escaped (i.e. Python
`json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
or the moral equivalent in any language).

**entry_core** = the entry object restricted to exactly these 12 fields:
`version, kind, run_id, scanner, target, label, seed, findings_count,
merkle_root, timestamp_ms, evidence, prev_entry_hash`.

```
entry_hash = SHA256( UTF8( canon(entry_core) ) )          — 64 hex
signature  = Ed25519-Sign(project_private_seed, entry_hash as 32 RAW bytes)
public_key = Ed25519-PublicKey(project_private_seed)      — 32 raw bytes, hex
```

`Ed25519-Sign` is RFC 8032 pure Ed25519 (no context, no prehash). The
`project_private_seed` is the 32-byte transparency signing key held by
the project (see §7).

**Chain rule**: entry *n* must carry `prev_entry_hash` equal to the
`entry_hash` of entry *n-1*; entry 0 carries 64 zeros. Removing,
reordering, or editing any entry breaks the chain from that point on.

**Key pinning**: a verifier MUST verify every entry under the public key
it obtained out-of-band (the published `transparency-log/pubkey.hex`
shipped with the repository, or a copy the verifier holder trusts), and
MUST reject any entry whose `public_key` differs — even if the signature
is internally valid. Otherwise an attacker could re-sign the whole log
with their own key.

## 4. The Merkle construction over findings

**Volatile keys** — the following object keys are removed RECURSIVELY at
every depth from each finding before hashing (timing-bearing and
statistical data must never move a root):

```
notes, duration, duration_s, wall_time, wall, elapsed, timestamp,
dur_s, latency, latency_ms, time_ms, time, generated_at, date, stats,
requests, started_at, finished_at, verified_at
```

**Leaf for finding `f`**:
```
leaf = SHA256( UTF8( canon( strip_volatile(f) ) ) )
```

**Tree**: leaves in findings order, bottom-up; an internal node is
`SHA256(left || right)` over the 32-byte child digests; when a level has
an odd number of hashes, its LAST hash is duplicated once before pairing
(Certificate-Transparency-style convention). The root of a single-leaf
tree is the leaf itself. **The empty findings set has the constant root
`SHA256("")` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.**

## 5. Evidence bundle

Directory `evidence/transparency-log/<run_id>/` containing:

- `findings.json` — `{"findings": [ ... ]}` — the exact findings array of
  the run, in run order.
- `entry.json` — the exact log entry object for this run.
- `inclusion_proofs.json` — `{"proofs": [ ... ]}` — one proof per finding,
  in the same order:
  ```
  { "index": <int, 0-based>,
    "finding_id": "<finding.id>",
    "leaf_hash": "<64 hex>",
    "path": [ {"side": "L"|"R", "sibling": "<64 hex>"}, ... ] }
  ```
  `path` is ordered from the leaf's level upward. `side` is the position
  of the SIBLING hash: `"L"` means the sibling is the left operand
  (`cur = SHA256(sibling || cur)`), `"R"` means the right operand
  (`cur = SHA256(cur || sibling)`). Folding the leaf through the whole
  path must reproduce the entry's `merkle_root`.
- `report_meta.json` — `{"run_id", "seed", "scanner", "target",
  "findings_count", "merkle_root", "audit"}` — the six identity fields
  (must match the entry) plus the report's own `audit` block when the
  report was enriched (§6).

**Bundle verification** (all must hold):
1. recompute every leaf from `findings.json`; each `leaf_hash` matches;
2. every `path` folds from its leaf to the entry's `merkle_root`;
3. `len(findings) == entry.findings_count` and proof order/indexes match;
4. the entry's `entry_hash` recomputes, its signature verifies under the
   PINNED key, and its `public_key` equals the pinned key;
5. `report_meta` identity fields equal the entry's fields;
6. when `--log` is given: the log's chain and signatures verify, and the
   log contains exactly this entry (same `run_id` AND same `entry_hash`).

## 6. The per-report audit block (optional cross-check)

Enriched scan reports carry an `audit` object with `merkle_root`,
`findings_count`, `public_key_b64`, `signature_b64`. Its verification
recipe (embedded verbatim in every enriched report):

1. The Merkle root is computed exactly as §4.
2. The keypair is derived from the run seed — HKDF-SHA256
   (RFC 5869, extract-then-expand, output length 32) with
   `salt = "SENTINEL-axis14-ed25519-HKDF-SHA256-v1"` (UTF-8 bytes),
   `info = "axis14-ed25519-keypair"` (UTF-8 bytes), and IKM = the seed:
   a seed that is ≥64 characters, even-length ASCII hex decodes as hex;
   any other seed uses its UTF-8 bytes (and must be ≥32 bytes).
3. The signed digest is
   `SHA256( run_id || 0x00 || merkle_root || 0x00 || findings_count || 0x00 || canon({"run_id","seed","scanner","target"}) )`
   where `findings_count` is decimal ASCII and the last component is the
   canonical JSON of the four identity fields
   (`{"run_id":…,"scanner":…,"seed":…,"target":…}` — sorted keys,
   compact).
4. `signature_b64` is the RFC 8032 Ed25519 signature of that 32-byte
   digest under the derived key; `public_key_b64` must equal the derived
   public key.

The per-run key is derived from a PUBLIC seed: it proves integrity of
the report against its own recorded run — it is not an identity system.
Identity and ordering come from the transparency log's project key (§3).

## 7. Key management and rotation

- The project signing seed (32 random bytes, hex) is generated once and
  stored OUTSIDE git: locally at `.transparency-seed` (gitignored) and,
  for CI signing, in the `TRANSPARENCY_SEED` Actions secret.
- `transparency-log/pubkey.hex` is the pinned verification key. Anyone
  can verify any entry with it and nothing else.
- **Rotation**: generate a new seed, commit the new `pubkey.hex`, and
  append a `kind: "key-rotation"` entry in the same chain (signed by the
  OLD key, naming the new public key) so verifiers can follow the
  transition. After rotation, old entries keep verifying under the old
  key, which the rotation entry authenticates.
- **Compromise**: if the private seed leaks, the log's integrity
  guarantees are void from the moment of compromise; the recovery is a
  rotation entry plus re-publication of affected evidence. The honest
  limitation: an append-only log in a git repository is tamper-EVIDENT
  (history rewrites are visible), not tamper-PROOF against an attacker
  who controls the repository.

## 8. Command reference

```
python3 tools/independent_verify.py verify-log  transparency-log/log.jsonl \
        --pubkey transparency-log/pubkey.hex
python3 tools/independent_verify.py verify-bundle evidence/transparency-log/<run_id> \
        --pubkey transparency-log/pubkey.hex --log transparency-log/log.jsonl
python3 tools/independent_verify.py verify-report <any enriched result.json>
```

Exit code `0` = verified; `1` = verification failed (reason printed);
`2` = IO/usage error.
