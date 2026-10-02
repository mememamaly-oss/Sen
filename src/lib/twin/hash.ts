// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: DETERMINISTIC IDs + CANONICAL SERIALIZATION + HASH
//
// Rules (spec §7/§8):
//   • Node/Edge/Conflict/KnownUnknown IDs are content-derived (sha256 of the
//     canonical identity) — NO random UUIDs, timestamps, PIDs or memory
//     addresses anywhere in the content hash.
//   • Canonical serialization: recursively key-sorted JSON, arrays kept in
//     their construction order (the normalizer sorts nodes/edges by id before
//     hashing, making the order deterministic).
//   • twinHash covers { schemaVersion, target, nodes, edges, conflicts,
//     knownUnknowns }. counts are derived projections and excluded.
// ─────────────────────────────────────────────────────────────────────────────
import { createHash } from "crypto";

export const TWIN_SCHEMA_VERSION = "l1-twin/1.0.0";

const SEP = "\u0000";

function sha256hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Deterministic node id: N-<sha256(type|key)[:16]> */
export function nodeId(type: string, key: string): string {
  return "N-" + sha256hex(type + SEP + key).slice(0, 16);
}

/** Deterministic edge id: E-<sha256(from|to|type)[:16]> */
export function edgeId(from: string, to: string, type: string): string {
  return "E-" + sha256hex(from + SEP + to + SEP + type).slice(0, 16);
}

/** Deterministic conflict id: C-<sha256(kind|left|right)[:16]> */
export function conflictId(kind: string, left: string, right: string): string {
  return "C-" + sha256hex(kind + SEP + left + SEP + right).slice(0, 16);
}

/** Deterministic known-unknown id: U-<sha256(dimension|description)[:16]> */
export function unknownId(dimension: string, description: string): string {
  return "U-" + sha256hex(dimension + SEP + description).slice(0, 16);
}

/** Canonical JSON: object keys sorted recursively; arrays preserved in order.
 *  Cycle-hardened (hostile inputs can never blow the stack — cycles
 *  serialize as a null marker) and depth-capped. */
export function canonicalJson(value: unknown): string {
  const seen = new WeakSet<object>();
  return serialize(value, seen, 0);
}

const MAX_DEPTH = 96;

function serialize(v: unknown, seen: WeakSet<object>, depth: number): string {
  if (depth > MAX_DEPTH) return "null";
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") return Number.isFinite(v) ? JSON.stringify(v) : "0";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "object") {
    if (seen.has(v as object)) return "\"<cycle>\"";
    seen.add(v as object);
    let out: string;
    try {
      if (Array.isArray(v)) out = "[" + v.map((x) => serialize(x, seen, depth + 1)).join(",") + "]";
      else {
        const keys = Object.keys(v as Record<string, unknown>).sort();
        out = "{" + keys.map((k) => JSON.stringify(k) + ":" + serialize((v as Record<string, unknown>)[k], seen, depth + 1)).join(",") + "}";
      }
    } finally {
      seen.delete(v as object);
    }
    return out;
  }
  return "null";
}

export interface TwinHashContent {
  schemaVersion: string;
  target: string;
  nodes: unknown[];
  edges: unknown[];
  conflicts: unknown[];
  knownUnknowns: unknown[];
}

/** twinHash — deterministic content hash of the normalized twin. */
export function computeTwinHash(content: TwinHashContent): string {
  return sha256hex(canonicalJson(content));
}

/** rawHash — deterministic fingerprint of the raw input (for traceability). */
export function computeRawHash(raw: unknown): string {
  return sha256hex(canonicalJson(raw));
}
