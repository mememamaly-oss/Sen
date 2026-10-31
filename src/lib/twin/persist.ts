// ─────────────────────────────────────────────────────────────────────────────
// Burhan — PHASE 02 L1: TWIN PERSISTENCE (spec §9)
//
// TwinGraph storage with MANDATORY tenant isolation: every read/write is
// scoped by orgId from the authorized access context (never a user-supplied
// orgId). unique(orgId, scanId). The raw engine output is never stored here
// as a substitute for normalization — graphJson holds the NORMALIZED twin.
// ─────────────────────────────────────────────────────────────────────────────
import { db } from "@/lib/db";
import type { NormalizedTwin } from "./types";
import { TWIN_SCHEMA_VERSION } from "./hash";

export interface StoredTwinMeta {
  twinSchemaVersion: string;
  contentHash: string;
  countsJson: string;
  createdAt: Date;
  updatedAt: Date;
}

/** Store/refresh the normalized twin for a scan (idempotent upsert). */
export async function saveTwinGraph(orgId: string, scanId: string, twin: NormalizedTwin): Promise<void> {
  const graphJson = JSON.stringify({
    schemaVersion: twin.schemaVersion,
    target: twin.target,
    scope: twin.scope,
    nodes: twin.nodes,
    edges: twin.edges,
    conflicts: twin.conflicts,
    knownUnknowns: twin.knownUnknowns,
    counts: twin.counts,
    twinHash: twin.twinHash,
    rawHash: twin.rawHash,
  });
  await db.twinGraph.upsert({
    where: { orgId_scanId: { orgId, scanId } },
    update: {
      twinSchemaVersion: twin.schemaVersion,
      contentHash: twin.twinHash,
      countsJson: JSON.stringify(twin.counts),
      graphJson,
    },
    create: {
      orgId,
      scanId,
      twinSchemaVersion: twin.schemaVersion,
      contentHash: twin.twinHash,
      countsJson: JSON.stringify(twin.counts),
      graphJson,
    },
  });
}

/** Tenant-scoped read: returns the stored twin ONLY for the authorized org. */
export async function loadTwinGraph(orgId: string, scanId: string): Promise<NormalizedTwin | null> {
  const row = await db.twinGraph.findFirst({
    where: { orgId, scanId },
    orderBy: { updatedAt: "desc" },
  });
  if (!row) return null;
  try {
    return JSON.parse(row.graphJson) as NormalizedTwin;
  } catch {
    return null;
  }
}

/** Metadata (hash/counts) — used by API contract tests. */
export async function loadTwinGraphMeta(orgId: string, scanId: string): Promise<StoredTwinMeta | null> {
  const row = await db.twinGraph.findFirst({
    where: { orgId, scanId },
    orderBy: { updatedAt: "desc" },
    select: {
      twinSchemaVersion: true, contentHash: true, countsJson: true,
      createdAt: true, updatedAt: true,
    },
  });
  return row ?? null;
}

/** True when the stored twin matches the current schema version. */
export function isCurrentSchema(twin: NormalizedTwin | null): boolean {
  return twin?.schemaVersion === TWIN_SCHEMA_VERSION;
}
