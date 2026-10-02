// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: RAW LOADER
//
// Assembles the RawEngineResult for a COMPLETED scan, preferring the
// authoritative engine output on disk (result.json) and falling back to a
// DB reconstruction (statsJson + Finding rows). Read-only: L1 never writes
// engine artifacts and never re-runs the engine (no new network requests).
// ─────────────────────────────────────────────────────────────────────────────
import fs from "fs";
import { db } from "@/lib/db";
import type { RawEngineResult, RawFinding } from "./types";

export interface LoadedRaw {
  raw: RawEngineResult;
  rawSource: "result.json" | "db-reconstruction";
  notes: string[]; // honest gaps of the reconstruction (recorded as known unknowns)
}

function parseJsonFile(path: string): unknown | null {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

export async function loadRawForScan(
  scanId: string,
): Promise<LoadedRaw | null> {
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) return null;

  // 1. authoritative: the engine's own result.json on disk
  const candidates = [scan.resultPath].filter(Boolean) as string[];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const parsed = parseJsonFile(p);
      if (parsed && typeof parsed === "object" && "stats" in (parsed as object)) {
        return { raw: parsed as RawEngineResult, rawSource: "result.json", notes: [] };
      }
    }
  }

  // 2. fallback: DB reconstruction (stats + imported findings)
  if (!scan.statsJson) return null;
  const stats = parseJsonText(scan.statsJson) as Record<string, unknown> | null;
  if (!stats) return null;
  const findings = await db.finding.findMany({
    where: { scanId },
    orderBy: [{ engineId: "asc" }],
  });
  const target = await db.target.findUnique({ where: { id: scan.targetId } });
  const raw: RawEngineResult = {
    run_id: scan.runId ?? undefined,
    scanner: scan.scanner ?? undefined,
    target: target?.url ?? "",
    findings: findings.map(
      (f): RawFinding => ({
        id: f.engineId,
        type: f.type,
        severity: f.severity,
        status: f.status,
        confidence: f.confidence,
        method: f.method ?? undefined,
        url: f.url,
        parameter: f.parameter ?? undefined,
        evidence: parseJsonTextArray(f.evidenceJson),
        verification: (parseJsonText(f.verificationJson) ?? {}) as Record<string, unknown>,
        impact: (parseJsonText(f.impactJson) ?? {}) as Record<string, unknown>,
        risk: f.risk,
      }),
    ),
    rejected_candidates: [], // not persisted by the import layer — honest gap
    stats,
  };
  return {
    raw,
    rawSource: "db-reconstruction",
    notes: [
      "Raw source reconstructed from the platform database (result.json unavailable): rejected_candidates and per-finding engine fingerprints are not persisted by the import layer.",
    ],
  };
}

function parseJsonText(text: string | null | undefined): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseJsonTextArray(text: string | null | undefined): Array<{ kind?: string; detail?: string }> {
  const v = parseJsonText(text);
  return Array.isArray(v) ? (v as Array<{ kind?: string; detail?: string }>) : [];
}
