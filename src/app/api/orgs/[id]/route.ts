import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, parseJsonSafe } from "@/lib/rbac";

// GET /api/orgs/:id — org overview (targets, recent scans, finding stats)
export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const access = await requireOrgAccess(user, id);
    const org = await db.organization.findUnique({
      where: { id: access.orgId },
      include: {
        _count: { select: { targets: true, scans: true, findings: true, reports: true, memberships: true } },
      },
    });
    const recentScans = await db.scan.findMany({
      where: { orgId: access.orgId },
      orderBy: { createdAt: "desc" },
      take: 5,
      include: { target: { select: { name: true, url: true } }, _count: { select: { findings: true, reports: true } } },
    });
    const bySeverity = await db.finding.groupBy({
      by: ["severity"],
      where: { orgId: access.orgId },
      _count: { _all: true },
    });
    const lastCompleted = await db.scan.findFirst({
      where: { orgId: access.orgId, status: "COMPLETED" },
      orderBy: { finishedAt: "desc" },
      select: { id: true, finishedAt: true, scanner: true, statsJson: true },
    });
    return NextResponse.json({
      org: { id: org!.id, name: org!.name, slug: org!.slug, createdAt: org!.createdAt, counts: org!._count },
      role: access.role,
      recentScans: recentScans.map((s) => ({
        id: s.id,
        status: s.status,
        createdAt: s.createdAt,
        finishedAt: s.finishedAt,
        durationSec: s.durationSec,
        targetName: s.target.name,
        findingsCount: s._count.findings,
        scanner: s.scanner,
        coverage: parseJsonSafe<Record<string, unknown>>(s.statsJson, {}).coverage ?? null,
      })),
      findingsBySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r._count._all])),
      lastCompleted: lastCompleted
        ? {
            id: lastCompleted.id,
            finishedAt: lastCompleted.finishedAt,
            scanner: lastCompleted.scanner,
            coverage: parseJsonSafe<Record<string, unknown>>(lastCompleted.statsJson, {}).coverage ?? null,
          }
        : null,
    });
  } catch (e) {
    return jsonError(e);
  }
}
