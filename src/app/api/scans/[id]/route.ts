import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError, parseJsonSafe, roleAtLeast } from "@/lib/rbac";
import { getScanProgress, engineCancelScan, reconcileScan } from "@/lib/engine";

// GET /api/scans/:id?orgId= — scan meta + live progress (reconciles state)
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);

    const progress = await getScanProgress(scan.id); // includes reconcile
    const fresh = await db.scan.findUnique({
      where: { id: scan.id },
      include: {
        target: { select: { id: true, name: true, url: true } },
        createdBy: { select: { name: true, email: true } },
        _count: { select: { findings: true, reports: true } },
      },
    });

    const stats = parseJsonSafe<Record<string, unknown>>(fresh!.statsJson, {});
    const bySeverity =
      fresh!.status === "COMPLETED"
        ? await db.finding.groupBy({ by: ["severity"], where: { scanId: scan.id }, _count: { _all: true } })
        : [];

    return NextResponse.json({
      scan: {
        id: fresh!.id,
        status: fresh!.status,
        target: fresh!.target,
        createdBy: fresh!.createdBy.name || fresh!.createdBy.email,
        options: parseJsonSafe<Record<string, unknown>>(fresh!.optionsJson, {}),
        runId: fresh!.runId,
        scanner: fresh!.scanner,
        durationSec: fresh!.durationSec,
        error: fresh!.error,
        enginePid: fresh!.enginePid,
        createdAt: fresh!.createdAt,
        startedAt: fresh!.startedAt,
        finishedAt: fresh!.finishedAt,
        findingsCount: fresh!._count.findings,
        reportsCount: fresh!._count.reports,
        bySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r._count._all])),
        stats:
          fresh!.status === "COMPLETED"
            ? {
                requests: stats.requests ?? null,
                endpoints: stats.endpoints ?? null,
                candidates: stats.candidates ?? null,
                verified: stats.verified ?? null,
                rejected: stats.rejected ?? null,
                duration: stats.duration ?? null,
                authenticated: stats.authenticated ?? null,
              }
            : null,
      },
      progress,
    });
  } catch (e) {
    return jsonError(e);
  }
}

// DELETE /api/scans/:id?orgId= — cancel an active scan (ADMIN+ or the scan creator)
export async function DELETE(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);
    const mayCancel = roleAtLeast(access.role, "ADMIN") || scan.createdById === user.id;
    if (!mayCancel) {
      return NextResponse.json({ error: "فقط منشئ الفحص أو ADMIN يمكنه الإلغاء" }, { status: 403 });
    }
    await reconcileScan(scan.id).catch(() => null);
    const ok = await engineCancelScan(scan.id);
    return NextResponse.json({ ok, cancelled: ok });
  } catch (e) {
    return jsonError(e);
  }
}
