import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireTargetAccess, jsonError, ApiError, audit } from "@/lib/rbac";
import { engineStartScan, normalizeScanOptions, reconcileScan } from "@/lib/engine";
import { ensureDemoTarget } from "@/lib/demo-target";

// GET /api/scans?orgId=&targetId=&limit= — scan history (org-scoped)
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const targetId = req.nextUrl.searchParams.get("targetId");
    const limit = Math.min(Number(req.nextUrl.searchParams.get("limit")) || 50, 200);
    const access = await requireOrgAccess(user, orgId);

    // opportunistic reconcile of any active scan (self-healing status)
    const active = await db.scan.findMany({
      where: { orgId: access.orgId, status: { in: ["QUEUED", "RUNNING"] } },
      select: { id: true },
    });
    await Promise.all(active.map((s) => reconcileScan(s.id).catch(() => null)));

    const scans = await db.scan.findMany({
      where: { orgId: access.orgId, ...(targetId ? { targetId } : {}) },
      include: {
        target: { select: { id: true, name: true, url: true } },
        createdBy: { select: { name: true, email: true } },
        _count: { select: { findings: true, reports: true } },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return NextResponse.json({
      scans: scans.map((s) => ({
        id: s.id,
        status: s.status,
        target: s.target,
        createdBy: s.createdBy.name || s.createdBy.email,
        runId: s.runId,
        scanner: s.scanner,
        durationSec: s.durationSec,
        findingsCount: s._count.findings,
        reportsCount: s._count.reports,
        error: s.error,
        createdAt: s.createdAt,
        startedAt: s.startedAt,
        finishedAt: s.finishedAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

// POST /api/scans — start a scan {orgId, targetId, options?}
//
// SECURITY (audit 2026-10-23):
//   1. Scan start is a WRITE-level action on the target (it consumes org
//      resources, writes findings/reports, and drives network egress from
//      the server) — previously it only required "read", which let any
//      MEMBER scan targets created by other members.
//   2. options.allowPrivate from the client is IGNORED by
//      normalizeScanOptions — the private-egress policy is computed
//      exclusively on the server (demo target / explicit lab mode).
export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");
    const target = await requireTargetAccess(access, String(body.targetId || ""), "write");

    const active = await db.scan.findFirst({
      where: { targetId: target.id, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (active) {
      throw new ApiError(409, "يوجد فحص نشط على هذا الهدف بالفعل — انتظر انتهاءه أو ألغِه أولًا (تسلسل الفحوصات لكل هدف)");
    }

    const options = normalizeScanOptions(body.options, { url: target.url, isDemo: target.isDemo });

    // self-healing demo target: restart the managed fixture if it is down
    if (target.isDemo) {
      const demo = await ensureDemoTarget();
      if (!demo.ok) throw new ApiError(503, demo.detail);
    }

    const scan = await db.scan.create({
      data: {
        orgId: access.orgId,
        targetId: target.id,
        createdById: user.id,
        status: "QUEUED",
        optionsJson: JSON.stringify(options),
      },
    });

    await audit("scan.started", {
      orgId: access.orgId,
      userId: user.id,
      detail: { scanId: scan.id, targetId: target.id, url: target.url, options },
    });

    // SECURITY (19-axis audit 2026-10-23, G8 — scan-start TOCTOU):
    // the active-scan check above is check-then-act. Three concurrent POSTs
    // all passed it and spawned THREE engine processes against the same
    // target (proven live: 3 scan rows RUNNING + 3 engine scan dirs).
    // Earliest-wins compensation: every participant re-reads the active
    // scans for this target under a total order (createdAt asc, id asc).
    // The globally-earliest scan sees itself and proceeds; every later scan
    // deterministically sees the earliest, cancels ITSELF before the engine
    // is spawned, and returns 409 — concurrent duplicate engine runs are
    // impossible regardless of how the requests interleave.
    const winner = await db.scan.findFirst({
      where: { targetId: target.id, status: { in: ["QUEUED", "RUNNING"] } },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    });
    if (winner && winner.id !== scan.id) {
      await db.scan.update({
        where: { id: scan.id },
        data: { status: "CANCELLED", error: "فحص متزامن آخر بدأ على نفس الهدف", finishedAt: new Date() },
      });
      await audit("scan.cancelled_duplicate", {
        orgId: access.orgId,
        userId: user.id,
        detail: { scanId: scan.id, targetId: target.id, keptScanId: winner.id },
      });
      throw new ApiError(409, "يوجد فحص نشط على هذا الهدف بالفعل — فحص متزامن مكرر أُلغي (تسلسل الفحوصات لكل هدف)");
    }

    try {
      await engineStartScan(scan.id, { id: target.id, url: target.url });
    } catch (e) {
      await db.scan.update({
        where: { id: scan.id },
        data: { status: "FAILED", error: `فشل تشغيل المحرك: ${String(e).slice(0, 300)}`, finishedAt: new Date() },
      });
      throw new ApiError(500, "فشل تشغيل محرك الفحص");
    }

    return NextResponse.json({ id: scan.id, status: "RUNNING" });
  } catch (e) {
    return jsonError(e);
  }
}
