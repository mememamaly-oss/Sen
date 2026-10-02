import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError, parseJsonSafe } from "@/lib/rbac";
import { reconcileScan } from "@/lib/engine";

// GET /api/scans/:id/coverage?orgId= — engine coverage + boundary account
export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    // orgId comes from the query string
    const url = new URL(_req.url);
    const orgId = String(url.searchParams.get("orgId") || "");
    const user = await requireUser();
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);
    await reconcileScan(scan.id).catch(() => null);

    const fresh = await db.scan.findUnique({ where: { id: scan.id } });
    if (!fresh || fresh.status !== "COMPLETED" || !fresh.statsJson) {
      return NextResponse.json({
        scanId: scan.id,
        status: fresh?.status ?? scan.status,
        coverage: null,
        boundary: null,
        note: "التغطية متاحة بعد اكتمال الفحص",
      });
    }
    const stats = parseJsonSafe<Record<string, unknown>>(fresh.statsJson, {});
    return NextResponse.json({
      scanId: scan.id,
      status: fresh.status,
      coverage: (stats.coverage as Record<string, unknown>) ?? null,
      boundary: (stats.boundary as Record<string, unknown>) ?? null,
      crawl: (stats.crawl as Record<string, unknown>) ?? null,
      openapi: (stats.openapi as Record<string, unknown>) ?? null,
      browserPages: stats.browser_pages ?? null,
      paramIntel: (stats.param_intel as Record<string, unknown>) ?? null,
    });
  } catch (e) {
    return jsonError(e);
  }
}
