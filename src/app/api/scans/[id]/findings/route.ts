import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError } from "@/lib/rbac";
import { reconcileScan } from "@/lib/engine";

// GET /api/scans/:id/findings?orgId=&severity=&type=&q=&limit=
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);
    await reconcileScan(scan.id).catch(() => null);

    const severity = req.nextUrl.searchParams.get("severity");
    const type = req.nextUrl.searchParams.get("type");
    const q = req.nextUrl.searchParams.get("q");
    const limit = Math.min(Number(req.nextUrl.searchParams.get("limit")) || 500, 2000);

    const findings = await db.finding.findMany({
      where: {
        scanId: scan.id,
        ...(severity ? { severity } : {}),
        ...(type ? { type } : {}),
        ...(q
          ? {
              OR: [
                { url: { contains: q } },
                { parameter: { contains: q } },
                { type: { contains: q } },
              ],
            }
          : {}),
      },
      orderBy: [{ risk: "desc" }, { severity: "desc" }],
      take: limit,
    });
    const types = await db.finding.groupBy({ by: ["type"], where: { scanId: scan.id }, _count: { _all: true } });
    return NextResponse.json({
      findings: findings.map((f) => ({
        id: f.id,
        engineId: f.engineId,
        type: f.type,
        severity: f.severity,
        status: f.status,
        confidence: f.confidence,
        risk: f.risk,
        method: f.method,
        url: f.url,
        parameter: f.parameter,
        hasProof: f.proofJson !== null,
      })),
      types: types.map((t) => ({ type: t.type, count: t._count._all })).sort((a, b) => b.count - a.count),
    });
  } catch (e) {
    return jsonError(e);
  }
}
