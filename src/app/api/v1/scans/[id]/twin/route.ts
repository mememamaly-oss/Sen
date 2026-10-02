import { NextRequest, NextResponse } from "next/server";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError, ApiError } from "@/lib/rbac";
import { getTwinForScan } from "@/lib/twin/service";

// GET /api/v1/scans/:scanId/twin?orgId= — the normalized Security Twin (L1).
//
// VERSIONED, READ-ONLY post-scan intelligence: no engine calls, no network
// requests, no active testing. The twin is rebuilt deterministically from the
// scan's raw engine output (result.json / DB reconstruction) and persisted in
// TwinGraph (tenant-scoped, unique orgId+scanId).
//
// Tenant isolation (same chain as /api/findings/[id]):
//   requireUser → requireOrgAccess (membership; non-members get 404 +
//   audit record) → requireScanAccess (findFirst scoped to access.orgId —
//   a scan of another org is indistinguishable from a nonexistent scan).
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id: scanId } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    if (!orgId) throw new ApiError(400, "orgId مطلوب");

    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, scanId);

    if (scan.status !== "COMPLETED") {
      return NextResponse.json({
        scanId: scan.id,
        status: scan.status,
        twin: null,
        note: "التوأم الأمني متاح بعد اكتمال الفحص",
      });
    }

    const result = await getTwinForScan(access.orgId, scan.id);
    if (!result) {
      return NextResponse.json({
        scanId: scan.id,
        status: scan.status,
        twin: null,
        note: "لا توجد مخرجات محرك قابلة للتطبيع لهذا الفحص",
      });
    }

    return NextResponse.json({
      apiVersion: "v1",
      scanId: scan.id,
      status: scan.status,
      built: result.built,
      invariants: { pass: result.invariants.pass, violations: result.invariants.violations.length },
      twin: result.twin,
    });
  } catch (e) {
    return jsonError(e);
  }
}
