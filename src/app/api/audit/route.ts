import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, parseJsonSafe } from "@/lib/rbac";

// GET /api/audit?orgId=&limit= — tenant isolation + RBAC evidence trail
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const limit = Math.min(Number(req.nextUrl.searchParams.get("limit")) || 100, 500);
    const access = await requireOrgAccess(user, orgId);
    const logs = await db.auditLog.findMany({
      where: { orgId: access.orgId },
      include: { user: { select: { email: true, name: true } } },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return NextResponse.json({
      logs: logs.map((l) => ({
        id: l.id,
        action: l.action,
        detail: parseJsonSafe<Record<string, unknown>>(l.detail, {}),
        by: l.user ? l.user.name || l.user.email : null,
        createdAt: l.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}
