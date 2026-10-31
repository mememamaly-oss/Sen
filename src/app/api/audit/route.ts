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
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    // 2.6: AuditLog no longer carries FK relations (append-only trail) —
    // resolve user labels manually; deleted users simply show as null
    // (same display behavior as the old SetNull relation produced).
    const userIds = [...new Set(logs.map((l) => l.userId).filter((x): x is string => !!x))];
    const users = userIds.length
      ? await db.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true, name: true } })
      : [];
    const byId = new Map(users.map((u) => [u.id, u.name || u.email]));
    return NextResponse.json({
      logs: logs.map((l) => ({
        id: l.id,
        action: l.action,
        detail: parseJsonSafe<Record<string, unknown>>(l.detail, {}),
        by: l.userId ? byId.get(l.userId) ?? null : null,
        createdAt: l.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}
