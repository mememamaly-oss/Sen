import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, ApiError, audit, ROLES, type Role } from "@/lib/rbac";

// PATCH /api/orgs/:id/members/:mid — change role  (ADMIN+; OWNER role: OWNER only)
export async function PATCH(req: NextRequest, ctx: { params: Promise<{ id: string; mid: string }> }) {
  try {
    const { id, mid } = await ctx.params;
    const user = await requireUser();
    const access = await requireOrgAccess(user, id, "ADMIN");
    const target = await db.membership.findUnique({ where: { id: mid } });
    if (!target || target.orgId !== access.orgId) throw new ApiError(404, "العضوية غير موجودة");
    const body = await req.json();
    const role = String(body.role || "").toUpperCase() as Role;
    if (!ROLES.includes(role)) throw new ApiError(400, `دور غير صالح — المسموح: ${ROLES.join(", ")}`);

    if (access.role !== "OWNER") {
      if (target.role === "OWNER") throw new ApiError(403, "ADMIN لا يمكنه تعديل عضوية OWNER");
      if (role === "OWNER") throw new ApiError(403, "فقط OWNER يمكنه منح دور OWNER");
    }
    // never leave an org without its last OWNER
    if (target.role === "OWNER" && role !== "OWNER") {
      const owners = await db.membership.count({ where: { orgId: access.orgId, role: "OWNER" } });
      if (owners <= 1) throw new ApiError(409, "لا يمكن إزالة آخر OWNER من المنظمة");
    }
    await db.membership.update({ where: { id: mid }, data: { role } });
    await audit("member.role_changed", { orgId: access.orgId, userId: user.id, detail: { mid, from: target.role, to: role } });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}

// DELETE /api/orgs/:id/members/:mid — remove member (ADMIN+; OWNER: OWNER only)
export async function DELETE(_req: NextRequest, ctx: { params: Promise<{ id: string; mid: string }> }) {
  try {
    const { id, mid } = await ctx.params;
    const user = await requireUser();
    const access = await requireOrgAccess(user, id, "ADMIN");
    const target = await db.membership.findUnique({ where: { id: mid } });
    if (!target || target.orgId !== access.orgId) throw new ApiError(404, "العضوية غير موجودة");
    if (access.role !== "OWNER" && target.role === "OWNER") {
      throw new ApiError(403, "ADMIN لا يمكنه إزالة OWNER");
    }
    if (target.role === "OWNER") {
      const owners = await db.membership.count({ where: { orgId: access.orgId, role: "OWNER" } });
      if (owners <= 1) throw new ApiError(409, "لا يمكن إزالة آخر OWNER من المنظمة");
    }
    if (target.userId === user.id) throw new ApiError(409, "لا يمكنك إزالة نفسك — اطلب من مدير آخر");
    await db.membership.delete({ where: { id: mid } });
    await audit("member.removed", { orgId: access.orgId, userId: user.id, detail: { mid, hadRole: target.role } });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}
