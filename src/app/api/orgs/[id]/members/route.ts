import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/passwords";
import { requireUser, requireOrgAccess, jsonError, ApiError, audit, ROLES, type Role } from "@/lib/rbac";

// GET /api/orgs/:id/members — list members (org members can see)
export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const access = await requireOrgAccess(user, id);
    const members = await db.membership.findMany({
      where: { orgId: access.orgId },
      include: { user: { select: { id: true, email: true, name: true, createdAt: true } } },
      orderBy: { createdAt: "asc" },
    });
    return NextResponse.json({
      members: members.map((m) => ({
        id: m.id,
        userId: m.user.id,
        email: m.user.email,
        name: m.user.name,
        role: m.role,
        joinedAt: m.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

// POST /api/orgs/:id/members — add member {email, name?, password, role}  (ADMIN+)
// Only OWNER may assign the OWNER role.
export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const access = await requireOrgAccess(user, id, "ADMIN");
    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const name = String(body.name || "").trim() || email.split("@")[0];
    const password = String(body.password || "");
    const role = String(body.role || "MEMBER").toUpperCase() as Role;
    if (!ROLES.includes(role)) throw new ApiError(400, `دور غير صالح — المسموح: ${ROLES.join(", ")}`);
    if (role === "OWNER" && access.role !== "OWNER") {
      throw new ApiError(403, "فقط OWNER يمكنه منح دور OWNER");
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ApiError(400, "البريد الإلكتروني غير صالح");
    if (password.length < 8) throw new ApiError(400, "كلمة المرور يجب أن تكون 8 أحرف على الأقل");

    // SECURITY (audit 2026-10-23): concurrent add-member requests for the
    // same new email raced user.create into an unhandled P2002 (500). The
    // unique constraints (User.email, Membership[userId,orgId]) are the
    // authority — violations map to explicit 409s, not 500s.
    let member = await db.user.findUnique({ where: { email } });
    const isNewUser = !member;
    if (!member) {
      try {
        member = await db.user.create({ data: { email, name, passwordHash: hashPassword(password) } });
      } catch (e) {
        if ((e as { code?: string }).code === "P2002") {
          // concurrent request created the user first — adopt it
          member = await db.user.findUnique({ where: { email } });
        }
        if (!member) throw e;
      }
    }
    try {
      await db.membership.create({ data: { userId: member.id, orgId: access.orgId, role } });
    } catch (e) {
      if ((e as { code?: string }).code === "P2002") {
        throw new ApiError(409, "هذا المستخدم عضو في المنظمة بالفعل");
      }
      throw e;
    }
    await audit("member.added", {
      orgId: access.orgId,
      userId: user.id,
      detail: { email, role, newAccount: isNewUser },
    });
    return NextResponse.json({ ok: true, userId: member.id, isNewUser, role });
  } catch (e) {
    return jsonError(e);
  }
}
