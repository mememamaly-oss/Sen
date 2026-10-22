import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireTargetAccess, jsonError, ApiError, audit } from "@/lib/rbac";
import { isLocalUrl, labModeEnabled } from "@/lib/engine";

// PATCH /api/targets/:id — update {orgId, name?, url?, description?}
export async function PATCH(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");
    const target = await requireTargetAccess(access, id, "write");

    const data: Record<string, string | null> = {};
    if (body.name !== undefined) {
      const name = String(body.name).trim();
      if (name.length < 1) throw new ApiError(400, "الاسم مطلوب");
      data.name = name;
    }
    if (body.url !== undefined) {
      if (target.isDemo) throw new ApiError(400, "لا يمكن تغيير URL للـ demo target");
      try {
        const u = new URL(String(body.url));
        if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error();
        if (u.username || u.password) throw new ApiError(400, "URL يتضمن بيانات اعتماد — غير مسموح");
        // SECURITY (audit 2026-10-23): same internal-network rejection as
        // target creation — PATCH must not become the SSRF bypass.
        if (isLocalUrl(u.toString()) && !labModeEnabled()) {
          throw new ApiError(400, "عناوين الشبكة الداخلية/المحلية غير مسموحة للأهداف خارج وضع المختبر");
        }
        data.url = u.toString();
      } catch (e) {
        if (e instanceof ApiError) throw e;
        throw new ApiError(400, "URL غير صالح");
      }
    }
    if (body.description !== undefined) {
      data.description = body.description ? String(body.description).slice(0, 500) : null;
    }
    await db.target.update({ where: { id: target.id }, data });
    await audit("target.updated", { orgId: access.orgId, userId: user.id, detail: { targetId: target.id, fields: Object.keys(data) } });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}

// DELETE /api/targets/:id — OWNER/ADMIN any; MEMBER only own
export async function DELETE(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");
    const target = await requireTargetAccess(access, id, "write");

    const active = await db.scan.findFirst({
      where: { targetId: target.id, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (active) throw new ApiError(409, "لا يمكن حذف الهدف أثناء وجود فحص نشط عليه");

    await db.target.delete({ where: { id: target.id } }); // cascades scans/findings
    await audit("target.deleted", { orgId: access.orgId, userId: user.id, detail: { targetId: target.id, url: target.url } });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}
