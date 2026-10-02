import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/passwords";
import { audit, jsonError, ApiError, slugify } from "@/lib/rbac";

// Bootstrap: create the FIRST platform user (platform admin).
// Allowed only while zero users exist. The first user also gets a default
// organization with OWNER role. After that, users are added by org admins
// from the members screen.

export async function GET() {
  try {
    const count = await db.user.count();
    return NextResponse.json({ needsBootstrap: count === 0 });
  } catch (e) {
    return jsonError(e);
  }
}

export async function POST(req: NextRequest) {
  try {
    const count = await db.user.count();
    if (count > 0) {
      throw new ApiError(409, "الحساب الأول موجود بالفعل — استخدم تسجيل الدخول أو اطلب من مدير منظمتك إضافتك");
    }
    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const name = String(body.name || "").trim() || email.split("@")[0];
    const password = String(body.password || "");
    const orgName = String(body.orgName || "").trim() || "منظمتي الأولى";
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ApiError(400, "البريد الإلكتروني غير صالح");
    if (password.length < 8) throw new ApiError(400, "كلمة المرور يجب أن تكون 8 أحرف على الأقل");

    const user = await db.user.create({
      data: { email, name, passwordHash: hashPassword(password) },
    });
    // default org with a unique slug
    let slug = slugify(orgName);
    for (let i = 0; ; i++) {
      const exists = await db.organization.findUnique({ where: { slug } });
      if (!exists) break;
      slug = `${slug}-${Date.now().toString(36).slice(-4)}`;
    }
    const org = await db.organization.create({ data: { name: orgName, slug } });
    await db.membership.create({ data: { userId: user.id, orgId: org.id, role: "OWNER" } });
    await audit("bootstrap.admin_created", { orgId: org.id, userId: user.id, detail: { email } });
    return NextResponse.json({ ok: true, userId: user.id, orgId: org.id });
  } catch (e) {
    return jsonError(e);
  }
}
