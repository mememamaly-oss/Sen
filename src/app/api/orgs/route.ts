import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, jsonError, ApiError, slugify, audit } from "@/lib/rbac";

export async function GET() {
  try {
    const user = await requireUser();
    const memberships = await db.membership.findMany({
      where: { userId: user.id },
      include: { org: true },
      orderBy: { createdAt: "asc" },
    });
    return NextResponse.json({
      orgs: memberships.map((m) => ({
        id: m.org.id,
        name: m.org.name,
        slug: m.org.slug,
        role: m.role,
        createdAt: m.org.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const name = String(body.name || "").trim();
    if (name.length < 2) throw new ApiError(400, "اسم المنظمة قصير جدًا");
    let slug = slugify(name);
    while (await db.organization.findUnique({ where: { slug } })) {
      slug = `${slug}-${Date.now().toString(36).slice(-4)}`;
    }
    const org = await db.organization.create({ data: { name, slug } });
    await db.membership.create({ data: { userId: user.id, orgId: org.id, role: "OWNER" } });
    await audit("org.created", { orgId: org.id, userId: user.id, detail: { name, slug } });
    return NextResponse.json({ id: org.id, name: org.name, slug: org.slug, role: "OWNER" });
  } catch (e) {
    return jsonError(e);
  }
}
