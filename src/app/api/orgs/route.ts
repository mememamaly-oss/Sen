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
    // SECURITY (audit 2026-10-23): slug uniqueness is enforced by the DB —
    // the old check-then-create loop raced into an unhandled P2002 (500).
    // Now collisions (concurrent same-name orgs) retry with a fresh slug.
    let org: { id: string; name: string; slug: string } | null = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      let slug = slugify(name);
      if (attempt > 0) slug = `${slug}-${Date.now().toString(36).slice(-4)}${attempt}`;
      try {
        // org + OWNER membership + audit row in ONE transaction (item 1.3,
        // fail-closed): an audit write failure rolls the whole org back —
        // an organization is never created without its evidence trail.
        org = await db.$transaction(async (tx) => {
          const created = await tx.organization.create({ data: { name, slug } });
          await tx.membership.create({ data: { userId: user.id, orgId: created.id, role: "OWNER" } });
          await audit("org.created", { orgId: created.id, userId: user.id, detail: { name, slug } }, tx);
          return created;
        });
        break;
      } catch (e) {
        const code = (e as { code?: string }).code;
        if (code === "P2002" || code === "P2034") continue; // slug taken / write conflict — retry
        throw e;
      }
    }
    if (!org) throw new ApiError(500, "تعذر توليد معرف فريد للمنظمة — أعد المحاولة");
    return NextResponse.json({ id: org.id, name: org.name, slug: org.slug, role: "OWNER" });
  } catch (e) {
    return jsonError(e);
  }
}
