import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, jsonError } from "@/lib/rbac";

export async function GET() {
  try {
    const user = await requireUser();
    const memberships = await db.membership.findMany({
      where: { userId: user.id },
      include: {
        org: {
          include: {
            _count: { select: { targets: true, scans: true, findings: true, reports: true, memberships: true } },
          },
        },
      },
      orderBy: { createdAt: "asc" },
    });
    return NextResponse.json({
      user,
      orgs: memberships.map((m) => ({
        id: m.org.id,
        name: m.org.name,
        slug: m.org.slug,
        role: m.role,
        createdAt: m.org.createdAt,
        counts: m.org._count,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}
