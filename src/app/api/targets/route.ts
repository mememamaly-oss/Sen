import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, ApiError, audit } from "@/lib/rbac";
import { ensureDemoTarget, DEMO_TARGET_URL, DEMO_TARGET_NAME } from "@/lib/demo-target";

// GET /api/targets?orgId=... — org-scoped list with scan stats
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const targets = await db.target.findMany({
      where: { orgId: access.orgId },
      include: {
        createdBy: { select: { name: true, email: true } },
        _count: { select: { scans: true, findings: true } },
        scans: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { status: true, createdAt: true, finishedAt: true, scanner: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });
    return NextResponse.json({
      targets: targets.map((t) => ({
        id: t.id,
        name: t.name,
        url: t.url,
        description: t.description,
        isDemo: t.isDemo,
        owner: t.createdBy.name || t.createdBy.email,
        ownerId: t.createdById,
        scansCount: t._count.scans,
        findingsCount: t._count.findings,
        lastScan: t.scans[0] ?? null,
        createdAt: t.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

function validHttpUrl(raw: string): URL | null {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

// POST /api/targets — create target {orgId, name, url, description?, isDemo?}
export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");

    let url = String(body.url || "").trim();
    let name = String(body.name || "").trim();
    const description = body.description ? String(body.description).slice(0, 500) : null;
    let isDemo = Boolean(body.isDemo);

    if (isDemo) {
      const demo = await ensureDemoTarget();
      if (!demo.ok) throw new ApiError(503, demo.detail);
      url = DEMO_TARGET_URL;
      if (!name) name = DEMO_TARGET_NAME;
    } else {
      if (!url) throw new ApiError(400, "URL مطلوب");
      const u = validHttpUrl(url);
      if (!u) throw new ApiError(400, "URL غير صالح — يجب أن يبدأ بـ http:// أو https://");
      url = u.toString();
      if (!name) name = u.hostname;
    }

    const dup = await db.target.findFirst({ where: { orgId: access.orgId, url } });
    if (dup) throw new ApiError(409, "هذا الهدف مسجل بالفعل في المنظمة");

    const target = await db.target.create({
      data: {
        orgId: access.orgId,
        createdById: user.id, // target ownership
        name,
        url,
        description,
        isDemo,
      },
    });
    await audit("target.created", {
      orgId: access.orgId,
      userId: user.id,
      detail: { targetId: target.id, url, isDemo },
    });
    return NextResponse.json({ id: target.id, name: target.name, url: target.url, isDemo: target.isDemo });
  } catch (e) {
    return jsonError(e);
  }
}
