import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError, ApiError, REPORT_FORMATS, audit, parseJsonSafe } from "@/lib/rbac";
import { engineGenerateReport } from "@/lib/engine";

const MIME: Record<string, string> = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  sarif: "application/json; charset=utf-8",
};

// GET /api/reports?orgId=&scanId=
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const scanId = req.nextUrl.searchParams.get("scanId");
    const access = await requireOrgAccess(user, orgId);
    const reports = await db.report.findMany({
      where: { orgId: access.orgId, ...(scanId ? { scanId } : {}) },
      include: {
        scan: { select: { id: true, runId: true, target: { select: { name: true, url: true } } } },
        createdBy: { select: { name: true, email: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
    return NextResponse.json({
      reports: reports.map((r) => ({
        id: r.id,
        title: r.title,
        format: r.format,
        sizeBytes: r.sizeBytes,
        createdAt: r.createdAt,
        createdBy: r.createdBy.name || r.createdBy.email,
        scan: r.scan ? { id: r.scan.id, runId: r.scan.runId, targetName: r.scan.target.name } : null,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

// POST /api/reports — generate report from engine {orgId, scanId, format}
export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");
    const scan = await requireScanAccess(access, String(body.scanId || ""));
    if (scan.status !== "COMPLETED" || !scan.runId) {
      throw new ApiError(409, "التقرير يتطلب فحصًا مكتملًا");
    }
    const format = String(body.format || "HTML").toUpperCase();
    if (!REPORT_FORMATS.includes(format as (typeof REPORT_FORMATS)[number])) {
      throw new ApiError(400, `صيغة غير مدعومة — المسموح: ${REPORT_FORMATS.join(", ")}`);
    }

    const generated = await engineGenerateReport(
      { id: scan.id, runId: scan.runId, targetId: scan.targetId },
      format
    );
    if (!generated) throw new ApiError(500, "فشل توليد التقرير من المحرك");
    const { filePath, sizeBytes } = generated;

    const title = `${scan.target.name} — تقرير ${format} — ${new Date().toISOString().slice(0, 16).replace("T", " ")}`;
    const report = await db.report.create({
      data: {
        orgId: access.orgId,
        scanId: scan.id,
        createdById: user.id,
        format,
        title,
        filePath,
        sizeBytes,
      },
    });
    await audit("report.created", {
      orgId: access.orgId,
      userId: user.id,
      detail: { reportId: report.id, scanId: scan.id, format, runId: scan.runId },
    });
    return NextResponse.json({ id: report.id, title: report.title, format, sizeBytes });
  } catch (e) {
    return jsonError(e);
  }
}
