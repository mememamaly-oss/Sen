import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, ApiError } from "@/lib/rbac";

// GET /api/reports/:id?orgId=&download=1 — report metadata or file content
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);

    const report = await db.report.findFirst({
      where: { id, orgId: access.orgId },
      include: {
        scan: { select: { id: true, runId: true, scanner: true, target: { select: { name: true, url: true } } } },
        createdBy: { select: { name: true, email: true } },
      },
    });
    if (!report) throw new ApiError(404, "التقرير غير موجود");

    if (!fs.existsSync(report.filePath)) {
      throw new ApiError(410, "ملف التقرير غير موجود على القرص");
    }
    const content = fs.readFileSync(report.filePath, "utf8");
    const ext = report.filePath.split(".").pop() || "html";
    const mime =
      ext === "html" ? "text/html; charset=utf-8" : "application/json; charset=utf-8";

    if (req.nextUrl.searchParams.get("download")) {
      return new NextResponse(content, {
        headers: {
          "Content-Type": mime,
          "Content-Disposition": `attachment; filename="sentinel-report-${report.id}.${ext}"`,
          // SECURITY (audit 2026-10-23): report HTML embeds target-controlled
          // strings; served as an attachment, nosniff guarantees browsers
          // never reinterpret it as executable content in another MIME type.
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
    return NextResponse.json({
      report: {
        id: report.id,
        title: report.title,
        format: report.format,
        sizeBytes: report.sizeBytes,
        createdAt: report.createdAt,
        createdBy: report.createdBy.name || report.createdBy.email,
        scan: report.scan
          ? { id: report.scan.id, runId: report.scan.runId, scanner: report.scan.scanner, targetName: report.scan.target.name, targetUrl: report.scan.target.url }
          : null,
      },
      ext,
      content,
    });
  } catch (e) {
    return jsonError(e);
  }
}
