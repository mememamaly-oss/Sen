import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";

// ─────────────────────────────────────────────────────────────────────────────
// RBAC + tenant isolation guards (P0)
// Every org-scoped API handler MUST pass through requireOrgAccess() — this is
// the single choke point that enforces:
//   1. authenticated session
//   2. membership of the requested org (tenant isolation — non-members get 404,
//      indistinguishable from a non-existent org)
//   3. minimum role for the action (RBAC)
// All denials are recorded in AuditLog for tenant-isolation evidence.
// ─────────────────────────────────────────────────────────────────────────────

export const ROLES = ["OWNER", "ADMIN", "MEMBER", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

const ROLE_RANK: Record<Role, number> = { OWNER: 4, ADMIN: 3, MEMBER: 2, VIEWER: 1 };

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const SCAN_STATUSES = ["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"] as const;
export const REPORT_FORMATS = ["HTML", "JSON", "SARIF", "EXECUTIVE", "GLASS"] as const;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function jsonError(e: unknown) {
  if (e instanceof ApiError) {
    return NextResponse.json({ error: e.message }, { status: e.status });
  }
  console.error("[api] unexpected error:", e);
  return NextResponse.json({ error: "خطأ داخلي في الخادم" }, { status: 500 });
}

export function slugify(name: string): string {
  const base = name
    .toLowerCase()
    .replace(/[^a-z0-9\u0600-\u06FF]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return base || `org-${Date.now().toString(36)}`;
}

export async function audit(
  action: string,
  opts: { orgId?: string | null; userId?: string | null; detail?: unknown } = {}
) {
  try {
    await db.auditLog.create({
      data: {
        action,
        orgId: opts.orgId ?? null,
        userId: opts.userId ?? null,
        detail: opts.detail === undefined ? null : JSON.stringify(opts.detail).slice(0, 4000),
      },
    });
  } catch (e) {
    console.error("[audit] failed to record", action, e);
  }
}

export type SessionUser = { id: string; email: string; name: string | null };

export async function requireUser(): Promise<SessionUser> {
  const user = await getSessionUser();
  if (!user) throw new ApiError(401, "غير مصرح — يجب تسجيل الدخول");
  return user;
}

export type OrgAccess = {
  user: SessionUser;
  orgId: string;
  role: Role;
};

/**
 * The tenant-isolation choke point. Returns { user, orgId, role } or throws.
 * Non-members receive 404 (org does not exist FOR THEM) — no tenant probing.
 */
export async function requireOrgAccess(
  user: SessionUser,
  orgId: string,
  minRole: Role = "VIEWER"
): Promise<OrgAccess> {
  const membership = await db.membership.findUnique({
    where: { userId_orgId: { userId: user.id, orgId } },
  });
  if (!membership) {
    // tenant isolation: record cross-tenant attempt, then 404
    await audit("rbac.org_access_denied", { userId: user.id, orgId, detail: { reason: "not_a_member" } });
    throw new ApiError(404, "المنظمة غير موجودة");
  }
  const role = membership.role as Role;
  if (ROLE_RANK[role] < ROLE_RANK[minRole]) {
    await audit("rbac.role_denied", {
      orgId,
      userId: user.id,
      detail: { reason: "insufficient_role", role, minRole },
    });
    throw new ApiError(403, `الدور الحالي (${role}) لا يملك صلاحية هذه العملية (مطلوب ${minRole}+)`);
  }
  return { user, orgId, role };
}

export function roleAtLeast(role: Role, min: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

// Target ownership rule (P0):
//   OWNER/ADMIN → any target in the org
//   MEMBER      → only targets they created
//   VIEWER      → never
export async function requireTargetAccess(
  access: OrgAccess,
  targetId: string,
  level: "read" | "write"
) {
  const target = await db.target.findFirst({ where: { id: targetId, orgId: access.orgId } });
  if (!target) throw new ApiError(404, "الهدف غير موجود");
  if (level === "write") {
    const isAdminish = roleAtLeast(access.role, "ADMIN");
    const isOwnerOfTarget = target.createdById === access.user.id && roleAtLeast(access.role, "MEMBER");
    if (!isAdminish && !isOwnerOfTarget) {
      await audit("rbac.target_write_denied", {
        orgId: access.orgId,
        userId: access.user.id,
        detail: { targetId, role: access.role, ownerId: target.createdById },
      });
      throw new ApiError(403, "لا تملك صلاحية تعديل/حذف هذا الهدف (الملكية لمنشئه)");
    }
  }
  return target;
}

export async function requireScanAccess(access: OrgAccess, scanId: string) {
  const scan = await db.scan.findFirst({
    where: { id: scanId, orgId: access.orgId },
    include: { target: true },
  });
  if (!scan) throw new ApiError(404, "الفحص غير موجود");
  return scan;
}

export function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}
