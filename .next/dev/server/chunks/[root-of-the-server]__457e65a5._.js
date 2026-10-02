module.exports = [
"[externals]/next/dist/compiled/next-server/app-route-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-route-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/@opentelemetry/api [external] (next/dist/compiled/@opentelemetry/api, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/@opentelemetry/api", () => require("next/dist/compiled/@opentelemetry/api"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-unit-async-storage.external.js [external] (next/dist/server/app-render/work-unit-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-unit-async-storage.external.js", () => require("next/dist/server/app-render/work-unit-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-async-storage.external.js [external] (next/dist/server/app-render/work-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-async-storage.external.js", () => require("next/dist/server/app-render/work-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/shared/lib/no-fallback-error.external.js [external] (next/dist/shared/lib/no-fallback-error.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/shared/lib/no-fallback-error.external.js", () => require("next/dist/shared/lib/no-fallback-error.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}),
"[project]/src/lib/db.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "db",
    ()=>db
]);
var __TURBOPACK__imported__module__$5b$externals$5d2f40$prisma$2f$client__$5b$external$5d$__$2840$prisma$2f$client$2c$__cjs$2c$__$5b$project$5d2f$node_modules$2f40$prisma$2f$client$29$__ = __turbopack_context__.i("[externals]/@prisma/client [external] (@prisma/client, cjs, [project]/node_modules/@prisma/client)");
;
const globalForPrisma = globalThis;
const db = globalForPrisma.prisma ?? new __TURBOPACK__imported__module__$5b$externals$5d2f40$prisma$2f$client__$5b$external$5d$__$2840$prisma$2f$client$2c$__cjs$2c$__$5b$project$5d2f$node_modules$2f40$prisma$2f$client$29$__["PrismaClient"]({
});
if ("TURBOPACK compile-time truthy", 1) globalForPrisma.prisma = db;
}),
"[externals]/util [external] (util, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("util", () => require("util"));

module.exports = mod;
}),
"[externals]/url [external] (url, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("url", () => require("url"));

module.exports = mod;
}),
"[externals]/http [external] (http, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("http", () => require("http"));

module.exports = mod;
}),
"[externals]/crypto [external] (crypto, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("crypto", () => require("crypto"));

module.exports = mod;
}),
"[externals]/assert [external] (assert, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("assert", () => require("assert"));

module.exports = mod;
}),
"[externals]/querystring [external] (querystring, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("querystring", () => require("querystring"));

module.exports = mod;
}),
"[externals]/buffer [external] (buffer, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("buffer", () => require("buffer"));

module.exports = mod;
}),
"[externals]/zlib [external] (zlib, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("zlib", () => require("zlib"));

module.exports = mod;
}),
"[externals]/https [external] (https, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("https", () => require("https"));

module.exports = mod;
}),
"[externals]/events [external] (events, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("events", () => require("events"));

module.exports = mod;
}),
"[project]/src/lib/passwords.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "hashPassword",
    ()=>hashPassword,
    "verifyPassword",
    ()=>verifyPassword
]);
var __TURBOPACK__imported__module__$5b$externals$5d2f$crypto__$5b$external$5d$__$28$crypto$2c$__cjs$29$__ = __turbopack_context__.i("[externals]/crypto [external] (crypto, cjs)");
;
// Password hashing with node:crypto scrypt — zero extra dependencies.
// Format: scrypt$<saltHex>$<hashHex>
const KEYLEN = 64;
function hashPassword(password) {
    const salt = (0, __TURBOPACK__imported__module__$5b$externals$5d2f$crypto__$5b$external$5d$__$28$crypto$2c$__cjs$29$__["randomBytes"])(16);
    const hash = (0, __TURBOPACK__imported__module__$5b$externals$5d2f$crypto__$5b$external$5d$__$28$crypto$2c$__cjs$29$__["scryptSync"])(password, salt, KEYLEN);
    return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}
function verifyPassword(password, stored) {
    try {
        const [scheme, saltHex, hashHex] = stored.split("$");
        if (scheme !== "scrypt" || !saltHex || !hashHex) return false;
        const salt = Buffer.from(saltHex, "hex");
        const expected = Buffer.from(hashHex, "hex");
        const actual = (0, __TURBOPACK__imported__module__$5b$externals$5d2f$crypto__$5b$external$5d$__$28$crypto$2c$__cjs$29$__["scryptSync"])(password, salt, expected.length);
        return (0, __TURBOPACK__imported__module__$5b$externals$5d2f$crypto__$5b$external$5d$__$28$crypto$2c$__cjs$29$__["timingSafeEqual"])(actual, expected);
    } catch  {
        return false;
    }
}
}),
"[project]/src/lib/auth.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "authOptions",
    ()=>authOptions,
    "getSessionUser",
    ()=>getSessionUser
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2d$auth$2f$providers$2f$credentials$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next-auth/providers/credentials.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2d$auth$2f$index$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next-auth/index.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/db.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$passwords$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/passwords.ts [app-route] (ecmascript)");
;
;
;
;
const authOptions = {
    session: {
        strategy: "jwt",
        maxAge: 12 * 60 * 60
    },
    secret: process.env.NEXTAUTH_SECRET,
    pages: {
        signIn: "/"
    },
    providers: [
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2d$auth$2f$providers$2f$credentials$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["default"])({
            name: "credentials",
            credentials: {
                email: {
                    label: "Email",
                    type: "text"
                },
                password: {
                    label: "Password",
                    type: "password"
                }
            },
            async authorize (credentials) {
                if (!credentials?.email || !credentials?.password) return null;
                const email = String(credentials.email).trim().toLowerCase();
                const user = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].user.findUnique({
                    where: {
                        email
                    }
                });
                if (!user) return null;
                if (!(0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$passwords$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["verifyPassword"])(String(credentials.password), user.passwordHash)) return null;
                return {
                    id: user.id,
                    email: user.email,
                    name: user.name
                };
            }
        })
    ],
    callbacks: {
        async jwt ({ token, user }) {
            if (user) token.uid = user.id;
            return token;
        },
        async session ({ session, token }) {
            if (session.user && token.uid) {
                session.user.id = token.uid;
            }
            return session;
        }
    }
};
async function getSessionUser() {
    const session = await (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2d$auth$2f$index$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["getServerSession"])(authOptions);
    const uid = session?.user?.id;
    if (!session?.user || !uid) return null;
    const user = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].user.findUnique({
        where: {
            id: uid
        }
    });
    if (!user) return null;
    return {
        id: user.id,
        email: user.email,
        name: user.name
    };
}
}),
"[project]/src/lib/rbac.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "ApiError",
    ()=>ApiError,
    "REPORT_FORMATS",
    ()=>REPORT_FORMATS,
    "ROLES",
    ()=>ROLES,
    "SCAN_STATUSES",
    ()=>SCAN_STATUSES,
    "SEVERITIES",
    ()=>SEVERITIES,
    "audit",
    ()=>audit,
    "jsonError",
    ()=>jsonError,
    "parseJsonSafe",
    ()=>parseJsonSafe,
    "requireOrgAccess",
    ()=>requireOrgAccess,
    "requireScanAccess",
    ()=>requireScanAccess,
    "requireTargetAccess",
    ()=>requireTargetAccess,
    "requireUser",
    ()=>requireUser,
    "roleAtLeast",
    ()=>roleAtLeast,
    "slugify",
    ()=>slugify
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/server.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/db.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$auth$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/auth.ts [app-route] (ecmascript)");
;
;
;
const ROLES = [
    "OWNER",
    "ADMIN",
    "MEMBER",
    "VIEWER"
];
const ROLE_RANK = {
    OWNER: 4,
    ADMIN: 3,
    MEMBER: 2,
    VIEWER: 1
};
const SEVERITIES = [
    "critical",
    "high",
    "medium",
    "low",
    "info"
];
const SCAN_STATUSES = [
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED"
];
const REPORT_FORMATS = [
    "HTML",
    "JSON",
    "SARIF",
    "EXECUTIVE",
    "GLASS"
];
class ApiError extends Error {
    status;
    constructor(status, message){
        super(message);
        this.status = status;
    }
}
function jsonError(e) {
    if (e instanceof ApiError) {
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            error: e.message
        }, {
            status: e.status
        });
    }
    console.error("[api] unexpected error:", e);
    return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
        error: "خطأ داخلي في الخادم"
    }, {
        status: 500
    });
}
function slugify(name) {
    const base = name.toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
    return base || `org-${Date.now().toString(36)}`;
}
async function audit(action, opts = {}) {
    try {
        await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].auditLog.create({
            data: {
                action,
                orgId: opts.orgId ?? null,
                userId: opts.userId ?? null,
                detail: opts.detail === undefined ? null : JSON.stringify(opts.detail).slice(0, 4000)
            }
        });
    } catch (e) {
        console.error("[audit] failed to record", action, e);
    }
}
async function requireUser() {
    const user = await (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$auth$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["getSessionUser"])();
    if (!user) throw new ApiError(401, "غير مصرح — يجب تسجيل الدخول");
    return user;
}
async function requireOrgAccess(user, orgId, minRole = "VIEWER") {
    const membership = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].membership.findUnique({
        where: {
            userId_orgId: {
                userId: user.id,
                orgId
            }
        }
    });
    if (!membership) {
        // tenant isolation: record cross-tenant attempt, then 404
        await audit("rbac.org_access_denied", {
            userId: user.id,
            orgId,
            detail: {
                reason: "not_a_member"
            }
        });
        throw new ApiError(404, "المنظمة غير موجودة");
    }
    const role = membership.role;
    if (ROLE_RANK[role] < ROLE_RANK[minRole]) {
        await audit("rbac.role_denied", {
            orgId,
            userId: user.id,
            detail: {
                reason: "insufficient_role",
                role,
                minRole
            }
        });
        throw new ApiError(403, `الدور الحالي (${role}) لا يملك صلاحية هذه العملية (مطلوب ${minRole}+)`);
    }
    return {
        user,
        orgId,
        role
    };
}
function roleAtLeast(role, min) {
    return ROLE_RANK[role] >= ROLE_RANK[min];
}
async function requireTargetAccess(access, targetId, level) {
    const target = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].target.findFirst({
        where: {
            id: targetId,
            orgId: access.orgId
        }
    });
    if (!target) throw new ApiError(404, "الهدف غير موجود");
    if (level === "write") {
        const isAdminish = roleAtLeast(access.role, "ADMIN");
        const isOwnerOfTarget = target.createdById === access.user.id && roleAtLeast(access.role, "MEMBER");
        if (!isAdminish && !isOwnerOfTarget) {
            await audit("rbac.target_write_denied", {
                orgId: access.orgId,
                userId: access.user.id,
                detail: {
                    targetId,
                    role: access.role,
                    ownerId: target.createdById
                }
            });
            throw new ApiError(403, "لا تملك صلاحية تعديل/حذف هذا الهدف (الملكية لمنشئه)");
        }
    }
    return target;
}
async function requireScanAccess(access, scanId) {
    const scan = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].scan.findFirst({
        where: {
            id: scanId,
            orgId: access.orgId
        },
        include: {
            target: true
        }
    });
    if (!scan) throw new ApiError(404, "الفحص غير موجود");
    return scan;
}
function parseJsonSafe(raw, fallback) {
    if (!raw) return fallback;
    try {
        return JSON.parse(raw);
    } catch  {
        return fallback;
    }
}
}),
"[project]/src/app/api/me/route.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "GET",
    ()=>GET
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/server.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/db.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$rbac$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/rbac.ts [app-route] (ecmascript)");
;
;
;
async function GET() {
    try {
        const user = await (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$rbac$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["requireUser"])();
        const memberships = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$db$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["db"].membership.findMany({
            where: {
                userId: user.id
            },
            include: {
                org: {
                    include: {
                        _count: {
                            select: {
                                targets: true,
                                scans: true,
                                findings: true,
                                reports: true,
                                memberships: true
                            }
                        }
                    }
                }
            },
            orderBy: {
                createdAt: "asc"
            }
        });
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            user,
            orgs: memberships.map((m)=>({
                    id: m.org.id,
                    name: m.org.name,
                    slug: m.org.slug,
                    role: m.role,
                    createdAt: m.org.createdAt,
                    counts: m.org._count
                }))
        });
    } catch (e) {
        return (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$rbac$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["jsonError"])(e);
    }
}
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__457e65a5._.js.map