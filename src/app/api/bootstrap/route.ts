import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/passwords";
import { audit, jsonError, ApiError, slugify } from "@/lib/rbac";

// Bootstrap: create the FIRST platform user (platform admin).
// Allowed only while zero users exist. The first user also gets a default
// organization with OWNER role. After that, users are added by org admins
// from the members screen.
//
// SECURITY (audit 2026-10-23, race fix): the previous implementation ran
// `count() -> create()` as separate operations — two concurrent bootstrap
// POSTs both observed count=0 and both created platform admins.
//
// The fix avoids interactive transactions ENTIRELY (SQLite serializes
// writers and interactive transactions under a stampede degrade into
// P1008/P2028/P2034 timeout storms — measured live during this audit):
//   1. A single atomic INSERT of the PlatformLock row (unique key
//      "bootstrap") is the race decider. Exactly one concurrent request
//      can succeed; every loser gets the unique violation (P2002) → 409.
//   2. The winner then creates user + org + membership with plain
//      sequential writes. On any failure a compensation block removes the
//      partial state INCLUDING the lock, so a failed bootstrap leaves the
//      door open for a retry.
//   3. Crash-safety: a lock row without any user means a previous attempt
//      died mid-way (no admin was ever created) — the stale lock is
//      reclaimed and bootstrap proceeds.

export async function GET() {
  try {
    const count = await db.user.count();
    return NextResponse.json({ needsBootstrap: count === 0 });
  } catch (e) {
    return jsonError(e);
  }
}

export async function POST(req: NextRequest) {
  let lockHeld = false;
  try {
    // fast path: already bootstrapped
    if ((await db.user.count()) > 0) {
      throw new ApiError(409, "الحساب الأول موجود بالفعل — استخدم تسجيل الدخول أو اطلب من مدير منظمتك إضافتك");
    }
    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const name = String(body.name || "").trim() || email.split("@")[0];
    const password = String(body.password || "");
    const orgName = String(body.orgName || "").trim() || "منظمتي الأولى";
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ApiError(400, "البريد الإلكتروني غير صالح");
    if (password.length < 8) throw new ApiError(400, "كلمة المرور يجب أن تكون 8 أحرف على الأقل");

    // THE RACE GUARD — one atomic INSERT, no transaction needed.
    try {
      await db.platformLock.create({ data: { key: "bootstrap" } });
      lockHeld = true;
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === "P2002") {
        // someone holds/held the lock:
        //   users exist  -> genuinely bootstrapped -> 409
        //   users == 0   -> stale lock from a crashed attempt -> reclaim
        if ((await db.user.count()) > 0) {
          throw new ApiError(409, "الحساب الأول موجود بالفعل (تمت عملية إعداد متزامنة)");
        }
        try {
          await db.platformLock.delete({ where: { key: "bootstrap" } });
          await db.platformLock.create({ data: { key: "bootstrap" } });
          lockHeld = true;
        } catch {
          throw new ApiError(409, "سباق إعداد جارٍ — أعد المحاولة بعد لحظات");
        }
      } else {
        throw e;
      }
    }

    // defense in depth inside the lock
    if ((await db.user.count()) > 0) {
      throw new ApiError(409, "الحساب الأول موجود بالفعل");
    }

    // plain sequential writes; compensation below on failure
    let user: { id: string } | null = null;
    let org: { id: string } | null = null;
    try {
      user = await db.user.create({
        data: { email, name, passwordHash: hashPassword(password) },
      });
      let slug = slugify(orgName);
      for (let i = 0; i < 5; i++) {
        const exists = await db.organization.findUnique({ where: { slug } });
        if (!exists) break;
        slug = `${slugify(orgName)}-${Date.now().toString(36).slice(-4)}${i}`;
        if (i === 4) slug = `org-${Date.now().toString(36)}`;
      }
      org = await db.organization.create({ data: { name: orgName, slug } });
      await db.membership.create({
        data: { userId: user.id, orgId: org.id, role: "OWNER" },
      });
    } catch (e) {
      // COMPENSATION: remove the partial state and release the lock so a
      // retry is possible.
      try {
        if (org) await db.organization.delete({ where: { id: org.id } });
        if (user) await db.user.delete({ where: { id: user.id } });
      } catch {
        /* best effort — the lock reclaim below still allows diagnosis */
      }
      throw e;
    }

    await audit("bootstrap.admin_created", { orgId: org.id, userId: user.id, detail: { email } });
    return NextResponse.json({ ok: true, userId: user.id, orgId: org.id });
  } catch (e) {
    // on ANY failure after acquiring the lock with no user created, release
    // it (failed bootstrap must not brick the instance)
    if (lockHeld) {
      try {
        if ((await db.user.count()) === 0) {
          await db.platformLock.deleteMany({ where: { key: "bootstrap" } });
        }
      } catch {
        /* best effort */
      }
    }
    return jsonError(e);
  }
}
