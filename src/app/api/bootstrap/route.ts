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
//
// RACE AUDIT 2026-10-31 (20× instrumented stampede, fresh DB each run):
// the reclaim path above as originally written could NOT tell a CRASHED
// attempt (lock row, zero users, safe to reclaim) from a winner STILL IN
// FLIGHT (lock row, zero users YET — scrypt + sequential writes take
// ~70-150ms). Both look identical to `user.count() === 0`. In 17/20
// stampedes a losing request deleted the in-flight winner's lock and
// re-created its own; the ONLY thing that preserved the single-winner
// invariant was the defense-in-depth count below — a non-atomic
// count-then-act check whose observed margin was ~1-2ms. Under different
// scheduling (a slower winner / faster loser — e.g. a loaded shared CI
// runner) that count passes before the winner's user commits and TWO
// platform admins get created. The fix: the reclaim is now AGE-GUARDED
// and ATOMIC — a single UPDATE ... WHERE created_at < now - LOCK_STALE_MS.
// A bootstrap attempt completes in well under 1s (measured ~0.2s worst
// case, scrypt included), so a lock older than LOCK_STALE_MS cannot be an
// in-flight attempt; and exactly one of N concurrent reclaimers can win
// that UPDATE. The compensation delete is likewise holder-scoped (it
// matches the createdAt value THIS request wrote), so a failed attempt
// can never delete another holder's lock.

export async function GET() {
  try {
    const count = await db.user.count();
    return NextResponse.json({ needsBootstrap: count === 0 });
  } catch (e) {
    return jsonError(e);
  }
}

// A bootstrap attempt's full critical path (validation + scrypt + the
// sequential user/org/membership/audit writes) measures ~70-150ms locally;
// 30s is a 200-400× margin. Residual exposure (documented, accepted): a
// winner that stalls > 30s mid-path without its user write committing could
// have its lock reclaimed by a later request; if the stalled write then
// lands anyway, two admins exist. Requires a 30s+ stall inside a 0.2s path.
const LOCK_STALE_MS = 30_000;

export async function POST(req: NextRequest) {
  let lockHeld = false;
  let myLockAt: Date | null = null; // the createdAt value THIS request wrote
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
      const row = await db.platformLock.create({ data: { key: "bootstrap" } });
      myLockAt = row.createdAt;
      lockHeld = true;
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === "P2002") {
        // someone holds/held the lock:
        //   users exist  -> genuinely bootstrapped -> 409
        //   users == 0   -> EITHER a crashed attempt OR a winner still in
        //                   flight — indistinguishable by row content, so
        //                   discriminate by AGE (see RACE AUDIT above):
        //                   only a lock older than LOCK_STALE_MS is
        //                   reclaimable, via ONE atomic guarded UPDATE.
        if ((await db.user.count()) > 0) {
          throw new ApiError(409, "الحساب الأول موجود بالفعل (تمت عملية إعداد متزامنة)");
        }
        const now = new Date();
        const reclaimed = await db.platformLock.updateMany({
          where: { key: "bootstrap", createdAt: { lt: new Date(now.getTime() - LOCK_STALE_MS) } },
          data: { createdAt: now },
        });
        if (reclaimed.count === 1) {
          myLockAt = now;
          lockHeld = true; // a stale (crashed-attempt) lock — safely ours now
        } else {
          // lock exists but is FRESH: a bootstrap attempt is in flight right
          // now — do NOT touch it (this is the exact spot the pre-fix code
          // deleted an in-flight winner's lock)
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
      // FAIL-CLOSED AUDIT (item 1.3, 2026-10-31): the evidence write runs
      // INSIDE the guarded block — if it cannot be persisted, compensation
      // below removes the partial state and the request fails. The admin
      // account is never created without its audit row.
      await audit("bootstrap.admin_created", { orgId: org.id, userId: user.id, detail: { email } });
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

    return NextResponse.json({ ok: true, userId: user.id, orgId: org.id });
  } catch (e) {
    // on ANY failure after acquiring the lock with no user created, release
    // it (failed bootstrap must not brick the instance)
    if (lockHeld && myLockAt) {
      try {
        if ((await db.user.count()) === 0) {
          // holder-scoped: delete only the lock row THIS request wrote
          // (createdAt equality) — never another in-flight/reclaiming
          // holder's row
          await db.platformLock.deleteMany({
            where: { key: "bootstrap", createdAt: myLockAt },
          });
        }
      } catch {
        /* best effort */
      }
    }
    return jsonError(e);
  }
}
