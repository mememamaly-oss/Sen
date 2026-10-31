/**
 * QA DIAGNOSTIC (2026-10-31, Part 3 order) — NOT a test, no assertions.
 * Fires the exact same 10-concurrent-POST bootstrap stampede as the
 * integration race test, but prints the full outcome distribution per
 * iteration: every response's status, elapsed ms, and which 409 path
 * produced it (classified by the three distinct production messages):
 *
 *   A) fast path        "الحساب الأول موجود بالفعل — استخدم تسجيل الدخول"
 *   B) P2002, users>0   "الحساب الأول موجود بالفعل (تمت عملية إعداد متزامنة)"
 *   C) reclaim failed   "سباق إعداد جارٍ — أعد المحاولة بعد لحظات"
 *   D) reclaim SUCCEEDED (a second request got past the lock!) → any 200
 *      beyond the first, or a non-409 failure — the dangerous case.
 *
 * Usage: bun run tests/qa_race_diagnose.ts <BASE_URL> <iterations>
 * Caller truncates the platform tables between iterations (fresh state).
 */
const BASE = process.argv[2] || "http://127.0.0.1:3188";
const ITER = Number(process.argv[3] || 20);

const FAST = "الحساب الأول موجود بالفعل — استخدم";
const P2002_USERS = "(تمت عملية إعداد متزامنة)";
const RECLAIM_FAIL = "سباق إعداد جارٍ";

async function one(i: number) {
  const t0 = Date.now();
  try {
    const r = await fetch(`${BASE}/api/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: `racer${i}@integration.test`,
        password: "Racer-Passw0rd!",
        name: "Racer",
        orgName: "Race Org",
      }),
    });
    let body: Record<string, unknown> = {};
    try { body = (await r.json()) as Record<string, unknown>; } catch { /* non-json */ }
    const msg = typeof body.error === "string" ? body.error : "";
    let path = "?";
    if (r.status === 200) path = "WIN-200";
    else if (msg.includes(FAST)) path = "A-fast409";
    else if (msg.includes(P2002_USERS)) path = "B-p2002-users-409";
    else if (msg.includes(RECLAIM_FAIL)) path = "C-reclaim-failed-409";
    else if (r.status === 409) path = "D-409-unknown-msg";
    else path = `E-status-${r.status}`;
    return { i, status: r.status, path, ms: Date.now() - t0, msg: msg.slice(0, 60) };
  } catch (e) {
    return { i, status: 0, path: "F-fetch-error", ms: Date.now() - t0, msg: String(e).slice(0, 60) };
  }
}

let multiWinnerRuns = 0;
let anyReclaim = 0;
for (let it = 1; it <= ITER; it++) {
  // pre-flight: confirm fresh state
  const g = await fetch(`${BASE}/api/bootstrap`);
  const gb = (await g.json()) as { needsBootstrap?: boolean };
  if (gb.needsBootstrap !== true) {
    console.log(`iter ${it}: PRE-FLIGHT NOT FRESH (needsBootstrap=${gb.needsBootstrap}) — ABORT`);
    process.exit(1);
  }
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) => one(i)));
  const wins = results.filter((r) => r.status === 200);
  const paths: Record<string, number> = {};
  for (const r of results) paths[r.path] = (paths[r.path] || 0) + 1;
  const reclaimSeen = results.some((r) => r.path.startsWith("C") || r.path.startsWith("D"));
  if (wins.length !== 1) multiWinnerRuns++;
  if (reclaimSeen) anyReclaim++;
  const detail = results
    .map((r) => `${r.status}/${r.path}/${r.ms}ms`)
    .join("  ");
  console.log(
    `iter ${it}: wins=${wins.length} paths=${JSON.stringify(paths)} reclaim-path-seen=${reclaimSeen}`
  );
  console.log(`   ${detail}`);
}
console.log(
  `===== DIAGNOSTIC ${ITER}x: multi-winner runs=${multiWinnerRuns}, runs-where-reclaim-path-appeared=${anyReclaim} =====`
);
