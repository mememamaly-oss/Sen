import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { ENGINE_DIR, SCANS_DIR } from "@/lib/engine";

// Managed local demo target — the engine's own fixture app (vulnapp.py),
// started by the PLATFORM as a detached child. The engine tree is untouched.
// Port 8777 is the fixture's fixed port (127.0.0.1 only).

export const DEMO_TARGET_URL = "http://127.0.0.1:8777";
export const DEMO_TARGET_NAME = "Sentinel Demo App (vulnapp محلي)";

const g = globalThis as unknown as { __sentinelDemoStarted?: boolean };

export async function demoTargetHealthy(): Promise<boolean> {
  try {
    const res = await fetch(DEMO_TARGET_URL, {
      signal: AbortSignal.timeout(1500),
      cache: "no-store",
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function ensureDemoTarget(): Promise<{ ok: boolean; detail: string }> {
  if (await demoTargetHealthy()) {
    g.__sentinelDemoStarted = true;
    return { ok: true, detail: "demo target جاهز بالفعل" };
  }
  if (g.__sentinelDemoStarted) {
    // we started it this session but health check failed — give it a moment
    await new Promise((r) => setTimeout(r, 1200));
    if (await demoTargetHealthy()) return { ok: true, detail: "demo target جاهز" };
  }
  const logPath = path.join(path.dirname(SCANS_DIR), "demo-target.log");
  const out = fs.openSync(logPath, "a");
  // PORT must be pinned: the fixture reads `PORT` from its env (default 8777).
  // The Next server process carries PORT=3000 — inheriting it verbatim made the
  // child try to bind 127.0.0.1:3000 (the dev server itself) -> EADDRINUSE.
  // The demo target's contract is the fixture's designed fixed port 8777.
  const child = spawn(
    process.env.SENTINEL_PYTHON || "python3",
    ["fixtures/vulnapp.py"],
    { cwd: ENGINE_DIR, stdio: ["ignore", out, out], detached: true, env: { ...process.env, PORT: "8777" } }
  );
  child.unref();
  fs.closeSync(out);
  g.__sentinelDemoStarted = true;
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 500));
    if (await demoTargetHealthy()) {
      return { ok: true, detail: `demo target بدأ بنجاح (pid ${child.pid})` };
    }
  }
  return { ok: false, detail: "تعذر بدء demo target — راجع saas-data/demo-target.log" };
}
