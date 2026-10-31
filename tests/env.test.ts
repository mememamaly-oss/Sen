// v5.0.0 rename shim (owner order, part 1.4): legacy SENTINEL_* variables are
// honored with a clear warning — never silently ignored — and BURHAN_* wins.
import { afterEach, describe, expect, test } from "bun:test";
import { env, warnLegacyEnv } from "../src/lib/env";

const KEYS = [
  "BURHAN_PYTHON", "SENTINEL_PYTHON",
  "BURHAN_ENGINE_DIR", "SENTINEL_ENGINE_DIR",
  "BURHAN_TESTX", "SENTINEL_TESTX",
] as const;

afterEach(() => {
  for (const k of KEYS) delete process.env[k];
});

describe("env shim (v5.0.0 rename: SENTINEL_* -> BURHAN_*)", () => {
  test("legacy SENTINEL_ name is honored with exactly one warning that names the new variable", () => {
    process.env.SENTINEL_PYTHON = "/opt/legacy/python3";
    const warnings: string[] = [];
    const orig = console.warn;
    console.warn = (...a: unknown[]) => { warnings.push(a.map(String).join(" ")); };
    try {
      expect(env("PYTHON")).toBe("/opt/legacy/python3");
      expect(env("PYTHON")).toBe("/opt/legacy/python3"); // second read: no second warning
      expect(warnings.length).toBe(1);
      expect(warnings[0]).toContain("SENTINEL_PYTHON");
      expect(warnings[0]).toContain("BURHAN_PYTHON");
      expect(warnings[0]).toContain("WARNING");
    } finally {
      console.warn = orig;
    }
  });

  test("BURHAN_ takes precedence over the legacy SENTINEL_ name", () => {
    process.env.SENTINEL_PYTHON = "/opt/legacy/python3";
    process.env.BURHAN_PYTHON = "/opt/modern/python3";
    const orig = console.warn;
    console.warn = () => {};
    try {
      expect(env("PYTHON")).toBe("/opt/modern/python3");
    } finally {
      console.warn = orig;
    }
  });

  test("undefined when neither name is set", () => {
    expect(env("PYTHON")).toBeUndefined();
  });

  test("warnLegacyEnv lists every legacy variable with the new name in the warning", () => {
    process.env.SENTINEL_TESTX = "1";
    const warnings: string[] = [];
    const orig = console.warn;
    console.warn = (...a: unknown[]) => { warnings.push(a.map(String).join(" ")); };
    try {
      const found = warnLegacyEnv();
      expect(found).toContain("SENTINEL_TESTX");
      const hit = warnings.find((w) => w.includes("SENTINEL_TESTX"));
      expect(hit).toBeTruthy();
      expect(hit as string).toContain("BURHAN_TESTX");
    } finally {
      console.warn = orig;
    }
  });
});
