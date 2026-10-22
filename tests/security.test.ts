/**
 * SECURITY REGRESSION TESTS — SaaS platform policy layer (audit 2026-10-23).
 *
 * Pure-unit tests for the SSRF policy, rate limiter, password hashing and
 * slug generation. The HTTP-level integration suite (bootstrap race, RBAC
 * matrix, private-target rejection) lives in api.integration.test.ts.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
  normalizeScanOptions,
  isLocalUrl,
  labModeEnabled,
} from "@/lib/engine";
import { rateLimit, resetRateLimits } from "@/lib/rate-limit";
import { hashPassword, verifyPassword } from "@/lib/passwords";
import { slugify, roleAtLeast } from "@/lib/rbac";

// ---------------------------------------------------------------- SSRF policy

describe("SSRF policy: normalizeScanOptions (audit 2026-10-23)", () => {
  const ORIG_LAB = process.env.SENTINEL_ALLOW_PRIVATE_TARGETS;

  afterEach(() => {
    if (ORIG_LAB === undefined) delete process.env.SENTINEL_ALLOW_PRIVATE_TARGETS;
    else process.env.SENTINEL_ALLOW_PRIVATE_TARGETS = ORIG_LAB;
  });

  test("THE REGRESSION: client-supplied allowPrivate:true is IGNORED for non-demo public targets", () => {
    // Before the fix, this exact input produced allowPrivate:true and the
    // engine scanned internal networks. Must be false — always.
    const opts = normalizeScanOptions(
      { allowPrivate: true } as never,
      { url: "https://public-example.com/app", isDemo: false }
    );
    expect(opts.allowPrivate).toBe(false);
  });

  test("client allowPrivate:false on the demo target still allows private (server policy wins both ways)", () => {
    const opts = normalizeScanOptions(
      { allowPrivate: false } as never,
      { url: "http://127.0.0.1:8777", isDemo: true }
    );
    expect(opts.allowPrivate).toBe(true);
  });

  test("demo target => private egress allowed (platform-managed fixture)", () => {
    expect(
      normalizeScanOptions(undefined, { url: "http://127.0.0.1:8777", isDemo: true }).allowPrivate
    ).toBe(true);
  });

  test("non-demo local URL is denied without explicit lab mode", () => {
    delete process.env.SENTINEL_ALLOW_PRIVATE_TARGETS;
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(false);
  });

  test("non-demo local URL is allowed ONLY in explicit lab mode", () => {
    process.env.SENTINEL_ALLOW_PRIVATE_TARGETS = "1";
    expect(labModeEnabled()).toBe(true);
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(true);
    delete process.env.SENTINEL_ALLOW_PRIVATE_TARGETS;
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(false);
  });

  test("numeric option clamping survives (regression guard)", () => {
    const opts = normalizeScanOptions(
      { maxPages: 99999, timeout: 999, noBrowser: true } as never,
      { url: "https://x.com", isDemo: false }
    );
    expect(opts.maxPages).toBe(200);
    expect(opts.timeout).toBe(60);
    expect(opts.noBrowser).toBe(true);
  });
});

describe("isLocalUrl heuristic", () => {
  test("loopback + RFC1918 + CGNAT + link-local literals are local", () => {
    for (const u of [
      "http://localhost:3000/",
      "http://127.0.0.1/",
      "http://127.8.8.8/",               // any 127/8
      "http://0.0.0.0/",
      "http://10.1.2.3/",
      "http://172.16.0.1/",
      "http://172.31.255.254/",
      "http://192.168.1.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://100.64.0.1/",
      "http://[::1]:3000/",
      "http://[fe80::1]/",
      "http://[fc00::1]/",
    ]) {
      expect(isLocalUrl(u)).toBe(true);
    }
  });

  test("wildcard DNS conventions count as local", () => {
    expect(isLocalUrl("http://127.0.0.1.nip.io:8080/")).toBe(true);
    expect(isLocalUrl("http://10.0.0.5.sslip.io/")).toBe(true);
    expect(isLocalUrl("http://foo.localtest.me/")).toBe(true);
    expect(isLocalUrl("http://service.internal:8080/")).toBe(true);
    expect(isLocalUrl("http://db.local/")).toBe(true);
  });

  test("public hosts are not local", () => {
    for (const u of [
      "https://example.com/",
      "http://8.8.8.8/",
      "http://172.32.0.1/",   // just outside RFC1918
      "http://100.128.0.1/",  // just outside CGNAT
      "https://2606:4700::1111/",
    ]) {
      expect(isLocalUrl(u)).toBe(false);
    }
  });

  test("IPv4-mapped IPv6 and exotic v4 forms are local", () => {
    expect(isLocalUrl("http://[::ffff:127.0.0.1]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:10.0.0.1]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:169.254.169.254]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:8.8.8.8]/")).toBe(false);
    expect(isLocalUrl("http://0x7f.0.0.1/")).toBe(true);
    expect(isLocalUrl("http://0177.0.0.1/")).toBe(true);
  });

  test("garbage is not local (engine still fail-closes downstream)", () => {
    expect(isLocalUrl("not a url")).toBe(false);
    expect(isLocalUrl("")).toBe(false);
  });
});

// ------------------------------------------------------------- rate limiter

describe("login rate limiter (audit 2026-10-23)", () => {
  beforeEach(() => resetRateLimits());

  test("allows up to N hits then blocks, with retryAfter", () => {
    for (let i = 0; i < 10; i++) {
      const v = rateLimit("k1", 10, 60_000);
      expect(v.allowed).toBe(true);
    }
    const blocked = rateLimit("k1", 10, 60_000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    expect(blocked.retryAfterSec).toBeLessThanOrEqual(60);
  });

  test("keys are isolated", () => {
    for (let i = 0; i < 10; i++) rateLimit("a", 10, 60_000);
    expect(rateLimit("a", 10, 60_000).allowed).toBe(false);
    expect(rateLimit("b", 10, 60_000).allowed).toBe(true);
  });

  test("window slides (expired hits free the key)", async () => {
    // 3 hits / 80ms window: the 4th is blocked, but after the window
    // passes the bucket frees itself (no permanent lockout).
    for (let i = 0; i < 3; i++) rateLimit("slide", 3, 80);
    expect(rateLimit("slide", 3, 80).allowed).toBe(false);
    await new Promise((r) => setTimeout(r, 120));
    const later = rateLimit("slide", 3, 80);
    expect(later.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------- passwords

describe("password hashing", () => {
  test("round-trip verify", () => {
    const h = hashPassword("Correct-Horse-9!");
    expect(h.startsWith("scrypt$")).toBe(true);
    expect(verifyPassword("Correct-Horse-9!", h)).toBe(true);
    expect(verifyPassword("wrong", h)).toBe(false);
  });

  test("unique salts: same password, different hashes", () => {
    const a = hashPassword("same-password-1");
    const b = hashPassword("same-password-1");
    expect(a).not.toBe(b);
  });

  test("malformed stored hash fails closed", () => {
    expect(verifyPassword("x", "")).toBe(false);
    expect(verifyPassword("x", "plaintext")).toBe(false);
    expect(verifyPassword("x", "md5$abc$def")).toBe(false);
  });
});

// ---------------------------------------------------------------- rbac utils

describe("RBAC helpers", () => {
  test("role ranking is total and correct", () => {
    expect(roleAtLeast("OWNER", "ADMIN")).toBe(true);
    expect(roleAtLeast("ADMIN", "ADMIN")).toBe(true);
    expect(roleAtLeast("MEMBER", "ADMIN")).toBe(false);
    expect(roleAtLeast("VIEWER", "MEMBER")).toBe(false);
  });

  test("slugify: ascii, arabic, fallback", () => {
    expect(slugify("Acme Corp")).toBe("acme-corp");
    expect(slugify("شركة الأمن")).toBe("شركة-الأمن");
    expect(slugify("!!!")).toMatch(/^org-/);
  });
});

// ------------------------------------------- QA regression (2026-10-23 gate)

describe("production standalone fixes (QA gate 2026-10-23)", () => {
  test("ENGINE_DIR resolves to the real engine tree (standalone chdir regression)", async () => {
    // Before the fix, the standalone server chdir()s into .next/standalone,
    // making cwd-based ENGINE_DIR point at the build output — demo target
    // 503'd and every scan FAILED. The resolver must find sentinel/cli.py.
    const { ENGINE_DIR } = await import("@/lib/engine");
    const fs = await import("fs");
    const path = await import("path");
    expect(fs.existsSync(path.join(ENGINE_DIR, "sentinel", "cli.py"))).toBe(true);
    expect(ENGINE_DIR.endsWith(".next/standalone")).toBe(false);
  });

  test("security headers are configured for every route (headers regression)", async () => {
    const nextConfig = (await import("../next.config")).default;
    const result = await nextConfig.headers!();
    const all = result.find((r) => r.source === "/:path*");
    expect(all).toBeDefined();
    const keys = all!.headers.map((h) => h.key);
    expect(keys).toContain("X-Content-Type-Options");
    expect(keys).toContain("X-Frame-Options");
    expect(keys).toContain("Referrer-Policy");
    expect(keys).toContain("Content-Security-Policy");
    const csp = all!.headers.find((h) => h.key === "Content-Security-Policy")!.value;
    expect(csp).toContain("frame-ancestors 'none'");
  });
});
