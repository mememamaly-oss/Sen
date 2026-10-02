// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: INPUT SANITIZATION (spec §23 — malicious input safety)
//
// The twin NEVER executes input. Every raw string entering the normalized
// graph passes through here: control characters stripped, length capped.
// The twin never changes tenant, never breaks persistence, and carries no
// executable content (React text nodes on the UI side — XSS-safe by design).
// ─────────────────────────────────────────────────────────────────────────────

export const MAX_STRING = 256; // hard cap for any string inside the twin
export const MAX_LABEL = 96; // labels shown in the UI
export const MAX_NODES = 50000; // hard structural cap (documented limit)
export const MAX_EDGES = 250000;

/** Sanitize a raw string: strip control chars, cap length, mark truncation. */
export function sanitizeString(v: unknown, max = MAX_STRING): string {
  if (typeof v !== "string") return "";
  // remove C0/C1 control characters (incl. \n\r\t) — they never reach the twin
  let s = v.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  // collapse runs of whitespace (defensive against padding floods)
  s = s.replace(/\s{3,}/g, "  ").trim();
  if (s.length > max) s = s.slice(0, max) + "…";
  return s;
}

/** Sanitize a label (shorter cap — UI display). */
export function sanitizeLabel(v: unknown): string {
  return sanitizeString(v, MAX_LABEL);
}

/** Bounded integer coercion. */
export function safeInt(v: unknown, fallback = 0): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(-1, Math.min(1_000_000_000, Math.trunc(n)));
}

/** Bounded float coercion (confidence etc.). */
export function safeFloat(v: unknown, fallback = 0): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(1, n));
}

/** URL/path helper: extract the path (no query, no fragment), sanitized. */
export function pathOf(rawUrl: unknown): string {
  const s = typeof rawUrl === "string" ? rawUrl : "";
  if (!s) return "";
  try {
    const u = new URL(s);
    return sanitizeString(u.pathname || "/", MAX_STRING);
  } catch {
    // not an absolute URL — treat as path-ish string, strip query part
    const noQ = s.split("?")[0].split("#")[0];
    return sanitizeString(noQ.startsWith("/") ? noQ : "/" + noQ, MAX_STRING);
  }
}

/** Extract origin from a URL string ("" when unparseable). */
export function originOf(rawUrl: unknown): string {
  const s = typeof rawUrl === "string" ? rawUrl : "";
  try {
    return new URL(s).origin;
  } catch {
    return "";
  }
}

/** Extract host from a URL string ("" when unparseable). */
export function hostOf(rawUrl: unknown): string {
  const s = typeof rawUrl === "string" ? rawUrl : "";
  try {
    return new URL(s).hostname;
  } catch {
    return "";
  }
}

/** Uppercase HTTP method with a safe fallback. */
export function methodOf(m: unknown): string {
  const s = sanitizeString(m, 8).toUpperCase();
  return /^[A-Z]{3,8}$/.test(s) ? s : "GET";
}

/** Deterministic string sort helper. */
export function byKey(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
