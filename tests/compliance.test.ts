/**
 * P2-C (2026-10-31): platform-side compliance registry tests (bun:test).
 *
 * The platform must render the ENGINE's registry — never re-derive it.
 * These tests fail when:
 *   - the checked-in registry JSON drifts from `python -m burhan.cli
 *     compliance --json` (the single source of truth)
 *   - the registry loses shape (categories, official lists, PCI note)
 *   - lookup helpers return guesses instead of the honest unmapped shape
 */
import { describe, expect, test } from "bun:test";
import { spawnSync } from "child_process";
import {
  COMPLIANCE_TYPES,
  CWE_LABELS,
  OWASP_2021_CATEGORIES,
  OWASP_2025_CATEGORIES,
  PCI_DSS_NOTE,
  PCI_DSS_REQUIREMENT,
  complianceFor,
  complianceFromJson,
} from "@/lib/compliance";

const ROOT = new URL("..", import.meta.url).pathname;

describe("compliance registry (P2-C)", () => {
  test("engine parity: checked-in JSON == burhan CLI export", () => {
    const r = spawnSync("python3", ["-m", "burhan.cli", "compliance", "--json"], {
      cwd: ROOT,
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    expect(r.status).toBe(0);
    const engine = JSON.parse(r.stdout.toString()) as {
      types: Record<string, unknown>;
    };
    expect(Object.keys(engine.types).length).toBeGreaterThan(0);
    // every engine row must be present and equal in the checked-in copy
    for (const [type, row] of Object.entries(engine.types)) {
      expect(COMPLIANCE_TYPES[type], `missing type ${type} in checked-in registry`).toEqual(row);
    }
    expect(Object.keys(COMPLIANCE_TYPES).length).toBe(Object.keys(engine.types).length);
  });

  test("registry shape: categories, labels, official lists, PCI note", () => {
    expect(Object.keys(OWASP_2021_CATEGORIES)).toHaveLength(10);
    expect(Object.keys(OWASP_2025_CATEGORIES)).toHaveLength(10);
    expect(OWASP_2025_CATEGORIES["A03:2025"]).toBe("Software Supply Chain Failures");
    expect(OWASP_2021_CATEGORIES["A10:2021"]).toContain("SSRF");
    expect(CWE_LABELS["CWE-89"]).toBe("SQL Injection");
    expect(PCI_DSS_REQUIREMENT).toBe("6.4.2");
    expect(PCI_DSS_NOTE).toContain("6.6 in PCI DSS v3.2.1");
  });

  test("lookup: known type mapped; unknown type honestly unmapped", () => {
    const s = complianceFor("sql_injection");
    expect(s.mapped).toBe(true);
    expect(s.cwe).toBe("CWE-89");
    expect(s.owasp_2021).toBe("A03:2021");
    expect(s.owasp_2025).toBe("A05:2025");
    expect(s.pci_dss).toBe("6.4.2");

    const u = complianceFor("not_a_real_class");
    expect(u.mapped).toBe(false);
    expect(u.cwe).toBeNull();
    expect(u.owasp_2021).toBeNull();
    expect(u.pci_dss).toBeNull();
  });

  test("complianceFromJson: round-trips the stored column; rejects garbage", () => {
    const c = complianceFor("path_traversal");
    const back = complianceFromJson(JSON.stringify(c));
    expect(back?.cwe).toBe("CWE-23");
    expect(complianceFromJson(null)).toBeNull();
    expect(complianceFromJson("not json at all")).toBeNull();
    expect(complianceFromJson("{}")).not.toBeNull();
  });

  test("supply-chain mapping follows the 2025 final edition", () => {
    const v = complianceFor("vulnerable_js_dependency");
    expect(v.owasp_2025).toBe("A03:2025"); // Software Supply Chain Failures
    expect(v.owasp_2025_src).toBe("official");
    expect(v.cwe).toBe("CWE-1104");
  });
});
