"use client";

// P2-C: the public compliance map — rendered from src/lib/compliance-registry.json
// (GENERATED from burhan/compliance.py by scripts/gen_compliance_registry.py;
// CI fails on drift). The page never hardcodes a mapping — single source of truth.

import { useMemo, useState } from "react";
import { Search, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useI18n } from "@/lib/ui/i18n";
import {
  COMPLIANCE_TYPES,
  OWASP_2021_CATEGORIES,
  OWASP_2025_CATEGORIES,
  PCI_DSS_NOTE,
  PCI_DSS_REQUIREMENT,
} from "@/lib/compliance";

export default function ComplianceDocsPage() {
  const { t } = useI18n();
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return Object.values(COMPLIANCE_TYPES)
      .filter((c) =>
        !needle ||
        c.type.includes(needle) ||
        (c.cwe ?? "").toLowerCase().includes(needle) ||
        (c.cwe_label ?? "").toLowerCase().includes(needle) ||
        (c.owasp_2021 ?? "").toLowerCase().includes(needle) ||
        (c.owasp_2025 ?? "").toLowerCase().includes(needle)
      )
      .sort((a, b) => a.type.localeCompare(b.type));
  }, [q]);

  return (
    <article className="max-w-5xl">
      <h1 className="flex items-center gap-2 text-2xl font-extrabold tracking-tight">
        <ShieldCheck className="size-5 text-primary" aria-hidden /> {t("docs.compliance")}
      </h1>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        {t("landing.pillars.complianceBody")}
      </p>

      <div className="mt-4 rounded-xl border bg-card p-4 text-sm">
        <b>{t("compliance.pci")}</b> — {t("compliance.pciNote")}:{" "}
        <span className="num" dir="ltr">{PCI_DSS_REQUIREMENT}</span>
        <p className="mt-1 text-xs text-muted-foreground" dir="ltr">{PCI_DSS_NOTE}</p>
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">{t("compliance.srcLegend")}</p>

      <div className="mt-5 flex items-center gap-2">
        <Search className="size-4 text-muted-foreground" aria-hidden />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={`${t("common.search")}…`}
          className="h-9 max-w-xs"
          dir="ltr"
        />
        <span className="ms-auto text-xs text-muted-foreground num" dir="ltr">
          {rows.length}/{Object.keys(COMPLIANCE_TYPES).length}
        </span>
      </div>

      <div className="mt-4 overflow-x-auto rounded-xl border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50 text-start text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-3 py-2.5 text-start" dir="ltr">Detector class</th>
              <th className="px-3 py-2.5 text-start" dir="ltr">CWE</th>
              <th className="px-3 py-2.5 text-start">{t("compliance.owasp2021")}</th>
              <th className="px-3 py-2.5 text-start">{t("compliance.owasp2025")}</th>
              <th className="px-3 py-2.5 text-start">{t("compliance.pci")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.type} className="border-b last:border-0">
                <td className="px-3 py-2.5 num text-[12.5px] font-semibold" dir="ltr">
                  {c.type}
                  {!c.mapped ? (
                    <span className="ms-2 text-[11px] font-normal text-muted-foreground">
                      {t("compliance.unmapped")}
                    </span>
                  ) : null}
                </td>
                <td className="px-3 py-2.5" dir="ltr">
                  {c.cwe ? (
                    <span className="num text-[12px]" title={c.cwe_label ?? ""}>
                      {c.cwe}
                    </span>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-3 py-2.5" dir="ltr">
                  {c.owasp_2021 ? (
                    <Badge variant="outline" className="num text-[11px]" title={c.owasp_2021_title ?? ""}>
                      {c.owasp_2021} · {c.owasp_2021_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-3 py-2.5" dir="ltr">
                  {c.owasp_2025 ? (
                    <Badge variant="outline" className="num text-[11px]" title={c.owasp_2025_title ?? ""}>
                      {c.owasp_2025} · {c.owasp_2025_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-3 py-2.5 num text-[12px]" dir="ltr">{c.pci_dss ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="mt-8">
        <h2 className="text-sm font-extrabold" dir="ltr">
          OWASP Top 10:2025 (final) · categories
        </h2>
        <ul className="mt-3 grid gap-1.5 sm:grid-cols-2" dir="ltr">
          {Object.entries(OWASP_2025_CATEGORIES).map(([code, title]) => (
            <li key={code} className="num text-xs text-muted-foreground">
              <b className="text-foreground">{code}</b> — {title}
            </li>
          ))}
        </ul>
        <h2 className="mt-6 text-sm font-extrabold" dir="ltr">
          OWASP Top 10:2021 · categories
        </h2>
        <ul className="mt-3 grid gap-1.5 sm:grid-cols-2" dir="ltr">
          {Object.entries(OWASP_2021_CATEGORIES).map(([code, title]) => (
            <li key={code} className="num text-xs text-muted-foreground">
              <b className="text-foreground">{code}</b> — {title}
            </li>
          ))}
        </ul>
      </section>

      <p className="mt-8 text-xs leading-5 text-muted-foreground" dir="ltr">
        top10.owasp.org (2021 + 2025 final editions) — official mapped-CWE lists
        fetched 2026-10-31 and embedded in the engine registry; the parity test
        re-verifies every “official” tag against them on each run.
      </p>
    </article>
  );
}
