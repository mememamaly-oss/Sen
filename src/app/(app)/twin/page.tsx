"use client";

// SENTINEL digital twin — Phase 01 view.
// Shows ONLY what the current backend exposes: coverage dimensions, endpoint
// inventory, boundary categories — all real numbers from the latest completed
// scan. The interactive graph is Phase 02 of the ratified roadmap and is
// explicitly labeled as such. No fabricated graph data.

import Link from "next/link";
import { useMemo } from "react";
import { Network, Route, ShieldCheck } from "lucide-react";
import { api, type ScanRow } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { KpiCard, PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState, EmptyState } from "@/components/ui-kit/states";
import { cn } from "@/lib/utils";

function GraphMotif() {
  // decorative only — clearly an illustration, not data
  return (
    <svg viewBox="0 0 280 150" className="h-36 w-full text-primary/25" aria-hidden focusable="false">
      <g fill="none" stroke="currentColor" strokeWidth="1.2">
        <path d="M40 75h45m30 0h45m30 0h40" />
        <path d="M60 75l35-38 45 20 40-32" />
        <path d="M60 75l35 38 45-20 40 32" />
        <path d="M95 37v76m45-58v58m40-32v64" strokeDasharray="3 5" />
      </g>
      <g fill="currentColor">
        <circle cx="40" cy="75" r="4" />
        <circle cx="85" cy="75" r="3" />
        <circle cx="95" cy="37" r="3" />
        <circle cx="95" cy="113" r="3" />
        <circle cx="130" cy="75" r="3" />
        <circle cx="175" cy="57" r="3" />
        <circle cx="175" cy="93" r="3" />
        <circle cx="220" cy="25" r="3" />
        <circle cx="220" cy="125" r="3" />
        <circle cx="240" cy="75" r="4" />
      </g>
    </svg>
  );
}

export default function TwinPage() {
  const { t, fmtNum } = useI18n();
  const session = useSession();
  const org = session.org;

  const scansQ = useAsync(
    () => (org ? api.scans(org.id) : Promise.resolve({ scans: [] as ScanRow[] })),
    [org?.id]
  );
  const latestCompleted = useMemo(
    () => (scansQ.data?.scans ?? []).find((s) => s.status === "COMPLETED"),
    [scansQ.data]
  );
  const covQ = useAsync(
    () => (org && latestCompleted ? api.scanCoverage(org.id, latestCompleted.id) : Promise.resolve(null)),
    [org?.id, latestCompleted?.id]
  );

  const cov = covQ.data?.coverage ?? null;
  const boundary = covQ.data?.boundary ?? null;
  const dims = useMemo(() => Object.entries(cov?.dimensions ?? {}), [cov]);

  return (
    <>
      <PageHeader title={t("twin.title")} subtitle={t("twin.subtitle")} />

      {/* phase note — honest roadmap labeling */}
      <div className="mb-4 flex items-start gap-3 rounded-xl border border-dashed bg-[color-mix(in_oklab,var(--primary)_7%,transparent)] px-4 py-3">
        <Route className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
        <p className="text-[13px] leading-6 text-muted-foreground">{t("twin.phaseNote")}</p>
      </div>

      {scansQ.state === "loading" || (latestCompleted && covQ.state === "loading") ? (
        <div className="grid gap-3 md:grid-cols-2">
          <CardSkeleton lines={4} />
          <CardSkeleton lines={4} />
        </div>
      ) : scansQ.state === "error" ? (
        <ErrorState onRetry={scansQ.retry} message={scansQ.error ?? undefined} />
      ) : !latestCompleted ? (
        <EmptyState
          title={t("twin.noData")}
          icon={<Network className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : covQ.state === "error" ? (
        <ErrorState onRetry={covQ.retry} message={covQ.error ?? undefined} />
      ) : (
        <>
          {/* real numbers from the latest completed scan */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <KpiCard label={t("twin.stats.surfaces")} value={fmtNum(cov?.discovered ?? 0)} tone="primary" hint={latestCompleted?.target?.name} />
            <KpiCard label={t("scans.coverage")} value={`${fmtNum(cov?.coverage_pct ?? 0)}%`} tone="success" />
            <KpiCard label={`${t("findings.verified")}/${t("common.of")} ${t("twin.stats.surfaces")}`} value={`${fmtNum(cov?.tested ?? 0)}/${fmtNum(cov?.discovered ?? 0)}`} />
            <KpiCard label={t("findings.unverified")} value={fmtNum(cov?.untested ?? 0)} hint={boundary?.unresolved ? `${fmtNum(boundary.unresolved)} unresolved boundary` : undefined} />
          </div>

          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {/* coverage dimensions — real engine data (17 dims) */}
            <SectionCard title={t("twin.coverageDimensions")}>
              <ul className="divide-y">
                {dims.map(([name, d]) => (
                  <li key={name} className="flex items-center gap-3 px-4 py-2.5">
                    <span className="min-w-0 flex-1 truncate text-sm font-semibold">{name}</span>
                    <span className="num tnum text-xs text-muted-foreground">
                      {fmtNum(d.discovered ?? 0)} / {fmtNum(d.tested ?? 0)}
                    </span>
                    <span
                      className={cn(
                        "num tnum rounded px-1.5 py-0.5 text-[11px] font-bold",
                        (d.untested ?? 0) === 0
                          ? "bg-[color-mix(in_oklab,var(--success)_14%,transparent)] text-[var(--success)]"
                          : "bg-[color-mix(in_oklab,var(--severity-high)_14%,transparent)] text-[var(--severity-high)]"
                      )}
                    >
                      {fmtNum(d.untested ?? 0)} ⊘
                    </span>
                  </li>
                ))}
                {dims.length === 0 ? (
                  <li className="px-4 py-6 text-center text-sm text-muted-foreground">{t("common.none")}</li>
                ) : null}
              </ul>
            </SectionCard>

            {/* boundary categories — real engine data */}
            <SectionCard title="Boundary Intelligence">
              <div className="px-4 py-3.5">
                {boundary && Object.keys(boundary.by_category ?? {}).length ? (
                  <ul className="space-y-1.5">
                    {Object.entries(boundary.by_category ?? {}).map(([c, n]) => (
                      <li key={c} className="flex items-center justify-between gap-2 rounded-lg bg-muted/40 px-3 py-2">
                        <span className="num min-w-0 flex-1 truncate text-xs">{c}</span>
                        <span className="num tnum text-xs font-bold text-muted-foreground">{fmtNum(n)}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">{t("common.none")}</p>
                )}
                {boundary?.unresolved_detail?.length ? (
                  <ul className="mt-3 space-y-2">
                    {boundary.unresolved_detail.slice(0, 5).map((b, i) => (
                      <li key={i} className="rounded-lg border bg-muted/30 px-3 py-2">
                        <p className="text-xs font-bold">{b.category}</p>
                        <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{b.reason}</p>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            </SectionCard>
          </div>

          {/* Phase 02 placeholder — decorative, labeled */}
          <SectionCard
            title={`${t("twin.title")} — Phase 02`}
            className="mt-4"
            extra={<Link href="/scans" className="text-xs font-semibold text-primary hover:underline">{t("scans.title")}</Link>}
          >
            <div className="px-4 py-6">
              <GraphMotif />
              <p className="mt-2 text-center text-xs leading-6 text-muted-foreground">
                {t("twin.phaseNote")}
              </p>
            </div>
          </SectionCard>
        </>
      )}
    </>
  );
}
