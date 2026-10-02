"use client";

// SENTINEL overview — the executive dashboard. Every number comes from the
// platform APIs (org overview + membership counts). No invented metrics.

import Link from "next/link";
import { useMemo } from "react";
import {
  Activity,
  ArrowUpRight,
  FileText,
  Gauge,
  Radar,
  ShieldCheck,
  Target as TargetIcon,
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { useTheme } from "@/lib/ui/theme";
import { KpiCard, PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState, EmptyState } from "@/components/ui-kit/states";
import { SeverityChip, StatusPill, SEVERITIES } from "@/components/ui-kit/severity";
import { Button } from "@/components/ui/button";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--severity-info)",
};

export default function OverviewPage() {
  const { t, fmtNum, fmtDuration, relTime, fmtDate } = useI18n();
  const session = useSession();
  const { theme } = useTheme();
  const org = session.org;
  const q = useAsync(() => (org ? api.orgOverview(org.id) : Promise.resolve(null)), [org?.id]);

  const sevData = useMemo(() => {
    const bySev = q.data?.findingsBySeverity ?? {};
    return SEVERITIES.map((s) => ({ name: s, value: bySev[s] ?? 0 })).filter((x) => x.value > 0);
  }, [q.data]);

  const totalFindings = useMemo(
    () => Object.values(q.data?.findingsBySeverity ?? {}).reduce((a, b) => a + b, 0),
    [q.data]
  );

  const covPct = q.data?.lastCompleted?.coverage?.coverage_pct ?? null;
  const gridColor = theme === "dark" ? "rgba(148,163,184,0.14)" : "rgba(15,23,42,0.10)";
  const last = q.data?.lastCompleted;

  if (!org) return null;

  return (
    <>
      <PageHeader
        title={t("overview.title")}
        subtitle={t("overview.subtitle.exec")}
        meta={
          <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span className="num">{q.data?.lastCompleted?.scanner ?? "sentinel-core/4.1.1"}</span>
            {last?.finishedAt ? <span>· {t("overview.lastScan")}: {relTime(last.finishedAt)}</span> : null}
          </p>
        }
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href="/scans">
              {t("overview.viewAll")}
              <ArrowUpRight className="size-3.5" aria-hidden />
            </Link>
          </Button>
        }
      />

      {/* KPI row — real counts from membership + org overview */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiCard
          label={t("overview.kpi.targets")}
          value={fmtNum(org.counts.targets)}
          icon={<TargetIcon className="size-4" aria-hidden />}
          href="/targets"
          hrefLabel={t("overview.viewAll")}
          tone="primary"
        />
        <KpiCard
          label={t("overview.kpi.scans")}
          value={fmtNum(org.counts.scans)}
          icon={<Radar className="size-4" aria-hidden />}
          href="/scans"
          hrefLabel={t("overview.viewAll")}
        />
        <KpiCard
          label={t("overview.kpi.findings")}
          value={fmtNum(org.counts.findings)}
          hint={totalFindings ? `${fmtNum(totalFindings)} ${t("overview.findingsFound")}` : undefined}
          icon={<Activity className="size-4" aria-hidden />}
          href="/findings"
          hrefLabel={t("overview.viewAll")}
          tone={totalFindings > 0 ? "warning" : "success"}
        />
        <KpiCard
          label={t("overview.kpi.reports")}
          value={fmtNum(org.counts.reports)}
          icon={<FileText className="size-4" aria-hidden />}
          href="/reports"
          hrefLabel={t("overview.viewAll")}
        />
      </div>

      {/* charts row */}
      <div className="mt-4 grid gap-3 lg:grid-cols-3">
        {/* severity mix */}
        {q.state === "loading" ? (
          <CardSkeleton className="lg:col-span-1" />
        ) : q.state === "error" ? (
          <div className="lg:col-span-1"><ErrorState onRetry={q.retry} message={q.error ?? undefined} /></div>
        ) : sevData.length === 0 ? (
          <SectionCard title={t("overview.severityMix")} className="lg:col-span-1">
            <div className="px-4 py-10">
              <EmptyState title={t("common.empty")} hint={t("overview.severityMixEmpty")}
                icon={<ShieldCheck className="size-6 text-muted-foreground" aria-hidden />} />
            </div>
          </SectionCard>
        ) : (
          <SectionCard title={t("overview.severityMix")} className="lg:col-span-1">
            <div className="px-2 py-4">
              <div className="mx-auto h-44 max-w-[240px]" dir="ltr">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sevData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={52}
                      outerRadius={72}
                      paddingAngle={3}
                      strokeWidth={0}
                    >
                      {sevData.map((d) => (
                        <Cell key={d.name} fill={SEV_COLOR[d.name]} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="mt-2 flex flex-wrap justify-center gap-2 px-4">
                {SEVERITIES.filter((s) => (q.data?.findingsBySeverity?.[s] ?? 0) > 0).map((s) => (
                  <li key={s}>
                    <SeverityChip severity={s} count={q.data?.findingsBySeverity?.[s]} />
                  </li>
                ))}
              </ul>
            </div>
          </SectionCard>
        )}

        {/* coverage gauge */}
        {q.state === "loading" ? (
          <CardSkeleton className="lg:col-span-1" />
        ) : q.state === "error" ? (
          <div className="lg:col-span-1"><ErrorState onRetry={q.retry} message={q.error ?? undefined} /></div>
        ) : (
          <SectionCard title={t("overview.kpi.coverage")} className="lg:col-span-1">
            <div className="px-4 py-4">
              {covPct === null ? (
                <div className="py-8">
                  <EmptyState
                    title={t("overview.noCompleted")}
                    hint={t("twin.noData")}
                    icon={<Gauge className="size-6 text-muted-foreground" aria-hidden />}
                  />
                </div>
              ) : (
                <>
                  <div className="mx-auto h-40 max-w-[240px]" dir="ltr">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadialBarChart
                        data={[{ name: "coverage", value: covPct }]}
                        innerRadius="72%"
                        outerRadius="100%"
                        startAngle={210}
                        endAngle={-30}
                      >
                        <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                        <RadialBar dataKey="value" cornerRadius={8} fill="var(--primary)" background={{ fill: gridColor }} />
                      </RadialBarChart>
                    </ResponsiveContainer>
                  </div>
                  <p className="text-center">
                    <span className="num tnum text-3xl font-extrabold">{fmtNum(covPct)}%</span>
                    <span className="ms-1.5 text-xs font-semibold text-muted-foreground">
                      {last?.finishedAt ? fmtDate(last.finishedAt, { time: false }) : ""}
                    </span>
                  </p>
                </>
              )}
            </div>
          </SectionCard>
        )}

        {/* recent scans */}
        {q.state === "loading" ? (
          <CardSkeleton className="lg:col-span-1" lines={5} />
        ) : q.state === "error" ? (
          <div className="lg:col-span-1"><ErrorState onRetry={q.retry} message={q.error ?? undefined} /></div>
        ) : (q.data?.recentScans ?? []).length === 0 ? (
          <SectionCard title={t("overview.recentScans")} className="lg:col-span-1">
            <div className="px-4 py-10">
              <EmptyState title={t("overview.recentEmpty")} hint={t("scans.empty.hint")} />
            </div>
          </SectionCard>
        ) : (
          <SectionCard
            title={t("overview.recentScans")}
            className="lg:col-span-1"
            extra={
              <Link href="/scans" className="text-xs font-semibold text-primary hover:underline">
                {t("overview.viewAll")}
              </Link>
            }
          >
            <ul className="divide-y">
              {(q.data?.recentScans ?? []).slice(0, 6).map((s) => (
                <li key={s.id}>
                  <Link
                    href={`/scans/${s.id}`}
                    className="flex items-center gap-3 px-4 py-2.5 transition-colors duration-150 hover:bg-muted/50"
                  >
                    <StatusPill status={s.status} live={s.status === "RUNNING"} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold leading-5">{s.targetName}</p>
                      <p className="truncate text-[11px] leading-4 text-muted-foreground">
                        {relTime(s.createdAt)} · {s.findingsCount} {t("overview.findingsFound")} ·{" "}
                        {s.durationSec ? fmtDuration(s.durationSec) : "—"}
                        {s.coverage?.coverage_pct != null ? ` · ${fmtNum(s.coverage.coverage_pct)}%` : ""}
                      </p>
                    </div>
                    <ArrowUpRight className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  </Link>
                </li>
              ))}
            </ul>
          </SectionCard>
        )}
      </div>
    </>
  );
}
