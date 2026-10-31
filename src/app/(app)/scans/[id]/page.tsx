"use client";

// Burhan scan monitor — the live scan experience.
// While RUNNING: progress strip + engine log terminal (poll 2.5s).
// On COMPLETED: engine stats, findings, coverage, boundary + report generation.
// Every number is engine-sourced; nothing is invented.

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Ban,
  Cpu,
  FileOutput,
  Gauge,
  Link2,
  ListChecks,
  Radio,
  ScrollText,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync, usePolling } from "@/lib/ui/use-async";
import { useToast } from "@/lib/ui/toast";
import { KpiCard, PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState, EmptyState } from "@/components/ui-kit/states";
import { SeverityChip, StatusPill, VerificationChip, SEVERITIES } from "@/components/ui-kit/severity";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const REPORT_FORMATS = ["HTML", "SARIF", "EXECUTIVE", "GLASS"] as const;

export default function ScanMonitorPage() {
  const { id } = useParams<{ id: string }>();
  const { t, fmtNum, fmtDuration, fmtDate, relTime } = useI18n();
  const session = useSession();
  const toast = useToast();
  const org = session.org;
  const orgId = org?.id ?? "";

  const live = usePolling(
    () => (orgId && id ? api.scanDetail(orgId, id) : Promise.resolve(null as never)),
    2500,
    !!orgId && !!id
  );
  const scan = live.data?.scan;
  const progress = live.data?.progress;
  const isTerminal = !!scan && ["COMPLETED", "FAILED", "CANCELLED"].includes(scan.status);
  const isLive = !!scan && ["RUNNING", "QUEUED"].includes(scan.status);

  // findings + coverage + boundary for completed scans (real engine data)
  const findingsQ = useAsync(
    () => (orgId && id && scan?.status === "COMPLETED" ? api.scanFindings(orgId, id) : Promise.resolve(null)),
    [orgId, id, scan?.status]
  );
  const coverageQ = useAsync(
    () => (orgId && id && scan?.status === "COMPLETED" ? api.scanCoverage(orgId, id) : Promise.resolve(null)),
    [orgId, id, scan?.status]
  );

  // local ticking elapsed between polls
  const [elapsed, setElapsed] = useState<number | null>(null);
  const elapsedRef = useRef<number | null>(null);
  useEffect(() => {
    if (progress?.elapsedSec != null) elapsedRef.current = progress.elapsedSec;
  }, [progress?.elapsedSec]);
  useEffect(() => {
    if (!isLive) return;
    const timer = setInterval(() => {
      setElapsed((cur) => (cur == null ? elapsedRef.current ?? 0 : cur + 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [isLive]);
  useEffect(() => {
    if (scan?.durationSec != null) setElapsed(scan.durationSec);
  }, [scan?.durationSec]);

  // report generation
  const [fmt, setFmt] = useState<string>("HTML");
  const [genBusy, setGenBusy] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);

  const findings = findingsQ.data?.findings ?? [];
  const types = findingsQ.data?.types ?? [];
  const coverage = coverageQ.data?.coverage ?? null;
  const boundary = coverageQ.data?.boundary ?? null;

  const verifiedCount = useMemo(() => findings.filter((f) => (f.status ?? "").toLowerCase().includes("verified")).length, [findings]);

  async function generateReport() {
    if (!orgId || !id) return;
    setGenBusy(true);
    try {
      await api.createReport({ orgId, scanId: id, format: fmt });
      toast.success(t("reports.generated"));
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    } finally {
      setGenBusy(false);
    }
  }

  async function cancelScan() {
    if (!orgId || !id) return;
    setConfirmCancel(false);
    try {
      await api.cancelScan(orgId, id);
      toast.info(t("scans.cancelled"));
      live.reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    }
  }

  if (live.state === "loading" && !scan) return <CardSkeleton lines={6} />;
  if (live.state === "error" && !scan) return <ErrorState onRetry={live.retry} message={live.error ?? undefined} />;
  if (!scan) return null;

  return (
    <>
      <PageHeader
        title={scan.target?.name ?? t("scans.monitor.title")}
        subtitle={`${t("scans.runId")}: ${scan.runId ?? "—"} · ${scan.scanner ?? "—"} · ${t("scans.startedBy")}: ${scan.createdBy ?? "—"}`}
        meta={
          <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <StatusPill status={scan.status} live={isLive} />
            <span>{fmtDate(scan.createdAt)}</span>
            {scan.finishedAt ? <span>· {t("overview.duration")}: {fmtDuration(scan.durationSec)}</span> : null}
          </p>
        }
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href="/scans">
                <ArrowLeft className="size-3.5" aria-hidden />
                {t("common.back")}
              </Link>
            </Button>
            {isLive ? (
              <Button variant="outline" size="sm" className="text-[var(--severity-critical)]" onClick={() => setConfirmCancel(true)}>
                <Ban className="size-3.5" aria-hidden />
                {t("scans.monitor.cancel")}
              </Button>
            ) : null}
          </>
        }
      />

      {/* ── live progress strip ── */}
      {isLive ? (
        <div className="card-elevated mb-4 overflow-hidden rounded-xl border bg-card">
          <div className="flex items-center gap-2 border-b px-4 py-3">
            <Radio className="size-4 text-primary live-dot" aria-hidden />
            <p className="text-sm font-bold">{t("scans.monitor.title")}</p>
            <span className="ms-auto rounded bg-[color-mix(in_oklab,var(--primary)_16%,transparent)] px-2 py-0.5 text-xs font-extrabold text-primary">
              {t("scans.live")}
            </span>
          </div>
          <div className="grid grid-cols-2 divide-x divide-x-reverse border-b sm:grid-cols-4" dir="ltr">
            {[
              { label: t("scans.monitor.elapsed"), value: fmtDuration(elapsed ?? progress?.elapsedSec ?? 0), icon: <Timer className="size-4" aria-hidden /> },
              { label: t("scans.monitor.eta"), value: progress?.etaSec != null ? fmtDuration(progress.etaSec) : "—", icon: <Gauge className="size-4" aria-hidden /> },
              { label: t("scans.monitor.cpu"), value: progress?.cpuSec != null ? `${fmtNum(progress.cpuSec)}s` : "—", icon: <Cpu className="size-4" aria-hidden /> },
              { label: t("scans.monitor.connections"), value: fmtNum(progress?.connections ?? 0), icon: <Link2 className="size-4" aria-hidden /> },
            ].map((m, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3.5" dir={i % 2 === 0 ? "ltr" : "ltr"}>
                <span className="text-muted-foreground">{m.icon}</span>
                <div className="leading-tight">
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{m.label}</p>
                  <p className="num tnum text-lg font-extrabold">{m.value}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="px-4 py-3">
            <p className="mb-1.5 text-xs font-bold text-muted-foreground">{t("scans.monitor.engineLog")}</p>
            <pre
              className="num max-h-44 overflow-auto rounded-lg bg-muted/60 p-3 text-[11px] leading-5 text-muted-foreground"
              aria-label={t("scans.monitor.engineLog")}
              dir="ltr"
            >
              {progress?.logTail?.slice(-2000) || "…"}
            </pre>
            <p className="mt-2 text-xs text-muted-foreground">{t("scans.monitor.noFindingsYet")}</p>
          </div>
        </div>
      ) : null}

      {/* ── failed reason (honest) ── */}
      {scan.status === "FAILED" ? (
        <div role="alert" className="mb-4 rounded-xl border border-[var(--severity-critical)]/40 bg-[color-mix(in_oklab,var(--severity-critical)_8%,transparent)] px-4 py-3">
          <p className="text-sm font-bold text-[var(--severity-critical)]">{t("scans.status.FAILED")}</p>
          <p className="mt-1 text-sm text-muted-foreground">{t("scans.failedReason")}: {scan.error ?? "—"}</p>
        </div>
      ) : null}

      {/* ── completed: engine stats ── */}
      {scan.status === "COMPLETED" ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <KpiCard label={t("overview.kpi.findings")} value={fmtNum(scan.findingsCount)} tone={scan.findingsCount > 0 ? "warning" : "success"} hint={scan.bySeverity ? Object.entries(scan.bySeverity).filter(([, n]) => n > 0).map(([s, n]) => `${t(`severity.${s}` as never)} ${n}`).join(" · ") || undefined : undefined} />
            <KpiCard label="requests" value={fmtNum(scan.stats?.requests ?? null)} />
            <KpiCard label="endpoints" value={fmtNum(scan.stats?.endpoints ?? null)} />
            <KpiCard label="verified / rejected" value={`${fmtNum(scan.stats?.verified ?? null)} / ${fmtNum(scan.stats?.rejected ?? null)}`} tone="primary" />
          </div>

          {/* severity chips */}
          <div className="mt-3 flex flex-wrap gap-2">
            {SEVERITIES.filter((s) => (scan.bySeverity?.[s] ?? 0) > 0).map((s) => (
              <SeverityChip key={s} severity={s} count={scan.bySeverity?.[s]} />
            ))}
          </div>

          {/* report generation */}
          <SectionCard title={t("reports.create")} className="mt-4" extra={<span className="text-xs text-muted-foreground">{t("reports.generate")} →</span>}>
            <div className="flex flex-wrap items-center gap-2 px-4 py-3.5">
              <Select value={fmt} onValueChange={setFmt}>
                <SelectTrigger className="w-40" aria-label={t("reports.format")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REPORT_FORMATS.map((f) => (
                    <SelectItem key={f} value={f}>{f}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={generateReport} disabled={genBusy}>
                <FileOutput className="size-4" aria-hidden />
                {genBusy ? t("common.loading") : t("reports.generate")}
              </Button>
              <Button asChild variant="outline">
                <Link href="/reports">{t("reports.title")}</Link>
              </Button>
            </div>
          </SectionCard>

          {/* findings table */}
          <div className="mt-4">
            {findingsQ.state === "loading" ? (
              <CardSkeleton lines={6} />
            ) : findingsQ.state === "error" ? (
              <ErrorState onRetry={findingsQ.retry} message={findingsQ.error ?? undefined} />
            ) : findings.length === 0 ? (
              <EmptyState title={t("findings.empty.title")} hint={t("findings.empty.hint")} icon={<ShieldCheck className="size-6 text-muted-foreground" aria-hidden />} />
            ) : (
              <SectionCard title={`${t("overview.kpi.findings")} · ${fmtNum(findings.length)}`} extra={<Link href={`/findings?scan=${id}`} className="text-xs font-semibold text-primary hover:underline">{t("overview.viewAll")}</Link>}>
                <ul className="divide-y">
                  {findings.slice(0, 8).map((f) => (
                    <li key={f.id}>
                      <Link href={`/findings/${f.id}`} className="flex flex-wrap items-center gap-2 px-4 py-2.5 transition-colors duration-150 hover:bg-muted/50">
                        <SeverityChip severity={f.severity} />
                        <span className="num min-w-0 flex-1 truncate text-sm font-semibold" dir="ltr">{f.type}</span>
                        <span className="num max-w-52 truncate text-xs text-muted-foreground" dir="ltr">{f.url}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </SectionCard>
            )}
          </div>

          {/* coverage + boundary (real engine panels) */}
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {coverageQ.state === "loading" ? (
              <CardSkeleton lines={5} />
            ) : coverageQ.state === "error" ? (
              <ErrorState onRetry={coverageQ.retry} message={coverageQ.error ?? undefined} />
            ) : coverage ? (
              <SectionCard title={t("scans.coverage")}>
                <div className="px-4 py-3.5">
                  <div className="flex items-baseline gap-2">
                    <span className="num tnum text-3xl font-extrabold">{fmtNum(coverage.coverage_pct ?? 0)}%</span>
                    <span className="text-xs text-muted-foreground">
                      {fmtNum(coverage.tested ?? 0)}/{fmtNum(coverage.discovered ?? 0)} {t("common.of")} {fmtNum(coverage.discovered ?? 0)}
                    </span>
                  </div>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted" role="meter" aria-valuenow={coverage.coverage_pct ?? 0} aria-valuemin={0} aria-valuemax={100}>
                    <div className="h-full rounded-full bg-primary" style={{ width: `${coverage.coverage_pct ?? 0}%` }} />
                  </div>
                  {coverage.endpoints?.length ? (
                    <ul className="mt-3 max-h-64 space-y-1.5 overflow-auto pe-1" dir="ltr">
                      {coverage.endpoints.map((ep, i) => (
                        <li key={i} className="flex items-center gap-2 rounded-lg bg-muted/40 px-2.5 py-1.5">
                          <span className="num rounded bg-primary/15 px-1.5 py-0.5 text-[10px] font-extrabold text-primary">{ep.method}</span>
                          <span className="num min-w-0 flex-1 truncate text-[11px] text-muted-foreground">{ep.url}</span>
                          <span className="num text-[10px] text-[var(--success)]">{ep.activity.length}✓</span>
                          {ep.skips.length ? <span className="num text-[10px] text-[var(--severity-high)]">{ep.skips.length}⊘</span> : null}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              </SectionCard>
            ) : null}

            {boundary ? (
              <SectionCard title="Boundary Intelligence">
                <div className="px-4 py-3.5">
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(boundary.by_state ?? {}).map(([st, n]) => (
                      <span key={st} className="rounded-full bg-muted px-2.5 py-1 text-xs font-bold text-muted-foreground">
                        {st}: <span className="num tnum">{fmtNum(n)}</span>
                      </span>
                    ))}
                  </div>
                  {(boundary.unresolved_detail ?? []).length ? (
                    <ul className="mt-3 space-y-2">
                      {boundary.unresolved_detail!.slice(0, 6).map((b, i) => (
                        <li key={i} className="rounded-lg border bg-muted/30 px-3 py-2">
                          <p className="text-xs font-bold">{b.category} <span className="font-normal text-muted-foreground">· {b.target}</span></p>
                          <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{b.reason}</p>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-3 text-xs text-muted-foreground">{t("common.none")}</p>
                  )}
                </div>
              </SectionCard>
            ) : null}
          </div>
        </>
      ) : null}

      {/* cancel confirm */}
      <AlertDialog open={confirmCancel} onOpenChange={setConfirmCancel}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("scans.monitor.cancelConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{t("scans.monitor.cancelConfirmBody")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={cancelScan} className="bg-[var(--severity-critical)] text-white hover:bg-[var(--severity-critical)]/90">
              {t("scans.monitor.cancel")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
