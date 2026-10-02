"use client";

// SENTINEL scans — run registry with status filter + deep links (?target=)
// + REAL scan start on the filtered target (FG-1).

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowUpRight, Loader2, Play, Radar } from "lucide-react";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { useToast } from "@/lib/ui/toast";
import { PageHeader } from "@/components/ui-kit/page";
import { EmptyState, TableSkeleton, ErrorState } from "@/components/ui-kit/states";
import { StatusPill, VerificationChip } from "@/components/ui-kit/severity";
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
import { cn } from "@/lib/utils";

const STATUSES = ["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"] as const;

function ScansInner() {
  const { t, fmtNum, fmtDuration, relTime } = useI18n();
  const session = useSession();
  const toast = useToast();
  const router = useRouter();
  const org = session.org;
  const params = useSearchParams();
  const targetFilter = params.get("target");

  const q = useAsync(
    () => (org ? api.scans(org.id, targetFilter ?? undefined) : Promise.resolve({ scans: [] })),
    [org?.id, targetFilter]
  );

  const [status, setStatus] = useState<string>("ALL");
  const [startOpen, setStartOpen] = useState(false);
  const [starting, setStarting] = useState(false);
  // POST /api/scans requires MEMBER rank (VIEWER cannot scan) — mirror that here.
  const canScan = session.role === "OWNER" || session.role === "ADMIN" || session.role === "MEMBER";

  // FG-1: start a REAL scan on the filtered target, then follow it live.
  async function startScan() {
    if (!org || !targetFilter) return;
    setStarting(true);
    try {
      const r = await api.startScan({ orgId: org.id, targetId: targetFilter });
      toast.success(t("scans.started"));
      setStartOpen(false);
      router.push(`/scans/${r.id}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    } finally {
      setStarting(false);
    }
  }

  const rows = useMemo(() => {
    const list = (q.data?.scans ?? []).slice();
    const filtered = status === "ALL" ? list : list.filter((s) => s.status === status);
    filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return filtered;
  }, [q.data, status]);

  const activeCount = rows.filter((s) => s.status === "RUNNING" || s.status === "QUEUED").length;

  return (
    <>
      <PageHeader
        title={t("scans.title")}
        subtitle={t("scans.subtitle")}
        actions={
          targetFilter && canScan ? (
            <Button size="sm" onClick={() => setStartOpen(true)}>
              <Play className="size-4" aria-hidden />
              {t("scans.start")}
            </Button>
          ) : undefined
        }
        meta={
          targetFilter ? (
            <p className="mt-1 text-xs text-muted-foreground">
              {t("scans.target")}:{" "}
              <Link href="/targets" className="font-semibold text-primary hover:underline">
                {rows[0]?.target?.name ?? targetFilter}
              </Link>
            </p>
          ) : undefined
        }
      />

      {/* status filter chips */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5" role="group" aria-label={t("scans.status")}>
        <button
          type="button"
          onClick={() => setStatus("ALL")}
          aria-pressed={status === "ALL"}
          className={cn(
            "rounded-full border px-3 py-1.5 text-xs font-bold transition-colors duration-150",
            status === "ALL"
              ? "border-primary bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary"
              : "border-border text-muted-foreground hover:text-foreground"
          )}
        >
          {t("scans.statusFilter.all")}
          <span className="num tnum ms-1.5 opacity-70">{fmtNum((q.data?.scans ?? []).length)}</span>
        </button>
        {STATUSES.map((s) => {
          const n = (q.data?.scans ?? []).filter((x) => x.status === s).length;
          if (!n) return null;
          return (
            <button
              key={s}
              type="button"
              onClick={() => setStatus(s)}
              aria-pressed={status === s}
              className={cn(
                "rounded-full border px-3 py-1.5 text-xs font-bold transition-colors duration-150",
                status === s
                  ? "border-primary bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}
            >
              {t(`scans.status.${s}` as never)}
              <span className="num tnum ms-1.5 opacity-70">{fmtNum(n)}</span>
            </button>
          );
        })}
      </div>

      {q.state === "loading" ? (
        <TableSkeleton rows={6} cols={6} />
      ) : q.state === "error" ? (
        <ErrorState onRetry={q.retry} message={q.error ?? undefined} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("scans.empty.title")}
          hint={t("scans.empty.hint")}
          icon={<Radar className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : (
        <div className="card-elevated overflow-hidden rounded-xl border bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  <th scope="col" className="px-4 py-3 text-start">{t("scans.status")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("scans.target")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("overview.kpi.findings")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("scans.duration")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("scans.runId")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("audit.when")}</th>
                  <th scope="col" className="px-4 py-3 text-end">{t("common.open")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((s) => (
                  <tr key={s.id} className="transition-colors duration-150 hover:bg-muted/40">
                    <td className="px-4 py-3">
                      <StatusPill status={s.status} live={s.status === "RUNNING"} />
                    </td>
                    <td className="max-w-56 px-4 py-3">
                      <p className="truncate font-semibold leading-5">{s.target?.name}</p>
                      <p className="num truncate text-xs text-muted-foreground" dir="ltr">{s.target?.url}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`num tnum font-bold ${s.findingsCount > 0 ? "text-[var(--severity-high)]" : "text-[var(--success)]"}`}>
                        {fmtNum(s.findingsCount)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {fmtDuration(s.durationSec)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="num text-xs text-muted-foreground" dir="ltr">
                        {s.runId ? s.runId.slice(0, 12) + "…" : "—"}
                      </span>
                      <p className="text-[11px] text-muted-foreground">{s.scanner ?? "—"}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{relTime(s.createdAt)}</td>
                    <td className="px-4 py-3">
                      <Button asChild variant="ghost" size="icon" className="size-8" aria-label={`${t("common.open")} ${s.target?.name}`}>
                        <Link href={`/scans/${s.id}`}>
                          <ArrowUpRight className="size-4" aria-hidden />
                        </Link>
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeCount > 0 ? (
        <p className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
          <span className="live-dot inline-block size-2 rounded-full bg-primary" aria-hidden />
          {fmtNum(activeCount)} {t("scans.status.RUNNING")} — {t("scans.monitor.findingsImported")}
        </p>
      ) : null}

      {/* scan start confirm (FG-1) */}
      <AlertDialog open={startOpen} onOpenChange={(o) => !o && !starting && setStartOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("scans.startConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-semibold">{rows[0]?.target?.name ?? t("scans.target")}</span>
              {"— " + t("scans.startConfirmBody")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={starting}>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault(); // keep the dialog open while starting
                void startScan();
              }}
              disabled={starting}
            >
              {starting ? (
                <>
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  {t("scans.starting")}
                </>
              ) : (
                <>
                  <Play className="size-4" aria-hidden />
                  {t("scans.start")}
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

export default function ScansPage() {
  return (
    <Suspense>
      <ScansInner />
    </Suspense>
  );
}
