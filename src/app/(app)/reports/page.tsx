"use client";

// SENTINEL reports — the gallery. Format filter + deep links to /reports/[id].

import Link from "next/link";
import { useMemo, useState } from "react";
import { FileCode2, FileText, ScrollText } from "lucide-react";
import { api, type ReportRow } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { PageHeader } from "@/components/ui-kit/page";
import { EmptyState, TableSkeleton, ErrorState } from "@/components/ui-kit/states";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const FMT_STYLE: Record<string, string> = {
  HTML: "border-transparent bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary",
  GLASS: "border-transparent bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary",
  SARIF: "border-transparent bg-[color-mix(in_oklab,var(--severity-low)_14%,transparent)] text-[var(--severity-low)]",
  EXECUTIVE: "border-transparent bg-[color-mix(in_oklab,var(--severity-medium)_18%,transparent)] text-[var(--severity-medium)]",
};

export default function ReportsPage() {
  const { t, fmtNum, fmtBytes, fmtDate } = useI18n();
  const session = useSession();
  const org = session.org;

  const listQ = useAsync(
    () => (org ? api.reports(org.id) : Promise.resolve({ reports: [] as ReportRow[] })),
    [org?.id]
  );
  const [formatFilter, setFormatFilter] = useState<string>("ALL");

  const rows = useMemo(() => {
    const list = (listQ.data?.reports ?? []).slice();
    const out = formatFilter === "ALL" ? list : list.filter((r) => r.format === formatFilter);
    out.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return out;
  }, [listQ.data, formatFilter]);

  const formats = useMemo(() => Array.from(new Set((listQ.data?.reports ?? []).map((r) => r.format))), [listQ.data]);

  return (
    <>
      <PageHeader title={t("reports.title")} subtitle={t("reports.subtitle")} />

      <div className="mb-3 flex flex-wrap items-center gap-1.5" role="group" aria-label={t("reports.format")}>
        <button
          type="button"
          onClick={() => setFormatFilter("ALL")}
          aria-pressed={formatFilter === "ALL"}
          className={cn(
            "rounded-full border px-3 py-1.5 text-xs font-bold transition-colors duration-150",
            formatFilter === "ALL"
              ? "border-primary bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary"
              : "border-border text-muted-foreground hover:text-foreground"
          )}
        >
          {t("common.all")} <span className="num tnum ms-1 opacity-70">{fmtNum((listQ.data?.reports ?? []).length)}</span>
        </button>
        {formats.map((f) => {
          const n = (listQ.data?.reports ?? []).filter((r) => r.format === f).length;
          return (
            <button
              key={f}
              type="button"
              onClick={() => setFormatFilter(f)}
              aria-pressed={formatFilter === f}
              className={cn(
                "rounded-full border px-3 py-1.5 text-xs font-bold transition-colors duration-150",
                formatFilter === f
                  ? "border-primary bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}
            >
              {f} <span className="num tnum ms-1 opacity-70">{fmtNum(n)}</span>
            </button>
          );
        })}
      </div>

      {listQ.state === "loading" ? (
        <TableSkeleton rows={4} cols={5} />
      ) : listQ.state === "error" ? (
        <ErrorState onRetry={listQ.retry} message={listQ.error ?? undefined} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("reports.empty.title")}
          hint={t("reports.empty.hint")}
          icon={<FileText className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : (
        <div className="card-elevated overflow-hidden rounded-xl border bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  <th scope="col" className="px-4 py-3 text-start">{t("reports.format")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("reports.scan")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("reports.size")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("reports.createdBy")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("audit.when")}</th>
                  <th scope="col" className="px-4 py-3 text-end">{t("common.open")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((r) => (
                  <tr key={r.id} className="transition-colors duration-150 hover:bg-muted/40">
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={cn("font-bold", FMT_STYLE[r.format] ?? "")}>
                        {r.format === "HTML" || r.format === "GLASS" ? <FileText className="size-3" aria-hidden /> : <FileCode2 className="size-3" aria-hidden />}
                        {r.format}
                      </Badge>
                    </td>
                    <td className="max-w-64 px-4 py-3">
                      <p className="truncate text-sm font-semibold">{r.scan?.targetName ?? "—"}</p>
                      <p className="num truncate text-[11px] text-muted-foreground" dir="ltr">{r.scan?.runId?.slice(0, 12) ?? "—"}</p>
                    </td>
                    <td className="px-4 py-3"><span className="num text-xs text-muted-foreground">{fmtBytes(r.sizeBytes)}</span></td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{r.createdBy}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{fmtDate(r.createdAt)}</td>
                    <td className="px-4 py-3">
                      <Button asChild variant="ghost" size="icon" className="size-8" aria-label={r.title}>
                        <Link href={`/reports/${r.id}`}>
                          <ScrollText className="size-4" aria-hidden />
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
    </>
  );
}
