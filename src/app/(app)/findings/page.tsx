"use client";

// SENTINEL findings explorer — pick a scan, then search/filter/sort its
// findings. Verification language comes from the engine only.

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowUpRight, ListFilter, Search, ShieldCheck } from "lucide-react";
import { api, type ScanRow } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { PageHeader } from "@/components/ui-kit/page";
import { EmptyState, TableSkeleton, ErrorState } from "@/components/ui-kit/states";
import { SeverityChip, severityRank } from "@/components/ui-kit/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

type SevFilter = "ALL" | "critical" | "high" | "medium" | "low" | "info";
type Sort = "severity" | "confidence" | "risk" | "newest";
const SORTS: Array<{ v: Sort; label: string }> = [
  { v: "severity", label: "severity" },
  { v: "confidence", label: "confidence" },
  { v: "risk", label: "risk" },
  { v: "newest", label: "newest" },
];

function FindingsInner() {
  const { t, fmtNum } = useI18n();
  const session = useSession();
  const org = session.org;
  const params = useSearchParams();
  const scansQ = useAsync(
    () => (org ? api.scans(org.id) : Promise.resolve({ scans: [] as ScanRow[] })),
    [org?.id]
  );
  const completed = useMemo(
    () => (scansQ.data?.scans ?? []).filter((s) => s.status === "COMPLETED"),
    [scansQ.data]
  );

  const [scanId, setScanId] = useState<string>("");
  const deep = params.get("scan");
  useEffect(() => {
    if (deep && completed.some((s) => s.id === deep)) setScanId(deep);
    else if (!scanId && completed.length) setScanId(completed[0].id);
  }, [completed, deep]);

  const findingsQ = useAsync(
    () => (org && scanId ? api.scanFindings(org.id, scanId) : Promise.resolve(null)),
    [org?.id, scanId]
  );

  const [search, setSearch] = useState("");
  const [sev, setSev] = useState<SevFilter>("ALL");
  const [sort, setSort] = useState<Sort>("severity");

  const rows = useMemo(() => {
    const list = (findingsQ.data?.findings ?? []).slice();
    const needle = search.trim().toLowerCase();
    let out = list;
    if (needle)
      out = out.filter(
        (f) => f.type.toLowerCase().includes(needle) || f.url.toLowerCase().includes(needle)
      );
    if (sev !== "ALL") out = out.filter((f) => f.severity === sev);
    out.sort((a, b) => {
      if (sort === "severity") return severityRank(b.severity) - severityRank(a.severity) || b.confidence - a.confidence;
      if (sort === "confidence") return b.confidence - a.confidence;
      if (sort === "risk") return b.risk - a.risk;
      return 0;
    });
    return out;
  }, [findingsQ.data, search, sev, sort]);

  const activeScan = completed.find((s) => s.id === scanId);

  return (
    <>
      <PageHeader
        title={t("findings.title")}
        subtitle={t("findings.subtitle")}
        meta={
          activeScan ? (
            <p className="mt-1 text-xs text-muted-foreground">
              {activeScan.target?.name} · {activeScan.runId?.slice(0, 12)}… · {fmtNum(activeScan.findingsCount)} {t("overview.findingsFound")}
            </p>
          ) : undefined
        }
      />

      {/* scan picker + toolbar */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Select value={scanId} onValueChange={setScanId}>
          <SelectTrigger className="w-64" aria-label={t("findings.pickScan")}>
            <SelectValue placeholder={t("findings.pickScan")} />
          </SelectTrigger>
          <SelectContent>
            {completed.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.target?.name} — {fmtNum(s.findingsCount)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative min-w-44 flex-1">
          <Search className="absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("findings.searchPlaceholder")}
            className="ps-8"
            aria-label={t("common.search")}
          />
        </div>
        <div className="flex items-center gap-1" role="group" aria-label={t("findings.severity")}>
          {(["ALL", "critical", "high", "medium", "low", "info"] as SevFilter[]).map((s) => {
            const n = s === "ALL" ? (findingsQ.data?.findings ?? []).length : (findingsQ.data?.findings ?? []).filter((f) => f.severity === s).length;
            if (s !== "ALL" && !n) return null;
            return (
              <button
                key={s}
                type="button"
                onClick={() => setSev(s)}
                aria-pressed={sev === s}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-xs font-bold transition-colors duration-150",
                  sev === s
                    ? "border-primary bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary"
                    : "border-border text-muted-foreground hover:text-foreground"
                )}
              >
                {s === "ALL" ? t("common.all") : t(`severity.${s}` as never)}
              </button>
            );
          })}
        </div>
        <Select value={sort} onValueChange={(v) => setSort(v as Sort)}>
          <SelectTrigger className="w-40" aria-label={t("common.sort")}>
            <ListFilter className="size-3.5" aria-hidden />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SORTS.map((s) => (
              <SelectItem key={s.v} value={s.v}>
                {s.v === "severity"
                  ? t("findings.sort.severity")
                  : s.v === "confidence"
                    ? t("findings.sort.confidence")
                    : s.v === "risk"
                      ? t("findings.sort.risk")
                      : t("findings.sort.newest")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {scansQ.state === "loading" || findingsQ.state === "loading" ? (
        <TableSkeleton rows={8} cols={5} />
      ) : scansQ.state === "error" ? (
        <ErrorState onRetry={scansQ.retry} message={scansQ.error ?? undefined} />
      ) : completed.length === 0 ? (
        <EmptyState title={t("findings.empty.title")} hint={t("scans.empty.hint")} />
      ) : findingsQ.state === "error" ? (
        <ErrorState onRetry={findingsQ.retry} message={findingsQ.error ?? undefined} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("findings.empty.title")}
          hint={t("findings.empty.hint")}
          icon={<ShieldCheck className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : (
        <div className="card-elevated overflow-hidden rounded-xl border bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  <th scope="col" className="px-4 py-3 text-start">{t("findings.severity")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("findings.type")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("findings.url")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("findings.confidence")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("findings.verification")}</th>
                  <th scope="col" className="px-4 py-3 text-end">{t("common.open")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((f) => (
                  <tr key={f.id} className="transition-colors duration-150 hover:bg-muted/40">
                    <td className="px-4 py-3"><SeverityChip severity={f.severity} /></td>
                    <td className="max-w-64 px-4 py-3"><span className="num text-sm font-semibold" dir="ltr">{f.type}</span></td>
                    <td className="max-w-72 px-4 py-3">
                      <p className="num truncate text-xs text-muted-foreground" dir="ltr">
                        {f.method ? `${f.method} ` : ""}{f.url}
                        {f.parameter ? ` · ${f.parameter}` : ""}
                      </p>
                    </td>
                    <td className="px-4 py-3"><span className="num tnum text-xs font-bold">{fmtNum(f.confidence)}%</span></td>
                    <td className="px-4 py-3">
                      <span className={cn("text-xs font-bold", (f.status ?? "").toLowerCase().includes("verified") ? "text-[var(--success)]" : "text-muted-foreground")}>
                        {(f.status ?? "").toLowerCase().includes("verified") ? t("findings.verified") : t("findings.unverified")}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Button asChild variant="ghost" size="icon" className="size-8" aria-label={f.type}>
                        <Link href={`/findings/${f.id}`}>
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
    </>
  );
}

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsInner />
    </Suspense>
  );
}
