"use client";

// Burhan audit — the append-only trail. Search + expandable detail.

import { useMemo, useState } from "react";
import { ChevronRight, Search, ScrollText } from "lucide-react";
import { api, type AuditRow } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { PageHeader, SectionCard } from "@/components/ui-kit/page";
import { EmptyState, TableSkeleton, ErrorState } from "@/components/ui-kit/states";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export default function AuditPage() {
  const { t, fmtDate, relTime, fmtNum } = useI18n();
  const session = useSession();
  const org = session.org;
  const q = useAsync(
    () => (org ? api.audit(org.id) : Promise.resolve({ logs: [] as AuditRow[] })),
    [org?.id]
  );

  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const list = (q.data?.logs ?? []).slice();
    const needle = search.trim().toLowerCase();
    const filtered = needle
      ? list.filter(
          (x) =>
            x.action.toLowerCase().includes(needle) ||
            (x.by ?? "").toLowerCase().includes(needle) ||
            JSON.stringify(x.detail ?? {}).toLowerCase().includes(needle)
        )
      : list;
    filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return filtered;
  }, [q.data, search]);

  return (
    <>
      <PageHeader title={t("audit.title")} subtitle={t("audit.subtitle")} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          <Search className="absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("audit.searchPlaceholder")}
            className="ps-8"
            aria-label={t("common.search")}
          />
        </div>
        <span className="num tnum text-xs font-bold text-muted-foreground">
          {fmtNum(rows.length)} / {fmtNum((q.data?.logs ?? []).length)}
        </span>
      </div>

      {q.state === "loading" ? (
        <TableSkeleton rows={7} cols={4} />
      ) : q.state === "error" ? (
        <ErrorState onRetry={q.retry} message={q.error ?? undefined} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("audit.empty")}
          icon={<ScrollText className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : (
        <SectionCard title={t("audit.title")}>
          <ul className="divide-y">
            {rows.map((x) => {
              const isOpen = open === x.id;
              return (
                <li key={x.id}>
                  <button
                    type="button"
                    onClick={() => setOpen(isOpen ? null : x.id)}
                    aria-expanded={isOpen}
                    className="flex w-full items-center gap-3 px-4 py-3 text-start transition-colors duration-150 hover:bg-muted/40"
                  >
                    <ChevronRight
                      aria-hidden
                      className={cn("size-4 shrink-0 text-muted-foreground transition-transform duration-150", isOpen && "rotate-90")}
                    />
                    <span className="num min-w-0 flex-1 truncate text-sm font-semibold" dir="ltr">
                      {x.action}
                    </span>
                    <span className="max-w-40 truncate text-xs text-muted-foreground">{x.by ?? "—"}</span>
                    <span className="shrink-0 text-xs text-muted-foreground" title={fmtDate(x.createdAt)}>
                      {relTime(x.createdAt)}
                    </span>
                  </button>
                  {isOpen ? (
                    <pre className="num overflow-auto border-t bg-muted/40 px-4 py-3 text-[11.5px] leading-5 text-muted-foreground" dir="ltr">
                      {JSON.stringify(x.detail ?? {}, null, 2)}
                    </pre>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </SectionCard>
      )}
    </>
  );
}
