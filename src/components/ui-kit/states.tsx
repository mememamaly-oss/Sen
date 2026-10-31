"use client";

// Burhan ui-kit — page states: loading skeletons, error+retry, empty.
// Every async surface goes through these — no page invents its own states.

import { AlertOctagon, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useI18n } from "@/lib/ui/i18n";

export function CardSkeleton({ lines = 3, className = "" }: { lines?: number; className?: string }) {
  return (
    <div className={`rounded-xl border bg-card p-4 ${className}`}>
      <Skeleton className="mb-3 h-4 w-1/3" />
      <div className="space-y-2.5">
        {Array.from({ length: lines }).map((_, i) => (
          <Skeleton key={i} className="h-3" style={{ width: `${88 - i * 12}%` } as React.CSSProperties} />
        ))}
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="rounded-xl border bg-card">
      <div className="border-b p-4">
        <div className="flex gap-4">
          {Array.from({ length: cols }).map((_, i) => (
            <Skeleton key={i} className="h-3 flex-1" />
          ))}
        </div>
      </div>
      <div className="divide-y">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex items-center gap-4 p-4">
            {Array.from({ length: cols }).map((_, c) => (
              <Skeleton key={c} className={`h-4 flex-1 ${c === 0 ? "max-w-40" : ""}`} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function ErrorState({
  onRetry,
  message,
}: {
  onRetry?: () => void;
  message?: string;
}) {
  const { t } = useI18n();
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed bg-card px-6 py-14 text-center"
    >
      <AlertOctagon className="size-8 text-[var(--severity-high)]" aria-hidden />
      <p className="text-sm font-semibold">{message || t("common.error")}</p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          {t("common.retry")}
        </Button>
      ) : null}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  action,
  icon,
}: {
  title: string;
  hint?: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed bg-card px-6 py-14 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-muted">
        {icon || <Inbox className="size-6 text-muted-foreground" aria-hidden />}
      </div>
      <p className="text-sm font-semibold">{title}</p>
      {hint ? <p className="max-w-md text-sm leading-6 text-muted-foreground">{hint}</p> : null}
      {action}
    </div>
  );
}

/** Compose: null=loading, false=error, [] =empty, data = children */
export function AsyncBoundary<T>({
  state,
  data,
  retry,
  isEmpty,
  emptyTitle,
  emptyHint,
  emptyAction,
  skeleton,
  children,
}: {
  state: "loading" | "error" | "ready";
  data: T | null;
  retry?: () => void;
  isEmpty: (d: T) => boolean;
  emptyTitle: string;
  emptyHint?: string;
  emptyAction?: React.ReactNode;
  skeleton?: React.ReactNode;
  children: (d: T) => React.ReactNode;
}) {
  if (state === "loading") return skeleton ?? <CardSkeleton />;
  if (state === "error") return <ErrorState onRetry={retry} />;
  if (!data || isEmpty(data))
    return <EmptyState title={emptyTitle} hint={emptyHint} action={emptyAction} />;
  return <>{children(data)}</>;
}
