"use client";

// SENTINEL ui-kit — severity + status language. ONE scale, everywhere.

import { Badge } from "@/components/ui/badge";
import { useI18n } from "@/lib/ui/i18n";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
const RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function severityOf(s: string): Severity {
  return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "info";
}
export function severityRank(s: string): number {
  return RANK[severityOf(s)];
}

const CHIP: Record<Severity, string> = {
  critical:
    "border-transparent bg-[color-mix(in_oklab,var(--severity-critical)_16%,transparent)] text-[var(--severity-critical)]",
  high: "border-transparent bg-[color-mix(in_oklab,var(--severity-high)_16%,transparent)] text-[var(--severity-high)]",
  medium:
    "border-transparent bg-[color-mix(in_oklab,var(--severity-medium)_18%,transparent)] text-[var(--severity-medium)]",
  low: "border-transparent bg-[color-mix(in_oklab,var(--severity-low)_16%,transparent)] text-[var(--severity-low)]",
  info: "border-transparent bg-muted text-muted-foreground",
};

export function SeverityChip({ severity, count }: { severity: string; count?: number }) {
  const { t, fmtNum } = useI18n();
  const s = severityOf(severity);
  return (
    <Badge variant="outline" className={`gap-1.5 px-2 font-semibold ${CHIP[s]}`}>
      <span aria-hidden className="inline-block size-1.5 rounded-full bg-current" />
      {t(`severity.${s}`)}
      {count !== undefined ? <span className="tnum opacity-80">{fmtNum(count)}</span> : null}
    </Badge>
  );
}

const STATUS_STYLE: Record<string, string> = {
  QUEUED: "bg-muted text-muted-foreground",
  RUNNING: "border-transparent bg-[color-mix(in_oklab,var(--primary)_18%,transparent)] text-primary",
  COMPLETED: "border-transparent bg-[color-mix(in_oklab,var(--success)_16%,transparent)] text-[var(--success)]",
  FAILED: "border-transparent bg-[color-mix(in_oklab,var(--severity-critical)_16%,transparent)] text-[var(--severity-critical)]",
  CANCELLED: "bg-muted text-muted-foreground",
};

export function StatusPill({ status, live }: { status: string; live?: boolean }) {
  const { t } = useI18n();
  return (
    <Badge variant="outline" className={`gap-1.5 font-semibold ${STATUS_STYLE[status] ?? ""}`}>
      {live ? (
        <span aria-hidden className="live-dot inline-block size-1.5 rounded-full bg-current" />
      ) : null}
      {t(`scans.status.${status}` as never)}
    </Badge>
  );
}

/** verified / unverified — engine evidence language, never invented */
export function VerificationChip({ verified }: { verified: boolean }) {
  const { t } = useI18n();
  return (
    <Badge
      variant="outline"
      className={
        verified
          ? "border-transparent bg-[color-mix(in_oklab,var(--success)_14%,transparent)] text-[var(--success)]"
          : "bg-muted text-muted-foreground"
      }
    >
      {verified ? t("findings.verified") : t("findings.unverified")}
    </Badge>
  );
}

export function ConfidenceBar({ value }: { value: number }) {
  const { fmtNum } = useI18n();
  const pct = Math.max(0, Math.min(100, value));
  const color =
    pct >= 80 ? "var(--success)" : pct >= 50 ? "var(--severity-medium)" : "var(--severity-high)";
  return (
    <div className="flex items-center gap-2" title={`${pct}%`}>
      <div
        className="h-1.5 w-16 overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="confidence"
      >
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="tnum text-xs text-muted-foreground">{fmtNum(pct)}%</span>
    </div>
  );
}
