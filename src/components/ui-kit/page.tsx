"use client";

// SENTINEL ui-kit — executive KPI card + page header.

import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";

export function KpiCard({
  label,
  value,
  unit,
  hint,
  tone = "neutral",
  icon,
  href,
  hrefLabel,
}: {
  label: string;
  value: string;
  unit?: string;
  hint?: string;
  tone?: "neutral" | "primary" | "success" | "warning" | "danger";
  icon?: React.ReactNode;
  href?: string;
  hrefLabel?: string;
}) {
  const toneRing: Record<string, string> = {
    neutral: "",
    primary: "border-s-[3px] border-s-primary/70",
    success: "border-s-[3px] border-s-[var(--success)]/70",
    warning: "border-s-[3px] border-s-[var(--severity-high)]/70",
    danger: "border-s-[3px] border-s-[var(--severity-critical)]/70",
  };
  return (
    <div
      className={cn(
        "card-elevated relative rounded-xl border bg-card p-4 transition-shadow duration-150 hover:shadow-[var(--shadow-card)]",
        toneRing[tone]
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-[13px] font-semibold leading-6 text-muted-foreground">{label}</p>
        {icon ? <span className="text-muted-foreground/80">{icon}</span> : null}
      </div>
      <p className="mt-1.5 flex items-baseline gap-1.5">
        <span className="num tnum text-2xl font-extrabold leading-none tracking-tight">{value}</span>
        {unit ? <span className="text-xs font-semibold text-muted-foreground">{unit}</span> : null}
      </p>
      {hint ? <p className="mt-1 text-xs leading-5 text-muted-foreground">{hint}</p> : null}
      {href ? (
        <Link
          href={href}
          className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
        >
          {hrefLabel}
          <ArrowUpRight className="size-3" aria-hidden />
        </Link>
      ) : null}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
  meta,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  meta?: React.ReactNode;
}) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-extrabold leading-8 tracking-tight text-balance sm:text-2xl">
          {title}
        </h1>
        {subtitle ? (
          <p className="mt-0.5 text-sm leading-6 text-muted-foreground">{subtitle}</p>
        ) : null}
        {meta}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

export function SectionCard({
  title,
  extra,
  children,
  className,
}: {
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("card-elevated rounded-xl border bg-card", className)}>
      <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
        <h2 className="text-sm font-bold leading-6">{title}</h2>
        {extra}
      </div>
      {children}
    </section>
  );
}
