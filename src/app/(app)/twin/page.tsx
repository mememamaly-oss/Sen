"use client";

// Burhan — PHASE 02 L1: the normalized Security Twin, rendered for real.
//
// Every number, node, edge, provenance value, conflict and why() answer below
// comes from GET /api/v1/scans/:scanId/twin — the deterministic normalized
// twin rebuilt from raw engine output. No placeholders, no fabricated graph
// data, no direct DB access from the UI. Custom SVG with a deterministic
// layered layout (no heavy graph libraries).

import { useMemo, useState } from "react";
import { Network, ShieldQuestion, AlertTriangle, BadgeCheck, Ban, HelpCircle, GitBranch } from "lucide-react";
import { api, type NormalizedTwin, type ScanRow, type TwinEdge, type TwinNode, type TwinProvenance } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { KpiCard, PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState, EmptyState } from "@/components/ui-kit/states";
import { cn } from "@/lib/utils";

// ── deterministic layout constants ───────────────────────────────────────────

const LAYERS: string[][] = [
  ["application", "host"],
  ["endpoint", "browser_surface", "api"],
  ["parameter", "secret", "boundary"],
  ["identity", "role", "session"],
  ["workflow", "workflow_step", "state", "branch"],
  ["object", "entity"],
  ["finding", "hypothesis", "evidence"],
];
const LAYER_OF = new Map(LAYERS.flatMap((layer, i) => layer.map((t) => [t, i] as const)));
const NODE_PRIORITY = ["application", "host", "identity", "role", "finding", "endpoint", "api", "workflow", "secret", "hypothesis", "browser_surface", "session", "workflow_step", "state", "branch", "entity", "object", "boundary", "parameter", "evidence"];
const MAX_GRAPH_NODES = 160;
const COL_W = 150;
const ROW_H = 46;
const NODE_R = 7;

const PROV_COLOR: Record<string, string> = {
  OBSERVED: "var(--primary)",
  INFERRED: "#d97706",
  VERIFIED: "var(--success, #16a34a)",
  REFUTED: "var(--severity-critical, #dc2626)",
  UNKNOWN: "#94a3b8",
};
const PROV_CLASS: Record<string, string> = {
  OBSERVED: "bg-primary/10 text-primary",
  INFERRED: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
  VERIFIED: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  REFUTED: "bg-red-500/10 text-red-600 dark:text-red-400",
  UNKNOWN: "bg-slate-500/10 text-slate-500",
};

function ProvBadge({ p }: { p: TwinProvenance }) {
  return (
    <span className={cn("num rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wide", PROV_CLASS[p] ?? PROV_CLASS.UNKNOWN)}>
      {p}
    </span>
  );
}

function ClaimBadge({ state }: { state: string }) {
  const cls: Record<string, string> = {
    VERIFIED: "bg-emerald-500/14 text-emerald-600 dark:text-emerald-400",
    REFUTED: "bg-red-500/14 text-red-600 dark:text-red-400",
    UNKNOWN: "bg-slate-500/14 text-slate-500",
    CONFLICT: "bg-[color-mix(in_oklab,var(--severity-high)_16%,transparent)] text-[var(--severity-high)]",
  };
  return <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-bold", cls[state] ?? cls.UNKNOWN)}>{state}</span>;
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function TwinPage() {
  const { t, fmtNum } = useI18n();
  const session = useSession();
  const org = session.org;
  const [scanId, setScanId] = useState<string>("");
  const [selectedId, setSelectedId] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [provFilter, setProvFilter] = useState<string>("");

  const scansQ = useAsync(
    () => (org ? api.scans(org.id) : Promise.resolve({ scans: [] as ScanRow[] })),
    [org?.id]
  );
  const completed = useMemo(
    () => (scansQ.data?.scans ?? []).filter((s) => s.status === "COMPLETED"),
    [scansQ.data]
  );
  const effectiveScanId = scanId || completed[0]?.id || "";

  const twinQ = useAsync(
    () => (org && effectiveScanId ? api.scanTwin(org.id, effectiveScanId) : Promise.resolve(null)),
    [org?.id, effectiveScanId]
  );

  const twin = twinQ.data?.twin ?? null;

  // deterministic layout: filter → priority → cap → layered positions
  const layout = useMemo(() => {
    if (!twin) return null;
    const filtered = twin.nodes.filter(
      (n) => (!typeFilter || n.type === typeFilter) && (!provFilter || n.provenance === provFilter)
    );
    const ranked = [...filtered].sort((a, b) => {
      const pa = NODE_PRIORITY.indexOf(a.type); const pb = NODE_PRIORITY.indexOf(b.type);
      if (pa !== pb) return (pa < 0 ? 99 : pa) - (pb < 0 ? 99 : pb);
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    const shown = ranked.slice(0, MAX_GRAPH_NODES);
    const positions = new Map<string, { x: number; y: number }>();
    const colCount = new Map<number, number>();
    for (const n of shown) {
      const layer = LAYER_OF.get(n.type) ?? 6;
      const idx = colCount.get(layer) ?? 0;
      colCount.set(layer, idx + 1);
      positions.set(n.id, { x: 30 + layer * COL_W, y: 24 + idx * ROW_H });
    }
    const visible = new Set(shown.map((n) => n.id));
    const edges = twin.edges.filter((e) => visible.has(e.from) && visible.has(e.to));
    const height = 24 + Math.max(1, ...Array.from(colCount.values(), (v) => v + 1)) * ROW_H;
    return { shown, positions, edges, height, total: filtered.length };
  }, [twin, typeFilter, provFilter]);

  const selected = useMemo(
    () => twin?.nodes.find((n) => n.id === selectedId) ?? null,
    [twin, selectedId]
  );
  const related = useMemo(() => {
    if (!twin || !selected) return [];
    const byId = new Map(twin.nodes.map((n) => [n.id, n]));
    return twin.edges
      .filter((e) => e.from === selected.id || e.to === selected.id)
      .slice(0, 12)
      .map((e: TwinEdge) => {
        const otherId = e.from === selected.id ? e.to : e.from;
        return { edge: e, other: byId.get(otherId) };
      });
  }, [twin, selected]);

  const types = useMemo(
    () => Object.entries(twin?.counts.byNodeType ?? {}).sort((a, b) => b[1] - a[1]),
    [twin]
  );

  return (
    <>
      <PageHeader title={t("twin.l1.title")} subtitle={t("twin.l1.subtitle")} />

      {/* scan selector */}
      {completed.length > 1 ? (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-muted-foreground">{t("twin.l1.scan")}:</span>
          <select
            className="h-8 rounded-lg border bg-background px-2 text-xs"
            value={effectiveScanId}
            onChange={(e) => { setScanId(e.target.value); setSelectedId(""); }}
          >
            {completed.map((s) => (
              <option key={s.id} value={s.id}>
                {s.runId ?? s.id.slice(-8)} · {s.target?.name ?? ""} · {fmtNum(s.findingsCount ?? 0)}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {scansQ.state === "loading" || (effectiveScanId && twinQ.state === "loading") ? (
        <div className="grid gap-3 md:grid-cols-2">
          <CardSkeleton lines={5} />
          <CardSkeleton lines={5} />
        </div>
      ) : scansQ.state === "error" ? (
        <ErrorState onRetry={scansQ.retry} message={scansQ.error ?? undefined} />
      ) : !effectiveScanId ? (
        <EmptyState
          title={t("twin.noData")}
          icon={<Network className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : twinQ.state === "error" ? (
        <ErrorState onRetry={twinQ.retry} message={twinQ.error ?? undefined} />
      ) : !twin ? (
        <EmptyState
          title={twinQ.data?.note ?? t("twin.l1.noTwin")}
          icon={<ShieldQuestion className="size-6 text-muted-foreground" aria-hidden />}
        />
      ) : (
        <>
          {/* KPI row — all real twin numbers */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <KpiCard label={t("twin.l1.nodes")} value={fmtNum(twin.counts.nodes)} hint={`${t("twin.l1.edges")}: ${fmtNum(twin.counts.edges)}`} tone="primary" />
            <KpiCard
              label={`${t("twin.l1.claims")} · ${t("twin.l1.claim.VERIFIED")}`}
              value={fmtNum(twin.counts.claims.VERIFIED)}
              hint={`${t("twin.l1.claim.REFUTED")}: ${fmtNum(twin.counts.claims.REFUTED)} · ${t("twin.l1.claim.UNKNOWN")}: ${fmtNum(twin.counts.claims.UNKNOWN)}`}
              tone="success"
            />
            <KpiCard
              label={t("twin.l1.conflicts")}
              value={fmtNum(twin.counts.conflicts)}
              hint={twin.counts.conflicts > 0 ? t("twin.l1.conflict.desc") : undefined}
              tone={twin.counts.conflicts > 0 ? "warning" : undefined}
            />
            <KpiCard
              label={t("twin.l1.unknowns")}
              value={fmtNum(twin.counts.knownUnknowns)}
              hint={`${t("twin.l1.scope")}: ${twin.scope.host}`}
            />
          </div>

          {/* twinHash + provenance distribution */}
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border bg-muted/30 px-4 py-3">
            <div className="flex min-w-0 items-center gap-2">
              <span className="text-[11px] font-bold text-muted-foreground">{t("twin.l1.hash")}:</span>
              <code className="num truncate text-[11px] font-semibold" title={twin.twinHash}>{twin.twinHash.slice(0, 32)}…</code>
            </div>
            <span className="h-4 w-px bg-border" aria-hidden />
            <div className="flex flex-wrap items-center gap-2">
              {(Object.keys(twin.counts.provenance) as TwinProvenance[]).map((p) => (
                <span key={p} className="flex items-center gap-1">
                  <ProvBadge p={p} />
                  <span className="num tnum text-xs font-bold">{fmtNum(twin.counts.provenance[p] ?? 0)}</span>
                </span>
              ))}
            </div>
            <span className="h-4 w-px bg-border" aria-hidden />
            <span className="num text-[11px] text-muted-foreground">
              {twin.scope.scanner || "burhan"} · {twin.scope.runId || "—"} · {twinQ.data?.built ? t("twin.l1.built") : t("twin.l1.stored")}
            </span>
            {twinQ.data?.invariants ? (
              <span className={cn("num rounded px-1.5 py-0.5 text-[10px] font-bold", twinQ.data.invariants.pass ? "bg-emerald-500/14 text-emerald-600 dark:text-emerald-400" : "bg-red-500/14 text-red-600 dark:text-red-400")}>
                {twinQ.data.invariants.pass ? t("twin.l1.invariants.pass") : `${t("twin.l1.invariants.fail")}: ${twinQ.data.invariants.violations}`}
              </span>
            ) : null}
          </div>

          {/* graph + why panel */}
          <div className="mt-4 grid gap-3 xl:grid-cols-3">
            <SectionCard
              title={t("twin.l1.graph")}
              className="xl:col-span-2"
              extra={
                <div className="flex items-center gap-2">
                  <select className="h-7 rounded border bg-background px-1.5 text-[11px]" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                    <option value="">{t("twin.l1.filter.type")}: {t("common.all")}</option>
                    {types.map(([ty, c]) => <option key={ty} value={ty}>{ty} ({c})</option>)}
                  </select>
                  <select className="h-7 rounded border bg-background px-1.5 text-[11px]" value={provFilter} onChange={(e) => setProvFilter(e.target.value)}>
                    <option value="">{t("twin.l1.filter.provenance")}: {t("common.all")}</option>
                    {Object.keys(twin.counts.provenance).map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
              }
            >
              <div className="px-2 py-3">
                {layout && layout.shown.length > 0 ? (
                  <>
                    <p className="mb-2 px-2 text-[11px] text-muted-foreground">
                      {t("twin.l1.graph.cap").replace("{{shown}}", fmtNum(layout.shown.length)).replace("{{total}}", fmtNum(layout.total))}
                    </p>
                    <div dir="ltr" className="overflow-x-auto rounded-lg border bg-background">
                      <svg
                        width={COL_W * 7 + 60}
                        height={layout.height}
                        viewBox={`0 0 ${COL_W * 7 + 60} ${layout.height}`}
                        className="block"
                        role="img"
                        aria-label={t("twin.l1.graph")}
                      >
                        {layout.edges.map((e) => {
                          const a = layout.positions.get(e.from)!;
                          const b = layout.positions.get(e.to)!;
                          return (
                            <line
                              key={e.id}
                              x1={a.x + NODE_R} y1={a.y} x2={b.x - NODE_R} y2={b.y}
                              stroke={e.provenance === "REFUTED" ? "var(--severity-critical, #dc2626)" : "currentColor"}
                              strokeOpacity={e.provenance === "INFERRED" ? 0.18 : 0.3}
                              strokeDasharray={e.provenance === "INFERRED" ? "3 4" : undefined}
                              strokeWidth={1}
                              className={e.provenance === "REFUTED" ? "text-red-500" : "text-muted-foreground"}
                            />
                          );
                        })}
                        {layout.shown.map((n) => {
                          const pos = layout.positions.get(n.id)!;
                          const isSel = n.id === selectedId;
                          return (
                            <g
                              key={n.id}
                              transform={`translate(${pos.x}, ${pos.y})`}
                              onClick={() => setSelectedId(n.id === selectedId ? "" : n.id)}
                              className="cursor-pointer"
                            >
                              {isSel ? <circle r={NODE_R + 4} fill="none" stroke={PROV_COLOR[n.provenance] ?? PROV_COLOR.UNKNOWN} strokeWidth={1.5} /> : null}
                              <circle r={NODE_R} fill={PROV_COLOR[n.provenance] ?? PROV_COLOR.UNKNOWN} />
                              <title>{`${n.type} · ${n.key}`}</title>
                              <text x={-NODE_R - 4} textAnchor="end" y={3.5} fontSize={8.5} className="fill-foreground/80" fontWeight={600}>
                                {n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}
                              </text>
                            </g>
                          );
                        })}
                      </svg>
                    </div>
                  </>
                ) : (
                  <p className="px-2 py-6 text-center text-sm text-muted-foreground">{t("common.none")}</p>
                )}

                {/* node table (paged by slicing — deterministic order from API) */}
                <div className="mt-3 max-h-72 overflow-y-auto rounded-lg border">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-muted/60 backdrop-blur">
                      <tr className="text-start text-[10px] uppercase tracking-wide text-muted-foreground">
                        <th className="px-3 py-2 text-start font-bold">{t("twin.l1.filter.type")}</th>
                        <th className="px-3 py-2 text-start font-bold">Key</th>
                        <th className="px-3 py-2 text-start font-bold">{t("twin.l1.provenance")}</th>
                        <th className="px-3 py-2 text-start font-bold">{t("twin.l1.claims")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(layout?.shown ?? []).map((n) => (
                        <tr
                          key={n.id}
                          onClick={() => setSelectedId(n.id === selectedId ? "" : n.id)}
                          className={cn("cursor-pointer border-t transition-colors hover:bg-muted/40", n.id === selectedId && "bg-primary/5")}
                        >
                          <td className="num whitespace-nowrap px-3 py-1.5 font-semibold">{n.type}</td>
                          <td className="max-w-[240px] truncate px-3 py-1.5" title={n.key}>{n.key}</td>
                          <td className="px-3 py-1.5"><ProvBadge p={n.provenance} /></td>
                          <td className="px-3 py-1.5">{n.claim ? <ClaimBadge state={n.claim.state} /> : <span className="text-muted-foreground">—</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </SectionCard>

            {/* why() panel */}
            <SectionCard title={t("twin.l1.why")}>
              <div className="max-h-[560px] overflow-y-auto px-4 py-3">
                {selected ? (
                  <WhyPanel node={selected} related={related} twin={twin} />
                ) : (
                  <p className="py-8 text-center text-xs leading-6 text-muted-foreground">
                    {t("twin.l1.why")} — <Network className="inline size-3" aria-hidden /> {t("twin.l1.graph")}
                  </p>
                )}
              </div>
            </SectionCard>
          </div>

          {/* conflicts */}
          {twin.conflicts.length > 0 ? (
            <SectionCard title={`${t("twin.l1.conflicts")} (${fmtNum(twin.conflicts.length)})`} className="mt-4">
              <ul className="divide-y">
                {twin.conflicts.map((c) => (
                  <li key={c.id} className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="size-4 text-[var(--severity-high)]" aria-hidden />
                      <span className="num text-xs font-bold">{c.kind}</span>
                      <span className="num rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{c.resolution}</span>
                    </div>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">{c.description}</p>
                    <div className="mt-2 grid gap-2 md:grid-cols-2">
                      <div className="rounded-lg border bg-muted/30 p-2">
                        <ProvBadge p={c.left.provenance} />
                        <p className="mt-1 text-[11px] leading-5">{c.left.summary}</p>
                      </div>
                      <div className="rounded-lg border bg-muted/30 p-2">
                        <ProvBadge p={c.right.provenance} />
                        <p className="mt-1 text-[11px] leading-5">{c.right.summary}</p>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </SectionCard>
          ) : null}

          {/* known unknowns + counts */}
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            <SectionCard title={`${t("twin.l1.unknowns")} (${fmtNum(twin.knownUnknowns.length)})`}>
              <ul className="divide-y">
                {twin.knownUnknowns.length ? (
                  twin.knownUnknowns.map((u) => (
                    <li key={u.id} className="flex items-start gap-2 px-4 py-2.5">
                      <HelpCircle className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                      <div className="min-w-0">
                        <p className="text-xs leading-5">{u.description}</p>
                        <p className="num mt-0.5 text-[10px] text-muted-foreground">{u.dimension}</p>
                      </div>
                    </li>
                  ))
                ) : (
                  <li className="px-4 py-6 text-center text-sm text-muted-foreground">{t("common.none")}</li>
                )}
              </ul>
            </SectionCard>
            <SectionCard title={t("twin.l1.nodes")} extra={<span className="num text-[10px] text-muted-foreground">{twin.schemaVersion}</span>}>
              <ul className="grid grid-cols-2 gap-1.5 px-4 py-3 sm:grid-cols-3">
                {types.map(([ty, c]) => (
                  <li key={ty} className="flex items-center justify-between gap-2 rounded-lg bg-muted/40 px-2.5 py-1.5">
                    <span className="num truncate text-[11px] font-semibold">{ty}</span>
                    <span className="num tnum text-[11px] font-bold text-muted-foreground">{fmtNum(c)}</span>
                  </li>
                ))}
              </ul>
            </SectionCard>
          </div>
        </>
      )}
    </>
  );
}

// ── why panel ────────────────────────────────────────────────────────────────

function WhyPanel({
  node,
  related,
  twin,
}: {
  node: TwinNode;
  related: Array<{ edge: TwinEdge; other?: TwinNode }>;
  twin: NormalizedTwin;
}) {
  const { t } = useI18n();
  const attrs = Object.entries(node.attrs ?? {}).slice(0, 14);
  return (
    <div className="space-y-3">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="num rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-bold text-primary">{node.type}</span>
          <ProvBadge p={node.provenance} />
          {node.claim ? <ClaimBadge state={node.claim.state} /> : null}
        </div>
        <p className="mt-1.5 break-all text-sm font-bold">{node.label}</p>
        <code className="num block break-all text-[10px] text-muted-foreground">{node.key}</code>
      </div>

      {node.claim ? (
        <div className="rounded-lg border bg-muted/30 p-2.5">
          <div className="flex items-center gap-2">
            <ClaimBadge state={node.claim.state} />
            <span className="text-[10px] font-bold text-muted-foreground">{t("twin.l1.claims")}</span>
          </div>
          <p className="mt-1 text-[11px] leading-5">{node.claim.statement}</p>
          {node.claim.evidenceRefs.length ? (
            <p className="num mt-1 break-all text-[10px] text-muted-foreground">
              {t("twin.l1.why.evidence")}: {node.claim.evidenceRefs.slice(0, 5).join(" · ")}
            </p>
          ) : null}
        </div>
      ) : null}

      <div>
        <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-muted-foreground">
          <BadgeCheck className="size-3" aria-hidden /> {t("twin.l1.why.reason")}
        </p>
        <p className="mt-1 text-xs leading-6">{node.why.reason}</p>
      </div>

      <div>
        <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-muted-foreground">
          <GitBranch className="size-3" aria-hidden /> {t("twin.l1.why.sources")}
        </p>
        <ul className="mt-1 flex flex-wrap gap-1">
          {node.sourceRefs.slice(0, 8).map((r) => (
            <li key={r} className="num rounded bg-muted px-1.5 py-0.5 text-[10px]">{r}</li>
          ))}
        </ul>
      </div>

      {node.why.inferenceReason ? (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{t("twin.l1.why.inference")}</p>
          <p className="mt-1 text-[11px] leading-5 text-amber-600 dark:text-amber-400">{node.why.inferenceReason}</p>
        </div>
      ) : null}

      {node.why.evidenceRefs?.length ? (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{t("twin.l1.why.evidence")}</p>
          <ul className="mt-1 flex flex-wrap gap-1">
            {node.why.evidenceRefs.slice(0, 8).map((r) => (
              <li key={r} className="num rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-600 dark:text-emerald-400">{r}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {attrs.length ? (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{t("twin.l1.attrs")}</p>
          <dl className="mt-1 space-y-1">
            {attrs.map(([k, v]) => (
              <div key={k} className="flex items-start justify-between gap-3 rounded bg-muted/30 px-2 py-1">
                <dt className="num shrink-0 text-[10px] font-semibold">{k}</dt>
                <dd className="num break-all text-end text-[10px] text-muted-foreground">
                  {typeof v === "object" ? JSON.stringify(v).slice(0, 80) : String(v).slice(0, 100)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}

      {related.length ? (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{t("twin.l1.related")}</p>
          <ul className="mt-1 space-y-1">
            {related.map(({ edge, other }) => (
              <li key={edge.id} className="flex items-center gap-1.5 rounded bg-muted/30 px-2 py-1 text-[10px]">
                <Ban className={cn("size-2.5 shrink-0", edge.provenance === "REFUTED" ? "text-red-500" : "text-muted-foreground")} aria-hidden />
                <span className="num font-bold">{edge.type}</span>
                <span className="truncate text-muted-foreground" title={other?.key}>{other?.label ?? other?.id ?? "—"}</span>
                <ProvBadge p={edge.provenance} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <p className="num border-t pt-2 text-[9px] text-muted-foreground">
        {twin.schemaVersion} · {twin.counts.byNodeType[node.type] ?? 1} × {node.type}
      </p>
    </div>
  );
}
