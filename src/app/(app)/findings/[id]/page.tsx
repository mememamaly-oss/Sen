"use client";

// SENTINEL finding detail — the evidence-first view.
// Tabs: Evidence / Verification / Impact / Reproduction / Remediation.
// All content is engine output; the remediation tab is clearly labeled as
// platform-side guidance. Nothing is fabricated.

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import {
  ArrowLeft,
  BugPlay,
  FileSearch,
  Hammer,
  Scale,
  ShieldCheck,
  Siren,
} from "lucide-react";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState } from "@/components/ui-kit/states";
import { SeverityChip, ConfidenceBar, VerificationChip } from "@/components/ui-kit/severity";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";

function JsonBlock({ data }: { data: unknown }) {
  return (
    <pre className="num overflow-auto rounded-lg bg-muted/50 p-3 text-[11.5px] leading-5" dir="ltr">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { t, fmtDate, fmtNum } = useI18n();
  const session = useSession();
  const org = session.org;
  const q = useAsync(
    () => (org && id ? api.findingDetail(org.id, id) : Promise.resolve(null)),
    [org?.id, id]
  );

  if (q.state === "loading") return <CardSkeleton lines={7} />;
  if (q.state === "error") return <ErrorState onRetry={q.retry} message={q.error ?? undefined} />;
  if (!q.data) return null;
  const d = q.data;
  const f = d.finding;
  // P2-C: engine compliance mapping — rendered exactly as the engine exported it
  const comp = d.compliance as {
    mapped?: boolean;
    cwe?: string | null; cwe_label?: string | null;
    owasp_2021?: string | null; owasp_2021_title?: string | null; owasp_2021_src?: string | null;
    owasp_2025?: string | null; owasp_2025_title?: string | null; owasp_2025_src?: string | null;
    pci_dss?: string | null;
  } | null;
  const verified = (f.status ?? "").toLowerCase().includes("verified");
  const repro = d.reproduction;
  const hasRepro = repro && Object.keys(repro).length > 0;

  return (
    <>
      <PageHeader
        title={f.type}
        subtitle={`${d.target.name} — ${d.scan.runId?.slice(0, 12) ?? "—"}`}
        meta={
          <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="num" dir="ltr">{f.method ? `${f.method} ` : ""}{f.url}{f.parameter ? ` · ${f.parameter}` : ""}</span>
          </p>
        }
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href={`/findings?scan=${d.scan.id}`}>
              <ArrowLeft className="size-3.5" aria-hidden />
              {t("common.back")}
            </Link>
          </Button>
        }
      />

      {/* identity strip */}
      <div className="card-elevated mb-4 rounded-xl border bg-card">
        <div className="flex flex-wrap items-center gap-3 px-4 py-3.5">
          <SeverityChip severity={f.severity} />
          <VerificationChip verified={verified} />
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-muted-foreground">{t("finding.detail.confidence")}</span>
            <ConfidenceBar value={f.confidence} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-muted-foreground">{t("finding.detail.risk")}</span>
            <span className="num tnum text-sm font-extrabold">{fmtNum(f.risk)}</span>
          </div>
          <div className="ms-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
            <span>{t("finding.detail.engineId")}: <span className="num" dir="ltr">{f.engineId}</span></span>
            {f.fingerprint ? (
              <span className="num" dir="ltr">{t("finding.detail.fingerprint")}: {String(f.fingerprint).slice(0, 16)}…</span>
            ) : null}
            <span>{fmtDate(f.createdAt)}</span>
          </div>
        </div>

        {comp ? (
          <div className="flex flex-wrap items-center gap-2 border-t px-4 py-3">
            <span className="text-xs font-bold text-muted-foreground">{t("compliance.title")}</span>
            {comp.mapped === false ? (
              <Badge variant="outline" className="text-muted-foreground">{t("compliance.unmapped")}</Badge>
            ) : (
              <>
                {comp.cwe ? (
                  <Badge variant="secondary" className="num" dir="ltr" title={comp.cwe_label ?? ""}>
                    {t("compliance.cwe")} {comp.cwe}
                  </Badge>
                ) : null}
                {comp.owasp_2021 ? (
                  <Badge variant="outline" className="num" dir="ltr" title={comp.owasp_2021_title ?? ""}>
                    {comp.owasp_2021} · {comp.owasp_2021_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                  </Badge>
                ) : null}
                {comp.owasp_2025 ? (
                  <Badge variant="outline" className="num" dir="ltr" title={comp.owasp_2025_title ?? ""}>
                    {comp.owasp_2025} · {comp.owasp_2025_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                  </Badge>
                ) : null}
                {comp.pci_dss ? (
                  <Badge className="num" dir="ltr" title={t("compliance.pciNote")}>
                    {t("compliance.pci")} {comp.pci_dss}
                  </Badge>
                ) : null}
              </>
            )}
          </div>
        ) : null}
      </div>

      <Tabs defaultValue="evidence">
        <TabsList className="mb-3">
          <TabsTrigger value="evidence"><FileSearch className="size-3.5" aria-hidden /> {t("finding.detail.evidence")}</TabsTrigger>
          <TabsTrigger value="verification"><Scale className="size-3.5" aria-hidden /> {t("finding.detail.verification")}</TabsTrigger>
          <TabsTrigger value="impact"><Siren className="size-3.5" aria-hidden /> {t("finding.detail.impact")}</TabsTrigger>
          <TabsTrigger value="reproduction"><BugPlay className="size-3.5" aria-hidden /> {t("finding.detail.reproduction")}</TabsTrigger>
          <TabsTrigger value="remediation"><Hammer className="size-3.5" aria-hidden /> {t("finding.detail.remediation")}</TabsTrigger>
        </TabsList>

        <TabsContent value="evidence">
          <SectionCard title={`${t("finding.detail.evidence")} · ${fmtNum(d.evidence?.length ?? 0)}`}>
            <ul className="divide-y">
              {(d.evidence ?? []).map((e, i) => (
                <li key={i} className="px-4 py-2.5">
                  <p className="text-xs font-bold text-primary">
                    {e.kind ?? "evidence"}
                  </p>
                  <p className="num mt-0.5 whitespace-pre-wrap break-all text-[11.5px] leading-5 text-muted-foreground" dir="ltr">
                    {e.detail ?? JSON.stringify(e)}
                  </p>
                </li>
              ))}
              {!(d.evidence ?? []).length ? (
                <li className="px-4 py-6 text-center text-sm text-muted-foreground">{t("common.none")}</li>
              ) : null}
            </ul>
          </SectionCard>
        </TabsContent>

        <TabsContent value="verification">
          <SectionCard title={t("finding.detail.verification")}>
            <div className="px-4 py-3.5">
              {d.verification && Object.keys(d.verification).length ? (
                <JsonBlock data={d.verification} />
              ) : (
                <p className="text-sm text-muted-foreground">{t("common.none")}</p>
              )}
            </div>
          </SectionCard>
        </TabsContent>

        <TabsContent value="impact">
          <SectionCard title={t("finding.detail.impact")}>
            <div className="px-4 py-3.5">
              {d.impact && Object.keys(d.impact).length ? (
                <JsonBlock data={d.impact} />
              ) : (
                <p className="text-sm text-muted-foreground">{t("common.none")}</p>
              )}
            </div>
          </SectionCard>
        </TabsContent>

        <TabsContent value="reproduction">
          {hasRepro ? (
            <SectionCard
              title={t("finding.detail.reproduction")}
              extra={
                f.hasProof ? (
                  <Badge variant="outline" className="border-transparent bg-[color-mix(in_oklab,var(--success)_14%,transparent)] text-[var(--success)]">
                    <ShieldCheck className="size-3" aria-hidden />
                    {t("findings.verified")}
                  </Badge>
                ) : undefined
              }
            >
              <div className="px-4 py-3.5">
                <JsonBlock data={repro} />
              </div>
            </SectionCard>
          ) : (
            <SectionCard title={t("finding.detail.reproduction")}>
              <div className="px-4 py-8">
                <p className="text-center text-sm leading-7 text-muted-foreground">
                  {t("finding.detail.noReproduction")}
                </p>
              </div>
            </SectionCard>
          )}
        </TabsContent>

        <TabsContent value="remediation">
          <SectionCard title={t("finding.detail.remediation")}>
            <div className="px-4 py-3.5">
              {d.remediation?.steps?.length ? (
                <>
                  <p className="mb-1 text-sm font-bold">{d.remediation.title}</p>
                  <p className="text-sm leading-7 text-muted-foreground">{d.remediation.summary}</p>
                  <ol className="mt-2 space-y-1.5">
                    {d.remediation.steps.map((s, i) => (
                      <li key={i} className="flex gap-2 text-sm leading-6">
                        <span className="num mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[11px] font-extrabold text-primary">
                          {i + 1}
                        </span>
                        <span>{s}</span>
                      </li>
                    ))}
                  </ol>
                  <p className="mt-3 rounded-lg border border-dashed bg-muted/40 px-3 py-2 text-xs leading-5 text-muted-foreground">
                    {t("finding.detail.remediationNote")}
                  </p>
                </>
              ) : (
                <p className="text-sm text-muted-foreground">{t("common.none")}</p>
              )}
            </div>
          </SectionCard>
        </TabsContent>
      </Tabs>
    </>
  );
}
