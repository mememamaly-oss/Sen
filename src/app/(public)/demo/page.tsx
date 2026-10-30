"use client";

// P2-E: the public live demo — one real engine scan against the managed
// fixture. Client polls the job API; everything rendered comes verbatim
// from the engine (findings + compliance mappings). No tenant state.

import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Play, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/lib/ui/toast";
import { useI18n } from "@/lib/ui/i18n";

type DemoFinding = {
  id: string;
  type: string;
  severity: string;
  risk: number;
  url: string;
  parameter: string | null;
  compliance: {
    mapped?: boolean;
    cwe?: string | null;
    owasp_2021?: string | null;
    owasp_2021_src?: string | null;
    owasp_2025?: string | null;
    owasp_2025_src?: string | null;
    pci_dss?: string | null;
  } | null;
};

type DemoState = {
  id: string;
  status: "running" | "done" | "error";
  elapsedSec?: number;
  runId?: string;
  scanner?: string;
  durationSec?: number;
  bySeverity?: Record<string, number>;
  compliance?: {
    owasp_2021: Record<string, number>;
    owasp_2025: Record<string, number>;
    cwe: Record<string, number>;
    pci: Record<string, number>;
  } | null;
  findings?: DemoFinding[];
  error?: string;
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export default function DemoPage() {
  const { t } = useI18n();
  const toast = useToast();
  const [job, setJob] = useState<DemoState | null>(null);
  const [starting, setStarting] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const poll = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/demo/scan?id=${encodeURIComponent(id)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`poll ${res.status}`);
      const data = (await res.json()) as DemoState;
      setJob(data);
      if (data.status === "done" || data.status === "error") {
        if (timer.current) clearInterval(timer.current);
        timer.current = null;
        if (data.status === "error") {
          toast.error(t("common.error"));
        }
      }
    } catch {
      /* transient poll failure — keep polling; the interval is cleared on done/error */
    }
  }, [t, toast]);

  useEffect(() => () => { if (timer.current) clearInterval(timer.current); }, []);

  const start = async () => {
    setStarting(true);
    try {
      const res = await fetch("/api/demo/scan", { method: "POST" });
      if (res.status === 429) {
        toast.error(t("demo.rateLimited"));
        return;
      }
      if (res.status === 503) {
        toast.error(t("common.error"));
        return;
      }
      if (!res.ok) throw new Error(`start ${res.status}`);
      const data = (await res.json()) as { id: string };
      setJob({ id: data.id, status: "running" });
      timer.current = setInterval(() => void poll(data.id), 3000);
    } catch {
      toast.error(t("common.error"));
    } finally {
      setStarting(false);
    }
  };

  const running = job?.status === "running";
  const done = job?.status === "done";
  const findings = job?.findings ?? [];

  return (
    <article className="max-w-5xl">
      <h1 className="flex items-center gap-2 text-2xl font-extrabold tracking-tight">
        <Play className="size-5 text-primary" aria-hidden /> {t("demo.title")}
      </h1>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        {t("demo.subtitle")}
      </p>

      <div className="mt-6 flex flex-wrap items-center gap-3">
        <Button size="lg" onClick={start} disabled={starting || running}>
          {running ? (
            <Loader2 className="size-4 animate-spin" aria-hidden />
          ) : (
            <Play className="size-4" aria-hidden />
          )}
          {t("demo.start")}
        </Button>
        {running ? (
          <span className="text-sm text-muted-foreground">
            {t("demo.working")}
            {job?.elapsedSec ? <span className="num" dir="ltr"> · {job.elapsedSec}s</span> : null}
          </span>
        ) : null}
      </div>

      {done && job ? (
        <>
          <section className="mt-8 flex flex-wrap items-center gap-2">
            {SEV_ORDER.filter((s) => job.bySeverity?.[s]).map((s) => (
              <Badge key={s} variant={s === "critical" || s === "high" ? "destructive" : "secondary"} className="num" dir="ltr">
                {s}: {job.bySeverity?.[s]}
              </Badge>
            ))}
            {job.scanner ? <Badge variant="outline" className="num" dir="ltr">{job.scanner}</Badge> : null}
            {job.durationSec ? <Badge variant="outline" className="num" dir="ltr">{job.durationSec}s</Badge> : null}
            {job.runId ? <Badge variant="outline" className="num" dir="ltr">{job.runId}</Badge> : null}
          </section>

          {job.compliance ? (
            <section className="mt-4 rounded-xl border bg-card p-4">
              <h2 className="flex items-center gap-2 text-sm font-extrabold">
                <ShieldCheck className="size-4 text-primary" aria-hidden /> {t("compliance.title")}
              </h2>
              <div className="mt-3 flex flex-wrap gap-2">
                {Object.entries(job.compliance.owasp_2025).map(([k, v]) => (
                  <Badge key={k} variant="outline" className="num" dir="ltr">2025 {k}: {v}</Badge>
                ))}
                {Object.entries(job.compliance.owasp_2021).map(([k, v]) => (
                  <Badge key={k} variant="outline" className="num" dir="ltr">2021 {k}: {v}</Badge>
                ))}
                {Object.entries(job.compliance.pci).map(([k, v]) => (
                  <Badge key={k} className="num" dir="ltr">PCI DSS {k}: {v}</Badge>
                ))}
              </div>
              <p className="mt-3 text-xs text-muted-foreground">{t("demo.sourceLegend")}</p>
            </section>
          ) : null}

          <section className="mt-6">
            <h2 className="text-sm font-extrabold">
              {t("demo.findings")} · <span className="num" dir="ltr">{findings.length}</span>
            </h2>
            {findings.length === 0 ? (
              <p className="mt-3 text-sm text-muted-foreground">{t("demo.empty")}</p>
            ) : (
              <div className="mt-3 overflow-x-auto rounded-xl border">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
                      <th className="px-3 py-2.5 text-start" dir="ltr">Severity</th>
                      <th className="px-3 py-2.5 text-start" dir="ltr">Type</th>
                      <th className="px-3 py-2.5 text-start" dir="ltr">URL · param</th>
                      <th className="px-3 py-2.5 text-start" dir="ltr">Risk</th>
                      <th className="px-3 py-2.5 text-start">{t("compliance.title")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.id} className="border-b last:border-0">
                        <td className="px-3 py-2.5">
                          <Badge variant={f.severity === "critical" || f.severity === "high" ? "destructive" : "secondary"} className="num" dir="ltr">
                            {f.severity}
                          </Badge>
                        </td>
                        <td className="px-3 py-2.5 num text-[12.5px] font-semibold" dir="ltr">{f.type}</td>
                        <td className="max-w-[380px] truncate px-3 py-2.5 num text-[11.5px] text-muted-foreground" dir="ltr">
                          {f.url}
                          {f.parameter ? ` · ${f.parameter}` : ""}
                        </td>
                        <td className="px-3 py-2.5 num" dir="ltr">{f.risk}</td>
                        <td className="px-3 py-2.5" dir="ltr">
                          <div className="flex flex-wrap gap-1.5">
                            {f.compliance?.mapped === false ? (
                              <span className="text-[11px] text-muted-foreground">{t("compliance.unmapped")}</span>
                            ) : (
                              <>
                                {f.compliance?.cwe ? <Badge variant="secondary" className="num text-[10.5px]">{f.compliance.cwe}</Badge> : null}
                                {f.compliance?.owasp_2021 ? (
                                  <Badge variant="outline" className="num text-[10.5px]">
                                    {f.compliance.owasp_2021} · {f.compliance.owasp_2021_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                                  </Badge>
                                ) : null}
                                {f.compliance?.owasp_2025 ? (
                                  <Badge variant="outline" className="num text-[10.5px]">
                                    {f.compliance.owasp_2025} · {f.compliance.owasp_2025_src === "official" ? t("compliance.srcOfficial") : t("compliance.srcScope")}
                                  </Badge>
                                ) : null}
                                {f.compliance?.pci_dss ? <Badge className="num text-[10.5px]">PCI {f.compliance.pci_dss}</Badge> : null}
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="mt-3 text-xs text-muted-foreground">
              {t("demo.sourceLegend")}
            </p>
          </section>
        </>
      ) : null}
    </article>
  );
}
