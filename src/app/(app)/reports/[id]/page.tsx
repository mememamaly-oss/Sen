"use client";

// SENTINEL report viewer — HTML/GLASS render in a sandboxed iframe (srcDoc);
// SARIF/EXECUTIVE (JSON) render as formatted raw content. Download as blob.

import Link from "next/link";
import { useParams } from "next/navigation";
import { Download, FileText } from "lucide-react";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { useToast } from "@/lib/ui/toast";
import { PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState } from "@/components/ui-kit/states";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const FMT_STYLE: Record<string, string> = {
  HTML: "border-transparent bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary",
  GLASS: "border-transparent bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary",
  SARIF: "border-transparent bg-[color-mix(in_oklab,var(--severity-low)_14%,transparent)] text-[var(--severity-low)]",
  EXECUTIVE: "border-transparent bg-[color-mix(in_oklab,var(--severity-medium)_18%,transparent)] text-[var(--severity-medium)]",
};

export default function ReportViewerPage() {
  const { id } = useParams<{ id: string }>();
  const { t, fmtBytes, fmtDate } = useI18n();
  const session = useSession();
  const toast = useToast();
  const org = session.org;
  const q = useAsync(
    () => (org && id ? api.reportDetail(org.id, id) : Promise.resolve(null)),
    [org?.id, id]
  );

  function download() {
    const d = q.data;
    if (!d) return;
    try {
      const mime =
        d.ext === "html" ? "text/html" : d.ext === "sarif" || d.ext === "json" ? "application/json" : "text/plain";
      const blob = new Blob([d.content], { type: `${mime};charset=utf-8` });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `sentinel-report-${d.report.id.slice(-8)}.${d.ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      toast.error(t("toasts.errorGeneric"));
    }
  }

  if (q.state === "loading") return <CardSkeleton lines={6} />;
  if (q.state === "error") return <ErrorState onRetry={q.retry} message={q.error ?? undefined} />;
  if (!q.data) return null;
  const d = q.data;

  return (
    <>
      <PageHeader
        title={d.report.title}
        subtitle={
          d.report.scan
            ? `${d.report.scan.targetName} · ${d.report.scan.runId?.slice(0, 12) ?? "—"} · ${d.report.scan.scanner ?? "—"}`
            : undefined
        }
        meta={
          <p className="mt-1 text-xs text-muted-foreground">
            {t("reports.createdBy")}: {d.report.createdBy} · {fmtDate(d.report.createdAt)}
          </p>
        }
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href="/reports">
                {t("common.back")}
              </Link>
            </Button>
            <Button size="sm" onClick={download}>
              <Download className="size-3.5" aria-hidden />
              {t("common.download")}
            </Button>
          </>
        }
      />

      <SectionCard
        title={`${d.report.format} · ${fmtBytes(d.report.sizeBytes)}`}
        extra={
          <Badge variant="outline" className={cn("font-bold", FMT_STYLE[d.report.format] ?? "")}>
            <FileText className="size-3" aria-hidden />
            {d.report.format}
          </Badge>
        }
      >
        <div className="px-4 py-3">
          {d.ext === "html" ? (
            <iframe
              title={d.report.title}
              srcDoc={d.content}
              sandbox="allow-same-origin"
              className="h-[72vh] w-full rounded-lg border bg-white"
            />
          ) : (
            <pre className="num max-h-[72vh] overflow-auto rounded-lg bg-muted/50 p-4 text-[11.5px] leading-5" dir="ltr">
              {d.ext === "sarif" || d.ext === "json"
                ? (() => {
                    try {
                      return JSON.stringify(JSON.parse(d.content), null, 2);
                    } catch {
                      return d.content;
                    }
                  })()
                : d.content}
            </pre>
          )}
          <p className="mt-2 text-xs text-muted-foreground">{t("reports.downloadHint")}</p>
        </div>
      </SectionCard>
    </>
  );
}
