"use client";

// Burhan targets — the attack-surface registry. Search + sort + add
// (managed demo app / custom URL) + REAL scan start (api.startScan → live
// monitor). All rows are real platform rows.

import Link from "next/link";
import { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Activity,
  Loader2,
  Play,
  Plus,
  QrCode,
  Search,
  ShieldCheck,
  Target as TargetIcon,
  Trash2,
} from "lucide-react";
import { api, type TargetRow } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { useToast } from "@/lib/ui/toast";
import { PageHeader } from "@/components/ui-kit/page";
import { EmptyState, TableSkeleton, ErrorState } from "@/components/ui-kit/states";
import { StatusPill } from "@/components/ui-kit/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";

type Sort = "newest" | "scans" | "findings";
const SORTS: Array<{ v: Sort; key: "targets.sort.newest" | "targets.sort.mostScans" | "targets.sort.mostFindings" }> = [
  { v: "newest", key: "targets.sort.newest" },
  { v: "scans", key: "targets.sort.mostScans" },
  { v: "findings", key: "targets.sort.mostFindings" },
];

export default function TargetsPage() {
  const { t, fmtNum, relTime } = useI18n();
  const session = useSession();
  const toast = useToast();
  const router = useRouter();
  const org = session.org;
  const params = useSearchParams();

  const q = useAsync(() => (org ? api.targets(org.id) : Promise.resolve({ targets: [] })), [org?.id]);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<Sort>("newest");
  const [addOpen, setAddOpen] = useState(false);
  const [addMode, setAddMode] = useState<"demo" | "custom">("demo");
  const [form, setForm] = useState({ name: "", url: "", description: "" });
  const [busy, setBusy] = useState(false);
  const [deleteRow, setDeleteRow] = useState<TargetRow | null>(null);
  const [startRow, setStartRow] = useState<TargetRow | null>(null);
  const [startingId, setStartingId] = useState<string | null>(null);

  const rows = useMemo(() => {
    const list = (q.data?.targets ?? []).slice();
    const needle = search.trim().toLowerCase();
    const filtered = needle
      ? list.filter(
          (x) =>
            x.name.toLowerCase().includes(needle) ||
            x.url.toLowerCase().includes(needle) ||
            (x.description ?? "").toLowerCase().includes(needle)
        )
      : list;
    filtered.sort((a, b) => {
      if (sort === "scans") return b.scansCount - a.scansCount;
      if (sort === "findings") return b.findingsCount - a.findingsCount;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
    return filtered;
  }, [q.data, search, sort]);

  async function addTarget() {
    if (!org) return;
    setBusy(true);
    try {
      const body =
        addMode === "demo"
          ? { orgId: org.id, isDemo: true }
          : {
              orgId: org.id,
              url: form.url.trim(),
              name: form.name.trim() || undefined,
              description: form.description.trim() || undefined,
            };
      if (addMode === "custom") {
        try {
          const u = new URL(form.url.trim());
          if (!/^https?:$/.test(u.protocol)) throw new Error();
        } catch {
          toast.error(t("targets.invalidUrl"));
          return;
        }
      }
      await api.createTarget(body);
      toast.success(t("targets.created"));
      setAddOpen(false);
      setForm({ name: "", url: "", description: "" });
      await q.reload();
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    } finally {
      setBusy(false);
    }
  }

  async function doDelete() {
    if (!org || !deleteRow) return;
    try {
      await api.deleteTarget(org.id, deleteRow.id);
      toast.success(t("targets.deleted"));
      setDeleteRow(null);
      await q.reload();
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    }
  }

  // REAL scan start (FG-1): POST /api/scans via the existing api.startScan —
  // the engine runs; the UI then follows the run in the live monitor.
  async function startScan() {
    if (!org || !startRow) return;
    setStartingId(startRow.id);
    try {
      const r = await api.startScan({ orgId: org.id, targetId: startRow.id });
      toast.success(t("scans.started"));
      setStartRow(null);
      router.push(`/scans/${r.id}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    } finally {
      setStartingId(null);
    }
  }

  const canManage = session.role === "OWNER" || session.role === "ADMIN" || session.role === "MEMBER";

  return (
    <>
      <PageHeader
        title={t("targets.title")}
        subtitle={t("targets.subtitle")}
        actions={
          canManage ? (
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="size-4" aria-hidden />
              {t("targets.add")}
            </Button>
          ) : undefined
        }
      />

      {/* toolbar: search + sort */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-52 flex-1">
          <Search className="absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("targets.searchPlaceholder")}
            className="ps-8"
            aria-label={t("common.search")}
          />
        </div>
        <Select value={sort} onValueChange={(v) => setSort(v as Sort)}>
          <SelectTrigger className="w-44" aria-label={t("common.sort")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SORTS.map((s) => (
              <SelectItem key={s.v} value={s.v}>
                {t(s.key)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* table */}
      {q.state === "loading" ? (
        <TableSkeleton rows={5} cols={5} />
      ) : q.state === "error" ? (
        <ErrorState onRetry={q.retry} message={q.error ?? undefined} />
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("targets.empty.title")}
          hint={t("targets.empty.hint")}
          icon={<TargetIcon className="size-6 text-muted-foreground" aria-hidden />}
          action={
            canManage ? (
              <Button size="sm" variant="outline" onClick={() => setAddOpen(true)}>
                <Plus className="size-4" aria-hidden />
                {t("targets.add")}
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="card-elevated overflow-hidden rounded-xl border bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-start text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  <th scope="col" className="px-4 py-3 text-start">{t("targets.name")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("targets.lastScan")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("targets.scansCount")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("targets.findingsCount")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("targets.owner")}</th>
                  <th scope="col" className="px-4 py-3 text-end">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((x) => (
                  <tr key={x.id} className="transition-colors duration-150 hover:bg-muted/40">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <p className="font-semibold leading-5">{x.name}</p>
                        {x.isDemo ? (
                          <Badge variant="outline" className="gap-1 border-transparent bg-[color-mix(in_oklab,var(--primary)_14%,transparent)] text-primary">
                            <QrCode className="size-3" aria-hidden />
                            {t("targets.demoBadge")}
                          </Badge>
                        ) : null}
                      </div>
                      <p className="num mt-0.5 text-xs text-muted-foreground" dir="ltr">
                        {x.url}
                      </p>
                      {x.description ? (
                        <p className="mt-0.5 max-w-md truncate text-xs text-muted-foreground">{x.description}</p>
                      ) : null}
                    </td>
                    <td className="px-4 py-3 align-top">
                      {x.lastScan ? (
                        <div className="flex flex-col items-start gap-1.5">
                          <StatusPill status={x.lastScan.status} />
                          <span className="text-xs text-muted-foreground">{relTime(x.lastScan.createdAt)}</span>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">{t("targets.never")}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 align-top">
                      <Link
                        href={`/scans?target=${x.id}`}
                        className="num tnum font-bold hover:underline"
                        aria-label={`${t("targets.scansCount")}: ${x.name}`}
                      >
                        {fmtNum(x.scansCount)}
                      </Link>
                    </td>
                    <td className="px-4 py-3 align-top">
                      <span className={`num tnum font-bold ${(x.findingsCount ?? 0) > 0 ? "text-[var(--severity-high)]" : "text-[var(--success)]"}`}>
                        {fmtNum(x.findingsCount)}
                      </span>
                    </td>
                    <td className="px-4 py-3 align-top text-xs text-muted-foreground">{x.owner}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <Button asChild variant="ghost" size="sm" className="h-8 px-2 text-xs">
                          <Link href={`/scans?target=${x.id}`} aria-label={`${t("scans.title")}: ${x.name}`}>
                            <Activity className="size-3.5" aria-hidden />
                            {t("scans.title")}
                          </Link>
                        </Button>
                        {canManage ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 px-2 text-xs font-bold text-primary hover:text-primary"
                            onClick={() => setStartRow(x)}
                            aria-label={`${t("scans.start")}: ${x.name}`}
                          >
                            {startingId === x.id ? (
                              <Loader2 className="size-3.5 animate-spin" aria-hidden />
                            ) : (
                              <Play className="size-3.5" aria-hidden />
                            )}
                            {startingId === x.id ? t("scans.starting") : t("scans.start")}
                          </Button>
                        ) : null}
                        {canManage && (session.role !== "MEMBER" || x.ownerId === session.me?.user.id) ? (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-8 text-[var(--severity-critical)] hover:text-[var(--severity-critical)]"
                            onClick={() => setDeleteRow(x)}
                            aria-label={`${t("common.delete")}: ${x.name}`}
                          >
                            <Trash2 className="size-3.5" aria-hidden />
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t("targets.add")}</DialogTitle>
            <DialogDescription>{t("targets.empty.hint")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="grid grid-cols-2 gap-2" role="tablist" aria-label={t("targets.add")}>
              <Button
                type="button"
                variant={addMode === "demo" ? "default" : "outline"}
                onClick={() => setAddMode("demo")}
                role="tab"
                aria-selected={addMode === "demo"}
              >
                {t("targets.addDemo")}
              </Button>
              <Button
                type="button"
                variant={addMode === "custom" ? "default" : "outline"}
                onClick={() => setAddMode("custom")}
                role="tab"
                aria-selected={addMode === "custom"}
              >
                {t("targets.addCustom")}
              </Button>
            </div>
            {addMode === "demo" ? (
              <p className="rounded-lg border border-dashed bg-muted/40 px-3.5 py-2.5 text-[13px] leading-6 text-muted-foreground">
                <ShieldCheck className="me-1.5 inline size-4 text-primary" aria-hidden />
                127.0.0.1:8777 — vulnapp (fixture المحرك) — يبدأه النظام ويصلحه تلقائيًا.
              </p>
            ) : (
              <>
                <div className="grid gap-1.5">
                  <label className="text-sm font-semibold" htmlFor="t-url">{t("targets.url")}</label>
                  <Input
                    id="t-url" dir="ltr" className="text-start" placeholder="https://example.com"
                    value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })}
                  />
                </div>
                <div className="grid gap-1.5">
                  <label className="text-sm font-semibold" htmlFor="t-name">{t("targets.name")}</label>
                  <Input id="t-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </div>
                <div className="grid gap-1.5">
                  <label className="text-sm font-semibold" htmlFor="t-desc">{t("targets.description")}</label>
                  <Input id="t-desc" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                </div>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>{t("common.cancel")}</Button>
            <Button onClick={addTarget} disabled={busy}>
              {busy ? t("common.loading") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* delete confirm */}
      <AlertDialog open={!!deleteRow} onOpenChange={(o) => !o && setDeleteRow(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("targets.deleteConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{t("targets.deleteConfirmBody")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={doDelete}
              className="bg-[var(--severity-critical)] text-white hover:bg-[var(--severity-critical)]/90"
            >
              {t("common.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* scan start confirm (FG-1) */}
      <AlertDialog open={!!startRow} onOpenChange={(o) => !o && !startingId && setStartRow(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("scans.startConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-semibold">{startRow?.name}</span>
              <span className="num mx-1" dir="ltr">{startRow?.url}</span>
              {"— " + t("scans.startConfirmBody")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={!!startingId}>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault(); // keep the dialog open while starting
                void startScan();
              }}
              disabled={!!startingId}
            >
              {startingId ? (
                <>
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  {t("scans.starting")}
                </>
              ) : (
                <>
                  <Play className="size-4" aria-hidden />
                  {t("scans.start")}
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
