"use client";

// SENTINEL organization — identity card + members management
// (add / role change / remove). Roles: OWNER > ADMIN > MEMBER > VIEWER.

import { useState } from "react";
import { Building2, UserPlus, Users } from "lucide-react";
import { api } from "@/components/saas/api";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";
import { useAsync } from "@/lib/ui/use-async";
import { useToast } from "@/lib/ui/toast";
import { PageHeader, SectionCard } from "@/components/ui-kit/page";
import { CardSkeleton, ErrorState, EmptyState } from "@/components/ui-kit/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { MemberRow } from "@/components/saas/api";

const ROLES = ["ADMIN", "MEMBER", "VIEWER"] as const;
const ROLE_STYLE: Record<string, string> = {
  OWNER: "border-transparent bg-[color-mix(in_oklab,var(--primary)_16%,transparent)] text-primary",
  ADMIN: "border-transparent bg-[color-mix(in_oklab,var(--severity-low)_14%,transparent)] text-[var(--severity-low)]",
  MEMBER: "border-transparent bg-[color-mix(in_oklab,var(--severity-medium)_16%,transparent)] text-[var(--severity-medium)]",
  VIEWER: "bg-muted text-muted-foreground",
};

export default function OrganizationPage() {
  const { t, fmtDate, fmtNum } = useI18n();
  const session = useSession();
  const toast = useToast();
  const org = session.org;
  const canManage = session.role === "OWNER" || session.role === "ADMIN";

  const q = useAsync(
    () => (org ? api.members(org.id) : Promise.resolve({ members: [] as MemberRow[] })),
    [org?.id]
  );

  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "VIEWER" });
  const [busy, setBusy] = useState(false);
  const [removeRow, setRemoveRow] = useState<MemberRow | null>(null);

  async function addMember() {
    if (!org) return;
    setBusy(true);
    try {
      await api.addMember(org.id, {
        email: form.email.trim(),
        name: form.name.trim() || undefined,
        password: form.password,
        role: form.role,
      });
      toast.success(t("org.member.added"));
      setAddOpen(false);
      setForm({ email: "", name: "", password: "", role: "VIEWER" });
      await q.reload();
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    } finally {
      setBusy(false);
    }
  }

  async function changeRole(row: MemberRow, role: string) {
    if (!org) return;
    try {
      await api.changeMemberRole(org.id, row.id, role);
      toast.success(t("org.member.roleChanged"));
      await q.reload();
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    }
  }

  async function removeMember() {
    if (!org || !removeRow) return;
    try {
      await api.removeMember(org.id, removeRow.id);
      toast.success(t("org.member.removed"));
      setRemoveRow(null);
      await q.reload();
      await session.refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("toasts.errorGeneric"));
    }
  }

  const members = q.data?.members ?? [];

  return (
    <>
      <PageHeader
        title={t("org.title")}
        subtitle={t("org.subtitle")}
        actions={
          canManage ? (
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <UserPlus className="size-4" aria-hidden />
              {t("org.member.add")}
            </Button>
          ) : undefined
        }
      />

      {/* org identity */}
      <SectionCard title={t("org.about")} className="mb-4">
        <div className="grid gap-4 px-4 py-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: t("shell.org"), value: org?.name ?? "—" },
            { label: t("org.slug"), value: org?.slug ?? "—", num: true },
            { label: t("org.createdAt"), value: org ? fmtDate(org.createdAt, { time: false }) : "—" },
            { label: t("org.member.role"), value: t(`shell.role.${session.role.toLowerCase()}` as never) },
          ].map((x) => (
            <div key={x.label}>
              <p className="text-[11px] font-bold uppercase tracking-wide text-muted-foreground">{x.label}</p>
              <p className={`mt-0.5 text-sm font-bold ${x.num ? "num" : ""}`} dir={x.num ? "ltr" : undefined}>
                {x.value}
              </p>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* members */}
      {q.state === "loading" ? (
        <CardSkeleton lines={5} />
      ) : q.state === "error" ? (
        <ErrorState onRetry={q.retry} message={q.error ?? undefined} />
      ) : members.length === 0 ? (
        <EmptyState title={t("common.empty")} icon={<Users className="size-6 text-muted-foreground" aria-hidden />} />
      ) : (
        <SectionCard title={`${t("org.members")} · ${fmtNum(members.length)}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  <th scope="col" className="px-4 py-3 text-start">{t("org.member.name")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("org.member.role")}</th>
                  <th scope="col" className="px-4 py-3 text-start">{t("org.member.joined")}</th>
                  <th scope="col" className="px-4 py-3 text-end">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {members.map((m) => {
                  const self = m.userId === session.me?.user?.id;
                  return (
                    <tr key={m.id} className="transition-colors duration-150 hover:bg-muted/40">
                      <td className="px-4 py-3">
                        <p className="font-semibold leading-5">
                          {m.name || m.email}
                          {self ? <span className="ms-1.5 text-xs font-normal text-muted-foreground">({t("org.member.self")})</span> : null}
                        </p>
                        <p className="num text-xs text-muted-foreground" dir="ltr">{m.email}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={ROLE_STYLE[m.role] ?? ""}>{t(`shell.role.${m.role.toLowerCase()}` as never)}</Badge>
                          {canManage && m.role !== "OWNER" ? (
                            <Select value={m.role} onValueChange={(r) => changeRole(m, r)}>
                              <SelectTrigger className="h-7 w-24 text-xs" aria-label={`${t("org.member.role")}: ${m.email}`}>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {ROLES.map((r) => (
                                  <SelectItem key={r} value={r} className="text-xs">{r}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          ) : null}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">{fmtDate(m.joinedAt, { time: false })}</td>
                      <td className="px-4 py-3">
                        {canManage && m.role !== "OWNER" && !self ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs text-[var(--severity-critical)] hover:text-[var(--severity-critical)]"
                            onClick={() => setRemoveRow(m)}
                          >
                            {t("common.delete")}
                          </Button>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {/* add member dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              <Building2 className="me-2 inline size-4" aria-hidden />
              {t("org.member.add")}
            </DialogTitle>
            <DialogDescription>{org?.name}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="grid gap-1.5">
              <label className="text-sm font-semibold" htmlFor="m-email">{t("org.member.email")}</label>
              <Input id="m-email" type="email" dir="ltr" className="text-start" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <label className="text-sm font-semibold" htmlFor="m-name">{t("org.member.name")}</label>
              <Input id="m-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <label className="text-sm font-semibold" htmlFor="m-pw">{t("org.member.password")}</label>
              <Input id="m-pw" type="password" dir="ltr" className="text-start" minLength={8} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <label className="text-sm font-semibold" htmlFor="m-role">{t("org.member.role")}</label>
              <Select value={form.role} onValueChange={(r) => setForm({ ...form, role: r })}>
                <SelectTrigger id="m-role"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>{t("common.cancel")}</Button>
            <Button onClick={addMember} disabled={busy || !form.email || form.password.length < 8}>
              {busy ? t("common.loading") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* remove confirm */}
      <AlertDialog open={!!removeRow} onOpenChange={(o) => !o && setRemoveRow(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("org.member.removeConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{t("org.member.removeConfirmBody")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={removeMember} className="bg-[var(--severity-critical)] text-white hover:bg-[var(--severity-critical)]/90">
              {t("common.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
