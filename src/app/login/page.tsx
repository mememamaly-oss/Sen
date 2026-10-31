"use client";

// Burhan login — split screen: command-deck brand panel + auth form.
// Handles both states: sign-in, and first-run platform activation (bootstrap).

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, KeyRound, ShieldCheck, UserPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/components/saas/api";
import { useI18n } from "@/lib/ui/i18n";
import { useSession } from "@/lib/ui/session";
import { useToast } from "@/lib/ui/toast";

function BrandPanel() {
  const { t } = useI18n();
  return (
    <aside
      className="relative hidden overflow-hidden lg:flex lg:w-[46%] lg:flex-col lg:justify-between"
      style={{
        background:
          "radial-gradient(120% 90% at 85% 10%, color-mix(in oklab, var(--primary) 22%, var(--background)) 0%, var(--background) 55%), var(--background)",
      }}
      aria-hidden
    >
      <div className="scanline pointer-events-none absolute inset-0 opacity-30" />
      <div className="relative p-10">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="size-11">
            <path
              d="M16 2.5 27 7v9.2c0 6.6-4.4 11.6-11 13.3-6.6-1.7-11-6.7-11-13.3V7l11-4.5Z"
              className="fill-primary/15 stroke-primary"
              strokeWidth="1.6"
            />
            <path
              d="M9.5 16.5h4l2-5 3 9 2-4h4"
              fill="none"
              className="stroke-primary"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div className="leading-tight">
            <p className="text-2xl font-extrabold tracking-tight">{t("brand.name")}</p>
            <p className="text-sm font-medium text-muted-foreground">{t("brand.tagline")}</p>
          </div>
        </div>
      </div>

      <div className="relative p-10">
        <ul className="space-y-3 text-sm leading-6">
          <li className="flex items-center gap-2.5">
            <ShieldCheck className="size-4 shrink-0 text-primary" aria-hidden />
            <span className="text-muted-foreground">
              <b className="text-foreground">{t("brand.name")}</b> — {t("brand.tagline")}
            </span>
          </li>
          <li className="flex items-center gap-2.5">
            <Activity className="size-4 shrink-0 text-primary" aria-hidden />
            <span className="num text-muted-foreground">burhan-core/4.1.1 · F1&nbsp;1.000 ×3</span>
          </li>
        </ul>
      </div>
    </aside>
  );
}

export default function LoginPage() {
  const { t } = useI18n();
  const { refresh, me, ready } = useSession();
  const toast = useToast();
  const router = useRouter();

  const [mode, setMode] = useState<"checking" | "signin" | "bootstrap">("checking");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ready) return;
    if (me) {
      router.replace("/overview");
      return;
    }
    void api
      .bootstrapStatus()
      .then((b) => setMode(b.needsBootstrap ? "bootstrap" : "signin"))
      .catch(() => setMode("signin"));
  }, [ready, me, router]);

  async function signInWithCredentials(em: string, pw: string) {
    const csrf = (await fetch("/api/auth/csrf").then((r) => r.json())) as {
      csrfToken: string;
    };
    const res = await fetch("/api/auth/callback/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        csrfToken: csrf.csrfToken,
        email: em,
        password: pw,
        json: "true",
      }),
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`sign-in ${res.status}`);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "bootstrap") {
        await api.bootstrap({ email, name: name || undefined, password, orgName: orgName || undefined });
        toast.success(t("toasts.signedIn"));
      }
      await signInWithCredentials(email, password);
      await refresh();
      toast.success(t("toasts.signedIn"));
      router.replace("/overview");
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "";
      setError(/401|credentials|sign-in/i.test(msg) ? t("login.invalid") : msg || t("toasts.errorGeneric"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-dvh lg:grid-cols-[46%_54%]">
      <BrandPanel />
      <main className="flex items-center justify-center px-6 py-10">
        <div className="w-full max-w-sm">
          {mode === "checking" ? (
            <p className="text-sm text-muted-foreground" role="status">{t("common.loading")}</p>
          ) : mode === "bootstrap" ? (
            <>
              <div className="mb-6 flex items-center gap-3">
                <span className="flex size-10 items-center justify-center rounded-xl bg-[color-mix(in_oklab,var(--primary)_15%,transparent)]">
                  <UserPlus className="size-5 text-primary" aria-hidden />
                </span>
                <div>
                  <h1 className="text-xl font-extrabold leading-7">{t("login.bootstrapTitle")}</h1>
                  <p className="text-sm text-muted-foreground">{t("login.subtitle")}</p>
                </div>
              </div>
              <p className="mb-5 rounded-lg border border-dashed bg-muted/40 px-3.5 py-2.5 text-[13px] leading-6 text-muted-foreground">
                {t("login.bootstrapHint")}
              </p>
              <form onSubmit={submit} className="space-y-4" noValidate>
                <div className="grid gap-2">
                  <Label htmlFor="email">{t("login.email")}</Label>
                  <Input
                    id="email" type="email" required autoComplete="username" dir="ltr"
                    className="text-start"
                    value={email} onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="name">{t("login.yourName")}</Label>
                  <Input id="name" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="org">{t("login.orgName")}</Label>
                  <Input id="org" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="pw">{t("login.password")}</Label>
                  <Input
                    id="pw" type="password" required minLength={8} autoComplete="new-password" dir="ltr"
                    className="text-start"
                    value={password} onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                {error ? (
                  <p role="alert" className="text-sm font-semibold text-[var(--severity-critical)]">
                    {error}
                  </p>
                ) : null}
                <Button type="submit" className="w-full" disabled={busy}>
                  <KeyRound className="size-4" aria-hidden />
                  {busy ? t("login.working") : t("login.bootstrapSubmit")}
                </Button>
              </form>
            </>
          ) : (
            <>
              <div className="mb-6 flex items-center gap-3">
                <span className="flex size-10 items-center justify-center rounded-xl bg-[color-mix(in_oklab,var(--primary)_15%,transparent)]">
                  <ShieldCheck className="size-5 text-primary" aria-hidden />
                </span>
                <div>
                  <h1 className="text-xl font-extrabold leading-7">{t("login.title")}</h1>
                  <p className="text-sm text-muted-foreground">{t("login.subtitle")}</p>
                </div>
              </div>
              <form onSubmit={submit} className="space-y-4" noValidate>
                <div className="grid gap-2">
                  <Label htmlFor="email">{t("login.email")}</Label>
                  <Input
                    id="email" type="email" required autoComplete="username" dir="ltr"
                    className="text-start"
                    value={email} onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="pw">{t("login.password")}</Label>
                  <Input
                    id="pw" type="password" required autoComplete="current-password" dir="ltr"
                    className="text-start"
                    value={password} onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                {error ? (
                  <p role="alert" className="text-sm font-semibold text-[var(--severity-critical)]">
                    {error}
                  </p>
                ) : null}
                <Button type="submit" className="w-full" disabled={busy}>
                  <KeyRound className="size-4" aria-hidden />
                  {busy ? t("login.working") : t("login.submit")}
                </Button>
              </form>
              <p className="mt-5 text-center text-xs leading-5 text-muted-foreground">
                {t("login.secureNote")}
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
