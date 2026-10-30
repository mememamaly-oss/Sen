"use client";

// P2-E (2026-10-31): PUBLIC landing (root). The platform itself moved behind
// /login + the (app) server guard; landing/docs/demo stay reachable without
// a session so a prospect can read and try before any sign-up.
// Authenticated visitors get a direct console link — no forced redirect.

import Link from "next/link";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, BookOpen, Gauge, Play, ShieldCheck, TerminalSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";

export default function LandingPage() {
  const { ready, me } = useSession();
  const router = useRouter();
  const { t } = useI18n();

  // deep links keep working: authenticated users may jump straight in
  useEffect(() => {
    if (ready && me && typeof window !== "undefined" && window.location.hash === "#app") {
      router.replace("/overview");
    }
  }, [ready, me, router]);

  return (
    <div className="relative min-h-dvh overflow-hidden">
      <div className="scanline pointer-events-none absolute inset-0 opacity-25" aria-hidden />
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(120% 90% at 85% 10%, color-mix(in oklab, var(--primary) 20%, var(--background)) 0%, var(--background) 55%), var(--background)",
        }}
        aria-hidden
      />

      <main className="relative mx-auto flex w-full max-w-6xl flex-col gap-14 px-5 py-14 lg:py-20">
        {/* brand + nav */}
        <header className="flex flex-wrap items-center gap-4">
          <svg viewBox="0 0 32 32" className="size-10" aria-hidden>
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
            <p className="text-xl font-extrabold tracking-tight">{t("brand.name")}</p>
            <p className="text-xs font-medium text-muted-foreground">{t("brand.tagline")}</p>
          </div>
          <nav className="ms-auto flex flex-wrap items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <Link href="/docs">{t("landing.cta.docs")}</Link>
            </Button>
            <Button asChild variant="ghost" size="sm">
              <Link href="/demo">{t("landing.cta.demo")}</Link>
            </Button>
            <Button asChild size="sm">
              <Link href={ready && me ? "/overview" : "/login"}>
                {ready && me ? <>{t("landing.cta.login")}<ArrowLeft className="size-3.5" aria-hidden /></> : t("landing.cta.login")}
              </Link>
            </Button>
          </nav>
        </header>

        {/* hero */}
        <section className="max-w-3xl">
          <h1 className="text-3xl font-extrabold leading-tight tracking-tight sm:text-4xl">
            {t("landing.heroTagline")}
          </h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
            {t("landing.heroSub")}
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-3">
            <Button asChild size="lg">
              <Link href="/demo">
                <Play className="size-4" aria-hidden /> {t("landing.cta.demo")}
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link href="/login">{t("landing.cta.login")}</Link>
            </Button>
          </div>
        </section>

        {/* stats strip */}
        <section className="grid gap-3 sm:grid-cols-3">
          {(
            [
              ["replay", t("landing.stats.determinism"), ShieldCheck],
              ["compliance", t("landing.stats.compliance"), Gauge],
              ["honesty", t("landing.stats.honesty"), BookOpen],
            ] as const
          ).map(([key, label, Icon]) => (
            <div key={key} className="card-elevated rounded-xl border bg-card p-4">
              <div className="flex items-center gap-2.5">
                <Icon className="size-4 text-primary" aria-hidden />
                <p className="text-sm font-bold">{label}</p>
              </div>
            </div>
          ))}
        </section>

        {/* pillars */}
        <section className="grid gap-4 lg:grid-cols-3">
          {(
            [
              ["replay", TerminalSquare],
              ["compliance", ShieldCheck],
              ["honesty", BookOpen],
            ] as const
          ).map(([key, Icon]) => (
            <div key={key} className="rounded-2xl border bg-card p-5">
              <div className="flex items-center gap-2.5">
                <span className="flex size-8 items-center justify-center rounded-lg bg-primary/10">
                  <Icon className="size-4 text-primary" aria-hidden />
                </span>
                <h2 className="text-sm font-extrabold">{t(`landing.pillars.${key}Title`)}</h2>
              </div>
              <p className="mt-3 text-[13px] leading-6 text-muted-foreground">
                {t(`landing.pillars.${key}Body`)}
              </p>
            </div>
          ))}
        </section>

        {/* footer note */}
        <footer className="flex flex-wrap items-center gap-3 border-t pt-6 text-xs text-muted-foreground">
          <Badge variant="outline" className="num" dir="ltr">DAST · deterministic</Badge>
          <span>{t("landing.publicNote")}</span>
          <Link className="font-semibold text-primary hover:underline" href="/docs">
            {t("landing.cta.docs")} →
          </Link>
        </footer>
      </main>
    </div>
  );
}
