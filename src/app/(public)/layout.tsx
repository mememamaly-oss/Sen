"use client";

// P2-E: the PUBLIC shell for /docs and /demo — a light top bar (no app nav,
// no org context) + footer. Public pages must render without a session.

import Link from "next/link";
import { BookOpen, LogIn } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/ui/i18n";
import { useSession } from "@/lib/ui/session";

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const { ready, me } = useSession();

  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-30 border-b bg-background/85 backdrop-blur">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center gap-3 px-5 py-3">
          <Link href="/" className="flex items-center gap-2.5 leading-tight">
            <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
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
            <span className="text-sm font-extrabold tracking-tight">{t("brand.name")}</span>
          </Link>
          <nav className="ms-auto flex items-center gap-1.5">
            <Button asChild variant="ghost" size="sm">
              <Link href="/docs">
                <BookOpen className="size-3.5" aria-hidden /> {t("landing.cta.docs")}
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link href={ready && me ? "/overview" : "/login"}>
                <LogIn className="size-3.5" aria-hidden /> {t("landing.cta.login")}
              </Link>
            </Button>
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl px-5 py-8">{children}</main>
      <footer className="border-t py-5 text-center text-xs text-muted-foreground">
        {t("landing.publicNote")}
      </footer>
    </div>
  );
}
