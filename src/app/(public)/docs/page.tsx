"use client";

// P2-E: public docs index — quickstart + section cards.
// Content mirrors the repo docs (README, docs/, .github/workflows) — no
// invented claims; every technical statement is verifiable in-repo.

import Link from "next/link";
import { ArrowLeft, BookOpen, Cloud, GitBranch, ShieldCheck, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/ui/i18n";

export default function DocsPage() {
  const { t } = useI18n();

  const sections = [
    { href: "/docs/compliance", key: "compliance", Icon: ShieldCheck },
    { href: "/docs/ci", key: "ci", Icon: GitBranch },
    { href: "/docs/deployment", key: "deployment", Icon: Cloud },
    { href: "/docs/security", key: "security", Icon: Zap },
  ] as const;

  return (
    <article className="max-w-3xl">
      <h1 className="text-2xl font-extrabold tracking-tight">{t("docs.title")}</h1>
      <p className="mt-2 text-sm text-muted-foreground">{t("docs.subtitle")}</p>

      <section className="mt-8">
        <h2 className="flex items-center gap-2 text-lg font-extrabold">
          <Zap className="size-4 text-primary" aria-hidden /> {t("docs.quickstart")}
        </h2>
        <ol className="mt-4 space-y-3 text-sm leading-6 text-muted-foreground">
          <li>
            <b className="text-foreground">1.</b>{" "}
            <span dir="ltr" className="num">cp .env.example .env</span> — set{" "}
            <code dir="ltr">NEXTAUTH_SECRET</code> and{" "}
            <code dir="ltr">POSTGRES_PASSWORD</code>.
          </li>
          <li>
            <b className="text-foreground">2.</b>{" "}
            <span dir="ltr" className="num">bash scripts/pg_dev_start.sh</span> — an
            unprivileged PostgreSQL cluster (127.0.0.1:55432); its URI is printed and
            goes into <code dir="ltr">DATABASE_URL</code>.
          </li>
          <li>
            <b className="text-foreground">3.</b>{" "}
            <span dir="ltr" className="num">bunx prisma migrate deploy</span> then{" "}
            <span dir="ltr" className="num">bun run dev</span> — first visit to{" "}
            <code dir="ltr">/login</code> activates the platform (first user = org owner).
          </li>
          <li>
            <b className="text-foreground">4.</b> Register the managed demo target from the
            Targets page (one click) or point a scan at your own app — the engine runs a
            real scan and every verified finding carries its evidence chain.
          </li>
        </ol>
        <div className="mt-4 flex flex-wrap gap-2">
          <Badge variant="outline" dir="ltr" className="num">engine: burhan-core/4.4.0</Badge>
          <Badge variant="outline" dir="ltr" className="num">Next 16 · React 19 · Prisma 6 · PostgreSQL</Badge>
          <Badge variant="outline" dir="ltr" className="num">next-auth 4 · scrypt</Badge>
        </div>
      </section>

      <section className="mt-10 grid gap-3 sm:grid-cols-2">
        {sections.map(({ href, key, Icon }) => (
          <Link
            key={key}
            href={href}
            className="group rounded-2xl border bg-card p-5 transition-colors hover:border-primary/60"
          >
            <div className="flex items-center gap-2.5">
              <span className="flex size-8 items-center justify-center rounded-lg bg-primary/10">
                <Icon className="size-4 text-primary" aria-hidden />
              </span>
              <h3 className="text-sm font-extrabold">{t(`docs.${key}`)}</h3>
              <ArrowLeft className="ms-auto size-4 text-muted-foreground transition-transform group-hover:-translate-x-1" aria-hidden />
            </div>
          </Link>
        ))}
      </section>

      <p className="mt-8 flex items-center gap-2 text-xs text-muted-foreground">
        <BookOpen className="size-3.5" aria-hidden />
        <span dir="ltr" className="num">
          README.md · KNOWN_LIMITATIONS.md · docs/ (repo)
        </span>
      </p>
    </article>
  );
}
