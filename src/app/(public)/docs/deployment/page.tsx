"use client";

// P2-D/P2-B: public deployment guide — PostgreSQL + auth + engine bridge.

import { Cloud } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useI18n } from "@/lib/ui/i18n";

export default function DeploymentDocsPage() {
  const { t } = useI18n();
  return (
    <article className="max-w-3xl" dir="auto">
      <h1 className="flex items-center gap-2 text-2xl font-extrabold tracking-tight">
        <Cloud className="size-5 text-primary" aria-hidden /> {t("docs.deployment")}
      </h1>

      <section className="mt-6">
        <h2 className="text-sm font-extrabold" dir="ltr">1 · PostgreSQL (platform DB)</h2>
        <p className="mt-2 text-xs leading-6 text-muted-foreground" dir="ltr">
          The platform/tenant database is PostgreSQL (Prisma). The engine’s
          per-target stores stay SQLite by design — deterministic,
          file-per-target under <code>saas-data/stores</code>.
        </p>
        <pre className="num mt-3 overflow-auto rounded-xl border bg-muted/50 p-4 text-[11.5px] leading-5" dir="ltr">
{`# docker compose (loopback only) — or any managed PostgreSQL
POSTGRES_PASSWORD=$(openssl rand -hex 16) docker compose up -d
export DATABASE_URL=postgresql://burhan:<pw>@127.0.0.1:5432/burhan
bunx prisma migrate deploy
bash scripts/verify_postgres.sh   # end-to-end verification`}
        </pre>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-extrabold" dir="ltr">2 · Auth (next-auth 4)</h2>
        <ul className="mt-2 space-y-1.5 text-xs leading-6 text-muted-foreground" dir="ltr">
          <li><code>NEXTAUTH_SECRET</code> — required, fails loudly in production if missing.</li>
          <li><code>NEXTAUTH_URL</code> — the public origin as browsers see it (required behind the Caddy proxy).</li>
          <li>Sessions: JWT, 12h. Passwords: scrypt. Login: per-email + per-IP sliding-window rate limit, timing-equalized for unknown accounts.</li>
          <li>Every <code>(app)</code> page is server-guarded (layout-level redirect) — the client-side redirect is UX only, never the boundary.</li>
        </ul>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-extrabold" dir="ltr">3 · Engine bridge</h2>
        <pre className="num mt-3 overflow-auto rounded-xl border bg-muted/50 p-4 text-[11.5px] leading-5" dir="ltr">
{`BURHAN_PYTHON=python3            # default
BURHAN_DATA_DIR=/var/lib/sen      # scans/ stores/ reports/
BURHAN_ALLOW_PRIVATE_TARGETS=0    # lab mode OFF by default`}
        </pre>
        <p className="mt-2 text-xs text-muted-foreground" dir="ltr">
          SSRF posture: private-network egress is allowed only for the managed
          demo target, or when the operator explicitly opts into lab mode —
          never a per-request client decision. The engine re-validates every
          connection (DNS answers and redirect hops included) and fails closed.
        </p>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-extrabold" dir="ltr">4 · Reverse proxy</h2>
        <p className="mt-2 text-xs leading-6 text-muted-foreground" dir="ltr">
          Caddyfile at the repo root: TLS automatic, <code>X-Real-IP</code> /
          <code> X-Forwarded-For</code> forwarded (used by the login rate limiter),
          loopback-only upstreams.
        </p>
      </section>

      <div className="mt-8 flex flex-wrap gap-2">
        <Badge variant="outline" dir="ltr" className="num">Node/Bun · Next 16 standalone</Badge>
        <Badge variant="outline" dir="ltr" className="num">PostgreSQL 17</Badge>
        <Badge variant="outline" dir="ltr" className="num">Caddy 2</Badge>
      </div>
    </article>
  );
}
